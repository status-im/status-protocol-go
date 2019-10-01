package statusproto

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/pkg/errors"

	"github.com/status-im/status-protocol-go/crypto"
)

const (
	MembershipUpdateChatCreated   = "chat-created"
	MembershipUpdateNameChanged   = "name-changed"
	MembershipUpdateMembersAdded  = "members-added"
	MembershipUpdateMemberJoined  = "member-joined"
	MembershipUpdateMemberRemoved = "member-removed"
	MembershipUpdateAdminsAdded   = "admins-added"
	MembershipUpdateAdminRemoved  = "admin-removed"
)

// MembershipUpdateMessage is a message used to propagate information
// about group membership changes.
// For more information, see https://github.com/status-im/specs/blob/master/status-group-chats-spec.md.
type MembershipUpdateMessage struct {
	ChatID  string             `json:"chatId"` // UUID concatenated with hex-encoded public key of the creator for the chat
	Updates []MembershipUpdate `json:"updates"`
	Message *Message           `json:"message"` // optional message
}

func (m *MembershipUpdateMessage) Process() error {
	for idx, update := range m.Updates {
		if err := update.extractFrom(); err != nil {
			return err
		}
		m.Updates[idx] = update
	}
	return nil
}

type MembershipUpdate struct {
	ChatID    string                  `json:"chatId"`
	Signature string                  `json:"signature"`
	Events    []MembershipUpdateEvent `json:"events"`

	From *ecdsa.PublicKey // extracted from signature
}

// Sign creates a signature from MembershipUpdateEvents
// and updates MembershipUpdate's signature.
// It follows the algorithm describe in the spec:
// https://github.com/status-im/specs/blob/master/status-group-chats-spec.md#signature.
func (u *MembershipUpdate) Sign(identity *ecdsa.PrivateKey) error {
	signature, err := createMembershipUpdateSignature(u.ChatID, u.Events, identity)
	if err != nil {
		return err
	}
	u.Signature = signature
	return nil
}

func (u *MembershipUpdate) extractFrom() error {
	content, err := stringifyMembershipUpdateEvents(u.ChatID, u.Events)
	if err != nil {
		return errors.Wrap(err, "failed to stringify events")
	}
	signatureBytes, err := hex.DecodeString(u.Signature)
	if err != nil {
		return errors.Wrap(err, "failed to decode signature")
	}
	publicKey, err := crypto.ExtractSignature(content, signatureBytes)
	if err != nil {
		return errors.Wrap(err, "failed to extract signature")
	}
	u.From = publicKey
	return nil
}

func stringifyMembershipUpdateEvents(chatID string, events []MembershipUpdateEvent) ([]byte, error) {
	sort.Slice(events, func(i, j int) bool {
		return events[i].ClockValue < events[j].ClockValue
	})
	tuples := make([]interface{}, len(events))
	for idx, event := range events {
		tuples[idx] = tupleMembershipUpdateEvent(event)
	}
	structureToSign := []interface{}{
		tuples,
		chatID,
	}
	return json.Marshal(structureToSign)
}

func createMembershipUpdateSignature(chatID string, events []MembershipUpdateEvent, identity *ecdsa.PrivateKey) (string, error) {
	data, err := stringifyMembershipUpdateEvents(chatID, events)
	if err != nil {
		return "", err
	}
	return crypto.SignBytesAsHex(data, identity)
}

type MembershipUpdateEvent struct {
	Type       string   `json:"type"`
	ClockValue int64    `json:"clockValue"`
	Member     string   `json:"member,omitempty"`  // in "member-joined", "member-removed" and "admin-removed" events
	Members    []string `json:"members,omitempty"` // in "members-added" and "admins-added" events
	Name       string   `json:"name,omitempty"`    // name of the group chat
}

func NewChatCreatedEvent(name string, clock int64) MembershipUpdateEvent {
	return MembershipUpdateEvent{
		Type:       MembershipUpdateChatCreated,
		Name:       name,
		ClockValue: clock,
	}
}

func NewNameChangedEvent(name string, clock int64) MembershipUpdateEvent {
	return MembershipUpdateEvent{
		Type:       MembershipUpdateNameChanged,
		Name:       name,
		ClockValue: clock,
	}
}

func NewMembersAddedEvent(members []string, clock int64) MembershipUpdateEvent {
	return MembershipUpdateEvent{
		Type:       MembershipUpdateMembersAdded,
		Members:    members,
		ClockValue: clock,
	}
}

func NewMemberJoinedEvent(member string, clock int64) MembershipUpdateEvent {
	return MembershipUpdateEvent{
		Type:       MembershipUpdateMemberJoined,
		Member:     member,
		ClockValue: clock,
	}
}

func NewAdminsAddedEvent(admins []string, clock int64) MembershipUpdateEvent {
	return MembershipUpdateEvent{
		Type:       MembershipUpdateAdminsAdded,
		Members:    admins,
		ClockValue: clock,
	}
}

func NewMemberRemovedEvent(member string, clock int64) MembershipUpdateEvent {
	return MembershipUpdateEvent{
		Type:       MembershipUpdateMemberRemoved,
		Member:     member,
		ClockValue: clock,
	}
}

func NewAdminRemovedEvent(admin string, clock int64) MembershipUpdateEvent {
	return MembershipUpdateEvent{
		Type:       MembershipUpdateAdminRemoved,
		Member:     admin,
		ClockValue: clock,
	}
}

// EncodeMembershipUpdateMessage encodes a MembershipUpdateMessage using Transit serialization.
func EncodeMembershipUpdateMessage(value MembershipUpdateMessage) ([]byte, error) {
	var buf bytes.Buffer
	encoder := NewMessageEncoder(&buf)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var membershipUpdateEventFieldNamesCompat = map[string]string{
	"ClockValue": "clock-value",
	"Name":       "name",
	"Type":       "type",
	"Member":     "member",
	"Members":    "members",
}

func tupleMembershipUpdateEvent(update MembershipUpdateEvent) [][]interface{} {
	// Sort all slices first.
	sort.Slice(update.Members, func(i, j int) bool {
		return update.Members[i] < update.Members[j]
	})
	v := reflect.ValueOf(update)
	result := make([][]interface{}, 0, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		fieldName := v.Type().Field(i).Name
		if name, exists := membershipUpdateEventFieldNamesCompat[fieldName]; exists {
			fieldName = name
		}
		field := v.Field(i)
		if !isZeroValue(field) {
			result = append(result, []interface{}{fieldName, field.Interface()})
		}
	}
	// Sort the result lexicographically.
	// We know that the first item of a tuple is a string
	// because it's a field name.
	sort.Slice(result, func(i, j int) bool {
		return result[i][0].(string) < result[j][0].(string)
	})
	return result
}

type MembershipUpdateFlat struct {
	MembershipUpdateEvent
	From *ecdsa.PublicKey
}

type Group struct {
	chatID   string
	events   []MembershipUpdateFlat
	admins   []string
	contacts []string
}

func NewGroup(chatID string, events []MembershipUpdateFlat) *Group {
	g := Group{
		chatID: chatID,
		events: events,
	}
	g.init()
	return &g
}

func (g *Group) sortEvents() {
	sort.Slice(g.events, func(i, j int) bool {
		return g.events[i].ClockValue < g.events[j].ClockValue
	})
}

func (g *Group) init() {
	g.sortEvents()

	for _, event := range g.events {
		switch event.Name {
		case MembershipUpdateAdminsAdded:
			g.admins = append(g.admins, event.Members...)
		case MembershipUpdateAdminRemoved:
			g.admins = stringSliceFilter(g.admins, func(item string) bool { return item != event.Member })
		case MembershipUpdateMembersAdded:
			g.contacts = append(g.contacts, event.Members...)
		case MembershipUpdateMemberRemoved:
			g.contacts = stringSliceFilter(g.contacts, func(item string) bool { return item != event.Member })
		case MembershipUpdateMemberJoined:
			g.contacts = append(g.contacts, event.Member)
		}
	}
}

func (g Group) ValidChatID() bool {
	creator, err := g.Creator()
	if err != nil || creator == "" {
		return false
	}
	return strings.HasSuffix(g.chatID, creator)
}

func (g Group) LastClockValue() int64 {
	if len(g.events) == 0 {
		return 0
	}
	return g.events[len(g.events)-1].ClockValue
}

func (g Group) Creator() (*ecdsa.PublicKey, error) {
	if len(g.events) == 0 {
		return nil, errors.New("no events in the group")
	}
	first := g.events[0]
	if first.Name != MembershipUpdateChatCreated {
		return nil, fmt.Errorf("expected first event to be 'chat-created', got %s", first.Name)
	}
	return first.From, nil
}

// ValidateEvent returns true if a given event is valid.
func (g Group) ValidateEvent(from string, event MembershipUpdateEvent) bool {
	switch event.Type {
	case MembershipUpdateChatCreated:
		return len(g.admins) == 0 && len(g.contacts) == 0
	case MembershipUpdateNameChanged:
		return stringSliceContains(g.admins, from) && len(event.Name) > 0
	case MembershipUpdateMembersAdded:
		return stringSliceContains(g.admins, from)
	case MembershipUpdateMemberJoined:
		return stringSliceContains(g.contacts, from) && from == event.Member
	case MembershipUpdateMemberRemoved:
		// Member can remove themselves or admin can remove a member.
		return from == event.Member || (stringSliceContains(g.admins, from) && !stringSliceContains(g.admins, event.Member))
	case MembershipUpdateAdminsAdded:
		return stringSliceContains(g.admins, from) && stringSliceSubset(event.Members, g.contacts)
	case MembershipUpdateAdminRemoved:
		return stringSliceContains(g.admins, from) && from == event.Member
	default:
		return false
	}
}

func stringSliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func stringSliceSubset(subset []string, set []string) bool {
	for _, item1 := range set {
		var found bool
		for _, item2 := range subset {
			if item1 == item2 {
				found = true
				break
			}
		}
		if found {
			return true
		}
	}
	return false
}

func stringSliceFilter(slice []string, keep func(string) bool) []string {
	n := 0
	for _, item := range slice {
		if keep(item) {
			slice[n] = item
		}
	}
	return slice[:n]
}
