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

// Verify makes sure that the received update message has a valid signature.
// It also extracts public key from the signature available as From field.
// It does not verify the updates and their events. This should be done
// separately using Group struct.
func (m *MembershipUpdateMessage) Verify() error {
	for idx, update := range m.Updates {
		if err := update.extractFrom(); err != nil {
			return errors.Wrapf(err, "failed to extract an author of %d update", idx)
		}
		m.Updates[idx] = update
	}
	return nil
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
	From      string
	Signature string
}

type Group struct {
	chatID  string
	name    string
	updates []MembershipUpdateFlat
	admins  []string
	members []string
}

func NewGroup(chatID string, updates []MembershipUpdateFlat) (*Group, error) {
	g := Group{
		chatID:  chatID,
		updates: updates,
	}
	if err := g.init(); err != nil {
		return nil, err
	}
	return &g, nil
}

func (g *Group) init() error {
	g.sortEvents()

	for _, update := range g.updates {
		valid := g.validateEvent(update.From, update.MembershipUpdateEvent)
		if !valid {
			return fmt.Errorf("invalid event %#+v from %s", update.MembershipUpdateEvent, update.From)
		}
		g.processEvent(update.From, update.MembershipUpdateEvent)
	}

	if !g.validateChatID(g.chatID) {
		return fmt.Errorf("invalid chatID: %s", g.chatID)
	}

	return nil
}

func (g *Group) ProcessEvent(from string, event MembershipUpdateEvent) error {
	if !g.validateEvent(from, event) {
		return fmt.Errorf("invalid event %#+v from %s", event, from)
	}
	g.processEvent(from, event)
	return nil
}

func (g Group) LastClockValue() int64 {
	if len(g.updates) == 0 {
		return 0
	}
	return g.updates[len(g.updates)-1].ClockValue
}

func (g Group) NextClockValue() int64 {
	return g.LastClockValue() + 1
}

func (g Group) creator() (string, error) {
	if len(g.updates) == 0 {
		return "", errors.New("no events in the group")
	}
	first := g.updates[0]
	if first.Name != MembershipUpdateChatCreated {
		return "", fmt.Errorf("expected first event to be 'chat-created', got %s", first.Name)
	}
	return first.From, nil
}

func (g Group) validateChatID(chatID string) bool {
	creator, err := g.creator()
	if err != nil || creator == "" {
		return false
	}
	// TODO: It does not verify that the prefix is a valid UUID.
	//       Improve it so that the prefix follows UUIDv4 spec.
	return strings.HasSuffix(chatID, creator) && chatID != creator
}

// validateEvent returns true if a given event is valid.
func (g Group) validateEvent(from string, event MembershipUpdateEvent) bool {
	switch event.Type {
	case MembershipUpdateChatCreated:
		return len(g.admins) == 0 && len(g.members) == 0
	case MembershipUpdateNameChanged:
		return stringSliceContains(g.admins, from) && len(event.Name) > 0
	case MembershipUpdateMembersAdded:
		return stringSliceContains(g.admins, from)
	case MembershipUpdateMemberJoined:
		return stringSliceContains(g.members, from) && from == event.Member
	case MembershipUpdateMemberRemoved:
		// Member can remove themselves or admin can remove a member.
		return from == event.Member || (stringSliceContains(g.admins, from) && !stringSliceContains(g.admins, event.Member))
	case MembershipUpdateAdminsAdded:
		return stringSliceContains(g.admins, from) && stringSliceSubset(event.Members, g.members)
	case MembershipUpdateAdminRemoved:
		return stringSliceContains(g.admins, from) && from == event.Member
	default:
		return false
	}
}

func (g *Group) processEvent(from string, event MembershipUpdateEvent) {
	switch event.Type {
	case MembershipUpdateChatCreated,
		MembershipUpdateNameChanged:
		g.name = event.Name
	case MembershipUpdateAdminsAdded:
		g.admins = append(g.admins, event.Members...)
	case MembershipUpdateAdminRemoved:
		g.admins = stringSliceFilter(g.admins, func(item string) bool { return item != event.Member })
	case MembershipUpdateMembersAdded:
		g.members = append(g.members, event.Members...)
	case MembershipUpdateMemberRemoved:
		g.members = stringSliceFilter(g.members, func(item string) bool { return item != event.Member })
	case MembershipUpdateMemberJoined:
		g.members = append(g.members, event.Member)
	}
}

func (g *Group) sortEvents() {
	sort.Slice(g.updates, func(i, j int) bool {
		return g.updates[i].ClockValue < g.updates[j].ClockValue
	})
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
			n++
		}
	}
	return slice[:n]
}