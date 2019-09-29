package statusproto

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"reflect"
	"sort"

	"github.com/status-im/status-protocol-go/crypto"
)

// MembershipUpdateMessage is a message used to propagate information
// about group membership changes.
// For more information, see https://github.com/status-im/specs/blob/master/status-group-chats-spec.md.
type MembershipUpdateMessage struct {
	ChatID  string             `json:"chatId"` // UUID concatenated with hex-encoded public key of the creator for the chat
	Updates []MembershipUpdate `json:"updates"`
	Message *Message           `json:"message"` // optional message
}

type MembershipUpdate struct {
	ChatID    string                  `json:"chatId"`
	From      string                  `json:"from"`
	Signature string                  `json:"signature"`
	Events    []MembershipUpdateEvent `json:"events"`
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
		Type:       "chat-created",
		Name:       name,
		ClockValue: clock,
	}
}

func NewNameChangedEvent(name string, clock int64) MembershipUpdateEvent {
	return MembershipUpdateEvent{
		Type:       "name-changed",
		Name:       name,
		ClockValue: clock,
	}
}

func NewMembersAddedEvent(members []string, clock int64) MembershipUpdateEvent {
	return MembershipUpdateEvent{
		Type:       "members-added",
		Members:    members,
		ClockValue: clock,
	}
}

func NewMemberJoinedEvent(member string, clock int64) MembershipUpdateEvent {
	return MembershipUpdateEvent{
		Type:       "member-joined",
		Member:     member,
		ClockValue: clock,
	}
}

func NewAdminsAddedEvent(admins []string, clock int64) MembershipUpdateEvent {
	return MembershipUpdateEvent{
		Type:       "admins-added",
		Members:    admins,
		ClockValue: clock,
	}
}

func NewMemberRemovedEvent(member string, clock int64) MembershipUpdateEvent {
	return MembershipUpdateEvent{
		Type:       "member-removed",
		Member:     member,
		ClockValue: clock,
	}
}

func NewAdminRemovedEvent(admin string, clock int64) MembershipUpdateEvent {
	return MembershipUpdateEvent{
		Type:       "admin-removed",
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

// SignMembershipUpdate signs a slice of MembershipUpdateEvents
// and updates MembershipUpdate's signature.
// It follows the algorithm describe in the spec: https://github.com/status-im/specs/blob/master/status-group-chats-spec.md#signature.
func SignMembershipUpdate(update *MembershipUpdate, identity *ecdsa.PrivateKey) error {
	sort.Slice(update.Events, func(i, j int) bool {
		return update.Events[i].ClockValue < update.Events[j].ClockValue
	})
	tuples := make([]interface{}, len(update.Events))
	for idx, event := range update.Events {
		tuples[idx] = tupleMembershipUpdateEvent(event)
	}
	structureToSign := []interface{}{
		tuples,
		update.ChatID,
	}
	data, err := json.Marshal(structureToSign)
	if err != nil {
		return err
	}
	signature, err := crypto.SignBytesAsHex(data, identity)
	if err != nil {
		return err
	}
	update.Signature = signature
	return nil
}

var membershipUpdateEvenFieldNamesCompat = map[string]string{
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
		if name, exists := membershipUpdateEvenFieldNamesCompat[fieldName]; exists {
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
