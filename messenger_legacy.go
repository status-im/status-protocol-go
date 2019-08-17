package statusproto

import (
	"context"
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/pkg/errors"

	transport "github.com/status-im/status-protocol-go/transport/whisper"
	whisper "github.com/status-im/whisper/whisperv6"
)

type LegacyMessenger struct {
	*Messenger
}

func NewLegacyMessenger(
	identity *ecdsa.PrivateKey,
	shh *whisper.Whisper,
	installationID string,
	opts ...Option,
) (*LegacyMessenger, error) {
	messenger, err := NewMessenger(
		identity,
		shh,
		installationID,
		opts...,
	)
	if err != nil {
		return nil, err
	}
	return &LegacyMessenger{Messenger: messenger}, nil
}

// SendRaw takes encoded data, encrypts it and sends through the wire.
// DEPRECATED
func (m *LegacyMessenger) SendRaw(ctx context.Context, chat Chat, data []byte) ([]byte, *whisper.NewMessage, error) {
	message := &Message{
		sigPubKey: &m.identity.PublicKey,
		transportMeta: transportMeta{
			chatID: chat.ID,
			public: chat.ChatType == ChatTypePublic,
		},
		decryptedPayload: data,
	}
	if err := m.sendRaw(message); err != nil {
		return nil, nil, err
	}
	return message.ID(), message.transportMeta.newMessage, nil
}

func (m *Messenger) sendRaw(message *Message) error {
	return m.processor.SendEncoded(message)
}

// DEPRECATED
func (m *Messenger) RetrieveRawAll() (map[transport.Filter][]*whisper.ReceivedMessage, error) {
	return m.transport.RetrieveMessagesByFilter()
}

// DEPRECATED: required by status-react.
func (m *Messenger) MessageByID(id string) (*MessageLegacy, error) {
	return m.persistence.MessageByID(id)
}

// DEPRECATED: required by status-react.
func (m *Messenger) MessageExists(id string) (bool, error) {
	return m.persistence.MessageExists(id)
}

// DEPRECATED: required by status-react.
func (m *Messenger) MessageByChatID(chatID, cursor string, limit int) ([]*MessageLegacy, string, error) {
	return m.persistence.MessageByChatID(chatID, cursor, limit)
}

// DEPRECATED: required by status-react.
func (m *Messenger) MessagesFrom(from string) ([]*MessageLegacy, error) {
	publicKeyBytes, err := hexutil.Decode(from)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode from argument")
	}
	return m.persistence.MessagesFrom(publicKeyBytes)
}

// DEPRECATED: required by status-react.
func (m *Messenger) UnseenMessageIDs() ([]string, error) {
	ids, err := m.persistence.UnseenMessageIDs()
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(ids))
	for _, id := range ids {
		result = append(result, hexutil.Encode(id))
	}
	return result, nil
}

// DEPRECATED: required by status-react.
func (m *Messenger) SaveMessage(message *MessageLegacy) error {
	return m.persistence.SaveMessage(message)
}

// DEPRECATED: required by status-react.
func (m *Messenger) DeleteMessage(id string) error {
	return m.persistence.DeleteMessage(id)
}

// DEPRECATED: required by status-react.
func (m *Messenger) MarkMessagesSeen(ids ...string) error {
	return m.persistence.MarkMessagesSeen(ids...)
}

// DEPRECATED: required by status-react.
func (m *Messenger) UpdateMessageOutgoingStatus(id, newOutgoingStatus string) error {
	return m.persistence.UpdateMessageOutgoingStatus(id, newOutgoingStatus)
}

// DEPRECATED
func (m *Messenger) LoadFilters(chats []*transport.Filter) ([]*transport.Filter, error) {
	return m.transport.LoadFilters(chats, m.featureFlags.genericDiscoveryTopicEnabled)
}

// DEPRECATED
func (m *Messenger) RemoveFilters(chats []*transport.Filter) error {
	return m.transport.RemoveFilters(chats)
}
