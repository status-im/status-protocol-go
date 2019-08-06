package statusproto

import (
	"context"
	"crypto/ecdsa"

	transport "github.com/status-im/status-protocol-go/transport/whisper"
	whisper "github.com/status-im/whisper/whisperv6"
)

type LegacyMessenger struct {
	*Messenger
}

func NewLegacyMessenger(
	identity *ecdsa.PrivateKey,
	server transport.Server,
	shh *whisper.Whisper,
	installationID string,
	opts ...Option,
) (*LegacyMessenger, error) {
	messenger, err := NewMessenger(
		identity,
		server,
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
func (m *LegacyMessenger) SendRaw(ctx context.Context, chat Chat, data []byte) ([]byte, whisper.NewMessage, error) {
	message := &Message{
		sigPubKey: &m.identity.PublicKey,
		transportMeta: transportMeta{
			chatID: chat.ID,
			public: chat.ChatType == ChatTypePublic,
		},
		decryptedPayload: data,
	}
	if err := m.send(message, true); err != nil {
		return nil, whisper.NewMessage{}, err
	}
	return message.ID(), message.transportMeta.newMessage, nil
}
