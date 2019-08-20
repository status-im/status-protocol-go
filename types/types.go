package statusprototypes

import (
	"crypto/ecdsa"

	protocol "github.com/status-im/status-protocol-go/v1"
	whisper "github.com/status-im/whisper/whisperv6"
)

type WhisperChatMessages struct {
	Messages []*whisper.ReceivedMessage
	Public   bool
	ChatID   string
}

type ChatMessages struct {
	Messages []*protocol.Message
	Public   bool
	ChatID   string
}

type NegotiatedSecret struct {
	PublicKey *ecdsa.PublicKey
	Key       []byte
}

type WhisperInterface interface {
	NewMessageStore() whisper.MessageStore
	//SubscribeEnvelopeEvents(events chan<- whisper.EnvelopeEvent) events.Subscription
	AddKeyPair(key *ecdsa.PrivateKey) (string, error)
	AddSymKeyDirect(key []byte) (string, error)
	AddSymKeyFromPassword(password string) (string, error)
	DeleteSymKey(id string) bool
	GetSymKey(id string) ([]byte, error)
	Subscribe(f *whisper.Filter) (string, error) // TODO: Replace whisper.Filter type
	GetFilter(id string) *whisper.Filter
	Unsubscribe(id string) error
}
