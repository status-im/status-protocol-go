package whisper

import (
	"context"
	"crypto/ecdsa"

	whisper "github.com/status-im/whisper/whisperv6"

	"github.com/status-im/status-protocol-go/subscription"
)

type KeysManager interface {
	PrivateKey() *ecdsa.PrivateKey
	AddOrGetKeyPair(*ecdsa.PrivateKey) (string, error)
	AddOrGetSymKeyFromPassword(password string) (string, error)
	GetRawSymKey(string) ([]byte, error)
}

// WhisperTransport defines an interface which each Whisper transport
// should conform to.
type WhisperTransport interface {
	KeysManager() KeysManager
	Subscribe(context.Context, chan<- *whisper.ReceivedMessage, *whisper.Filter) (*subscription.Subscription, error)
	Send(context.Context, whisper.NewMessage) ([]byte, error)
	Request(context.Context, RequestOptions) error
}

type RequestOptions struct {
	Topics   []whisper.TopicType
	Password string
	Limit    int
	From     int64 // in seconds
	To       int64 // in seconds
}
