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
	SubscribePublic(context.Context, string, chan<- *whisper.ReceivedMessage) (*subscription.Subscription, error)
	SubscribePrivate(context.Context, *ecdsa.PublicKey, chan<- *whisper.ReceivedMessage) (*subscription.Subscription, error)
	SendPublic(context.Context, whisper.NewMessage, string) ([]byte, error)
	SendPrivateWithSharedSecret(context.Context, whisper.NewMessage, *ecdsa.PublicKey, []byte) ([]byte, error)
	SendPrivateWithPartitioned(context.Context, whisper.NewMessage, *ecdsa.PublicKey) ([]byte, error)
	SendPrivateOnDiscovery(context.Context, whisper.NewMessage, *ecdsa.PublicKey) ([]byte, error)
	Request(context.Context, RequestOptions) error
}

type RequestOptions struct {
	Topics   []whisper.TopicType
	Password string
	Limit    int
	From     int64 // in seconds
	To       int64 // in seconds
}
