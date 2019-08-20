package whisper

import (
	"context"
	"crypto/ecdsa"

	statusprototypes "github.com/status-im/status-protocol-go/types"
	whisper "github.com/status-im/whisper/whisperv6"
)

type WhisperServiceTransportInterface interface {
	JoinPublic(chatID string) error
	LeavePublic(chatID string) error
	JoinPrivate(publicKey *ecdsa.PublicKey) error
	LeavePrivate(publicKey *ecdsa.PublicKey) error
	// DEPRECATED
	//RetrieveRawAll() (map[filter.Chat][]*whisper.ReceivedMessage, error)
	RetrieveAllMessages() ([]statusprototypes.WhisperChatMessages, error)
	RetrievePublicMessages(chatID string) ([]*whisper.ReceivedMessage, error)
	RetrievePrivateMessages(publicKey *ecdsa.PublicKey) ([]*whisper.ReceivedMessage, error)
	SendPublic(ctx context.Context, newMessage *whisper.NewMessage, chatName string) ([]byte, error)
	SendPrivateWithSharedSecret(ctx context.Context, newMessage *whisper.NewMessage, publicKey *ecdsa.PublicKey, secret []byte) ([]byte, error)
	SendPrivateWithPartitioned(ctx context.Context, newMessage *whisper.NewMessage, publicKey *ecdsa.PublicKey) ([]byte, error)
	SendPrivateOnDiscovery(ctx context.Context, newMessage *whisper.NewMessage, publicKey *ecdsa.PublicKey) ([]byte, error)
	Reset() error
	// DEPRECATED
	LoadFilters(chats []*Filter, genericDiscoveryTopicEnabled bool) ([]*Filter, error)
	// DEPRECATED
	RemoveFilters(chats []*Filter) error
	ProcessNegotiatedSecret(secret statusprototypes.NegotiatedSecret) error
	Track(identifiers [][]byte, hash []byte, newMessage whisper.NewMessage)
	Stop()
}
