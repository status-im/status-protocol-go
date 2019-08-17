package statusproto

import (
	"context"
	"crypto/ecdsa"

	"github.com/golang/protobuf/proto"
	"github.com/status-im/status-protocol-go/encryption"
	transport "github.com/status-im/status-protocol-go/transport/whisper"
	whisper "github.com/status-im/whisper/whisperv6"
)

const (
	whisperTTL     = 15
	whisperPoW     = 0.002
	whisperPoWTime = 5
)

var defaultWhisperNewMessage = whisper.NewMessage{
	TTL:       whisperTTL,
	PowTarget: whisperPoW,
	PowTime:   whisperPoWTime,
}

type Sender interface {
	SendPublic(string, *encryption.ProtocolMessageSpec) ([]byte, *whisper.NewMessage, error)
	SendPrivate(*ecdsa.PublicKey, *encryption.ProtocolMessageSpec) ([]byte, *whisper.NewMessage, error)
	SendPublicRaw(string, []byte) ([]byte, *whisper.NewMessage, error)
}

type whisperSender struct {
	w                            *whisper.Whisper
	api                          *whisper.PublicWhisperAPI
	encryption                   *encryption.Protocol
	transport                    *transport.WhisperServiceTransport
	genericDiscoveryTopicEnabled bool
}

var _ Sender = (*whisperSender)(nil)

func (w *whisperSender) messageSpecToWhisper(spec *encryption.ProtocolMessageSpec) (whisper.NewMessage, error) {
	newMessage := defaultWhisperNewMessage
	payload, err := proto.Marshal(spec.Message)
	if err != nil {
		return newMessage, err
	}
	newMessage.Payload = payload
	return newMessage, nil
}

func (w *whisperSender) SendPublic(chatName string, spec *encryption.ProtocolMessageSpec) ([]byte, *whisper.NewMessage, error) {
	newMessage, err := w.messageSpecToWhisper(spec)
	if err != nil {
		return nil, nil, err
	}
	hash, err := w.transport.SendPublic(context.Background(), newMessage, chatName)
	return hash, &newMessage, err
}

func (w *whisperSender) SendPrivate(recipient *ecdsa.PublicKey, spec *encryption.ProtocolMessageSpec) ([]byte, *whisper.NewMessage, error) {
	newMessage, err := w.messageSpecToWhisper(spec)
	if err != nil {
		return nil, nil, err
	}

	var hash []byte

	switch {
	case spec.SharedSecret != nil:
		hash, err = w.transport.SendPrivateWithSharedSecret(context.Background(), newMessage, recipient, spec.SharedSecret)
	case spec.PartitionedTopicMode() == encryption.PartitionTopicV1:
		hash, err = w.transport.SendPrivateWithPartitioned(context.Background(), newMessage, recipient)
	case !w.genericDiscoveryTopicEnabled:
		hash, err = w.transport.SendPrivateWithPartitioned(context.Background(), newMessage, recipient)
	default:
		hash, err = w.transport.SendPrivateOnDiscovery(context.Background(), newMessage, recipient)
	}

	return hash, &newMessage, err
}

// SendPublicRaw sends a raw payload.
// It uses only Whisper encryption.
func (w *whisperSender) SendPublicRaw(chatName string, data []byte) ([]byte, *whisper.NewMessage, error) {
	newMessage := defaultWhisperNewMessage
	newMessage.Payload = data
	hash, err := w.transport.SendPublic(context.Background(), newMessage, chatName)
	return hash, &newMessage, err
}

// SendPrivateRaw sends a raw payload using the discovery topic.
// It uses only Whisper encryption.
// DEPRECATED: use SendPrivate instead.
func (w *whisperSender) SendPrivateRaw(recipient *ecdsa.PublicKey, data []byte) ([]byte, error) {
	newMessage := defaultWhisperNewMessage
	newMessage.Payload = data
	return w.transport.SendPrivateOnDiscovery(context.Background(), newMessage, recipient)
}
