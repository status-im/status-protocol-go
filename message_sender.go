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
	SendPublic(string, *encryption.ProtocolMessageSpec) ([]byte, whisper.NewMessage, error)
	SendPrivate(*encryption.ProtocolMessageSpec) ([]byte, whisper.NewMessage, error)
	SendPublicRaw(string, []byte) ([]byte, whisper.NewMessage, error)
}

type whisperSender struct {
	w                            *whisper.Whisper
	api                          *whisper.PublicWhisperAPI
	encryption                   *encryption.Protocol
	transport                    *transport.WhisperServiceTransport
	genericDiscoveryTopicEnabled bool
}

func (w *whisperSender) messageSpecToWhisper(spec *encryption.ProtocolMessageSpec) (whisper.NewMessage, error) {
	newMessage := defaultWhisperNewMessage
	payload, err := proto.Marshal(spec.Message)
	if err != nil {
		return newMessage, err
	}
	newMessage.Payload = payload
	return newMessage, nil
}

func (w *whisperSender) SendPublic(chatName string, spec *encryption.ProtocolMessageSpec) ([]byte, error) {
	newMessage, err := w.messageSpecToWhisper(spec)
	if err != nil {
		return nil, err
	}
	return w.transport.SendPublic(context.Background(), newMessage, chatName)
}

func (w *whisperSender) SendPrivate(recipient *ecdsa.PublicKey, spec *encryption.ProtocolMessageSpec) ([]byte, error) {
	newMessage, err := w.messageSpecToWhisper(spec)
	if err != nil {
		return nil, err
	}

	switch {
	case spec.SharedSecret != nil:
		return w.transport.SendPrivateWithSharedSecret(context.Background(), newMessage, recipient, spec.SharedSecret)
	case spec.PartitionedTopicMode() == encryption.PartitionTopicV1:
		return w.transport.SendPrivateWithPartitioned(context.Background(), newMessage, recipient)
	case !w.genericDiscoveryTopicEnabled:
		return w.transport.SendPrivateWithPartitioned(context.Background(), newMessage, recipient)
	default:
		return w.transport.SendPrivateOnDiscovery(context.Background(), newMessage, recipient)
	}
}

// SendPublicRaw sends a raw payload.
// It uses only Whisper encryption.
func (w *whisperSender) SendPublicRaw(chatName string, data []byte) ([]byte, error) {
	newMessage := defaultWhisperNewMessage
	newMessage.Payload = data
	return w.transport.SendPublic(context.Background(), newMessage, chatName)
}

// SendPrivateRaw sends a raw payload using the discovery topic.
// It uses only Whisper encryption.
// DEPRECATED: use SendPrivate instead.
func (w *whisperSender) SendPrivateRaw(recipient *ecdsa.PublicKey, data []byte) ([]byte, error) {
	newMessage := defaultWhisperNewMessage
	newMessage.Payload = data
	return w.transport.SendPrivateOnDiscovery(context.Background(), newMessage, recipient)
}
