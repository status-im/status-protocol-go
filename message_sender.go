package statusproto

import (
	"context"
	"crypto/ecdsa"

	"github.com/golang/protobuf/proto"
	"github.com/status-im/status-protocol-go/encryption"
	transport "github.com/status-im/status-protocol-go/transport/whisper"
	whisper "github.com/status-im/whisper/whisperv6"
)

type Sender interface {
	SendPublic(string, *encryption.ProtocolMessageSpec) ([]byte, error)
	SendPrivate(*encryption.ProtocolMessageSpec) ([]byte, error)
	SendPublicRaw(string, []byte) ([]byte, error)
}

type whisperSender struct {
	privKey                      *ecdsa.PrivateKey
	w                            *whisper.Whisper
	api                          *whisper.PublicWhisperAPI
	encryption                   *encryption.Protocol
	persistence                  *sqlitePersistence
	transport                    *transport.WhisperServiceTransport
	genericDiscoveryTopicEnabled bool
}

func (w *whisperSender) messageSpecToWhisper(spec *encryption.ProtocolMessageSpec) (whisper.NewMessage, error) {
	var newMessage whisper.NewMessage

	payload, err := proto.Marshal(spec.Message)
	if err != nil {
		return newMessage, err
	}

	newMessage = whisper.NewMessage{
		TTL:       whisperTTL,
		Payload:   payload,
		PowTarget: whisperPoW,
		PowTime:   whisperPoWTime,
	}
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
