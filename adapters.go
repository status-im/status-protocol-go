package statusproto

import (
	"context"
	"crypto/ecdsa"
	"log"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	whisper "github.com/status-im/whisper/whisperv6"

	"github.com/status-im/status-protocol-go/encryption"
	"github.com/status-im/status-protocol-go/subscription"
	transport "github.com/status-im/status-protocol-go/transport/whisper"
	protocol "github.com/status-im/status-protocol-go/v1"
)

// Whisper message properties.
const (
	whisperTTL     = 15
	whisperPoW     = 0.002
	whisperPoWTime = 5
)

type whisperAdapter struct {
	privateKey *ecdsa.PrivateKey
	transport  transport.WhisperTransport
	protocol   *encryption.Protocol
}

func newWhisperAdapter(pk *ecdsa.PrivateKey, t transport.WhisperTransport, p *encryption.Protocol) *whisperAdapter {
	return &whisperAdapter{
		privateKey: pk,
		transport:  t,
		protocol:   p,
	}
}

func (a *whisperAdapter) SubscribePublic(ctx context.Context, chatID string, messages chan<- *protocol.Message) (*subscription.Subscription, error) {
	in := make(chan *whisper.ReceivedMessage, 1024)
	sub, err := a.transport.SubscribePublic(ctx, chatID, in)
	if err != nil {
		return nil, err
	}

	go func() {
		for item := range in {
			whisperMessage := whisper.ToWhisperMessage(item)
			message, err := a.decodeMessage(whisperMessage)
			if err != nil {
				log.Printf("failed to decode message %#x: %v", item.EnvelopeHash.Bytes(), err)
				continue
			}
			messages <- message
		}
	}()

	return sub, nil
}

func (a *whisperAdapter) SubscribePrivate(ctx context.Context, publicKey *ecdsa.PublicKey, messages chan<- *protocol.Message) (*subscription.Subscription, error) {
	in := make(chan *whisper.ReceivedMessage, 1024)
	sub, err := a.transport.SubscribePrivate(ctx, publicKey, in)
	if err != nil {
		return nil, err
	}

	go func() {
		for item := range in {
			whisperMessage := whisper.ToWhisperMessage(item)

			publicKey, err := crypto.UnmarshalPubkey(whisperMessage.Sig)
			if err != nil {
				log.Printf("failed to get a public key from message sig: %v", err)
				continue
			}

			var protocolMessage encryption.ProtocolMessage

			err = proto.Unmarshal(whisperMessage.Payload, &protocolMessage)
			if err != nil {
				log.Printf("failed to unmarshal payload: %v", err)
			}

			payload, err := a.protocol.HandleMessage(a.privateKey, publicKey, &protocolMessage, whisperMessage.Hash)
			if err != nil {
				log.Printf("failed to handle a message by encryption protocol: %v", err)
			}

			whisperMessage.Payload = payload

			message, err := a.decodeMessage(whisperMessage)
			if err != nil {
				log.Printf("failed to decode message %#x: %v", item.EnvelopeHash.Bytes(), err)
				continue
			}

			if err := a.protocol.ConfirmMessageProcessed(item.EnvelopeHash.Bytes()); err != nil {
				log.Printf("failed to confirm a message: %v", err)
			}

			messages <- message
		}
	}()

	return sub, nil
}

func (a *whisperAdapter) decodeMessage(message *whisper.Message) (*protocol.Message, error) {
	publicKey, err := crypto.UnmarshalPubkey(message.Sig)
	if err != nil {
		return nil, err
	}

	decoded, err := protocol.DecodeMessage(message.Payload)
	if err != nil {
		return nil, err
	}
	decoded.ID = message.Hash
	decoded.SigPubKey = publicKey

	return &decoded, nil
}

func (a *whisperAdapter) SendPublic(ctx context.Context, chatID string, data []byte, clock int64) ([]byte, error) {
	message := protocol.CreatePublicTextMessage(data, clock, chatID)

	encodedMessage, err := protocol.EncodeMessage(message)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode message")
	}

	newMessage := whisper.NewMessage{
		TTL:       whisperTTL,
		Payload:   encodedMessage,
		PowTarget: whisperPoW,
		PowTime:   whisperPoWTime,
	}

	return a.transport.SendPublic(ctx, newMessage, chatID)
}

func (a *whisperAdapter) SendPrivate(ctx context.Context, publicKey *ecdsa.PublicKey, data []byte, clock int64) ([]byte, error) {
	// TODO: calculate chatID
	message := protocol.CreatePrivateTextMessage(data, clock, "")

	encodedMessage, err := protocol.EncodeMessage(message)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode message")
	}

	messageSpec, err := a.protocol.BuildDirectMessage(a.privateKey, publicKey, encodedMessage)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt message")
	}

	newMessage, err := a.messageSpecToWhisper(messageSpec)
	if err != nil {
		return nil, err
	}

	if messageSpec.SharedSecret != nil {
		return a.transport.SendPrivateWithSharedSecret(ctx, *newMessage, publicKey, messageSpec.SharedSecret)
	} else if messageSpec.PartitionedTopicMode() == encryption.PartitionTopicV1 {
		return a.transport.SendPrivateWithPartitioned(ctx, *newMessage, publicKey)
	} else {
		return a.transport.SendPrivateOnDiscovery(ctx, *newMessage, publicKey)
	}
}

func (a *whisperAdapter) messageSpecToWhisper(spec *encryption.ProtocolMessageSpec) (*whisper.NewMessage, error) {
	payload, err := proto.Marshal(spec.Message)
	if err != nil {
		return nil, err
	}

	newMessage := whisper.NewMessage{
		TTL:       whisperTTL,
		Payload:   payload,
		PowTarget: whisperPoW,
		PowTime:   whisperPoWTime,
	}

	return &newMessage, nil
}
