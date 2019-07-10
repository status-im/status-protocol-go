package statusproto

import (
	"context"
	"crypto/ecdsa"
	"log"
	"time"

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

// whisperAdapter is a bridge between encryption and transport
// layers.
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
		for {
			select {
			case <-sub.Done():
				return
			case rcvMessage := <-in:
				whisperMessage := whisper.ToWhisperMessage(rcvMessage)
				messageID := rcvMessage.EnvelopeHash.Bytes()
				message, err := a.decodeMessage(whisperMessage)
				if err != nil {
					log.Printf("failed to decode message %#x: %v", messageID, err)
					continue
				}
				messages <- message
			}
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
		for {
			select {
			case <-sub.Done():
				return
			case item := <-in:
				messageID := item.EnvelopeHash.Bytes()
				whisperMessage := whisper.ToWhisperMessage(item)

				err := a.processEncryptedMessage(ctx, whisperMessage)
				if err != nil {
					log.Printf("failed to process encrypted message %#x: %v", messageID, err)
					continue
				}

				message, err := a.decodeMessage(whisperMessage)
				if err != nil {
					log.Printf("failed to decode message %#x: %v", messageID, err)
					continue
				}

				if err := a.protocol.ConfirmMessageProcessed(messageID); err != nil {
					log.Printf("failed to confirm a message: %v", err)
				}

				messages <- message
			}
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

func (a *whisperAdapter) processEncryptedMessage(ctx context.Context, message *whisper.Message) error {
	publicKey, err := crypto.UnmarshalPubkey(message.Sig)
	if err != nil {
		return errors.Wrap(err, "failed to get signature")
	}

	var protocolMessage encryption.ProtocolMessage

	err = proto.Unmarshal(message.Payload, &protocolMessage)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ProtocolMessage")
	}

	payload, err := a.protocol.HandleMessage(
		a.privateKey,
		publicKey,
		&protocolMessage,
		message.Hash,
	)
	if err == encryption.ErrDeviceNotFound {
		err := a.handleErrDeviceNotFound(ctx, publicKey)
		if err != nil {
			log.Printf("failed to handle ErrDeviceNotFound: %v", err)
		}
	}
	if err != nil {
		return errors.Wrap(err, "failed to process an encrypted message")
	}

	message.Payload = payload
	return nil

}

func (a *whisperAdapter) handleErrDeviceNotFound(ctx context.Context, publicKey *ecdsa.PublicKey) error {
	now := time.Now().Unix()
	advertise, err := a.protocol.ShouldAdvertiseBundle(publicKey, now)
	if err != nil {
		return err
	}
	if !advertise {
		return nil
	}

	messageSpec, err := a.protocol.BuildBundleAdvertiseMessage(a.privateKey, publicKey)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, err = a.sendMessageSpec(ctx, publicKey, messageSpec)
	if err != nil {
		return err
	}

	a.protocol.ConfirmBundleAdvertisement(publicKey, now)

	return nil
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

	return a.sendMessageSpec(ctx, publicKey, messageSpec)
}

func (a *whisperAdapter) sendMessageSpec(ctx context.Context, publicKey *ecdsa.PublicKey, messageSpec *encryption.ProtocolMessageSpec) ([]byte, error) {
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
