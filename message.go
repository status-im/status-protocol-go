package statusproto

import (
	"crypto/ecdsa"
	"errors"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/status-im/status-protocol-go/encryption"
	"github.com/status-im/status-protocol-go/transport/whisper/filter"
	protocol "github.com/status-im/status-protocol-go/v1"
	whisper "github.com/status-im/whisper/whisperv6"
)

type transportMeta struct {
	hash         []byte
	sigPublicKey *ecdsa.PublicKey
	chatID       string
	public       bool
	newMessage   whisper.NewMessage // NewMessage is set when sending a message
}

type encryptionMeta struct {
	spec                *encryption.ProtocolMessageSpec
	bundleAdvertisement bool // when true, it means we want to only advertise our bundle
}

type Message struct {
	id              []byte           // calculated from a signature key and decrypted payload
	recipient       *ecdsa.PublicKey // recipient of a private message, used only in outgoing messages
	sigPubKey       *ecdsa.PublicKey // signature of a received unwrapped message; check transportMeta.sigPublicKey as well
	protocolMessage interface{}      // decoded message, it's interface{} because it might be of any supported type

	transportMeta    transportMeta // used for sending and receiving messages
	encryptedPayload []byte        // comes from the transport layer

	encryptionMeta   encryptionMeta // used for encrypting and sending a message
	decryptedPayload []byte         // either a new encoded message to send or decrypted received message
}

func newMessageFromTransport(m *whisper.Message, chatID string, public bool) (*Message, error) {
	sigPubKey, err := crypto.UnmarshalPubkey(m.Sig)
	if err != nil {
		return nil, err
	}

	return &Message{
		transportMeta: transportMeta{
			hash:         m.Hash,
			sigPublicKey: sigPubKey,
			chatID:       chatID,
			public:       public,
		},
		encryptedPayload: m.Payload,
	}, nil
}

func newPrivateMessage(sigPubKey *ecdsa.PublicKey, recipient *ecdsa.PublicKey, message interface{}) *Message {
	return &Message{
		sigPubKey:       sigPubKey,
		recipient:       recipient,
		protocolMessage: message,
	}
}

func newPublicMessage(sigPubKey *ecdsa.PublicKey, chatID string, message interface{}) *Message {
	return &Message{
		sigPubKey:       sigPubKey,
		protocolMessage: message,
		transportMeta: transportMeta{
			chatID: chatID,
			public: true,
		},
	}
}

func newContactCodeMessage(sigPubKey *ecdsa.PublicKey) *Message {
	chatID := filter.ContactCodeTopic(sigPubKey)
	return newPublicMessage(sigPubKey, chatID, nil)
}

func newAdvertiseMessage(sigPubKey *ecdsa.PublicKey, recipient *ecdsa.PublicKey) *Message {
	return &Message{
		recipient: recipient,
		sigPubKey: sigPubKey,
		encryptionMeta: encryptionMeta{
			bundleAdvertisement: true,
		},
	}
}

func (m Message) ID() []byte {
	if m.SigPubKey() != nil && len(m.decryptedPayload) > 0 {
		m.id = protocol.MessageID(m.SigPubKey(), m.decryptedPayload)
	}
	if m.id != nil {
		return m.id
	}
	return m.transportMeta.hash
}

func (m Message) SigPubKey() *ecdsa.PublicKey {
	if m.sigPubKey != nil {
		return m.sigPubKey
	}
	return m.transportMeta.sigPublicKey
}

// TODO: it should return error if there was no chance to get a decrypted message yet.
func (m Message) RawMessage() []byte {
	return m.decryptedPayload
}

func (m Message) clone() *Message {
	return &Message{
		sigPubKey:        m.sigPubKey,
		transportMeta:    m.transportMeta,
		encryptedPayload: m.encryptedPayload,
		decryptedPayload: m.decryptedPayload,
	}
}

func (m *Message) Encrypt(enc Encryptor) (err error) {
	m.encryptedPayload, m.encryptionMeta, err = enc.Encrypt(m.recipient, m.transportMeta.public, m.decryptedPayload)
	return
}

func (m *Message) Decrypt(dec Encryptor) (err error) {
	m.decryptedPayload, err = dec.Decrypt(m.SigPubKey(), m.transportMeta.hash, m.encryptedPayload)
	return
}

func (m *Message) DataSync(sync Syncer) error {
	return sync.Sync(m.recipient, m.decryptedPayload)
}

func (m *Message) DataDesync(sync Syncer) ([]*Message, error) {
	var messages []*Message
	payloads := sync.Desync(m.SigPubKey(), m.decryptedPayload)
	for _, payload := range payloads {
		cloned := m.clone()
		cloned.decryptedPayload = payload
		messages = append(messages, cloned)
	}
	return messages, nil
}

func (m *Message) Wrap(wrapper Wrapper) (err error) {
	m.decryptedPayload, err = wrapper.Wrap(m.decryptedPayload)
	return
}

func (m *Message) Unwrap(wrapper Wrapper) error {
	message, err := wrapper.Unwrap(m.decryptedPayload)
	if err != nil {
		return err
	}

	recoveredKey, err := message.RecoverKey()
	if err != nil {
		return err
	}

	m.decryptedPayload = message.Payload
	m.sigPubKey = recoveredKey
	return nil
}

func (m *Message) Encode(enc Encoder) (err error) {
	m.decryptedPayload, err = enc.Encode(m.protocolMessage)
	return
}

func (m *Message) Decode(dec Encoder) (err error) {
	m.protocolMessage, err = dec.Decode(m.decryptedPayload)
	return
}

func (m *Message) Send(sender Sender) (err error) {
	if m.encryptionMeta.spec != nil {
		if m.transportMeta.public {
			m.transportMeta.hash, m.transportMeta.newMessage, err = sender.SendPublic(m.transportMeta.chatID, m.encryptionMeta.spec)
		} else {
			m.transportMeta.hash, m.transportMeta.newMessage, err = sender.SendPrivate(m.encryptionMeta.spec)
		}
	} else if m.transportMeta.public {
		m.transportMeta.hash, m.transportMeta.newMessage, err = sender.SendPublicRaw(m.transportMeta.chatID, m.RawMessage())
	} else {
		err = errors.New("unable to send a message due to invalid configuration")
	}
	return
}
