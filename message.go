package statusproto

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"github.com/status-im/status-protocol-go/encryption"
	transport "github.com/status-im/status-protocol-go/transport/whisper"
	protocol "github.com/status-im/status-protocol-go/v1"
	whisper "github.com/status-im/whisper/whisperv6"
	"go.uber.org/zap"
)

var (
	errMissingSigPubKey       = errors.New("missing signature public key")
	errMissingRecipient       = errors.New("missing recipient's public key")
	errMissingProtocolMessage = errors.New("missing protocol message")
	errNotUserMessage         = errors.New("is not a user message")
	errUndefinedProtocolID    = errors.New("protocol ID is undefined")
)

type messageProcessor struct {
	Encryptor
	Encoder
	Syncer
	Wrapper
	Sender

	logger       *zap.Logger
	featureFlags featureFlags
}

// swallowErr logs errors which do not interrupt in processing the message.
func (ma messageProcessor) swallowErr(err error) {
	if err == nil {
		return
	}
	ma.logger.Error("processing message error", zap.Error(err))
}

func (ma *messageProcessor) Send(m *Message) (err error) {
	err = m.Encode(ma)
	if err != nil {
		return
	}

	return ma.SendEncoded(m)
}

func (ma *messageProcessor) SendEncoded(m *Message) (err error) {
	if ma.featureFlags.sendV1Messages {
		err = m.Wrap(ma)
		if err != nil {
			return
		}
	}

	if ma.featureFlags.datasync {
		err = m.Sync(ma)
		if err != nil {
			return
		}
	}

	err = m.Encrypt(ma)
	if err != nil {
		return
	}

	err = m.Send(ma)
	return
}

func (ma *messageProcessor) Resolve(m *Message) ([]*Message, error) {
	err := m.Decrypt(ma)
	if err != nil {
		return nil, err
	}

	messages, err := m.Desync(ma)
	if err != nil {
		messages = []*Message{m}
		ma.swallowErr(err)
	}

	for _, m := range messages {
		if err := m.Unwrap(ma); err != nil {
			ma.swallowErr(err)
		}
		if err := m.Decode(ma); err != nil {
			ma.swallowErr(err)
		}
	}

	return messages, nil
}

type transportMeta struct {
	hash       []byte
	chatID     string
	public     bool
	newMessage *whisper.NewMessage // set only when sending a message
}

type encryptionMeta struct {
	spec *encryption.ProtocolMessageSpec
}

type Message struct {
	id     []byte // cached result of ProtocolID() method; it can come from the database
	chatID string // ID of a chat this message belongs to

	recipient *ecdsa.PublicKey // recipient of a private message; if nil, then the message is public
	sigPubKey *ecdsa.PublicKey // signature of a received unwrapped message; check transportMeta.sigPublicKey as well

	protocolMessage interface{} // decoded message, it's interface{} because it might be of any supported type

	transportMeta    transportMeta // used for sending and receiving messages
	encryptedPayload []byte        // comes from the transport layer

	encryptionMeta   encryptionMeta // used for encrypting and sending a message
	decryptedPayload []byte         // either a new encoded message to send or decrypted received message
}

func newMessageFromTransport(m *whisper.Message, chatID string, public bool) (*Message, error) {
	sigPubKey, err := crypto.UnmarshalPubkey(m.Sig)
	if err != nil {
		return nil, errors.Wrap(err, "received a message with invalid signature")
	}

	return &Message{
		chatID:    chatID,
		sigPubKey: sigPubKey,
		transportMeta: transportMeta{
			hash:   m.Hash,
			chatID: chatID,
			public: public,
		},
		encryptedPayload: m.Payload,
	}, nil
}

func newPrivateMessage(
	sigPubKey *ecdsa.PublicKey,
	recipient *ecdsa.PublicKey,
	message interface{},
) (*Message, error) {
	if sigPubKey == nil {
		return nil, errMissingSigPubKey
	}
	if recipient == nil {
		return nil, errMissingRecipient
	}
	m := &Message{
		chatID:          "", // TODO
		sigPubKey:       sigPubKey,
		recipient:       recipient,
		protocolMessage: message,
		transportMeta: transportMeta{
			chatID: "", // TODO
		},
	}
	if err := validateUserMessage(m); err != nil {
		return nil, err
	}
	return m, nil
}

func newRawPrivateMessage(
	sigPubKey *ecdsa.PublicKey,
	recipient *ecdsa.PublicKey,
	data []byte,
) (*Message, error) {
	if sigPubKey == nil {
		return nil, errMissingSigPubKey
	}
	if recipient == nil {
		return nil, errMissingRecipient
	}
	m := &Message{
		chatID:           "", // TODO
		sigPubKey:        sigPubKey,
		recipient:        recipient,
		decryptedPayload: data,
		transportMeta: transportMeta{
			chatID: "", // TODO
		},
	}
	return m, nil
}

func newPublicMessage(
	sigPubKey *ecdsa.PublicKey,
	chatID string,
	message interface{},
) (*Message, error) {
	if sigPubKey == nil {
		return nil, errMissingSigPubKey
	}
	m := &Message{
		sigPubKey:       sigPubKey,
		protocolMessage: message,
		chatID:          chatID,
		transportMeta: transportMeta{
			chatID: chatID,
			public: true,
		},
	}
	if err := validateUserMessage(m); err != nil {
		return nil, err
	}
	return m, nil
}

func newRawPublicMessage(
	sigPubKey *ecdsa.PublicKey,
	chatID string,
	data []byte,
) (*Message, error) {
	if sigPubKey == nil {
		return nil, errMissingSigPubKey
	}
	return &Message{
		sigPubKey:        sigPubKey,
		decryptedPayload: data,
		chatID:           chatID,
		transportMeta: transportMeta{
			chatID: chatID,
			public: true,
		},
	}, nil
}

func newContactCodeMessage(sigPubKey *ecdsa.PublicKey) (*Message, error) {
	chatID := transport.ContactCodeTopic(sigPubKey)
	return newPublicMessage(sigPubKey, chatID, nil)
}

func validateUserMessage(m *Message) error {
	if m.Interface() == nil {
		return errMissingProtocolMessage
	}
	if !m.IsUserMessage() {
		return errNotUserMessage
	}
	return nil
}

func (m Message) Interface() interface{} {
	return m.protocolMessage
}

func (m Message) IsUserMessage() bool {
	_, ok := m.protocolMessage.(protocol.Message)
	return ok
}

func (m Message) ProtocolID() []byte {
	// Already cached or retrieved from the database.
	if m.id != nil {
		return m.id
	}
	// If signature or decrypted payload is not available,
	// it's not possible to compute a message ID.
	if m.SigPubKey() == nil || len(m.decryptedPayload) == 0 {
		return nil
	}
	m.id = protocol.MessageID(m.SigPubKey(), m.decryptedPayload)
	return m.id
}

// AnyID returns any identifier of the Message. In case of some messages,
// the content might be unspecified (for example, bundle advertise messages),
// in such a case, a transport envelope hash is returned.
func (m Message) AnyID() []byte {
	id := m.ProtocolID()
	if id != nil {
		return id
	}
	return m.transportMeta.hash
}

func (m Message) SigPubKey() *ecdsa.PublicKey {
	return m.sigPubKey
}

func (m Message) ChatID() string {
	return m.chatID
}

// Public returns true if a message has no recipient, i.e. it is a public message
// sent to a public chat.
func (m Message) Public() bool {
	return m.recipient == nil
}

func (m Message) Clock() int64 {
	if val, ok := m.Interface().(protocol.Message); ok {
		return val.Clock
	}
	return 0
}

func (m Message) Timestamp() int64 {
	if val, ok := m.Interface().(protocol.Message); ok {
		return int64(val.Timestamp)
	}
	return 0
}

func (m Message) RawMessage() []byte {
	return m.decryptedPayload
}

func (m Message) clone() *Message {
	return &Message{
		chatID:           m.chatID,
		recipient:        m.recipient,
		sigPubKey:        m.sigPubKey,
		transportMeta:    m.transportMeta,
		encryptedPayload: m.encryptedPayload,
		decryptedPayload: m.decryptedPayload,
	}
}

func (m *Message) Encrypt(enc Encryptor) (err error) {
	m.encryptedPayload, m.encryptionMeta, err = enc.Encrypt(m.recipient, m.decryptedPayload)
	return
}

func (m *Message) Decrypt(dec Encryptor) (err error) {
	m.decryptedPayload, err = dec.Decrypt(m.SigPubKey(), m.transportMeta.hash, m.encryptedPayload)
	return
}

func (m *Message) Sync(s Syncer) error {
	return s.Sync(m.recipient, m.decryptedPayload)
}

func (m *Message) Desync(s Syncer) ([]*Message, error) {
	var messages []*Message
	payloads := s.Desync(m.SigPubKey(), m.decryptedPayload)
	for _, payload := range payloads {
		cloned := m.clone()
		cloned.decryptedPayload = payload
		messages = append(messages, cloned)
	}
	return messages, nil
}

func (m *Message) Wrap(w Wrapper) (err error) {
	m.decryptedPayload, err = w.Wrap(m.decryptedPayload)
	return
}

func (m *Message) Unwrap(w Wrapper) error {
	meta, err := w.Unwrap(m.decryptedPayload)
	if err != nil {
		return err
	}

	recoveredKey, err := meta.RecoverKey()
	if err != nil {
		return err
	}

	m.decryptedPayload = meta.Payload
	m.sigPubKey = recoveredKey
	return nil
}

func (m *Message) Encode(enc Encoder) (err error) {
	m.decryptedPayload, err = enc.Encode(m.protocolMessage)
	return
}

func (m *Message) Decode(dec Encoder) error {
	val, err := dec.Decode(m.decryptedPayload)
	if err != nil {
		return err
	}

	switch v := val.(type) {
	case protocol.Message:
		v.ID = m.ProtocolID()
		if v.ID == nil {
			return errUndefinedProtocolID
		}
		m.protocolMessage = v
	case protocol.PairMessage:
		m.protocolMessage = v
	}

	return nil
}

func (m *Message) Send(s Sender) (err error) {
	if m.encryptionMeta.spec != nil {
		if m.transportMeta.public {
			m.transportMeta.hash, m.transportMeta.newMessage, err = s.SendPublic(m.transportMeta.chatID, m.encryptionMeta.spec)
		} else {
			m.transportMeta.hash, m.transportMeta.newMessage, err = s.SendPrivate(m.recipient, m.encryptionMeta.spec)
		}
	} else if m.transportMeta.public {
		m.transportMeta.hash, m.transportMeta.newMessage, err = s.SendPublicRaw(m.transportMeta.chatID, m.RawMessage())
	} else {
		err = errors.New("unable to send a message due to invalid configuration")
	}
	return
}
