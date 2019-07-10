package statusproto

import (
	"context"
	"crypto/ecdsa"
	"log"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	whisper "github.com/status-im/whisper/whisperv6"

	"github.com/status-im/status-protocol-go/encryption"
	"github.com/status-im/status-protocol-go/encryption/multidevice"
	"github.com/status-im/status-protocol-go/encryption/sharedsecret"
	"github.com/status-im/status-protocol-go/subscription"
	transport "github.com/status-im/status-protocol-go/transport/whisper"
	protocol "github.com/status-im/status-protocol-go/v1"
)

// Messenger is a entity managing chats and messages.
// It acts as a bridge between the application and encryption
// layers.
// It needs to expose an interface to manage installations
// because installations are managed by the user.
// Similarly, it needs to expose an interface to manage
// mailservers because they can also be managed by the user.
type Messenger struct {
	identity  *ecdsa.PrivateKey
	database  database
	adapter   *whisperAdapter
	encryptor *encryption.Protocol
}

type config struct {
	onAddedBundlesHandler    func([]*multidevice.Installation)
	onNewSharedSecretHandler func([]*sharedsecret.Secret)
}

type Option func(*config) error

func WithOnAddedBundlesHandler(h func([]*multidevice.Installation)) func(c *config) error {
	return func(c *config) error {
		c.onAddedBundlesHandler = h
		return nil
	}
}

func WithOnNewSharedSecret(h func([]*sharedsecret.Secret)) func(c *config) error {
	return func(c *config) error {
		c.onNewSharedSecretHandler = h
		return nil
	}
}

func NewMessenger(
	identity *ecdsa.PrivateKey,
	server transport.Server,
	shh *whisper.Whisper,
	dataDir string,
	dbKey string,
	installationID string,
	opts ...Option,
) (*Messenger, error) {
	var c config

	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return nil, err
		}
	}

	t, err := transport.NewWhisperServiceTransport(
		server,
		shh,
		identity,
		nil,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a WhisperServiceTransport")
	}

	p, err := encryption.New(
		dataDir,
		dbKey,
		installationID,
		c.onAddedBundlesHandler,
		c.onNewSharedSecretHandler,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create the encryption layer")
	}

	messagesDB, err := initializeDB(filepath.Join(dataDir, "messages.sql"), dbKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize messages db")
	}

	return &Messenger{
		identity:  identity,
		database:  messagesDB,
		adapter:   newWhisperAdapter(identity, t, p),
		encryptor: p,
	}, nil
}

func (m *Messenger) EnableInstallation(id string) error {
	return m.encryptor.EnableInstallation(&m.identity.PublicKey, id)
}

func (m *Messenger) DisableInstallation(id string) error {
	return m.encryptor.DisableInstallation(&m.identity.PublicKey, id)
}

func (m *Messenger) Installations() ([]*multidevice.Installation, error) {
	return m.encryptor.GetOurInstallations(&m.identity.PublicKey)
}

func (m *Messenger) SetInstallationMetadata(id string, data *multidevice.InstallationMetadata) error {
	return m.encryptor.SetInstallationMetadata(&m.identity.PublicKey, id, data)
}

// NOT_IMPLEMENTED
func (m *Messenger) SelectMailserver(id string) error {
	return nil
}

// NOT_IMPLEMENTED
func (m *Messenger) AddMailserver(enode string) error {
	return nil
}

// NOT_IMPLEMENTED
func (m *Messenger) RemoveMailserver(id string) error {
	return nil
}

// NOT_IMPLEMENTED
func (m *Messenger) Mailservers() ([]string, error) {
	return nil, nil
}

// NOT_IMPLEMENTED
func (m *Messenger) AddChat() error {
	return nil
}

// NOT_IMPLEMENTED
func (m *Messenger) RemoveChat(id string) error {
	return nil
}

// NOT_IMPLEMENTED
func (m *Messenger) BlockChat(id string) error {
	return nil
}

// NOT_IMPLEMENTED
func (m *Messenger) Chats() ([]string, error) {
	return nil, nil
}

// NOT_IMPLEMENTED
// Asuumes a chat is already added.
func (m *Messenger) SendPublic(ctx context.Context, chatID string) ([]byte, error) {
	return nil, nil
}

// NOT_IMPLEMENTED
// Asuumes a chat is already added.
func (m *Messenger) SendPrivate(ctx context.Context, chatID string) ([]byte, error) {
	return nil, nil
}

func (m *Messenger) RetrievePublicMessages(ctx context.Context, chatID string) ([]*protocol.Message, error) {
	messages, err := m.adapter.RetrievePublicMessages(chatID)
	if err != nil {
		return nil, err
	}

	c := Contact{Name: chatID}
	if err := m.storeMessages(c, messages...); err != nil {
		return nil, err
	}

	return messages, nil
}

func (m *Messenger) RetrievePrivateMessages(ctx context.Context, publicKey *ecdsa.PublicKey) ([]*protocol.Message, error) {
	messages, err := m.adapter.RetrievePrivateMessages(publicKey)
	if err != nil {
		return nil, err
	}

	c := Contact{PublicKey: publicKey}
	if err := m.storeMessages(c, messages...); err != nil {
		return nil, err
	}

	return messages, nil
}

func (m *Messenger) SubscribePublic(ctx context.Context, chatID string) (*subscription.Subscription, <-chan *protocol.Message, error) {
	ch := make(chan *protocol.Message, 1024)
	sub, err := m.adapter.SubscribePublic(ctx, chatID, ch)
	if err != nil {
		return nil, nil, err
	}

	c := Contact{Name: chatID}
	resultCh := make(chan *protocol.Message, 1014)

	go func() {
		err := m.processSubscription(c, sub, ch, resultCh)
		if err != nil {
			log.Printf("failed to process subscription: %v", err)
		}
	}()

	return sub, resultCh, nil
}

func (m *Messenger) SubscribePrivate(ctx context.Context, publicKey *ecdsa.PublicKey) (*subscription.Subscription, <-chan *protocol.Message, error) {
	ch := make(chan *protocol.Message, 1024)
	sub, err := m.adapter.SubscribePrivate(ctx, publicKey, ch)
	if err != nil {
		return nil, nil, err
	}

	c := Contact{PublicKey: publicKey}
	resultCh := make(chan *protocol.Message, 1014)

	go func() {
		err := m.processSubscription(c, sub, ch, resultCh)
		if err != nil {
			log.Printf("failed to process subscription: %v", err)
		}
	}()

	return sub, resultCh, nil
}

func (m *Messenger) processSubscription(c Contact, sub *subscription.Subscription, out <-chan *protocol.Message, in chan<- *protocol.Message) error {
	var cachedMessages []*protocol.Message

	for {
		select {
		case <-sub.Done():
			return sub.Err()
		case m := <-out:
			cachedMessages = append(cachedMessages, m)
			in <- m
		case <-time.After(time.Second):
			if len(cachedMessages) == 0 {
				continue
			}
			err := m.storeMessages(c, cachedMessages...)
			if err != nil {
				log.Printf("failed to store messages: %v", err)
				continue
			}
			cachedMessages = nil
		}
	}
}

func (m *Messenger) storeMessages(c Contact, messages ...*protocol.Message) error {
	_, err := m.database.SaveMessages(c, messages)
	return err
}
