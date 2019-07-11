package statusproto

import (
	"context"
	"crypto/ecdsa"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	whisper "github.com/status-im/whisper/whisperv6"

	"github.com/status-im/status-protocol-go/encryption"
	"github.com/status-im/status-protocol-go/encryption/multidevice"
	"github.com/status-im/status-protocol-go/encryption/sharedsecret"
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

func (m *Messenger) SendPublic(ctx context.Context, chat Chat, data []byte) ([]byte, error) {
	clock, err := m.database.LastMessageClock(chat.ID())
	if err != nil {
		return nil, err
	}
	return m.adapter.SendPublic(ctx, chat.ID(), data, clock)
}

func (m *Messenger) SendPrivate(ctx context.Context, chat Chat, data []byte) ([]byte, error) {
	clock, err := m.database.LastMessageClock(chat.ID())
	if err != nil {
		return nil, err
	}
	return m.adapter.SendPrivate(ctx, chat.PublicKey(), chat.ID(), data, clock)
}

type RetrieveConfig struct {
	From        time.Time
	To          time.Time
	latest      bool
	last24Hours bool
}

var (
	RetrieveLatest  = RetrieveConfig{latest: true}
	RetrieveLastDay = RetrieveConfig{latest: true, last24Hours: true}
)

func (m *Messenger) RetrievePublicMessages(ctx context.Context, chat Chat, c RetrieveConfig) (messages []*protocol.Message, err error) {
	if !c.latest {
		return m.retrieveMessages(ctx, chat, c, nil)
	}

	latest, err := m.adapter.RetrievePublicMessages(chat.ID())
	if err != nil {
		return nil, err
	}
	return m.retrieveMessages(ctx, chat, c, latest)
}

func (m *Messenger) RetrievePrivateMessages(ctx context.Context, chat Chat, c RetrieveConfig) (messages []*protocol.Message, err error) {
	if !c.latest {
		return m.retrieveMessages(ctx, chat, c, nil)
	}

	latest, err := m.adapter.RetrievePrivateMessages(chat.PublicKey())
	if err != nil {
		return nil, err
	}
	return m.retrieveMessages(ctx, chat, c, latest)
}

func (m *Messenger) LeavePublic(chat Chat) error {
	return m.adapter.LeavePublic(chat.ID())
}

func (m *Messenger) LeavePrivate(chat Chat) error {
	return m.adapter.LeavePrivate(chat.PublicKey())
}

func (m *Messenger) retrieveMessages(ctx context.Context, chat Chat, c RetrieveConfig, latest []*protocol.Message) (messages []*protocol.Message, err error) {
	if !c.latest {
		return m.database.Messages(chat.ID(), c.From, c.To)
	}

	if c.last24Hours {
		to := time.Now()
		from := to.Add(-time.Hour * 24)
		messages, err = m.database.Messages(chat.ID(), from, to)
	}

	messages = append(messages, latest...)

	if err := m.storeMessages(chat.ID(), latest...); err != nil {
		return nil, err
	}

	return messages, nil
}

func (m *Messenger) storeMessages(chatID string, messages ...*protocol.Message) error {
	_, err := m.database.SaveMessages(chatID, messages)
	return err
}
