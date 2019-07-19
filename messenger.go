package statusproto

import (
	"context"
	"crypto/ecdsa"
	"path/filepath"
	"time"

	"go.uber.org/zap"

	"github.com/pkg/errors"
	whisper "github.com/status-im/whisper/whisperv6"

	"github.com/status-im/status-protocol-go/encryption"
	"github.com/status-im/status-protocol-go/encryption/multidevice"
	"github.com/status-im/status-protocol-go/encryption/sharedsecret"
	migrations "github.com/status-im/status-protocol-go/internal/sqlite"
	"github.com/status-im/status-protocol-go/sqlite"
	transport "github.com/status-im/status-protocol-go/transport/whisper"
	"github.com/status-im/status-protocol-go/transport/whisper/filter"
	protocol "github.com/status-im/status-protocol-go/v1"
)

var (
	ErrChatIDEmpty    = errors.New("chat ID is empty")
	ErrNotImplemented = errors.New("not implemented")
)

// Messenger is a entity managing chats and messages.
// It acts as a bridge between the application and encryption
// layers.
// It needs to expose an interface to manage installations
// because installations are managed by the user.
// Similarly, it needs to expose an interface to manage
// mailservers because they can also be managed by the user.
type Messenger struct {
	identity    *ecdsa.PrivateKey
	persistence persistence
	adapter     *whisperAdapter
	encryptor   *encryption.Protocol

	ownMessages map[string][]*protocol.Message
	featureFlags featureFlags

	logger *zap.Logger

	shutdownTasks []func() error
}

type featureFlags struct {
	genericDiscoveryTopicEnabled bool
}

type config struct {
	onNewInstallationsHandler func([]*multidevice.Installation)
	// DEPRECATED: no need to expose it
	onNewSharedSecretHandler func([]*sharedsecret.Secret)
	// DEPRECATED: no need to expose it
	onSendContactCodeHandler func(*encryption.ProtocolMessageSpec)

	featureFlags featureFlags

	logger *zap.Logger
}

type Option func(*config) error

func WithOnNewInstallationsHandler(h func([]*multidevice.Installation)) func(c *config) error {
	return func(c *config) error {
		c.onNewInstallationsHandler = h
		return nil
	}
}

func WithOnNewSharedSecret(h func([]*sharedsecret.Secret)) func(c *config) error {
	return func(c *config) error {
		c.onNewSharedSecretHandler = h
		return nil
	}
}

func WithCustomLogger(logger *zap.Logger) func(c *config) error {
	return func(c *config) error {
		c.logger = logger
		return nil
	}
}

func WithGenericDiscoveryTopicSupport() func(c *config) error {
	return func(c *config) error {
		c.featureFlags.genericDiscoveryTopicEnabled = true
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
	var messenger *Messenger

	c := config{}

	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return nil, err
		}
	}

	logger := c.logger
	if c.logger == nil {
		var err error
		if logger, err = zap.NewDevelopment(); err != nil {
			return nil, errors.Wrap(err, "failed to create a logger")
		}
	}

	// Set default config fields.
	if c.onNewInstallationsHandler == nil {
		c.onNewInstallationsHandler = func(installations []*multidevice.Installation) {
			sugar := logger.Sugar().With("site", "onNewInstallationsHandler")
			for _, installation := range installations {
				sugar.Infow(
					"received a new installation",
					"identity", installation.Identity,
					"id", installation.ID)
			}
		}
	}
	if c.onNewSharedSecretHandler == nil {
		c.onNewSharedSecretHandler = func(secrets []*sharedsecret.Secret) {
			if err := messenger.handleSharedSecrets(secrets); err != nil {
				slogger := logger.With(zap.String("site", "onNewSharedSecretHandler"))
				slogger.Warn("failed to process secrets", zap.Error(err))
			}
		}
	}
	if c.onSendContactCodeHandler == nil {
		c.onSendContactCodeHandler = func(messageSpec *encryption.ProtocolMessageSpec) {
			slogger := logger.With(zap.String("site", "onSendContactCodeHandler"))
			slogger.Info("received a SendContactCode request")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := messenger.adapter.SendContactCode(ctx, messageSpec)
			slogger.Warn("failed to send a contact code", zap.Error(err))
		}
	}

	t, err := transport.NewWhisperServiceTransport(
		server,
		shh,
		identity,
		dataDir,
		dbKey,
		nil,
		logger,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a WhisperServiceTransport")
	}

	encryptionProtocol, err := encryption.New(
		dataDir,
		dbKey,
		installationID,
		c.onNewInstallationsHandler,
		c.onNewSharedSecretHandler,
		c.onSendContactCodeHandler,
		logger,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create the encryption layer")
	}

	messagesDB, err := sqlite.Open(filepath.Join(dataDir, "messages.sql"), dbKey, sqlite.MigrationConfig{
		AssetNames: migrations.AssetNames(),
		AssetGetter: func(name string) ([]byte, error) {
			return migrations.Asset(name)
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize messages db")
	}

	messenger = &Messenger{
		identity:    identity,
		persistence: &sqlitePersistence{db: messagesDB},
		adapter:     newWhisperAdapter(identity, t, encryptionProtocol, c.featureFlags, logger),
		encryptor:   encryptionProtocol,
		ownMessages: make(map[string][]*protocol.Message),
		featureFlags: c.featureFlags,
		shutdownTasks: []func() error {
			messenger.persistence.Close,
			logger.Sync,
		},
		logger: logger,
	}

	// Start all services immediately.
	// TODO: consider removing identity as an argument to Start().
	if err := encryptionProtocol.Start(identity); err != nil {
		return nil, err
	}

	return messenger, nil
}

// Shutdown takes care of ensuring a clean shutdown of Messenger
func (m *Messenger) Shutdown() (err error) {
	for _, task := range m.shutdownTasks {
		if tErr := task(); tErr != nil {
			if err == nil {
				err = tErr
			} else {
				err = errors.Wrap(err, tErr.Error())
			}
		}
	}
	return
}

func (m *Messenger) handleSharedSecrets(secrets []*sharedsecret.Secret) error {
	return m.adapter.handleSharedSecrets(secrets)
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
	return ErrNotImplemented
}

// NOT_IMPLEMENTED
func (m *Messenger) AddMailserver(enode string) error {
	return ErrNotImplemented
}

// NOT_IMPLEMENTED
func (m *Messenger) RemoveMailserver(id string) error {
	return ErrNotImplemented
}

// NOT_IMPLEMENTED
func (m *Messenger) Mailservers() ([]string, error) {
	return nil, ErrNotImplemented
}

func (m *Messenger) Join(chat Chat) error {
	if chat.PublicKey() != nil {
		return m.adapter.JoinPrivate(chat.PublicKey())
	} else if chat.PublicName() != "" {
		return m.adapter.JoinPublic(chat.PublicName())
	}
	return errors.New("chat is neither public nor private")
}

func (m *Messenger) Leave(chat Chat) error {
	if chat.PublicKey() != nil {
		return m.adapter.LeavePrivate(chat.PublicKey())
	} else if chat.PublicName() != "" {
		return m.adapter.LeavePublic(chat.PublicName())
	}
	return errors.New("chat is neither public nor private")
}

func (m *Messenger) Send(ctx context.Context, chat Chat, data []byte) ([]byte, error) {
	chatID := chat.ID()
	if chatID == "" {
		return nil, ErrChatIDEmpty
	}

	clock, err := m.persistence.LastMessageClock(chat.ID())
	if err != nil {
		return nil, err
	}

	if chat.PublicKey() != nil {
		hash, message, err := m.adapter.SendPrivate(ctx, chat.PublicKey(), chat.ID(), data, clock)
		if err != nil {
			return nil, err
		}

		// Save our message because it won't be received from the transport layer.
		message.ID = hash // a Message need ID to be properly stored in the db
		message.SigPubKey = &m.identity.PublicKey
		_, err = m.persistence.SaveMessages(chat.ID(), []*protocol.Message{message})
		if err != nil {
			return nil, err
		}

		// Cache it to be returned in Retrieve().
		m.ownMessages[chatID] = append(m.ownMessages[chatID], message)

		return hash, nil
	} else if chat.PublicName() != "" {
		return m.adapter.SendPublic(ctx, chat.PublicName(), chat.ID(), data, clock)
	}
	return nil, errors.New("chat is neither public nor private")
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

func (m *Messenger) Retrieve(ctx context.Context, chat Chat, c RetrieveConfig) (messages []*protocol.Message, err error) {
	var (
		latest    []*protocol.Message
		ownLatest []*protocol.Message
	)

	if chat.PublicKey() != nil {
		latest, err = m.adapter.RetrievePrivateMessages(chat.PublicKey())
		// Return any own messages for this chat as well.
		if ownMessages, ok := m.ownMessages[chat.ID()]; ok {
			ownLatest = ownMessages
		}
	} else if chat.PublicName() != "" {
		latest, err = m.adapter.RetrievePublicMessages(chat.PublicName())
	} else {
		return nil, errors.New("chat is neither public nor private")
	}

	if err != nil {
		err = errors.Wrap(err, "failed to retrieve messages")
		return
	}

	_, err = m.persistence.SaveMessages(chat.ID(), latest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to save latest messages")
	}

	// Confirm received and decrypted messages.
	// TODO: this should be done only if persistence is enabled.
	if chat.PublicKey() != nil {
		for _, message := range latest {
			// Confirm received and decrypted messages.
			if err := m.encryptor.ConfirmMessageProcessed(message.ID); err != nil {
				return nil, errors.Wrap(err, "failed to confirm message being processed")
			}
		}
	}

	// When our messages are returned, we can delete them.
	delete(m.ownMessages, chat.ID())

	return m.retrieveSaved(ctx, chat, c, append(latest, ownLatest...))
}

func (m *Messenger) retrieveSaved(ctx context.Context, chat Chat, c RetrieveConfig, latest []*protocol.Message) (messages []*protocol.Message, err error) {
	if !c.latest {
		return m.persistence.Messages(chat.ID(), c.From, c.To)
	}

	if c.last24Hours {
		to := time.Now()
		from := to.Add(-time.Hour * 24)
		return m.persistence.Messages(chat.ID(), from, to)
	}

	return latest, nil
}

func (m *Messenger) Reset() error {
	return m.adapter.transport.Reset()
}

// DEPRECATED
func (m *Messenger) LoadFilters(chats []*filter.Chat) ([]*filter.Chat, error) {
	return m.adapter.transport.LoadFilters(chats, m.featureFlags.genericDiscoveryTopicEnabled)
}

func (m *Messenger) RemoveFilters(chats []*filter.Chat) error {
	return m.adapter.transport.RemoveFilters(chats)
}

// DEPRECATED
func (m *Messenger) RetrieveAllRaw() (map[filter.Chat][]*whisper.Message, error) {
	return m.adapter.RetrieveAllRaw()
}

// DEPRECATED
func (m *Messenger) ConfirmMessagesProcessed(messageIDs [][]byte) error {
	for _, id := range messageIDs {
		if err := m.encryptor.ConfirmMessageProcessed(id); err != nil {
			return err
		}
	}
	return nil
}
