package statusproto

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"go.uber.org/zap"

	"github.com/pkg/errors"
	whisper "github.com/status-im/whisper/whisperv6"

	"github.com/status-im/status-protocol-go/datasync"
	datasyncpeer "github.com/status-im/status-protocol-go/datasync/peer"
	"github.com/status-im/status-protocol-go/encryption"
	"github.com/status-im/status-protocol-go/encryption/multidevice"
	"github.com/status-im/status-protocol-go/encryption/sharedsecret"
	"github.com/status-im/status-protocol-go/sqlite"
	transport "github.com/status-im/status-protocol-go/transport/whisper"
	protocol "github.com/status-im/status-protocol-go/v1"
	datasyncnode "github.com/vacp2p/mvds/node"
	datasyncpeers "github.com/vacp2p/mvds/peers"
	datasyncstate "github.com/vacp2p/mvds/state"
	datasyncstore "github.com/vacp2p/mvds/store"
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
	persistence *sqlitePersistence
	transport   *transport.WhisperServiceTransport
	encryptor   *encryption.Protocol
	logger      *zap.Logger

	ownMessages                []*Message
	featureFlags               featureFlags
	processor                  *messageProcessor
	messagesPersistenceEnabled bool
	shutdownTasks              []func() error
}

type featureFlags struct {
	genericDiscoveryTopicEnabled bool
	// sendV1Messages indicates whether we should send
	// messages compatible only with V1 and later.
	// V1 messages adds additional wrapping
	// which contains a signature and payload.
	sendV1Messages bool

	// datasync indicates whether direct messages should be sent exclusively
	// using datasync, breaking change for non-v1 clients. Public messages
	// are not impacted
	datasync bool
}

type dbConfig struct {
	dbPath string
	dbKey  string
}

type config struct {
	onNewInstallationsHandler func([]*multidevice.Installation)
	// DEPRECATED: no need to expose it
	onNewSharedSecretHandler func([]*sharedsecret.Secret)
	// DEPRECATED: no need to expose it
	onSendContactCodeHandler func(*encryption.ProtocolMessageSpec)

	// Config for the envelopes monitor
	envelopesMonitorConfig *transport.EnvelopesMonitorConfig

	messagesPersistenceEnabled bool
	featureFlags               featureFlags

	// A path to a database or a database instance is required.
	// The database instance has a higher priority.
	dbConfig dbConfig
	db       *sql.DB

	logger *zap.Logger
}

type Option func(*config) error

func WithOnNewInstallationsHandler(h func([]*multidevice.Installation)) Option {
	return func(c *config) error {
		c.onNewInstallationsHandler = h
		return nil
	}
}

func WithOnNewSharedSecret(h func([]*sharedsecret.Secret)) Option {
	return func(c *config) error {
		c.onNewSharedSecretHandler = h
		return nil
	}
}

func WithCustomLogger(logger *zap.Logger) Option {
	return func(c *config) error {
		c.logger = logger
		return nil
	}
}

func WithGenericDiscoveryTopicSupport() Option {
	return func(c *config) error {
		c.featureFlags.genericDiscoveryTopicEnabled = true
		return nil
	}
}

func WithMessagesPersistenceEnabled() Option {
	return func(c *config) error {
		c.messagesPersistenceEnabled = true
		return nil
	}
}

func WithDatabaseConfig(dbPath, dbKey string) Option {
	return func(c *config) error {
		c.dbConfig = dbConfig{dbPath: dbPath, dbKey: dbKey}
		return nil
	}
}

func WithDatabase(db *sql.DB) Option {
	return func(c *config) error {
		c.db = db
		return nil
	}
}

func WithSendV1Messages() Option {
	return func(c *config) error {
		c.featureFlags.sendV1Messages = true
		return nil
	}
}

func WithDatasync() func(c *config) error {
	return func(c *config) error {
		c.featureFlags.datasync = true
		return nil
	}
}

func WithEnvelopesMonitorConfig(emc *transport.EnvelopesMonitorConfig) Option {
	return func(c *config) error {
		c.envelopesMonitorConfig = emc
		return nil
	}
}

func NewMessenger(
	identity *ecdsa.PrivateKey,
	shh *whisper.Whisper,
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
			message := newContactCodeMessage(&identity.PublicKey)
			if err := message.Send(nil); err != nil {
				slogger.Warn("failed to send a contact code", zap.Error(err))
			}
		}
	}

	// Configure the database.
	database := c.db
	if c.db == nil && c.dbConfig == (dbConfig{}) {
		return nil, errors.New("database instance or database path needs to be provided")
	}
	if c.db == nil {
		logger.Info("opening a database", zap.String("dbPath", c.dbConfig.dbPath))
		var err error
		database, err = sqlite.Open(c.dbConfig.dbPath, c.dbConfig.dbKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to initialize database from the db config")
		}
	}

	// Apply migrations for all components.
	migrationNames, migrationGetter, err := prepareMigrations(defaultMigrations)
	if err != nil {
		return nil, errors.Wrap(err, "failed to prepare migrations")
	}
	err = sqlite.ApplyMigrations(database, migrationNames, migrationGetter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to apply migrations")
	}

	// Initialize transport layer.
	t, err := transport.NewWhisperServiceTransport(
		shh,
		identity,
		database,
		nil,
		c.envelopesMonitorConfig,
		logger,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a WhisperServiceTransport")
	}

	// Initialize encryption layer.
	encryptionProtocol := encryption.New(
		database,
		installationID,
		c.onNewInstallationsHandler,
		c.onNewSharedSecretHandler,
		c.onSendContactCodeHandler,
		logger,
	)

	// Initialize data sync.
	dataSyncTransport := datasync.NewDataSyncNodeTransport()
	dataSyncStore := datasyncstore.NewDummyStore()
	dataSyncNode := datasyncnode.NewNode(
		&dataSyncStore,
		dataSyncTransport,
		datasyncstate.NewSyncState(), // @todo sqlite syncstate
		datasync.CalculateSendTime,
		0,
		datasyncpeer.PublicKeyToPeerID(identity.PublicKey),
		datasyncnode.BATCH,
		datasyncpeers.NewMemoryPersistence(),
	)
	datasync := datasync.New(dataSyncNode, dataSyncTransport, c.featureFlags.datasync, logger)

	processor := messageProcessor{
		Encryptor: &protocolEncryptor{
			encryptionProtocol: encryptionProtocol,
			privateKey:         identity,
		},
		Encoder: &protocolV1Encoder{},
		Syncer: &dataSyncer{
			datasync:   datasync,
			privateKey: identity,
		},
		Wrapper: &wrapperV1{privateKey: identity},
		Sender: &whisperSender{
			w:                            shh,
			api:                          whisper.NewPublicWhisperAPI(shh),
			encryption:                   encryptionProtocol,
			transport:                    t,
			genericDiscoveryTopicEnabled: c.featureFlags.genericDiscoveryTopicEnabled,
		},
		featureFlags: c.featureFlags,
		logger:       logger,
	}

	messenger = &Messenger{
		identity:                   identity,
		persistence:                &sqlitePersistence{db: database},
		transport:                  t,
		encryptor:                  encryptionProtocol,
		processor:                  &processor,
		featureFlags:               c.featureFlags,
		messagesPersistenceEnabled: c.messagesPersistenceEnabled,
		shutdownTasks: []func() error{
			database.Close,
			t.Reset,
			func() error { datasync.Stop(); return nil },
			// Currently this often fails, seems like it's safe to ignore them
			// https://github.com/uber-go/zap/issues/328
			func() error { _ = logger.Sync; return nil },
		},
		logger: logger,
	}

	// Start all services immediately.
	// TODO: consider removing identity as an argument to Start().
	if err := encryptionProtocol.Start(identity); err != nil {
		return nil, err
	}
	if c.featureFlags.datasync {
		dataSyncNode.Start(300 * time.Millisecond)
	}

	logger.Debug("messages persistence", zap.Bool("enabled", c.messagesPersistenceEnabled))

	return messenger, nil
}

// Shutdown takes care of ensuring a clean shutdown of Messenger
func (m *Messenger) Shutdown() (err error) {
	for _, task := range m.shutdownTasks {
		if tErr := task(); tErr != nil {
			if err == nil {
				// First error appeared.
				err = tErr
			} else {
				// We return all errors. They will be concatenated in the order of occurrence,
				// however, they will also be returned as a single error.
				err = errors.Wrap(err, tErr.Error())
			}
		}
	}
	return
}

func (m *Messenger) handleSharedSecrets(secrets []*sharedsecret.Secret) error {
	logger := m.logger.With(zap.String("site", "handleSharedSecrets"))
	for _, secret := range secrets {
		logger.Debug("received shared secret", zap.Binary("identity", crypto.FromECDSAPub(secret.Identity)))
		fSecret := transport.NegotiatedSecret{
			PublicKey: secret.Identity,
			Key:       secret.Key,
		}
		if err := m.transport.ProcessNegotiatedSecret(fSecret); err != nil {
			return err
		}
	}
	return nil
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

// NOT IMPLEMENTED
func (m *Messenger) SelectMailserver(id string) error {
	return ErrNotImplemented
}

// NOT IMPLEMENTED
func (m *Messenger) AddMailserver(enode string) error {
	return ErrNotImplemented
}

// NOT IMPLEMENTED
func (m *Messenger) RemoveMailserver(id string) error {
	return ErrNotImplemented
}

// NOT IMPLEMENTED
func (m *Messenger) Mailservers() ([]string, error) {
	return nil, ErrNotImplemented
}

func (m *Messenger) Join(chat Chat) error {
	if chat.PublicKey != nil {
		return m.transport.JoinPrivate(chat.PublicKey)
	} else if chat.Name != "" {
		return m.transport.JoinPublic(chat.Name)
	}
	return errors.New("chat is neither public nor private")
}

func (m *Messenger) Leave(chat Chat) error {
	if chat.PublicKey != nil {
		return m.transport.LeavePrivate(chat.PublicKey)
	} else if chat.Name != "" {
		return m.transport.LeavePublic(chat.Name)
	}
	return errors.New("chat is neither public nor private")
}

func (m *Messenger) SaveChat(chat Chat) error {
	return m.persistence.SaveChat(chat)
}

func (m *Messenger) Chats(from, to int) ([]*Chat, error) {
	return m.persistence.Chats(from, to)
}

func (m *Messenger) DeleteChat(chatID string, chatType ChatType) error {
	return m.persistence.DeleteChat(chatID, chatType)
}

func (m *Messenger) SaveContact(contact Contact) error {
	return m.persistence.SaveContact(contact)
}

func (m *Messenger) Contacts() ([]*Contact, error) {
	return m.persistence.Contacts()
}

func (m *Messenger) Send(ctx context.Context, chat Chat, data []byte) ([]byte, error) {
	chatID := chat.ID
	if chatID == "" {
		return nil, ErrChatIDEmpty
	}

	clock, err := m.persistence.LastMessageClock(&m.identity.PublicKey, chat.ID)
	if err != nil {
		return nil, err
	}

	var (
		message         *Message
		protocolMessage protocol.Message
	)

	if chat.PublicKey != nil {
		protocolMessage = protocol.CreatePrivateTextMessage(data, clock, chat.ID)
		message = newPrivateMessage(&m.identity.PublicKey, chat.PublicKey, protocolMessage)
	} else if chat.Name != "" {
		protocolMessage := protocol.CreatePublicTextMessage(data, clock, chat.ID)
		message = newPublicMessage(&m.identity.PublicKey, chat.ID, protocolMessage)
	} else {
		return nil, errors.New("chat is neither public nor private")
	}

	if err := m.send(message); err != nil {
		return nil, err
	}

	// Track sent message.
	m.transport.Track([][]byte{message.ID()}, message.transportMeta.hash, *message.transportMeta.newMessage)

	// Cache private messages to return them in Retrieve().
	if !message.transportMeta.public {
		m.ownMessages = append(m.ownMessages, message)
	}

	if m.messagesPersistenceEnabled {
		err := m.persistence.SaveMessages(&m.identity.PublicKey, message)
		if err != nil {
			return nil, err
		}
	}

	return message.ID(), nil
}

func (m *Messenger) send(message *Message) error {
	return m.processor.Send(message)
}

func (m *Messenger) RetrieveNew(ctx context.Context) ([]*Message, error) {
	logger := m.logger.With(zap.String("site", "RetrieveNew"))

	chatMessages, err := m.transport.RetrieveMessages()
	if err != nil {
		return nil, err
	}

	logger.Debug("retrieved chats", zap.Int("count", len(chatMessages)))

	var allMessages []*Message

	for _, chat := range chatMessages {
		logger.Debug(
			"retrieved messages",
			zap.String("chatID", chat.ChatID),
			zap.Int("count", len(chat.Messages)),
		)

		for _, recv := range chat.Messages {
			newMessage, err := newMessageFromTransport(whisper.ToWhisperMessage(recv), chat.ChatID, chat.Public)
			if err != nil {
				return nil, err
			}
			decodedMessages, err := m.resolveMessage(newMessage)
			if err != nil {
				return nil, err
			}
			if err := m.handleDecodedMessages(decodedMessages); err != nil {
				return nil, err
			}
			allMessages = append(allMessages, decodedMessages...)
		}
	}

	if m.messagesPersistenceEnabled {
		if err := m.persistence.SaveMessages(&m.identity.PublicKey, allMessages...); err != nil {
			return nil, errors.Wrap(err, "failed to save retrieved messages")
		}
	}

	// Confirm only if persistence is enabled and message is not public.
	if m.messagesPersistenceEnabled {
		for _, message := range allMessages {
			if !message.transportMeta.public {
				if err := m.encryptor.ConfirmMessageProcessed(message.ID()); err != nil {
					m.logger.Error("failed to confirm processed message", zap.Error(err))
				}
			}
		}
	}

	allMessages = append(allMessages, m.ownMessages...)
	m.ownMessages = nil

	return allMessages, nil
}

func (m *Messenger) resolveMessage(message *Message) ([]*Message, error) {
	messages, err := m.processor.Resolve(message)
	switch err {
	case encryption.ErrDeviceNotFound:
		handleErr := m.handleErrDeviceNotFound(context.Background(), message.SigPubKey())
		if handleErr != nil {
			m.logger.Error("failed to handle error", zap.Error(err), zap.NamedError("handleErr", handleErr))
		}
		return nil, nil
	case nil:
		return messages, nil
	default:
		return nil, err
	}
}

func (m *Messenger) handleDecodedMessages(messages []*Message) error {
	for _, message := range messages {
		switch value := message.Interface().(type) {
		case protocol.PairMessage:
			fromOurDevice := isPubKeyEqual(message.SigPubKey(), &m.identity.PublicKey)
			if !fromOurDevice {
				m.logger.Debug("received PairMessage from not our device, skipping")
				continue
			}
			metadata := &multidevice.InstallationMetadata{
				Name:       value.Name,
				FCMToken:   value.FCMToken,
				DeviceType: value.DeviceType,
			}
			return m.encryptor.SetInstallationMetadata(&m.identity.PublicKey, value.InstallationID, metadata)
		}
	}
	return nil
}

func (m *Messenger) handleErrDeviceNotFound(ctx context.Context, publicKey *ecdsa.PublicKey) error {
	now := time.Now().Unix()
	advertise, err := m.encryptor.ShouldAdvertiseBundle(publicKey, now)
	if err != nil {
		return err
	}
	if !advertise {
		return nil
	}

	message := Message{
		sigPubKey: &m.identity.PublicKey,
		recipient: publicKey,
	}
	if err := message.Encrypt(nil); err != nil {
		return err
	}
	if err := message.Send(nil); err != nil {
		return err
	}

	m.encryptor.ConfirmBundleAdvertisement(publicKey, now)

	return nil
}

type RetrieveConfig struct {
	From        time.Time
	To          time.Time
	latest      bool
	last24Hours bool
}

var (
	RetrieveLatest  = RetrieveConfig{latest: true}
	RetrieveLastDay = RetrieveConfig{latest: false, last24Hours: true}
)

// RetrieveAll retrieves all previously fetched messages
func (m *Messenger) RetrieveWithConfig(ctx context.Context, c RetrieveConfig) ([]*Message, error) {
	if c.latest {
		latest, err := m.RetrieveNew(ctx)
		if err != nil {
			err = errors.Wrap(err, "failed to retrieve messages")
		}
		return latest, err
	}
	return m.retrieveSaved(ctx, c)
}

func (m *Messenger) retrieveSaved(ctx context.Context, c RetrieveConfig) ([]*Message, error) {
	if !m.messagesPersistenceEnabled {
		return nil, errors.New("message persistence is disabled")
	}

	if c.last24Hours {
		to := time.Now()
		from := to.Add(-time.Hour * 24)
		return m.persistence.Messages(&m.identity.PublicKey, from, to, "")
	}

	if !c.latest {
		return m.persistence.Messages(&m.identity.PublicKey, c.From, c.To, "")
	}

	m.logger.Error("invalid config reached retrieveSaved()")

	return nil, nil
}

func (m *Messenger) ConfirmMessagesProcessed(messageIDs [][]byte) error {
	for _, id := range messageIDs {
		if err := m.encryptor.ConfirmMessageProcessed(id); err != nil {
			return err
		}
	}
	return nil
}

// isPubKeyEqual checks that two public keys are equal
func isPubKeyEqual(a, b *ecdsa.PublicKey) bool {
	// the curve is always the same, just compare the points
	return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}
