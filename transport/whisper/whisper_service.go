package whisper

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	whisper "github.com/status-im/whisper/whisperv6"
	"go.uber.org/zap"
)

var (
	// ErrNoMailservers returned if there is no configured mailservers that can be used.
	ErrNoMailservers = errors.New("no configured mailservers")
)

type whisperServiceKeysManager struct {
	shh *whisper.Whisper

	// Identity of the current user.
	privateKey *ecdsa.PrivateKey

	passToSymKeyMutex sync.RWMutex
	passToSymKeyCache map[string]string
}

func (m *whisperServiceKeysManager) AddOrGetKeyPair(priv *ecdsa.PrivateKey) (string, error) {
	// caching is handled in Whisper
	return m.shh.AddKeyPair(priv)
}

func (m *whisperServiceKeysManager) AddOrGetSymKeyFromPassword(password string) (string, error) {
	m.passToSymKeyMutex.Lock()
	defer m.passToSymKeyMutex.Unlock()

	if val, ok := m.passToSymKeyCache[password]; ok {
		return val, nil
	}

	id, err := m.shh.AddSymKeyFromPassword(password)
	if err != nil {
		return id, err
	}

	m.passToSymKeyCache[password] = id

	return id, nil
}

func (m *whisperServiceKeysManager) RawSymKey(id string) ([]byte, error) {
	return m.shh.GetSymKey(id)
}

// WhisperServiceTransport is a transport based on Whisper service.
type WhisperServiceTransport struct {
	shh         *whisper.Whisper
	shhAPI      *whisper.PublicWhisperAPI // only PublicWhisperAPI implements logic to send messages
	keysManager *whisperServiceKeysManager
	chats       *filtersManager
	logger      *zap.Logger

	mailservers      []string
	envelopesMonitor *EnvelopesMonitor
}

// NewWhisperService returns a new WhisperServiceTransport.
func NewWhisperServiceTransport(
	shh *whisper.Whisper,
	privateKey *ecdsa.PrivateKey,
	db *sql.DB,
	mailservers []string,
	envelopesMonitorConfig *EnvelopesMonitorConfig,
	logger *zap.Logger,
) (*WhisperServiceTransport, error) {
	chats, err := newFiltersManager(db, shh, privateKey, logger)
	if err != nil {
		return nil, err
	}

	var envelopesMonitor *EnvelopesMonitor
	if envelopesMonitorConfig != nil {
		envelopesMonitor = NewEnvelopesMonitor(shh, envelopesMonitorConfig)
		envelopesMonitor.Start()
	}
	return &WhisperServiceTransport{
		shh:              shh,
		shhAPI:           whisper.NewPublicWhisperAPI(shh),
		envelopesMonitor: envelopesMonitor,

		keysManager: &whisperServiceKeysManager{
			shh:               shh,
			privateKey:        privateKey,
			passToSymKeyCache: make(map[string]string),
		},
		chats:       chats,
		mailservers: mailservers,
		logger:      logger.With(zap.Namespace("WhisperServiceTransport")),
	}, nil
}

// DEPRECATED
func (a *WhisperServiceTransport) LoadFilters(chats []*Filter, genericDiscoveryTopicEnabled bool) ([]*Filter, error) {
	return a.chats.InitWithChats(chats, genericDiscoveryTopicEnabled)
}

// DEPRECATED
func (a *WhisperServiceTransport) RemoveFilters(chats []*Filter) error {
	return a.chats.Remove(chats...)
}

func (a *WhisperServiceTransport) Reset() error {
	return a.chats.Reset()
}

func (a *WhisperServiceTransport) ProcessNegotiatedSecret(secret NegotiatedSecret) error {
	_, err := a.chats.LoadNegotiated(secret)
	return err
}

func (a *WhisperServiceTransport) JoinPublic(chatID string) error {
	a.logger.Debug("joining public chat", zap.String("chatID", chatID))
	_, err := a.chats.LoadPublic(chatID)
	return err
}

func (a *WhisperServiceTransport) LeavePublic(chatID string) error {
	chat := a.chats.FilterByChatID(chatID)
	if chat != nil {
		return nil
	}
	return a.chats.Remove(chat)
}

func (a *WhisperServiceTransport) JoinPrivate(publicKey *ecdsa.PublicKey) error {
	_, err := a.chats.LoadDiscovery()
	if err != nil {
		return err
	}
	_, err = a.chats.LoadContactCode(publicKey)
	return err
}

func (a *WhisperServiceTransport) LeavePrivate(publicKey *ecdsa.PublicKey) error {
	chats := a.chats.FiltersByPublicKey(publicKey)
	return a.chats.Remove(chats...)
}

type ChatMessages struct {
	Messages []*whisper.ReceivedMessage
	Public   bool
	ChatID   string
}

func (a *WhisperServiceTransport) RetrieveMessages() ([]ChatMessages, error) {
	chatMessages := make(map[string]ChatMessages)

	for _, chat := range a.chats.Filters() {
		f := a.shh.GetFilter(chat.FilterID)
		if f == nil {
			return nil, errors.New("failed to return a filter")
		}

		ch := chatMessages[chat.ChatID]
		ch.ChatID = chat.ChatID
		ch.Public = chat.IsPublic()

		newMessages := f.Retrieve()
		ch.Messages = append(ch.Messages, newMessages...)

		chatMessages[chat.ChatID] = ch
	}

	var result []ChatMessages
	for _, messages := range chatMessages {
		result = append(result, messages)
	}
	return result, nil
}

func (a *WhisperServiceTransport) RetrieveMessagesByFilter() (map[Filter][]*whisper.ReceivedMessage, error) {
	result := make(map[Filter][]*whisper.ReceivedMessage)
	for _, chat := range a.chats.Filters() {
		f := a.shh.GetFilter(chat.FilterID)
		if f == nil {
			return nil, errors.New("failed to return a filter")
		}
		result[*chat] = append(result[*chat], f.Retrieve()...)
	}
	return result, nil
}

// SendPublic sends a new message using the Whisper service.
// For public filters, chat name is used as an ID as well as
// a topic.
func (a *WhisperServiceTransport) SendPublic(ctx context.Context, newMessage whisper.NewMessage, chatName string) ([]byte, error) {
	a.logger.
		With(zap.String("field", "SendPublic")).
		Debug("sending", zap.String("chatName", chatName))

	if err := a.addSig(&newMessage); err != nil {
		return nil, err
	}

	chat, err := a.chats.LoadPublic(chatName)
	if err != nil {
		return nil, err
	}

	newMessage.SymKeyID = chat.SymKeyID
	newMessage.Topic = chat.Topic

	return a.shhAPI.Post(ctx, newMessage)
}

func (a *WhisperServiceTransport) SendPrivateWithSharedSecret(ctx context.Context, newMessage whisper.NewMessage, publicKey *ecdsa.PublicKey, secret []byte) ([]byte, error) {
	a.logger.
		With(zap.String("field", "SendPrivateWithSharedSecret")).
		Debug("sending", zap.Binary("publicKey", crypto.FromECDSAPub(publicKey)))

	if err := a.addSig(&newMessage); err != nil {
		return nil, err
	}

	chat, err := a.chats.LoadNegotiated(NegotiatedSecret{
		PublicKey: publicKey,
		Key:       secret,
	})
	if err != nil {
		return nil, err
	}

	newMessage.SymKeyID = chat.SymKeyID
	newMessage.Topic = chat.Topic
	newMessage.PublicKey = nil

	return a.shhAPI.Post(ctx, newMessage)
}

func (a *WhisperServiceTransport) SendPrivateWithPartitioned(ctx context.Context, newMessage whisper.NewMessage, publicKey *ecdsa.PublicKey) ([]byte, error) {
	logger := a.logger.With(zap.String("field", "SendPrivateWithPartitioned"))
	logger.Debug("sending", zap.Binary("publicKey", crypto.FromECDSAPub(publicKey)))

	if err := a.addSig(&newMessage); err != nil {
		return nil, err
	}

	filter, err := a.chats.LoadPartitioned(publicKey)
	if err != nil {
		return nil, err
	}

	logger.Debug("loaded filter", zap.String("chatID", filter.ChatID))

	newMessage.Topic = filter.Topic
	newMessage.PublicKey = crypto.FromECDSAPub(publicKey)

	return a.shhAPI.Post(ctx, newMessage)
}

func (a *WhisperServiceTransport) SendPrivateOnDiscovery(ctx context.Context, newMessage whisper.NewMessage, publicKey *ecdsa.PublicKey) ([]byte, error) {
	a.logger.
		With(zap.String("field", "SendPrivateOnDiscovery")).
		Debug("sending", zap.Binary("publicKey", crypto.FromECDSAPub(publicKey)))

	if err := a.addSig(&newMessage); err != nil {
		return nil, err
	}

	// There is no need to load any chat
	// because listening on the discovery topic
	// is done automatically.
	// TODO: change this anyway, it should be explicit
	// and idempotent.

	newMessage.Topic = whisper.BytesToTopic(
		ToTopic(discoveryTopic),
	)
	newMessage.PublicKey = crypto.FromECDSAPub(publicKey)

	return a.shhAPI.Post(ctx, newMessage)
}

func (a *WhisperServiceTransport) addSig(newMessage *whisper.NewMessage) error {
	sigID, err := a.keysManager.AddOrGetKeyPair(a.keysManager.privateKey)
	if err != nil {
		return err
	}
	newMessage.Sig = sigID
	return nil
}

func (a *WhisperServiceTransport) Track(identifiers [][]byte, hash []byte, newMessage whisper.NewMessage) {
	if a.envelopesMonitor != nil {
		a.envelopesMonitor.Add(identifiers, common.BytesToHash(hash), newMessage)
	}
}

func (a *WhisperServiceTransport) Stop() {
	if a.envelopesMonitor != nil {
		a.envelopesMonitor.Stop()
	}
}
