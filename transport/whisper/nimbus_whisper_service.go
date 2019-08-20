package whisper

import (
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	mrand "math/rand"
	"sync"

	"github.com/status-im/status-protocol-go/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/pkg/errors"
	nimstatus "github.com/status-im/status-protocol-go/transport/nimbus"
	whisper "github.com/status-im/whisper/whisperv6"
	"go.uber.org/zap"
	"golang.org/x/crypto/pbkdf2"
)

// Whisper protocol parameters
const (
	aesKeyLength = 32 // in bytes
	keyIDSize    = 32 // in bytes
)

type inMemoryWhisperServiceKeysManager struct {
	shh statusprototypes.WhisperInterface

	privateKeys map[string]*ecdsa.PrivateKey // Private key storage
	symKeys     map[string][]byte            // Symmetric key storage
	keyMu       sync.RWMutex                 // Mutex associated with key storages

	// Identity of the current user.
	privateKey *ecdsa.PrivateKey

	passToSymKeyMutex sync.RWMutex
	passToSymKeyCache map[string]string
}

func (m *inMemoryWhisperServiceKeysManager) AddOrGetKeyPair(priv *ecdsa.PrivateKey) (string, error) {
	id, err := makeDeterministicID(common.ToHex(crypto.FromECDSAPub(&priv.PublicKey)), keyIDSize)
	if err != nil {
		return "", err
	}
	if m.hasKeyPair(id) {
		return id, nil // no need to re-inject
	}

	m.keyMu.Lock()
	m.privateKeys[id] = priv
	m.keyMu.Unlock()
	log.Info("Whisper identity added", "id", id, "pubkey", common.ToHex(crypto.FromECDSAPub(&priv.PublicKey)))

	return id, nil
}

func (m *inMemoryWhisperServiceKeysManager) AddOrGetSymKeyFromPassword(password string) (string, error) {
	m.passToSymKeyMutex.Lock()
	defer m.passToSymKeyMutex.Unlock()

	if val, ok := m.passToSymKeyCache[password]; ok {
		return val, nil
	}

	id, err := m.addSymKeyFromPassword(password)
	if err != nil {
		return id, err
	}

	m.passToSymKeyCache[password] = id

	return id, nil
}

// addSymKeyFromPassword generates the key from password, stores it, and returns its id.
func (m *inMemoryWhisperServiceKeysManager) addSymKeyFromPassword(password string) (string, error) {
	id, err := generateRandomID()
	if err != nil {
		return "", fmt.Errorf("failed to generate ID: %s", err)
	}
	if m.hasSymKey(id) {
		return "", fmt.Errorf("failed to generate unique ID")
	}

	// kdf should run no less than 0.1 seconds on an average computer,
	// because it's an once in a session experience
	derived := pbkdf2.Key([]byte(password), nil, 65356, aesKeyLength, sha256.New)
	if err != nil {
		return "", err
	}

	m.keyMu.Lock()
	defer m.keyMu.Unlock()

	// double check is necessary, because deriveKeyMaterial() is very slow
	if m.symKeys[id] != nil {
		return "", fmt.Errorf("critical error: failed to generate unique ID")
	}
	m.symKeys[id] = derived
	return id, nil
}

// generateRandomID generates a random string, which is then returned to be used as a key id
func generateRandomID() (id string, err error) {
	buf, err := generateSecureRandomData(keyIDSize)
	if err != nil {
		return "", err
	}
	if !validateDataIntegrity(buf, keyIDSize) {
		return "", fmt.Errorf("error in generateRandomID: crypto/rand failed to generate random data")
	}
	id = common.Bytes2Hex(buf)
	return id, err
}

// generateSecureRandomData generates random data where extra security is required.
// The purpose of this function is to prevent some bugs in software or in hardware
// from delivering not-very-random data. This is especially useful for AES nonce,
// where true randomness does not really matter, but it is very important to have
// a unique nonce for every message.
func generateSecureRandomData(length int) ([]byte, error) {
	x := make([]byte, length)
	y := make([]byte, length)
	res := make([]byte, length)

	_, err := crand.Read(x)
	if err != nil {
		return nil, err
	} else if !validateDataIntegrity(x, length) {
		return nil, errors.New("crypto/rand failed to generate secure random data")
	}
	_, err = mrand.Read(y)
	if err != nil {
		return nil, err
	} else if !validateDataIntegrity(y, length) {
		return nil, errors.New("math/rand failed to generate secure random data")
	}
	for i := 0; i < length; i++ {
		res[i] = x[i] ^ y[i]
	}
	if !validateDataIntegrity(res, length) {
		return nil, errors.New("failed to generate secure random data")
	}
	return res, nil
}

// validateDataIntegrity returns false if the data have the wrong or contains all zeros,
// which is the simplest and the most common bug.
func validateDataIntegrity(k []byte, expectedSize int) bool {
	if len(k) != expectedSize {
		return false
	}
	if expectedSize > 3 && containsOnlyZeros(k) {
		return false
	}
	return true
}

// containsOnlyZeros checks if the data contain only zeros.
func containsOnlyZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// makeDeterministicID generates a deterministic ID, based on a given input
func makeDeterministicID(input string, keyLen int) (id string, err error) {
	buf := pbkdf2.Key([]byte(input), nil, 4096, keyLen, sha256.New)
	if !validateDataIntegrity(buf, keyIDSize) {
		return "", fmt.Errorf("error in GenerateDeterministicID: failed to generate key")
	}
	id = common.Bytes2Hex(buf)
	return id, err
}

// toDeterministicID reviews incoming id, and transforms it to format
// expected internally be private key store. Originally, public keys
// were used as keys, now random keys are being used. And in order to
// make it easier to consume, we now allow both random IDs and public
// keys to be passed.
func toDeterministicID(id string, expectedLen int) (string, error) {
	if len(id) != (expectedLen * 2) { // we received hex key, so number of chars in id is doubled
		var err error
		id, err = makeDeterministicID(id, expectedLen)
		if err != nil {
			return "", err
		}
	}

	return id, nil
}

// hasSymKey returns true if there is a key associated with the given id.
// Otherwise returns false.
func (m *inMemoryWhisperServiceKeysManager) hasSymKey(id string) bool {
	m.keyMu.RLock()
	defer m.keyMu.RUnlock()
	return m.symKeys[id] != nil
}

// hasKeyPair checks if the whisper node is configured with the private key
// of the specified public pair.
func (m *inMemoryWhisperServiceKeysManager) hasKeyPair(id string) bool {
	deterministicID, err := toDeterministicID(id, keyIDSize)
	if err != nil {
		return false
	}

	m.keyMu.RLock()
	defer m.keyMu.RUnlock()
	return m.privateKeys[deterministicID] != nil
}

// GetPrivateKey retrieves the private key of the specified identity.
func (m *inMemoryWhisperServiceKeysManager) GetPrivateKey(id string) (*ecdsa.PrivateKey, error) {
	deterministicID, err := toDeterministicID(id, keyIDSize)
	if err != nil {
		return nil, err
	}

	m.keyMu.RLock()
	defer m.keyMu.RUnlock()
	key := m.privateKeys[deterministicID]
	if key == nil {
		return nil, fmt.Errorf("invalid id")
	}
	return key, nil
}

func (m *inMemoryWhisperServiceKeysManager) RawSymKey(id string) ([]byte, error) {
	m.keyMu.RLock()
	defer m.keyMu.RUnlock()
	if m.symKeys[id] != nil {
		return m.symKeys[id], nil
	}
	return nil, fmt.Errorf("non-existent key ID")
}

// NimbusWhisperServiceTransport is a transport based on Whisper service.
type NimbusWhisperServiceTransport struct {
	shh statusprototypes.WhisperInterface
	//shhAPI      whisperv6.PublicWhisperAPIInterface // only PublicWhisperAPI implements logic to send messages
	keysManager *inMemoryWhisperServiceKeysManager
	chats       *filtersManager
	logger      *zap.Logger

	mailservers []string
	//envelopesMonitor *EnvelopesMonitor
}

// NewWhisperService returns a new NimbusWhisperServiceTransport.
func NewNimbusWhisperServiceTransport(
	shh statusprototypes.WhisperInterface,
	privateKey *ecdsa.PrivateKey,
	db *sql.DB,
	mailservers []string,
	envelopesMonitorConfig *EnvelopesMonitorConfig,
	logger *zap.Logger,
) (*NimbusWhisperServiceTransport, error) {
	chats, err := newFiltersManager(db, shh, privateKey, logger)
	if err != nil {
		return nil, err
	}

	// var envelopesMonitor *EnvelopesMonitor
	// if envelopesMonitorConfig != nil {
	// 	envelopesMonitor = NewEnvelopesMonitor(shh, envelopesMonitorConfig)
	// 	envelopesMonitor.Start()
	// }
	return &NimbusWhisperServiceTransport{
		shh: shh,
		// shhAPI: NewSimplePublicWhisperAPI(shh),
		//envelopesMonitor: envelopesMonitor,

		keysManager: &inMemoryWhisperServiceKeysManager{
			shh:               shh,
			privateKey:        privateKey,
			passToSymKeyCache: make(map[string]string),
		},
		chats:       chats,
		mailservers: mailservers,
		logger:      logger.With(zap.Namespace("NimbusWhisperServiceTransport")),
	}, nil
}

// DEPRECATED
func (a *NimbusWhisperServiceTransport) LoadFilters(chats []*Filter, genericDiscoveryTopicEnabled bool) ([]*Filter, error) {
	return a.chats.InitWithChats(chats, genericDiscoveryTopicEnabled)
}

// DEPRECATED
func (a *NimbusWhisperServiceTransport) RemoveFilters(chats []*Filter) error {
	return a.chats.Remove(chats...)
}

func (a *NimbusWhisperServiceTransport) Reset() error {
	return a.chats.Reset()
}

func (a *NimbusWhisperServiceTransport) ProcessNegotiatedSecret(secret statusprototypes.NegotiatedSecret) error {
	_, err := a.chats.LoadNegotiated(secret)
	return err
}

func (a *NimbusWhisperServiceTransport) JoinPublic(chatID string) error {
	_, err := a.chats.LoadPublic(chatID)
	return err
}

func (a *NimbusWhisperServiceTransport) LeavePublic(chatID string) error {
	chat := a.chats.ChatByID(chatID)
	if chat != nil {
		return nil
	}
	return a.chats.Remove(chat)
}

func (a *NimbusWhisperServiceTransport) JoinPrivate(publicKey *ecdsa.PublicKey) error {
	_, err := a.chats.LoadContactCode(publicKey)
	return err
}

func (a *NimbusWhisperServiceTransport) LeavePrivate(publicKey *ecdsa.PublicKey) error {
	chats := a.chats.ChatsByPublicKey(publicKey)
	return a.chats.Remove(chats...)
}

func (a *NimbusWhisperServiceTransport) RetrieveAllMessages() ([]statusprototypes.WhisperChatMessages, error) {
	chatMessages := make(map[string]statusprototypes.WhisperChatMessages)

	for _, chat := range a.chats.Chats() {
		f := a.shh.GetFilter(chat.FilterID)
		if f == nil {
			return nil, errors.New("failed to return a filter")
		}

		messages := chatMessages[chat.ChatID]
		messages.ChatID = chat.ChatID
		messages.Public = chat.IsPublic()
		messages.Messages = append(messages.Messages, f.Retrieve()...)
	}

	var result []statusprototypes.WhisperChatMessages
	for _, messages := range chatMessages {
		result = append(result, messages)
	}
	return result, nil
}

func (a *NimbusWhisperServiceTransport) RetrievePublicMessages(chatID string) ([]*whisper.ReceivedMessage, error) {
	chat, err := a.chats.LoadPublic(chatID)
	if err != nil {
		return nil, err
	}

	f := a.shh.GetFilter(chat.FilterID)
	if f == nil {
		return nil, errors.New("failed to return a filter")
	}

	return f.Retrieve(), nil
}

func (a *NimbusWhisperServiceTransport) RetrievePrivateMessages(publicKey *ecdsa.PublicKey) ([]*whisper.ReceivedMessage, error) {
	chats := a.chats.ChatsByPublicKey(publicKey)
	discoveryChats, err := a.chats.Init(nil, nil, true)
	if err != nil {
		return nil, err
	}

	var result []*whisper.ReceivedMessage

	for _, chat := range append(chats, discoveryChats...) {
		f := a.shh.GetFilter(chat.FilterID)
		if f == nil {
			return nil, errors.New("failed to return a filter")
		}

		result = append(result, f.Retrieve()...)
	}

	return result, nil
}

// DEPRECATED
func (a *NimbusWhisperServiceTransport) RetrieveRawAll() (map[Filter][]*whisper.ReceivedMessage, error) {
	result := make(map[Filter][]*whisper.ReceivedMessage)

	allChats := a.chats.Chats()
	for _, chat := range allChats {
		f := a.shh.GetFilter(chat.FilterID)
		if f == nil {
			return nil, errors.New("failed to return a filter")
		}

		result[*chat] = append(result[*chat], f.Retrieve()...)
	}

	return result, nil
}

// DEPRECATED
func (a *NimbusWhisperServiceTransport) RetrieveRaw(filterID string) ([]*whisper.ReceivedMessage, error) {
	f := a.shh.GetFilter(filterID)
	if f == nil {
		return nil, errors.New("failed to return a filter")
	}
	return f.Retrieve(), nil
}

// SendPublic sends a new message using the Whisper service.
// For public filters, chat name is used as an ID as well as
// a topic.
func (a *NimbusWhisperServiceTransport) SendPublic(ctx context.Context, newMessage *whisper.NewMessage, chatName string) ([]byte, error) {
	if err := a.addSig(newMessage); err != nil {
		return nil, err
	}

	chat, err := a.chats.LoadPublic(chatName)
	if err != nil {
		return nil, err
	}

	newMessage.SymKeyID = chat.SymKeyID
	newMessage.Topic = chat.Topic

	return a.post(ctx, *newMessage)
}

func (a *NimbusWhisperServiceTransport) SendPrivateWithSharedSecret(ctx context.Context, newMessage *whisper.NewMessage, publicKey *ecdsa.PublicKey, secret []byte) ([]byte, error) {
	if err := a.addSig(newMessage); err != nil {
		return nil, err
	}

	chat, err := a.chats.LoadNegotiated(statusprototypes.NegotiatedSecret{
		PublicKey: publicKey,
		Key:       secret,
	})
	if err != nil {
		return nil, err
	}

	newMessage.SymKeyID = chat.SymKeyID
	newMessage.Topic = chat.Topic
	newMessage.PublicKey = nil

	return a.post(ctx, *newMessage)
}

func (a *NimbusWhisperServiceTransport) SendPrivateWithPartitioned(ctx context.Context, newMessage *whisper.NewMessage, publicKey *ecdsa.PublicKey) ([]byte, error) {
	if err := a.addSig(newMessage); err != nil {
		return nil, err
	}

	chat, err := a.chats.LoadPartitioned(publicKey)
	if err != nil {
		return nil, err
	}

	newMessage.Topic = chat.Topic
	newMessage.PublicKey = crypto.FromECDSAPub(publicKey)

	return a.post(ctx, *newMessage)
}

func (a *NimbusWhisperServiceTransport) SendPrivateOnDiscovery(ctx context.Context, newMessage *whisper.NewMessage, publicKey *ecdsa.PublicKey) ([]byte, error) {
	if err := a.addSig(newMessage); err != nil {
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

	return a.post(ctx, *newMessage)
}

func (a *NimbusWhisperServiceTransport) addSig(newMessage *whisper.NewMessage) error {
	sigID, err := a.keysManager.AddOrGetKeyPair(a.keysManager.privateKey)
	if err != nil {
		return err
	}
	newMessage.Sig = sigID
	return nil
}

func (a *NimbusWhisperServiceTransport) Track(identifiers [][]byte, hash []byte, newMessage whisper.NewMessage) {
	// if a.envelopesMonitor != nil {
	// 	a.envelopesMonitor.Add(identifiers, common.BytesToHash(hash), newMessage)
	// }
}

func (a *NimbusWhisperServiceTransport) Stop() {
	// if a.envelopesMonitor != nil {
	// 	a.envelopesMonitor.Stop()
	// }
}

func (a *NimbusWhisperServiceTransport) post(ctx context.Context, req whisper.NewMessage) (hexutil.Bytes, error) {
	var (
		symKeyGiven = len(req.SymKeyID) > 0
		pubKeyGiven = len(req.PublicKey) > 0
		err         error
	)

	// user must specify either a symmetric or an asymmetric key
	if (symKeyGiven && pubKeyGiven) || (!symKeyGiven && !pubKeyGiven) {
		return nil, whisper.ErrSymAsym
	}

	params := &whisper.MessageParams{
		TTL:      req.TTL,
		Payload:  req.Payload,
		Padding:  req.Padding,
		WorkTime: req.PowTime,
		PoW:      req.PowTarget,
		Topic:    req.Topic,
	}

	// Set key that is used to sign the message
	if len(req.Sig) > 0 {
		if params.Src, err = a.keysManager.GetPrivateKey(req.Sig); err != nil {
			return nil, err
		}
	}

	// Set symmetric key that is used to encrypt the message
	if symKeyGiven {
		if params.Topic == (whisper.TopicType{}) { // topics are mandatory with symmetric encryption
			return nil, whisper.ErrNoTopics
		}
		if params.KeySym, err = a.keysManager.RawSymKey(req.SymKeyID); err != nil {
			return nil, err
		}
		if !validateDataIntegrity(params.KeySym, aesKeyLength) {
			return nil, whisper.ErrInvalidSymmetricKey
		}
	}

	// Set asymmetric key that is used to encrypt the message
	if pubKeyGiven {
		if params.Dst, err = crypto.UnmarshalPubkey(req.PublicKey); err != nil {
			return nil, whisper.ErrInvalidPublicKey
		}
	}

	// encrypt and send message
	var result []byte
	// whisperMsg, err := whisper.NewSentMessage(params)
	// if err != nil {
	// 	return nil, err
	// }

	// var result []byte
	// env, err := whisperMsg.Wrap(params, api.w.GetCurrentTime())
	// if err != nil {
	// 	return nil, err
	// }

	// // send to specific node (skip PoW check)
	if len(req.TargetPeer) > 0 {
		n, err := enode.ParseV4(req.TargetPeer)
		if err != nil {
			return nil, fmt.Errorf("failed to parse target peer: %s", err)
		}
		//err = api.w.SendP2PMessage(n.ID().Bytes(), env)
		envHash := nimstatus.Post(n.ID().Bytes(), params.Topic, params.KeySym, params.Dst, params.Src, params.Payload, params.Padding, params.PoW, params.TTL)
		if envHash == "" {
			err = errors.New("failed to post message")
		}

		if err == nil {
			hash := common.HexToHash(envHash)
			result = hash[:]
		}
		return result, err
	}

	// // ensure that the message PoW meets the node's minimum accepted PoW
	// if req.PowTarget < api.w.MinPow() {
	// 	return nil, whisper.ErrTooLowPoW
	// }

	envHash := nimstatus.Post(nil, params.Topic, params.KeySym, params.Dst, params.Src, params.Payload, params.Padding, params.PoW, params.TTL)
	if envHash == "" {
		err = errors.New("failed to post message")
	}
	// err = api.w.Send(env)
	if err == nil {
		hash := common.HexToHash(envHash)
		result = hash[:]
	}
	return result, err
}
