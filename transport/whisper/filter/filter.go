package filter

import (
	"crypto/ecdsa"
	"encoding/hex"
	"log"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	whisper "github.com/status-im/whisper/whisperv6"
)

const (
	discoveryTopic = "contact-discovery"
)

var (
	// The number of partitions.
	nPartitions = big.NewInt(5000)
	minPow      = 0.0
)

type Filter struct {
	FilterID string
	Topic    whisper.TopicType
	SymKeyID string
}

type NegodiatedSecret struct {
	PublicKey *ecdsa.PublicKey
	Key       []byte
}

type Chat struct {
	// ChatID is the identifier of the chat
	ChatID string `json:"chatId"`
	// FilterID the whisper filter id generated
	FilterID string `json:"filterId"`
	// SymKeyID is the symmetric key id used for symmetric chats
	SymKeyID string `json:"symKeyId"`
	// Identity is the public key of the other recipient for non-public chats.
	// It's encoded using encoding/hex.
	Identity string `json:"identity"`
	// Topic is the whisper topic
	Topic whisper.TopicType `json:"topic"`
}

type Messages struct {
	Chat     *Chat              `json:"chat"`
	Messages []*whisper.Message `json:"messages"`
	Error    error              `json:"error"`
}

type ChatsManager struct {
	whisper     *whisper.Whisper
	persistence Persistence
	privateKey  *ecdsa.PrivateKey
	keys        map[string][]byte

	mutex sync.Mutex
	chats map[string]*Chat

	onNewMessages func([]*Messages)
	quit          chan struct{}
}

// New returns a new filter service
func New(w *whisper.Whisper, p Persistence, onNewMessages func([]*Messages)) (*ChatsManager, error) {
	// TODO: legacy private key selection
	keyID := w.SelectedKeyPairID()
	privateKey, err := w.GetPrivateKey(keyID)
	if err != nil {
		return nil, err
	}

	return &ChatsManager{
		privateKey:    privateKey,
		whisper:       w,
		persistence:   p,
		chats:         make(map[string]*Chat),
		onNewMessages: onNewMessages,
	}, nil
}

func (s *ChatsManager) Init(chatIDs []string, publicKeys []*ecdsa.PublicKey, negotiated []NegodiatedSecret) ([]*Chat, error) {
	log.Printf("[FiltersManager::Init] initializing")

	keys, err := s.persistence.All()
	if err != nil {
		return nil, err
	}
	s.keys = keys

	// Load our contact code.
	_, err = s.loadContactCode(&s.privateKey.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load contact code")
	}

	// Load partitioned topic.
	_, err = s.loadMyPartitioned()

	// Add discovery topic.
	err = s.loadDiscovery()
	if err != nil {
		return nil, err
	}

	// Add public, one-to-one and generic chats.
	for _, chatID := range chatIDs {
		_, err := s.loadPublic(chatID)
		if err != nil {
			return nil, err
		}
	}

	for _, publicKey := range publicKeys {
		_, err := s.loadContactCode(publicKey)
		if err != nil {
			return nil, err
		}
	}

	for _, secret := range negotiated {
		if _, err := s.LoadNegotiated(secret); err != nil {
			return nil, err
		}
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	var allChats []*Chat
	for _, chat := range s.chats {
		allChats = append(allChats, chat)
	}
	return allChats, nil
}

func (s *ChatsManager) Uninitialize() error {
	var chats []*Chat

	s.mutex.Lock()
	for _, chat := range s.chats {
		chats = append(chats, chat)
	}
	s.mutex.Unlock()

	return s.Remove(chats...)
}

func (s *ChatsManager) Start(checkPeriod time.Duration) {
	ticker := time.NewTicker(checkPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			messages := s.getMessages()

			if len(messages) != 0 {
				s.onNewMessages(messages)
			}
		case <-s.quit:
			return
		}
	}
}

// Stop removes all the filters
func (s *ChatsManager) Stop() error {
	close(s.quit)

	var chats []*Chat

	s.mutex.Lock()
	for _, chat := range s.chats {
		chats = append(chats, chat)
	}
	s.mutex.Unlock()

	return s.Remove(chats...)
}

// ChatByID returns a chat by chatID.
func (s *ChatsManager) ChatByID(chatID string) *Chat {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.chats[chatID]
}

// Remove remove all the filters associated with a chat/identity
func (s *ChatsManager) Remove(chats ...*Chat) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, chat := range chats {
		if err := s.whisper.Unsubscribe(chat.FilterID); err != nil {
			return err
		}
		if chat.SymKeyID != "" {
			s.whisper.DeleteSymKey(chat.SymKeyID)
		}
		delete(s.chats, chat.ChatID)
	}

	return nil
}

// LoadPartitioned creates a filter for a partitioned topic.
func (s *ChatsManager) LoadPartitioned(publicKey *ecdsa.PublicKey) (*Chat, error) {
	return s.loadPartitioned(publicKey, false)
}

func (s *ChatsManager) loadMyPartitioned() (*Chat, error) {
	return s.loadPartitioned(&s.privateKey.PublicKey, true)
}

func (s *ChatsManager) loadPartitioned(publicKey *ecdsa.PublicKey, listen bool) (*Chat, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	chatID := partitionedTopic(publicKey)
	if _, ok := s.chats[chatID]; ok {
		return s.chats[chatID], nil
	}

	// We set up a filter so we can publish,
	// but we discard envelopes if listen is false.
	filter, err := s.addAsymmetric(chatID, listen)
	if err != nil {
		return nil, err
	}

	identityStr := hex.EncodeToString(crypto.FromECDSAPub(publicKey))

	chat := &Chat{
		ChatID:   chatID,
		FilterID: filter.FilterID,
		Topic:    filter.Topic,
		Identity: identityStr,
	}

	s.chats[chatID] = chat

	return chat, nil
}

// LoadNegotiated loads a negotiated secret as a filter.
func (s *ChatsManager) LoadNegotiated(secret NegodiatedSecret) (*Chat, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	chatID := negotiatedTopic(secret.PublicKey)

	if _, ok := s.chats[chatID]; ok {
		return s.chats[chatID], nil
	}

	keyString := hex.EncodeToString(secret.Key)
	filter, err := s.addSymmetric(keyString)
	if err != nil {
		return nil, err
	}

	chat := &Chat{
		ChatID:   chatID,
		Topic:    filter.Topic,
		SymKeyID: filter.SymKeyID,
		FilterID: filter.FilterID,
		Identity: publicKeyToStr(secret.PublicKey),
	}

	s.chats[chat.ChatID] = chat

	return chat, nil
}

// loadDiscovery adds two discovery filters: for generic discovery topic
// and for the personal discovery topic.
func (s *ChatsManager) loadDiscovery() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.chats[discoveryTopic]; ok {
		return nil
	}

	// Load generic discovery topic.
	identityStr := publicKeyToStr(&s.privateKey.PublicKey)

	discoveryChat := &Chat{
		ChatID:   discoveryTopic,
		Identity: identityStr,
	}

	discoveryResponse, err := s.addAsymmetric(discoveryChat.ChatID, true)
	if err != nil {
		return err
	}

	discoveryChat.Topic = discoveryResponse.Topic
	discoveryChat.FilterID = discoveryResponse.FilterID

	s.chats[discoveryChat.ChatID] = discoveryChat

	// Load personal discovery
	personalDiscoveryTopic := personalDiscoveryTopic(&s.privateKey.PublicKey)
	personalDiscoveryChat := &Chat{
		ChatID:   personalDiscoveryTopic,
		Identity: identityStr,
	}

	discoveryResponse, err = s.addAsymmetric(personalDiscoveryChat.ChatID, true)
	if err != nil {
		return err
	}

	personalDiscoveryChat.Topic = discoveryResponse.Topic
	personalDiscoveryChat.FilterID = discoveryResponse.FilterID

	s.chats[personalDiscoveryChat.ChatID] = personalDiscoveryChat

	return nil
}

// loadPublic adds a filter for a public chat.
func (s *ChatsManager) loadPublic(chatID string) (*Chat, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if chat, ok := s.chats[chatID]; ok {
		return chat, nil
	}

	filterAndTopic, err := s.addSymmetric(chatID)
	if err != nil {
		return nil, err
	}

	chat := &Chat{
		ChatID:   chatID,
		FilterID: filterAndTopic.FilterID,
		SymKeyID: filterAndTopic.SymKeyID,
		Topic:    filterAndTopic.Topic,
	}

	s.chats[chatID] = chat

	return chat, nil
}

// loadContactCode creates a filter for the advertise topic for a given public key.
func (s *ChatsManager) loadContactCode(pubKey *ecdsa.PublicKey) (*Chat, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	chatID := contactCodeTopic(pubKey)

	if _, ok := s.chats[chatID]; ok {
		return s.chats[chatID], nil
	}

	contactCodeFilter, err := s.addSymmetric(chatID)
	if err != nil {
		return nil, err
	}

	chat := &Chat{
		ChatID:   chatID,
		FilterID: contactCodeFilter.FilterID,
		Topic:    contactCodeFilter.Topic,
		SymKeyID: contactCodeFilter.SymKeyID,
		Identity: publicKeyToStr(pubKey),
	}

	s.chats[chatID] = chat
	return chat, nil
}

// addSymmetric adds a symmetric key filter
func (s *ChatsManager) addSymmetric(chatID string) (*Filter, error) {
	var symKeyID string
	var err error

	topic := toTopic(chatID)
	topics := [][]byte{topic}

	symKey, ok := s.keys[chatID]
	if ok {
		symKeyID, err = s.whisper.AddSymKeyDirect(symKey)
		if err != nil {
			return nil, err
		}
	} else {
		symKeyID, err = s.whisper.AddSymKeyFromPassword(chatID)
		if err != nil {
			return nil, err
		}
		if symKey, err = s.whisper.GetSymKey(symKeyID); err != nil {
			return nil, err
		}
		s.keys[chatID] = symKey

		err = s.persistence.Add(chatID, symKey)
		if err != nil {
			return nil, err
		}
	}

	f := &whisper.Filter{
		KeySym:   symKey,
		PoW:      minPow,
		AllowP2P: true,
		Topics:   topics,
		Messages: s.whisper.NewMessageStore(),
	}

	id, err := s.whisper.Subscribe(f)
	if err != nil {
		return nil, err
	}

	return &Filter{
		FilterID: id,
		SymKeyID: symKeyID,
		Topic:    whisper.BytesToTopic(topic),
	}, nil
}

// addAsymmetricFilter adds a filter with our private key
// and set minPow according to the listen parameter.
func (s *ChatsManager) addAsymmetric(chatID string, listen bool) (*Filter, error) {
	var (
		err error
		pow = 1.0 // use PoW high enough to discard all messages for the filter
	)

	if listen {
		pow = minPow
	}

	topic := toTopic(chatID)
	topics := [][]byte{topic}

	f := &whisper.Filter{
		KeyAsym:  s.privateKey,
		PoW:      pow,
		AllowP2P: true,
		Topics:   topics,
		Messages: s.whisper.NewMessageStore(),
	}

	id, err := s.whisper.Subscribe(f)
	if err != nil {
		return nil, err
	}
	return &Filter{FilterID: id, Topic: whisper.BytesToTopic(topic)}, nil
}

// Get returns a negotiated chat given an identity
func (s *ChatsManager) GetNegotiated(identity *ecdsa.PublicKey) *Chat {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.chats[negotiatedTopic(identity)]
}

// DEPRECATED
func (s *ChatsManager) InitDeprecated(chats []*Chat, secrets []NegodiatedSecret) ([]*Chat, error) {
	var (
		chatIDs    []string
		publicKeys []*ecdsa.PublicKey
	)

	for _, chat := range chats {
		if chat.ChatID != "" {
			chatIDs = append(chatIDs, chat.ChatID)
		} else if chat.Identity != "" {
			publicKeyBytes, err := hex.DecodeString(chat.Identity)
			if err != nil {
				return nil, err
			}

			publicKey, err := crypto.UnmarshalPubkey(publicKeyBytes)
			if err != nil {
				return nil, err
			}

			publicKeys = append(publicKeys, publicKey)
		}
	}

	return s.Init(chatIDs, publicKeys, secrets)
}

// DEPRECATED
func (s *ChatsManager) Load(chat *Chat) ([]*Chat, error) {
	if chat.ChatID != "" {
		chat, err := s.loadPublic(chat.ChatID)
		return []*Chat{chat}, err
	} else if chat.Identity != "" {
		publicKeyBytes, err := hex.DecodeString(chat.Identity)
		if err != nil {
			return nil, err
		}

		publicKey, err := crypto.UnmarshalPubkey(publicKeyBytes)
		if err != nil {
			return nil, err
		}

		chat, err := s.loadContactCode(publicKey)
		return []*Chat{chat}, err
	}

	return nil, errors.New("invalid Chat to load")
}

func (s *ChatsManager) getMessages() []*Messages {
	var response []*Messages
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for chatID := range s.chats {
		messages := s.getMessagesForChat(chatID)
		if messages.Error != nil || len(messages.Messages) != 0 {
			response = append(response, messages)
		}
	}

	return response
}

func (s *ChatsManager) getMessagesForChat(chatID string) *Messages {
	response := &Messages{}

	response.Chat = s.chats[chatID]
	if response.Chat == nil {
		response.Error = errors.New("Chat not found")

		return response
	}

	filter := s.whisper.GetFilter(response.Chat.FilterID)
	if filter == nil {
		response.Error = errors.New("Filter not found")
		return response
	}

	receivedMessages := filter.Retrieve()
	response.Messages = make([]*whisper.Message, 0, len(receivedMessages))
	for _, msg := range receivedMessages {
		response.Messages = append(response.Messages, whisper.ToWhisperMessage(msg))
	}

	return response
}

// toTopic converts a string to a whisper topic.
func toTopic(s string) []byte {
	return crypto.Keccak256([]byte(s))[:whisper.TopicLength]
}

func ToTopic(s string) []byte {
	return toTopic(s)
}

func publicKeyToStr(publicKey *ecdsa.PublicKey) string {
	return hex.EncodeToString(crypto.FromECDSAPub(publicKey))
}

func personalDiscoveryTopic(publicKey *ecdsa.PublicKey) string {
	return "contact-discovery-" + publicKeyToStr(publicKey)
}

// partitionedTopic returns the associated partitioned topic string
// with the given public key.
func partitionedTopic(publicKey *ecdsa.PublicKey) string {
	partition := big.NewInt(0)
	partition.Mod(publicKey.X, nPartitions)
	return "contact-discovery-" + strconv.FormatInt(partition.Int64(), 10)
}

// PublicKeyToPartitionedTopicBytes returns the bytes of the partitioned topic
// associated with the given public key
func PublicKeyToPartitionedTopicBytes(publicKey *ecdsa.PublicKey) []byte {
	return toTopic(partitionedTopic(publicKey))
}

func ContactCodeTopic(publicKey *ecdsa.PublicKey) string {
	return contactCodeTopic(publicKey)
}

func contactCodeTopic(publicKey *ecdsa.PublicKey) string {
	return "0x" + publicKeyToStr(publicKey) + "-contact-code"
}

func negotiatedTopic(publicKey *ecdsa.PublicKey) string {
	return "0x" + publicKeyToStr(publicKey) + "-negotiated"
}
