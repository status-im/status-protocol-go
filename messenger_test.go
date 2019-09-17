package statusproto

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/status-im/status-protocol-go/sqlite"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	_ "github.com/mutecomm/go-sqlcipher" // require go-sqlcipher that overrides default implementation
	"github.com/status-im/status-protocol-go/tt"
	protocol "github.com/status-im/status-protocol-go/v1"
	whisper "github.com/status-im/whisper/whisperv6"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestMessengerSuite(t *testing.T) {
	suite.Run(t, new(MessengerSuite))
}

func TestMessengerWithDataSyncEnabledSuite(t *testing.T) {
	suite.Run(t, &MessengerSuite{enableDataSync: true})
}

func TestPostProcessorSuite(t *testing.T) {
	suite.Run(t, new(PostProcessorSuite))
}

type MessengerSuite struct {
	suite.Suite

	enableDataSync bool

	m          *Messenger        // main instance of Messenger
	privateKey *ecdsa.PrivateKey // private key for the main instance of Messenger
	// If one wants to send messages between different instances of Messenger,
	// a single Whisper service should be shared.
	shh      *whisper.Whisper
	tmpFiles []*os.File // files to clean up
	logger   *zap.Logger
}

func (s *MessengerSuite) SetupTest() {
	s.logger = tt.MustCreateTestLogger()

	config := whisper.DefaultConfig
	config.MinimumAcceptedPOW = 0
	s.shh = whisper.New(&config)
	s.Require().NoError(s.shh.Start(nil))

	s.m = s.newMessenger()
	s.privateKey = s.m.identity
}

func (s *MessengerSuite) newMessenger() *Messenger {
	tmpFile, err := ioutil.TempFile("", "")
	s.Require().NoError(err)

	privateKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	options := []Option{
		WithCustomLogger(s.logger),
		WithMessagesPersistenceEnabled(),
		WithDatabaseConfig(tmpFile.Name(), "some-key"),
	}
	if s.enableDataSync {
		options = append(options, WithDatasync())
	}
	m, err := NewMessenger(
		privateKey,
		s.shh,
		"installation-1",
		options...,
	)
	s.Require().NoError(err)

	err = m.Init()
	s.Require().NoError(err)

	s.tmpFiles = append(s.tmpFiles, tmpFile)

	return m
}

func (s *MessengerSuite) TearDownTest() {
	s.Require().NoError(s.m.Shutdown())
	for _, f := range s.tmpFiles {
		_ = os.Remove(f.Name())
	}
	_ = s.logger.Sync()
}

func (s *MessengerSuite) TestInMemoryDatabase() {
	key, err := crypto.GenerateKey()
	s.Require().NoError(err)
	m, err := NewMessenger(
		key,
		s.shh,
		"installation-1",
	)
	s.Require().NoError(err)
	// Verify the in-memory database works.
	err = m.persistence.SaveChat(Chat{
		ID:       "abc",
		Name:     "abc",
		Active:   true,
		ChatType: ChatTypePublic,
	})
	s.Require().NoError(err)
	result, err := m.persistence.Chats()
	s.Require().NoError(err)
	s.Require().Len(result, 1)
}

func (s *MessengerSuite) TestInit() {
	testCases := []struct {
		Name         string
		Prep         func()
		AddedFilters int
	}{
		{
			Name:         "no chats and contacts",
			Prep:         func() {},
			AddedFilters: 3,
		},
		{
			Name: "active public chat",
			Prep: func() {
				publicChat := Chat{
					ChatType: ChatTypePublic,
					ID:       "some-public-chat",
					Active:   true,
				}
				err := s.m.SaveChat(publicChat)
				s.Require().NoError(err)
			},
			AddedFilters: 1,
		},
		{
			Name: "active one-to-one chat",
			Prep: func() {
				key, err := crypto.GenerateKey()
				s.Require().NoError(err)
				privateChat := Chat{
					ID:        hexutil.Encode(crypto.FromECDSAPub(&key.PublicKey)),
					ChatType:  ChatTypeOneToOne,
					PublicKey: &key.PublicKey,
					Active:    true,
				}
				err = s.m.SaveChat(privateChat)
				s.Require().NoError(err)
			},
			AddedFilters: 1,
		},
		{
			Name: "active group chat",
			Prep: func() {
				key1, err := crypto.GenerateKey()
				s.Require().NoError(err)
				key2, err := crypto.GenerateKey()
				s.Require().NoError(err)
				groupChat := Chat{
					ChatType: ChatTypePrivateGroupChat,
					Active:   true,
					Members: []ChatMember{
						{
							ID: hexutil.Encode(crypto.FromECDSAPub(&key1.PublicKey)),
						},
						{
							ID: hexutil.Encode(crypto.FromECDSAPub(&key2.PublicKey)),
						},
					},
				}
				err = s.m.SaveChat(groupChat)
				s.Require().NoError(err)
			},
			AddedFilters: 2,
		},
		{
			Name: "inactive chat",
			Prep: func() {
				publicChat := Chat{
					ChatType: ChatTypePublic,
					ID:       "some-public-chat-2",
					Active:   false,
				}
				err := s.m.SaveChat(publicChat)
				s.Require().NoError(err)
			},
			AddedFilters: 0,
		},
		{
			Name: "added contact",
			Prep: func() {
				key, err := crypto.GenerateKey()
				s.Require().NoError(err)
				contact := Contact{
					ID:         hexutil.Encode(crypto.FromECDSAPub(&key.PublicKey)),
					Name:       "Some Contact",
					SystemTags: []string{contactAdded},
				}
				err = s.m.SaveContact(contact)
				s.Require().NoError(err)
			},
			AddedFilters: 1,
		},
		{
			Name: "added and blocked contact",
			Prep: func() {
				key, err := crypto.GenerateKey()
				s.Require().NoError(err)
				contact := Contact{
					ID:         hexutil.Encode(crypto.FromECDSAPub(&key.PublicKey)),
					Name:       "Some Contact",
					SystemTags: []string{contactAdded, contactBlocked},
				}
				err = s.m.SaveContact(contact)
				s.Require().NoError(err)
			},
			AddedFilters: 0,
		},
		{
			Name: "added by them contact",
			Prep: func() {
				key, err := crypto.GenerateKey()
				s.Require().NoError(err)
				contact := Contact{
					ID:         hexutil.Encode(crypto.FromECDSAPub(&key.PublicKey)),
					Name:       "Some Contact",
					SystemTags: []string{contactRequestReceived},
				}
				err = s.m.SaveContact(contact)
				s.Require().NoError(err)
			},
			AddedFilters: 0,
		},
	}

	expectedFilters := 0
	for _, tc := range testCases {
		s.Run(tc.Name, func() {
			tc.Prep()
			err := s.m.Init()
			s.Require().NoError(err)
			filters := s.m.transport.Filters()
			expectedFilters += tc.AddedFilters
			s.Equal(expectedFilters, len(filters))
		})
	}
}

func (s *MessengerSuite) TestSendPublic() {
	chat := CreatePublicChat("test-chat")
	err := s.m.SaveChat(chat)
	s.NoError(err)
	_, err = s.m.Send(context.Background(), chat.ID, []byte("test"))
	s.NoError(err)
}

func (s *MessengerSuite) TestSendPrivate() {
	recipientKey, err := crypto.GenerateKey()
	s.NoError(err)
	chat := CreateOneToOneChat("XXX", &recipientKey.PublicKey)
	err = s.m.SaveChat(chat)
	s.NoError(err)
	_, err = s.m.Send(context.Background(), chat.ID, []byte("test"))
	s.NoError(err)
}

func (s *MessengerSuite) TestRetrieveOwnPublic() {
	chat := CreatePublicChat("status")
	err := s.m.SaveChat(chat)
	s.NoError(err)

	_, err = s.m.Send(context.Background(), chat.ID, []byte("test"))
	s.NoError(err)

	// Give Whisper some time to propagate message to filters.
	time.Sleep(time.Millisecond * 500)

	// Retrieve chat
	messages, err := s.m.RetrieveAll(context.Background(), RetrieveLatest)
	s.NoError(err)
	s.Len(messages, 1)

	// Retrieve again to test skipping already existing err.
	messages, err = s.m.RetrieveAll(context.Background(), RetrieveLastDay)
	s.NoError(err)
	s.Require().Len(messages, 1)

	// Verify message fields.
	message := messages[0]
	s.NotEmpty(message.ID)
	s.Equal(&s.privateKey.PublicKey, message.SigPubKey) // this is OUR message
}

func (s *MessengerSuite) TestRetrieveOwnPrivate() {
	recipientKey, err := crypto.GenerateKey()
	s.NoError(err)
	chat := CreateOneToOneChat("XXX", &recipientKey.PublicKey)
	err = s.m.SaveChat(chat)
	s.NoError(err)

	messageID, err := s.m.Send(context.Background(), chat.ID, []byte("test"))
	s.NoError(err)

	// No need to sleep because the message is returned from own messages in the processor.

	// Retrieve chat
	messages, err := s.m.RetrieveAll(context.Background(), RetrieveLatest)
	s.NoError(err)
	s.Len(messages, 1)

	// Retrieve again to test skipping already existing err.
	messages, err = s.m.RetrieveAll(context.Background(), RetrieveLastDay)
	s.NoError(err)
	s.Len(messages, 1)

	// Verify message fields.
	message := messages[0]
	s.Equal(messageID, message.ID)
	s.Equal(&s.privateKey.PublicKey, message.SigPubKey) // this is OUR message
}

func (s *MessengerSuite) TestRetrieveTheirPrivate() {
	theirMessenger := s.newMessenger()
	chat := CreateOneToOneChat("XXX", &s.privateKey.PublicKey)
	err := theirMessenger.SaveChat(chat)
	s.NoError(err)

	messageID, err := theirMessenger.Send(context.Background(), chat.ID, []byte("test"))
	s.NoError(err)

	var messages []*protocol.Message

	err = tt.RetryWithBackOff(func() error {
		var err error
		messages, err = s.m.RetrieveAll(context.Background(), RetrieveLatest)
		if err == nil && len(messages) == 0 {
			err = errors.New("no messages")
		}
		return err
	})
	s.NoError(err)

	// Validate received message.
	s.Require().Len(messages, 1)
	message := messages[0]
	s.Equal(messageID, message.ID)
	s.Equal(&theirMessenger.identity.PublicKey, message.SigPubKey)
}

func (s *MessengerSuite) TestChatPersistencePublic() {
	chat := Chat{
		ID:                     "chat-name",
		Name:                   "chat-name",
		Color:                  "#fffff",
		Active:                 true,
		ChatType:               ChatTypePublic,
		Timestamp:              10,
		LastClockValue:         20,
		DeletedAtClockValue:    30,
		UnviewedMessagesCount:  40,
		LastMessageContentType: "something",
		LastMessageContent:     "something-else",
	}

	s.Require().NoError(s.m.SaveChat(chat))
	savedChats, err := s.m.Chats()
	s.Require().NoError(err)
	s.Require().Equal(1, len(savedChats))

	actualChat := savedChats[0]
	expectedChat := &chat

	s.Require().Equal(actualChat, expectedChat)
}

func (s *MessengerSuite) TestDeleteChat() {
	chatID := "chatid"
	chat := Chat{
		ID:                     chatID,
		Name:                   "chat-name",
		Color:                  "#fffff",
		Active:                 true,
		ChatType:               ChatTypePublic,
		Timestamp:              10,
		LastClockValue:         20,
		DeletedAtClockValue:    30,
		UnviewedMessagesCount:  40,
		LastMessageContentType: "something",
		LastMessageContent:     "something-else",
	}

	s.Require().NoError(s.m.SaveChat(chat))
	savedChats, err := s.m.Chats()
	s.Require().NoError(err)
	s.Require().Equal(1, len(savedChats))

	s.Require().NoError(s.m.DeleteChat(chatID))
	savedChats, err = s.m.Chats()
	s.Require().NoError(err)
	s.Require().Equal(0, len(savedChats))
}

func (s *MessengerSuite) TestChatPersistenceUpdate() {
	chat := Chat{
		ID:                     "chat-name",
		Name:                   "chat-name",
		Color:                  "#fffff",
		Active:                 true,
		ChatType:               ChatTypePublic,
		Timestamp:              10,
		LastClockValue:         20,
		DeletedAtClockValue:    30,
		UnviewedMessagesCount:  40,
		LastMessageContentType: "something",
		LastMessageContent:     "something-else",
	}

	s.Require().NoError(s.m.SaveChat(chat))
	savedChats, err := s.m.Chats()
	s.Require().NoError(err)
	s.Require().Equal(1, len(savedChats))

	actualChat := savedChats[0]
	expectedChat := &chat

	s.Require().Equal(expectedChat, actualChat)

	chat.Name = "updated-name"
	s.Require().NoError(s.m.SaveChat(chat))
	updatedChats, err := s.m.Chats()
	s.Require().NoError(err)
	s.Require().Equal(1, len(updatedChats))

	actualUpdatedChat := updatedChats[0]
	expectedUpdatedChat := &chat

	s.Require().Equal(expectedUpdatedChat, actualUpdatedChat)
}

func (s *MessengerSuite) TestChatPersistenceOneToOne() {
	pkStr := "0x0424a68f89ba5fcd5e0640c1e1f591d561fa4125ca4e2a43592bc4123eca10ce064e522c254bb83079ba404327f6eafc01ec90a1444331fe769d3f3a7f90b0dde1"
	chat := Chat{
		ID:                     pkStr,
		Name:                   pkStr,
		Color:                  "#fffff",
		Active:                 true,
		ChatType:               ChatTypeOneToOne,
		Timestamp:              10,
		LastClockValue:         20,
		DeletedAtClockValue:    30,
		UnviewedMessagesCount:  40,
		LastMessageContentType: "something",
		LastMessageContent:     "something-else",
	}
	publicKeyBytes, err := hex.DecodeString(pkStr[2:])
	s.Require().NoError(err)

	pk, err := crypto.UnmarshalPubkey(publicKeyBytes)
	s.Require().NoError(err)

	s.Require().NoError(s.m.SaveChat(chat))
	savedChats, err := s.m.Chats()
	s.Require().NoError(err)
	s.Require().Equal(1, len(savedChats))

	actualChat := savedChats[0]
	expectedChat := &chat
	expectedChat.PublicKey = pk

	s.Require().Equal(expectedChat, actualChat)
}

func (s *MessengerSuite) TestChatPersistencePrivateGroupChat() {
	chat := Chat{
		ID:        "chat-id",
		Name:      "chat-id",
		Color:     "#fffff",
		Active:    true,
		ChatType:  ChatTypePrivateGroupChat,
		Timestamp: 10,
		Members: []ChatMember{
			ChatMember{
				ID:     "1",
				Admin:  false,
				Joined: true,
			},
			ChatMember{
				ID:     "2",
				Admin:  true,
				Joined: false,
			},
			ChatMember{
				ID:     "3",
				Admin:  true,
				Joined: true,
			},
		},
		MembershipUpdates: []ChatMembershipUpdate{
			ChatMembershipUpdate{
				ID:         "1",
				Type:       "type-1",
				Name:       "name-1",
				ClockValue: 1,
				Signature:  "signature-1",
				From:       "from-1",
				Member:     "member-1",
				Members:    []string{"member-1", "member-2"},
			},
			ChatMembershipUpdate{
				ID:         "2",
				Type:       "type-2",
				Name:       "name-2",
				ClockValue: 2,
				Signature:  "signature-2",
				From:       "from-2",
				Member:     "member-2",
				Members:    []string{"member-2", "member-3"},
			},
		},
		LastClockValue:         20,
		DeletedAtClockValue:    30,
		UnviewedMessagesCount:  40,
		LastMessageContentType: "something",
		LastMessageContent:     "something-else",
	}
	s.Require().NoError(s.m.SaveChat(chat))
	savedChats, err := s.m.Chats()
	s.Require().NoError(err)
	s.Require().Equal(1, len(savedChats))

	actualChat := savedChats[0]
	expectedChat := &chat

	s.Require().Equal(expectedChat, actualChat)
}

func (s *MessengerSuite) TestBlockContact() {
	pk := "0x0424a68f89ba5fcd5e0640c1e1f591d561fa4125ca4e2a43592bc4123eca10ce064e522c254bb83079ba404327f6eafc01ec90a1444331fe769d3f3a7f90b0dde1"

	contact := Contact{
		ID:          pk,
		Address:     "contact-address",
		Name:        "contact-name",
		Photo:       "contact-photo",
		LastUpdated: 20,
		SystemTags:  []string{"1", "2"},
		DeviceInfo: []ContactDeviceInfo{
			ContactDeviceInfo{
				InstallationID: "1",
				Timestamp:      2,
				FCMToken:       "token",
			},
			ContactDeviceInfo{
				InstallationID: "2",
				Timestamp:      3,
				FCMToken:       "token-2",
			},
		},
		TributeToTalk: "talk",
	}

	chat1 := Chat{
		ID:                    contact.ID,
		Name:                  "chat-name",
		Color:                 "#fffff",
		Active:                true,
		ChatType:              ChatTypeOneToOne,
		Timestamp:             1,
		LastClockValue:        20,
		DeletedAtClockValue:   30,
		UnviewedMessagesCount: 40,
	}

	chat2 := Chat{
		ID:                    "chat-2",
		Name:                  "chat-name",
		Color:                 "#fffff",
		Active:                true,
		ChatType:              ChatTypePublic,
		Timestamp:             2,
		LastClockValue:        20,
		DeletedAtClockValue:   30,
		UnviewedMessagesCount: 40,
	}

	chat3 := Chat{
		ID:                    "chat-3",
		Name:                  "chat-name",
		Color:                 "#fffff",
		Active:                true,
		ChatType:              ChatTypePublic,
		Timestamp:             3,
		LastClockValue:        20,
		DeletedAtClockValue:   30,
		UnviewedMessagesCount: 40,
	}

	s.Require().NoError(s.m.SaveChat(chat1))
	s.Require().NoError(s.m.SaveChat(chat2))
	s.Require().NoError(s.m.SaveChat(chat3))

	s.Require().NoError(s.m.SaveContact(contact))

	contact.Name = "blocked"

	messages := []*Message{
		&Message{
			ID:          "test-1",
			ChatID:      chat2.ID,
			ContentType: "content-type-1",
			Content:     "test-1",
			ClockValue:  1,
			From:        contact.ID,
		},
		&Message{
			ID:          "test-2",
			ChatID:      chat2.ID,
			ContentType: "content-type-2",
			Content:     "test-2",
			ClockValue:  2,
			From:        contact.ID,
		},
		&Message{
			ID:          "test-3",
			ChatID:      chat2.ID,
			ContentType: "content-type-3",
			Content:     "test-3",
			ClockValue:  3,
			Seen:        false,
			From:        "test",
		},
		&Message{
			ID: "test-4",

			ChatID:      chat2.ID,
			ContentType: "content-type-4",
			Content:     "test-4",
			ClockValue:  4,
			Seen:        false,
			From:        "test",
		},
		&Message{
			ID:          "test-5",
			ChatID:      chat2.ID,
			ContentType: "content-type-5",
			Content:     "test-5",
			ClockValue:  5,
			Seen:        true,
			From:        "test",
		},
		&Message{
			ID:          "test-6",
			ChatID:      chat3.ID,
			ContentType: "content-type-6",
			Content:     "test-6",
			ClockValue:  6,
			Seen:        false,
			From:        contact.ID,
		},
		&Message{
			ID:          "test-7",
			ChatID:      chat3.ID,
			ContentType: "content-type-7",
			Content:     "test-7",
			ClockValue:  7,
			Seen:        false,
			From:        "test",
		},
	}

	err := s.m.SaveMessages(messages)
	s.Require().NoError(err)

	response, err := s.m.BlockContact(contact)
	s.Require().NoError(err)

	// The new unviewed count is updated
	s.Require().Equal(uint(1), response[0].UnviewedMessagesCount)
	s.Require().Equal(uint(2), response[1].UnviewedMessagesCount)

	// The new message content is updated
	s.Require().Equal("test-7", response[0].LastMessageContent)
	s.Require().Equal("test-5", response[1].LastMessageContent)

	// The new message content-type is updated
	s.Require().Equal("content-type-7", response[0].LastMessageContentType)
	s.Require().Equal("content-type-5", response[1].LastMessageContentType)

	// The contact is updated
	savedContacts, err := s.m.Contacts()
	s.Require().NoError(err)
	s.Require().Equal(1, len(savedContacts))
	s.Require().Equal("blocked", savedContacts[0].Name)

	// The chat is deleted
	actualChats, err := s.m.Chats()
	s.Require().NoError(err)
	s.Require().Equal(2, len(actualChats))

	// The messages have been deleted
	chat2Messages, _, err := s.m.MessageByChatID(chat2.ID, "", 20)
	s.Require().NoError(err)
	s.Require().Equal(3, len(chat2Messages))

	chat3Messages, _, err := s.m.MessageByChatID(chat3.ID, "", 20)
	s.Require().NoError(err)
	s.Require().Equal(1, len(chat3Messages))

}

func (s *MessengerSuite) TestContactPersistence() {
	contact := Contact{
		ID:          "contact-id",
		Address:     "contact-address",
		Name:        "contact-name",
		Photo:       "contact-photo",
		LastUpdated: 20,
		SystemTags:  []string{"1", "2"},
		DeviceInfo: []ContactDeviceInfo{
			ContactDeviceInfo{
				InstallationID: "1",
				Timestamp:      2,
				FCMToken:       "token",
			},
			ContactDeviceInfo{
				InstallationID: "2",
				Timestamp:      3,
				FCMToken:       "token-2",
			},
		},
		TributeToTalk: "talk",
	}

	s.Require().NoError(s.m.SaveContact(contact))
	savedContacts, err := s.m.Contacts()
	s.Require().NoError(err)
	s.Require().Equal(1, len(savedContacts))

	actualContact := savedContacts[0]
	expectedContact := &contact

	s.Require().Equal(expectedContact, actualContact)
}

func (s *MessengerSuite) TestContactPersistenceUpdate() {
	contactID := "0424a68f89ba5fcd5e0640c1e1f591d561fa4125ca4e2a43592bc4123eca10ce064e522c254bb83079ba404327f6eafc01ec90a1444331fe769d3f3a7f90b0dde1"

	contact := Contact{
		ID:          contactID,
		Address:     "contact-address",
		Name:        "contact-name",
		Photo:       "contact-photo",
		LastUpdated: 20,
		SystemTags:  []string{"1", "2"},
		DeviceInfo: []ContactDeviceInfo{
			ContactDeviceInfo{
				InstallationID: "1",
				Timestamp:      2,
				FCMToken:       "token",
			},
			ContactDeviceInfo{
				InstallationID: "2",
				Timestamp:      3,
				FCMToken:       "token-2",
			},
		},
		TributeToTalk: "talk",
	}

	s.Require().NoError(s.m.SaveContact(contact))
	savedContacts, err := s.m.Contacts()
	s.Require().NoError(err)
	s.Require().Equal(1, len(savedContacts))

	actualContact := savedContacts[0]
	expectedContact := &contact

	s.Require().Equal(expectedContact, actualContact)

	contact.Name = "updated-name"
	s.Require().NoError(s.m.SaveContact(contact))
	updatedContact, err := s.m.Contacts()
	s.Require().NoError(err)
	s.Require().Equal(1, len(updatedContact))

	actualUpdatedContact := updatedContact[0]
	expectedUpdatedContact := &contact

	s.Require().Equal(expectedUpdatedContact, actualUpdatedContact)
}

func (s *MessengerSuite) TestSharedSecretHandler() {
	_, err := s.m.handleSharedSecrets(nil)
	s.NoError(err)
}

type PostProcessorSuite struct {
	suite.Suite

	postProcessor *postProcessor
	logger        *zap.Logger
}

func (s *PostProcessorSuite) SetupTest() {
	s.logger = tt.MustCreateTestLogger()

	privateKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	db, err := sqlite.OpenInMemory()
	s.Require().NoError(err)

	s.postProcessor = &postProcessor{
		myPublicKey: &privateKey.PublicKey,
		persistence: &sqlitePersistence{db: db},
		logger:      s.logger,
		config: postProcessorConfig{
			MatchChat: true,
			Persist:   true,
		},
	}
}

func (s *PostProcessorSuite) TearDownTest() {
	_ = s.logger.Sync()
}

func (s *PostProcessorSuite) TestRun() {
	key1, err := crypto.GenerateKey()
	s.Require().NoError(err)
	key2, err := crypto.GenerateKey()
	s.Require().NoError(err)

	testCases := []struct {
		Name           string
		Chat           Chat // Chat to create
		Message        protocol.Message
		SigPubKey      *ecdsa.PublicKey
		ExpectedChatID string
	}{
		{
			Name:           "Public chat",
			Chat:           CreatePublicChat("test-chat"),
			Message:        protocol.CreatePublicTextMessage([]byte("test"), 0, "test-chat"),
			SigPubKey:      &key1.PublicKey,
			ExpectedChatID: "test-chat",
		},
		{
			Name:           "Private message from myself with existing chat",
			Chat:           CreateOneToOneChat("test-private-chat", &key1.PublicKey),
			Message:        protocol.CreatePrivateTextMessage([]byte("test"), 0, oneToOneChatID(&key1.PublicKey)),
			SigPubKey:      &key1.PublicKey,
			ExpectedChatID: oneToOneChatID(&key1.PublicKey),
		},
		{
			Name:           "Private message from other with existing chat",
			Chat:           CreateOneToOneChat("test-private-chat", &key2.PublicKey),
			Message:        protocol.CreatePrivateTextMessage([]byte("test"), 0, oneToOneChatID(&key1.PublicKey)),
			SigPubKey:      &key2.PublicKey,
			ExpectedChatID: oneToOneChatID(&key2.PublicKey),
		},
		{
			Name:           "Private message from myself without chat",
			Message:        protocol.CreatePrivateTextMessage([]byte("test"), 0, oneToOneChatID(&key1.PublicKey)),
			SigPubKey:      &key1.PublicKey,
			ExpectedChatID: oneToOneChatID(&key1.PublicKey),
		},
		{
			Name:           "Private message from other without chat",
			Message:        protocol.CreatePrivateTextMessage([]byte("test"), 0, oneToOneChatID(&key1.PublicKey)),
			SigPubKey:      &key2.PublicKey,
			ExpectedChatID: oneToOneChatID(&key2.PublicKey),
		},
		// TODO: add test for group messages
	}

	for idx, tc := range testCases {
		s.Run(tc.Name, func() {
			if tc.Chat.ID != "" {
				err := s.postProcessor.persistence.SaveChat(tc.Chat)
				s.Require().NoError(err)
				defer func() {
					err := s.postProcessor.persistence.DeleteChat(tc.Chat.ID)
					s.Require().NoError(err)
				}()
			}

			message := tc.Message
			message.SigPubKey = tc.SigPubKey
			// ChatID is not set at the beginning.
			s.Empty(message.ChatID)

			message.ID = []byte(strconv.Itoa(idx)) // manually set the ID because messages does not go through messageProcessor
			messages, err := s.postProcessor.Run([]*protocol.Message{&message})
			s.NoError(err)
			s.Equal(tc.ExpectedChatID, message.ChatID)
			s.Require().Len(messages, 1)
			s.EqualValues(&message, messages[0])
		})
	}
}
