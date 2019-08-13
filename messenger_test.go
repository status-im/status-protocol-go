package statusproto

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/status-im/status-protocol-go/tt"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/ethereum/go-ethereum/crypto"
	whisper "github.com/status-im/whisper/whisperv6"
)

func TestMessengerSuite(t *testing.T) {
	suite.Run(t, new(MessengerSuite))
}

type MessengerSuite struct {
	suite.Suite

	m          *Messenger
	tmpFile    *os.File
	privateKey *ecdsa.PrivateKey
	logger     *zap.Logger
}

func (s *MessengerSuite) SetupTest() {
	var err error

	s.logger = tt.MustCreateTestLogger()

	s.tmpFile, err = ioutil.TempFile("", "messenger-test.sql")
	s.Require().NoError(err)

	s.privateKey, err = crypto.GenerateKey()
	s.Require().NoError(err)

	config := whisper.DefaultConfig
	config.MinimumAcceptedPOW = 0
	shh := whisper.New(&config)
	s.Require().NoError(shh.Start(nil))

	s.m, err = NewMessenger(
		s.privateKey,
		shh,
		"installation-1",
		WithCustomLogger(s.logger),
		WithMessagesPersistenceEnabled(),
		WithDatabaseConfig(s.tmpFile.Name(), "some-key"),
	)
	s.Require().NoError(err)
}

func (s *MessengerSuite) TearDownTest() {
	s.Require().NoError(s.m.Shutdown())
	_ = os.Remove(s.tmpFile.Name())
	_ = s.logger.Sync()
}

func (s *MessengerSuite) TestSendPublic() {
	_, err := s.m.Send(context.Background(), Chat{Name: "status", ID: "status"}, []byte("test"))
	s.NoError(err)
}

func (s *MessengerSuite) TestSendPrivate() {
	recipientKey, err := crypto.GenerateKey()
	s.NoError(err)
	_, err = s.m.Send(context.Background(), Chat{ID: "x", PublicKey: &recipientKey.PublicKey}, []byte("test"))
	s.NoError(err)
}

func (s *MessengerSuite) TestRetrievePublic() {
	chat := Chat{ID: "status", Name: "status"}

	_, err := s.m.Send(context.Background(), chat, []byte("test"))
	s.NoError(err)

	// Give Whisper some time to propagate message to filters.
	time.Sleep(time.Millisecond * 500)

	// Retrieve chat
	messages, err := s.m.Retrieve(context.Background(), chat, RetrieveLatest)
	s.NoError(err)
	s.Len(messages, 1)

	// Retrieve again to test skipping already existing err.
	messages, err = s.m.Retrieve(context.Background(), chat, RetrieveLastDay)
	s.NoError(err)
	s.Require().Len(messages, 1)

	// Verify message fields.
	message := messages[0]
	s.NotEmpty(message.ID)
	s.Equal(&s.privateKey.PublicKey, message.SigPubKey) // this is OUR message
}

func (s *MessengerSuite) TestRetrievePrivate() {
	publicContact, err := crypto.GenerateKey()
	s.NoError(err)
	chat := Chat{ID: "x", PublicKey: &publicContact.PublicKey}

	_, err = s.m.Send(context.Background(), chat, []byte("test"))
	s.NoError(err)

	// Give Whisper some time to propagate message to filters.
	time.Sleep(time.Millisecond * 500)

	// Retrieve chat
	messages, err := s.m.Retrieve(context.Background(), chat, RetrieveLatest)
	s.NoError(err)
	s.Len(messages, 1)

	// Retrieve again to test skipping already existing err.
	messages, err = s.m.Retrieve(context.Background(), chat, RetrieveLastDay)
	s.NoError(err)
	s.Len(messages, 1)

	// Verify message fields.
	message := messages[0]
	s.NotEmpty(message.ID)
	s.Equal(&s.privateKey.PublicKey, message.SigPubKey) // this is OUR message
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
	savedChats, err := s.m.Chats(0, 10)
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
	savedChats, err := s.m.Chats(0, 10)
	s.Require().NoError(err)
	s.Require().Equal(1, len(savedChats))

	s.Require().NoError(s.m.DeleteChat(chatID))
	savedChats, err = s.m.Chats(0, 10)
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
	savedChats, err := s.m.Chats(0, 10)
	s.Require().NoError(err)
	s.Require().Equal(1, len(savedChats))

	actualChat := savedChats[0]
	expectedChat := &chat

	s.Require().Equal(expectedChat, actualChat)

	chat.Name = "updated-name"
	s.Require().NoError(s.m.SaveChat(chat))
	updatedChats, err := s.m.Chats(0, 10)
	s.Require().NoError(err)
	s.Require().Equal(1, len(updatedChats))

	actualUpdatedChat := updatedChats[0]
	expectedUpdatedChat := &chat

	s.Require().Equal(expectedUpdatedChat, actualUpdatedChat)
}

func (s *MessengerSuite) TestChatPagination() {
	for i := 0; i <= 20; i++ {
		chat := Chat{
			ID:                     fmt.Sprintf("chat-name-%d", i),
			Name:                   "chat-name",
			Color:                  "#fffff",
			Active:                 true,
			ChatType:               ChatTypePublic,
			Timestamp:              int64(i),
			LastClockValue:         20,
			DeletedAtClockValue:    30,
			UnviewedMessagesCount:  40,
			LastMessageContentType: "something",
			LastMessageContent:     "something-else",
		}

		s.Require().NoError(s.m.SaveChat(chat))
	}
	firstPageChats, err := s.m.Chats(0, 10)
	s.Require().NoError(err)
	s.Require().Equal(10, len(firstPageChats))
	s.Require().Equal(int64(20), firstPageChats[0].Timestamp)
	s.Require().Equal(int64(11), firstPageChats[9].Timestamp)

	secondPageChats, err := s.m.Chats(10, -1)
	s.Require().NoError(err)
	s.Require().Equal(11, len(secondPageChats))
	s.Require().Equal(int64(10), secondPageChats[0].Timestamp)
	s.Require().Equal(int64(0), secondPageChats[10].Timestamp)
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
	savedChats, err := s.m.Chats(0, 10)
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
	savedChats, err := s.m.Chats(0, 10)
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
	actualChats, err := s.m.Chats(0, -1)
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
	err := s.m.handleSharedSecrets(nil)
	s.NoError(err)
}
