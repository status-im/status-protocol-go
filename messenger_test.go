package statusproto

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
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

type testChat struct {
	publicName string
	publicKey  *ecdsa.PublicKey
}

func (c testChat) ID() string {
	if c.publicKey != nil {
		return hex.EncodeToString(crypto.FromECDSAPub(c.publicKey))
	}
	// Deliberately use a different ID than public name.
	return hex.EncodeToString([]byte(c.publicName))
}

func (c testChat) PublicKey() *ecdsa.PublicKey {
	return c.publicKey
}

func (c testChat) PublicName() string {
	return c.publicName
}

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
		nil,
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
	_, err := s.m.Send(context.Background(), testChat{publicName: "status"}, []byte("test"))
	s.NoError(err)
}

func (s *MessengerSuite) TestSendPrivate() {
	recipientKey, err := crypto.GenerateKey()
	s.NoError(err)
	_, err = s.m.Send(context.Background(), testChat{publicKey: &recipientKey.PublicKey}, []byte("test"))
	s.NoError(err)
}

func (s *MessengerSuite) TestRetrievePublic() {
	chat := testChat{publicName: "status"}

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
	chat := testChat{publicKey: &publicContact.PublicKey}

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

func (s *MessengerSuite) TestSharedSecretHandler() {
	err := s.m.handleSharedSecrets(nil)
	s.NoError(err)
}
