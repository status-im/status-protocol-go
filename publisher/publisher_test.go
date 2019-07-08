package publisher

import (
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	whisper "github.com/status-im/whisper/whisperv6"
	"github.com/stretchr/testify/suite"

	"github.com/status-im/status-protocol-go/encryption"
	"github.com/status-im/status-protocol-go/encryption/multidevice"
	"github.com/status-im/status-protocol-go/encryption/sharedsecret"
	whisperutils "github.com/status-im/status-protocol-go/transport/whisper"
	"github.com/status-im/status-protocol-go/transport/whisper/filter"
)

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

type TestKey struct {
	privateKey     *ecdsa.PrivateKey
	keyID          string
	publicKeyBytes hexutil.Bytes
}

type ServiceTestSuite struct {
	suite.Suite
	alice    *Publisher
	bob      *Publisher
	aliceKey *TestKey
	bobKey   *TestKey
}

func (s *ServiceTestSuite) createPublisher(installationID string) (*Publisher, *TestKey) {
	dir, err := ioutil.TempDir("", "publisher-test")
	s.Require().NoError(err)

	config := Config{PFSEnabled: true}

	whisper := whisper.New(nil)
	err = whisper.SetMinimumPoW(0)
	s.Require().NoError(err)

	publisher := New(whisper, config)

	pk, err := crypto.GenerateKey()
	s.Require().NoError(err)

	keyID, err := whisper.AddKeyPair(pk)
	s.Require().NoError(err)

	testKey := TestKey{
		privateKey:     pk,
		keyID:          keyID,
		publicKeyBytes: crypto.FromECDSAPub(&pk.PublicKey),
	}

	persistence, err := encryption.NewSQLLitePersistence(filepath.Join(dir, "db1.sql"), "pass")
	s.Require().NoError(err)

	sharedSecretService := sharedsecret.NewService(persistence.GetSharedSecretStorage())

	multideviceConfig := &multidevice.Config{
		InstallationID:   installationID,
		ProtocolVersion:  encryption.ProtocolVersion,
		MaxInstallations: 3,
	}
	multideviceService := multidevice.New(multideviceConfig, persistence.GetMultideviceStorage())

	protocolService := encryption.NewProtocolService(
		encryption.NewEncryptionService(
			persistence,
			encryption.DefaultEncryptionServiceConfig(installationID)),
		sharedSecretService,
		multideviceService,
		func(addedBundles []*multidevice.Installation) {},
		publisher.ProcessNegotiatedSecret,
	)

	err = publisher.Init(persistence.DB, protocolService, func(msg []*filter.Messages) {})
	s.Require().NoError(err)

	err = publisher.Start(func() bool { return true }, false)
	s.Require().NoError(err)

	return publisher, &testKey
}

func (s *ServiceTestSuite) SetupTest() {
	s.alice, s.aliceKey = s.createPublisher("installation-1")
	_, err := s.alice.LoadFilters([]*filter.Chat{})
	s.Require().NoError(err)

	s.bob, s.bobKey = s.createPublisher("installation-2")
	_, err = s.bob.LoadFilters([]*filter.Chat{})
	s.Require().NoError(err)
}

func (s *ServiceTestSuite) TestCreateDirectMessage() {
	newMessage, err := s.alice.CreateDirectMessage(s.aliceKey.privateKey, &s.bobKey.privateKey.PublicKey, false, []byte("hello"))
	s.Require().NoError(err)

	message := &whisper.Message{
		Sig:     s.aliceKey.publicKeyBytes,
		Topic:   newMessage.Topic,
		Payload: newMessage.Payload,
		Dst:     newMessage.PublicKey,
	}

	err = s.bob.ProcessMessage(message, []byte("1"))
	s.Require().NoError(err)
	s.Require().Equal([]byte("hello"), message.Payload)
}

func (s *ServiceTestSuite) TestTopic() {
	// We build an initial message
	newMessage1, err := s.alice.CreateDirectMessage(s.aliceKey.privateKey, &s.bobKey.privateKey.PublicKey, false, []byte("hello"))
	s.Require().NoError(err)

	message1 := &whisper.Message{
		Sig:     s.aliceKey.publicKeyBytes,
		Topic:   newMessage1.Topic,
		Payload: newMessage1.Payload,
		Dst:     newMessage1.PublicKey,
	}

	// We have no information, it should use the discovery topic
	s.Require().Equal(whisperutils.DiscoveryTopicBytes, message1.Topic)

	// We build a contact code from user 2
	newMessage2, err := s.bob.sendContactCode()
	s.Require().NoError(err)
	s.Require().NotNil(newMessage2)

	message2 := &whisper.Message{
		Sig:     s.bobKey.publicKeyBytes,
		Topic:   newMessage2.Topic,
		Payload: newMessage2.Payload,
		Dst:     newMessage2.PublicKey,
	}

	// We receive the contact code
	err = s.alice.ProcessMessage(message2, []byte("1"))
	s.Require().EqualError(err, encryption.ErrNoPayload.Error())

	// We build another message, this time it should use the partitioned topic
	newMessage3, err := s.alice.CreateDirectMessage(s.aliceKey.privateKey, &s.bobKey.privateKey.PublicKey, false, []byte("hello"))
	s.Require().NoError(err)

	message3 := &whisper.Message{
		Sig:     s.aliceKey.publicKeyBytes,
		Topic:   newMessage3.Topic,
		Payload: newMessage3.Payload,
		Dst:     newMessage3.PublicKey,
	}
	expectedTopic3 := whisper.BytesToTopic(filter.PublicKeyToPartitionedTopicBytes(&s.bobKey.privateKey.PublicKey))

	s.Require().Equal(expectedTopic3, message3.Topic)

	// We receive the message
	err = s.bob.ProcessMessage(message3, []byte("1"))
	s.Require().NoError(err)

	// We build another message, this time it should use the negotiated topic
	newMessage4, err := s.bob.CreateDirectMessage(s.bobKey.privateKey, &s.aliceKey.privateKey.PublicKey, false, []byte("hello"))
	s.Require().NoError(err)

	message4 := &whisper.Message{
		Sig:     s.bobKey.publicKeyBytes,
		Topic:   newMessage4.Topic,
		Payload: newMessage4.Payload,
		Dst:     newMessage4.PublicKey,
	}
	sharedSecret, err := ecies.ImportECDSA(s.bobKey.privateKey).GenerateShared(
		ecies.ImportECDSAPublic(&s.aliceKey.privateKey.PublicKey),
		16,
		16)
	s.Require().NoError(err)
	keyString := fmt.Sprintf("%x", sharedSecret)

	negotiatedTopic := whisper.BytesToTopic(filter.ToTopic(keyString))

	s.Require().Equal(negotiatedTopic, message4.Topic)

	// We receive the message
	err = s.alice.ProcessMessage(message4, []byte("1"))
	s.Require().NoError(err)

	// Alice sends another message to Bob, this time it should use the negotiated topic
	newMessage5, err := s.alice.CreateDirectMessage(s.aliceKey.privateKey, &s.bobKey.privateKey.PublicKey, false, []byte("hello"))
	s.Require().NoError(err)

	message5 := &whisper.Message{
		Sig:     s.aliceKey.publicKeyBytes,
		Topic:   newMessage5.Topic,
		Payload: newMessage5.Payload,
		Dst:     newMessage5.PublicKey,
	}
	s.Require().NoError(err)
	s.Require().Equal(negotiatedTopic, message5.Topic)

}
