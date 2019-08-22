package statusproto

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/status-im/status-protocol-go/encryption"
	"github.com/status-im/status-protocol-go/encryption/multidevice"
	"github.com/status-im/status-protocol-go/encryption/sharedsecret"
	"github.com/status-im/status-protocol-go/sqlite"
	protocol "github.com/status-im/status-protocol-go/v1"

	"github.com/status-im/status-protocol-go/datasync"
	datasyncpeer "github.com/status-im/status-protocol-go/datasync/peer"
	transport "github.com/status-im/status-protocol-go/transport/whisper"
	whisper "github.com/status-im/whisper/whisperv6"
	datasyncnode "github.com/vacp2p/mvds/node"
	datasyncpeers "github.com/vacp2p/mvds/peers"
	datasyncproto "github.com/vacp2p/mvds/protobuf"
	datasyncstate "github.com/vacp2p/mvds/state"
	datasyncstore "github.com/vacp2p/mvds/store"

	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"

	"github.com/stretchr/testify/suite"
)

func TestMessageProcessorSuite(t *testing.T) {
	suite.Run(t, new(MessageProcessorSuite))
}

type MessageProcessorSuite struct {
	suite.Suite

	processor   *messageProcessor
	tmpDir      string
	testMessage protocol.Message
	logger      *zap.Logger
}

func (s *MessageProcessorSuite) SetupTest() {
	s.testMessage = protocol.Message{
		Text:      "abc123",
		ContentT:  "text/plain",
		MessageT:  "public-group-user-message",
		Clock:     154593077368201,
		Timestamp: 1545930773682,
		Content: protocol.Content{
			ChatID: "testing-adamb",
			Text:   "abc123",
		},
	}

	var err error

	s.tmpDir, err = ioutil.TempDir("", "")
	s.Require().NoError(err)

	s.logger, err = zap.NewDevelopment()
	s.Require().NoError(err)

	identity, err := crypto.GenerateKey()
	s.Require().NoError(err)

	names, getter, err := prepareMigrations(defaultMigrations)
	s.Require().NoError(err)
	database, err := sqlite.Open(filepath.Join(s.tmpDir, "processor-test.sql"), "some-key", sqlite.MigrationConfig{
		AssetNames:  names,
		AssetGetter: getter,
	})
	s.Require().NoError(err)

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
	datasync := datasync.New(dataSyncNode, dataSyncTransport, true, s.logger)
	dataSyncNode.Start(100 * time.Second)

	onNewInstallations := func([]*multidevice.Installation) {}
	onNewSharedSecret := func([]*sharedsecret.Secret) {}
	onSendContactCode := func(*encryption.ProtocolMessageSpec) {}
	encryptionProtocol := encryption.New(
		database,
		"installation-1",
		onNewInstallations,
		onNewSharedSecret,
		onSendContactCode,
		s.logger,
	)

	whisperConfig := whisper.DefaultConfig
	whisperConfig.MinimumAcceptedPOW = 0
	shh := whisper.New(&whisperConfig)
	s.Require().NoError(shh.Start(nil))
	config := &config{}
	s.Require().NoError(WithDatasync()(config))

	whisperTransport, err := transport.NewWhisperServiceTransport(
		shh,
		identity,
		database,
		nil,
		nil,
		s.logger,
	)
	s.Require().NoError(err)

	s.processor = &messageProcessor{
		identity:     identity,
		datasync:     datasync,
		protocol:     encryptionProtocol,
		transport:    whisperTransport,
		logger:       s.logger,
		featureFlags: featureFlags{},
	}
}

func (s *MessageProcessorSuite) TearDownTest() {
	os.Remove(s.tmpDir)
	_ = s.logger.Sync()
}

func (s *MessageProcessorSuite) TestHandleDecodedMessagesSingle() {
	privateKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	encodedPayload, err := protocol.EncodeMessage(s.testMessage)
	s.Require().NoError(err)

	message := &whisper.Message{}
	message.Sig = crypto.FromECDSAPub(&privateKey.PublicKey)
	message.Payload = encodedPayload

	decodedMessages, err := s.processor.handleMessages(message, true)
	s.Require().NoError(err)
	s.Require().Equal(1, len(decodedMessages))
	s.Require().Equal(encodedPayload, decodedMessages[0].DecryptedPayload)
	s.Require().Equal(&privateKey.PublicKey, decodedMessages[0].SigPubKey())
	s.Require().Equal(protocol.MessageID(&privateKey.PublicKey, encodedPayload), decodedMessages[0].ID)
	s.Require().Equal(s.testMessage, decodedMessages[0].ParsedMessage)
}

func (s *MessageProcessorSuite) TestHandleDecodedMessagesRaw() {
	privateKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	encodedPayload, err := protocol.EncodeMessage(s.testMessage)
	s.Require().NoError(err)

	message := &whisper.Message{}
	message.Sig = crypto.FromECDSAPub(&privateKey.PublicKey)
	message.Payload = encodedPayload

	decodedMessages, err := s.processor.handleMessages(message, false)
	s.Require().NoError(err)
	s.Require().Equal(1, len(decodedMessages))
	s.Require().Equal(message, decodedMessages[0].TransportMessage)
	s.Require().Equal(encodedPayload, decodedMessages[0].DecryptedPayload)
	s.Require().Equal(&privateKey.PublicKey, decodedMessages[0].SigPubKey())
	s.Require().Equal(protocol.MessageID(&privateKey.PublicKey, encodedPayload), decodedMessages[0].ID)
	s.Require().Equal(nil, decodedMessages[0].ParsedMessage)
}

func (s *MessageProcessorSuite) TestHandleDecodedMessagesWrapped() {
	relayerKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	authorKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	encodedPayload, err := protocol.EncodeMessage(s.testMessage)
	s.Require().NoError(err)

	wrappedPayload, err := protocol.WrapMessageV1(encodedPayload, authorKey)
	s.Require().NoError(err)

	message := &whisper.Message{}
	message.Sig = crypto.FromECDSAPub(&relayerKey.PublicKey)
	message.Payload = wrappedPayload

	decodedMessages, err := s.processor.handleMessages(message, true)
	s.Require().NoError(err)

	s.Require().Equal(1, len(decodedMessages))
	s.Require().Equal(&authorKey.PublicKey, decodedMessages[0].SigPubKey())
	s.Require().Equal(protocol.MessageID(&authorKey.PublicKey, wrappedPayload), decodedMessages[0].ID)
	s.Require().Equal(encodedPayload, decodedMessages[0].DecryptedPayload)
	s.Require().Equal(s.testMessage, decodedMessages[0].ParsedMessage)
}

func (s *MessageProcessorSuite) TestHandleDecodedMessagesDatasync() {
	relayerKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	authorKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	encodedPayload, err := protocol.EncodeMessage(s.testMessage)
	s.Require().NoError(err)

	wrappedPayload, err := protocol.WrapMessageV1(encodedPayload, authorKey)
	s.Require().NoError(err)

	dataSyncMessage := datasyncproto.Payload{
		Messages: []*datasyncproto.Message{
			{Body: encodedPayload},
			{Body: wrappedPayload},
		},
	}
	marshalledDataSyncMessage, err := proto.Marshal(&dataSyncMessage)
	s.Require().NoError(err)
	message := &whisper.Message{}
	message.Sig = crypto.FromECDSAPub(&relayerKey.PublicKey)
	message.Payload = marshalledDataSyncMessage

	decodedMessages, err := s.processor.handleMessages(message, true)
	s.Require().NoError(err)

	// We send two messages, the unwrapped one will be attributed to the relayer, while the wrapped one will be attributed to the author
	s.Require().Equal(2, len(decodedMessages))
	s.Require().Equal(&relayerKey.PublicKey, decodedMessages[0].SigPubKey())
	s.Require().Equal(protocol.MessageID(&relayerKey.PublicKey, encodedPayload), decodedMessages[0].ID)
	s.Require().Equal(encodedPayload, decodedMessages[0].DecryptedPayload)
	s.Require().Equal(s.testMessage, decodedMessages[0].ParsedMessage)

	s.Require().Equal(&authorKey.PublicKey, decodedMessages[1].SigPubKey())
	s.Require().Equal(protocol.MessageID(&authorKey.PublicKey, wrappedPayload), decodedMessages[1].ID)
	s.Require().Equal(encodedPayload, decodedMessages[1].DecryptedPayload)
	s.Require().Equal(s.testMessage, decodedMessages[1].ParsedMessage)
}

func (s *MessageProcessorSuite) TestHandleDecodedMessagesDatasyncEncrypted() {
	relayerKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	authorKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	encodedPayload, err := protocol.EncodeMessage(s.testMessage)
	s.Require().NoError(err)

	wrappedPayload, err := protocol.WrapMessageV1(encodedPayload, authorKey)
	s.Require().NoError(err)

	dataSyncMessage := datasyncproto.Payload{
		Messages: []*datasyncproto.Message{
			&datasyncproto.Message{Body: encodedPayload},
			&datasyncproto.Message{Body: wrappedPayload},
		},
	}
	marshalledDataSyncMessage, err := proto.Marshal(&dataSyncMessage)
	s.Require().NoError(err)

	// Create sender encryption protocol.
	names, getter, err := prepareMigrations(defaultMigrations)
	s.Require().NoError(err)
	senderDatabase, err := sqlite.Open(filepath.Join(s.tmpDir, "sender.db.sql"), "some-key", sqlite.MigrationConfig{
		AssetNames:  names,
		AssetGetter: getter,
	})
	s.Require().NoError(err)
	senderEncryptionProtocol := encryption.New(
		senderDatabase,
		"installation-2",
		func([]*multidevice.Installation) {},
		func([]*sharedsecret.Secret) {},
		func(*encryption.ProtocolMessageSpec) {},
		s.logger,
	)

	messageSpec, err := senderEncryptionProtocol.BuildDirectMessage(
		relayerKey,
		&s.processor.identity.PublicKey,
		marshalledDataSyncMessage,
	)
	s.Require().NoError(err)

	encryptedPayload, err := proto.Marshal(messageSpec.Message)
	s.Require().NoError(err)

	message := &whisper.Message{}
	message.Sig = crypto.FromECDSAPub(&relayerKey.PublicKey)
	message.Payload = encryptedPayload

	decodedMessages, err := s.processor.handleMessages(message, true)
	s.Require().NoError(err)

	// We send two messages, the unwrapped one will be attributed to the relayer,
	// while the wrapped one will be attributed to the author.
	s.Require().Equal(2, len(decodedMessages))
	s.Require().Equal(&relayerKey.PublicKey, decodedMessages[0].SigPubKey())
	s.Require().Equal(protocol.MessageID(&relayerKey.PublicKey, encodedPayload), decodedMessages[0].ID)
	s.Require().Equal(encodedPayload, decodedMessages[0].DecryptedPayload)
	s.Require().Equal(s.testMessage, decodedMessages[0].ParsedMessage)

	s.Require().Equal(&authorKey.PublicKey, decodedMessages[1].SigPubKey())
	s.Require().Equal(protocol.MessageID(&authorKey.PublicKey, wrappedPayload), decodedMessages[1].ID)
	s.Require().Equal(encodedPayload, decodedMessages[1].DecryptedPayload)
	s.Require().Equal(s.testMessage, decodedMessages[1].ParsedMessage)
}
