package statusproto

import (
	"crypto/ecdsa"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/status-im/status-protocol-go/sqlite"

	"github.com/golang/protobuf/proto"
	"github.com/status-im/status-protocol-go/encryption"
	"github.com/status-im/status-protocol-go/encryption/multidevice"
	"github.com/status-im/status-protocol-go/encryption/sharedsecret"
	transport "github.com/status-im/status-protocol-go/transport/whisper"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/status-im/status-protocol-go/datasync"
	datasyncpeer "github.com/status-im/status-protocol-go/datasync/peer"
	datasyncnode "github.com/vacp2p/mvds/node"
	datasyncpeers "github.com/vacp2p/mvds/peers"
	datasyncproto "github.com/vacp2p/mvds/protobuf"
	datasyncstate "github.com/vacp2p/mvds/state"
	datasyncstore "github.com/vacp2p/mvds/store"

	protocol "github.com/status-im/status-protocol-go/v1"
	whisper "github.com/status-im/whisper/whisperv6"
)

var (
	testMessageStruct = protocol.Message{
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
)

func TestAdaptersSuite(t *testing.T) {
	suite.Run(t, new(AdaptersSuite))
}

type AdaptersSuite struct {
	suite.Suite

	a          *whisperAdapter
	tmpDir     string
	privateKey *ecdsa.PrivateKey
	logger     *zap.Logger
}

func (s *AdaptersSuite) SetupTest() {
	var err error

	logger, err := zap.NewDevelopment()
	s.Require().NoError(err)
	s.logger = logger

	s.tmpDir, err = ioutil.TempDir("", "adapters-test")
	s.Require().NoError(err)

	names, getter, err := prepareMigrations(defaultMigrations)
	s.Require().NoError(err)
	database, err := sqlite.Open(filepath.Join(s.tmpDir, "transport.db.sql"), "some-key", sqlite.MigrationConfig{
		AssetNames:  names,
		AssetGetter: getter,
	})
	s.Require().NoError(err)

	s.privateKey, err = crypto.GenerateKey()
	s.Require().NoError(err)

	whisperConfig := whisper.DefaultConfig
	whisperConfig.MinimumAcceptedPOW = 0
	shh := whisper.New(&whisperConfig)
	s.Require().NoError(shh.Start(nil))
	config := &config{}
	s.Require().NoError(WithDatasync()(config))

	whisperTransport, err := transport.NewWhisperServiceTransport(
		nil,
		shh,
		s.privateKey,
		database,
		nil,
		logger,
	)
	s.Require().NoError(err)

	onNewInstallations := func([]*multidevice.Installation) {}
	onNewSharedSecret := func([]*sharedsecret.Secret) {}
	onSendContactCode := func(*encryption.ProtocolMessageSpec) {}
	encryptionProtocol := encryption.New(
		database,
		"installation-1",
		onNewInstallations,
		onNewSharedSecret,
		onSendContactCode,
		logger,
	)

	dataSyncTransport := datasync.NewDataSyncNodeTransport()
	dataSyncStore := datasyncstore.NewDummyStore()
	dataSyncNode := datasyncnode.NewNode(
		&dataSyncStore,
		dataSyncTransport,
		datasyncstate.NewSyncState(), // @todo sqlite syncstate
		datasync.CalculateSendTime,
		0,
		datasyncpeer.PublicKeyToPeerID(s.privateKey.PublicKey),
		datasyncnode.BATCH,
		datasyncpeers.NewMemoryPersistence(),
	)

	datasync := datasync.New(dataSyncNode, dataSyncTransport, true, logger)

	s.a = newWhisperAdapter(
		s.privateKey,
		whisperTransport,
		encryptionProtocol,
		datasync,
		config.featureFlags,
		logger,
	)

	dataSyncNode.Start(100 * time.Second)
}

func (s *AdaptersSuite) TestHandleDecodedMessagesSingle() {

	privateKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	encodedPayload, err := protocol.EncodeMessage(testMessageStruct)
	s.Require().NoError(err)

	message := &whisper.Message{}
	message.Sig = crypto.FromECDSAPub(&privateKey.PublicKey)
	message.Payload = encodedPayload

	decodedMessages, err := s.a.handleMessages(message, true)
	s.Require().NoError(err)
	s.Require().Equal(1, len(decodedMessages))
	s.Require().Equal(encodedPayload, decodedMessages[0].DecryptedPayload)
	s.Require().Equal(&privateKey.PublicKey, decodedMessages[0].SigPubKey())
	s.Require().Equal(protocol.MessageID(&privateKey.PublicKey, encodedPayload), decodedMessages[0].ID)
	s.Require().Equal(testMessageStruct, decodedMessages[0].ParsedMessage)
}

func (s *AdaptersSuite) TestHandleDecodedMessagesRaw() {

	privateKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	encodedPayload, err := protocol.EncodeMessage(testMessageStruct)
	s.Require().NoError(err)

	message := &whisper.Message{}
	message.Sig = crypto.FromECDSAPub(&privateKey.PublicKey)
	message.Payload = encodedPayload

	decodedMessages, err := s.a.handleMessages(message, false)
	s.Require().NoError(err)
	s.Require().Equal(1, len(decodedMessages))
	s.Require().Equal(message, decodedMessages[0].TransportMessage)
	s.Require().Equal(encodedPayload, decodedMessages[0].DecryptedPayload)
	s.Require().Equal(&privateKey.PublicKey, decodedMessages[0].SigPubKey())
	s.Require().Equal(protocol.MessageID(&privateKey.PublicKey, encodedPayload), decodedMessages[0].ID)
	s.Require().Equal(nil, decodedMessages[0].ParsedMessage)
}

func (s *AdaptersSuite) TestHandleDecodedMessagesWrapped() {
	relayerKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	authorKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	encodedPayload, err := protocol.EncodeMessage(testMessageStruct)
	s.Require().NoError(err)

	wrappedPayload, err := protocol.WrapMessageV1(encodedPayload, authorKey)
	s.Require().NoError(err)

	message := &whisper.Message{}
	message.Sig = crypto.FromECDSAPub(&relayerKey.PublicKey)
	message.Payload = wrappedPayload

	decodedMessages, err := s.a.handleMessages(message, true)
	s.Require().NoError(err)

	s.Require().Equal(1, len(decodedMessages))
	s.Require().Equal(&authorKey.PublicKey, decodedMessages[0].SigPubKey())
	s.Require().Equal(protocol.MessageID(&authorKey.PublicKey, encodedPayload), decodedMessages[0].ID)
	s.Require().Equal(encodedPayload, decodedMessages[0].DecryptedPayload)
	s.Require().Equal(testMessageStruct, decodedMessages[0].ParsedMessage)
}

func (s *AdaptersSuite) TestHandleDecodedMessagesDatasync() {

	relayerKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	authorKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	encodedPayload, err := protocol.EncodeMessage(testMessageStruct)
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
	message := &whisper.Message{}
	message.Sig = crypto.FromECDSAPub(&relayerKey.PublicKey)
	message.Payload = marshalledDataSyncMessage

	decodedMessages, err := s.a.handleMessages(message, true)
	s.Require().NoError(err)

	// We send two messages, the unwrapped one will be attributed to the relayer, while the wrapped one will be attributed to the author
	s.Require().Equal(2, len(decodedMessages))
	s.Require().Equal(&relayerKey.PublicKey, decodedMessages[0].SigPubKey())
	s.Require().Equal(protocol.MessageID(&relayerKey.PublicKey, encodedPayload), decodedMessages[0].ID)
	s.Require().Equal(encodedPayload, decodedMessages[0].DecryptedPayload)
	s.Require().Equal(testMessageStruct, decodedMessages[0].ParsedMessage)

	s.Require().Equal(&authorKey.PublicKey, decodedMessages[1].SigPubKey())
	s.Require().Equal(protocol.MessageID(&authorKey.PublicKey, encodedPayload), decodedMessages[1].ID)
	s.Require().Equal(encodedPayload, decodedMessages[1].DecryptedPayload)
	s.Require().Equal(testMessageStruct, decodedMessages[1].ParsedMessage)
}

func (s *AdaptersSuite) TearDownTest() {
	os.Remove(s.tmpDir)

	_ = s.logger.Sync()
}
