package encryption

import (
	"io/ioutil"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/suite"

	"github.com/status-im/status-protocol-go/encryption/multidevice"
	"github.com/status-im/status-protocol-go/encryption/sharedsecret"
)

func TestProtocolServiceTestSuite(t *testing.T) {
	suite.Run(t, new(ProtocolServiceTestSuite))
}

type ProtocolServiceTestSuite struct {
	suite.Suite
	alice *Protocol
	bob   *Protocol
}

func (s *ProtocolServiceTestSuite) SetupTest() {
	aliceDBPath, err := ioutil.TempFile("", "alice.db")
	s.Require().NoError(err)
	aliceDBKey := "alice"

	bobDBPath, err := ioutil.TempFile("", "bob.db")
	s.Require().NoError(err)
	bobDBKey := "bob"

	addedBundlesHandler := func(addedBundles []*multidevice.Installation) {}
	onNewSharedSecretHandler := func(secret []*sharedsecret.Secret) {}

	s.alice, err = New(
		aliceDBPath.Name(),
		aliceDBKey,
		"1",
		addedBundlesHandler,
		onNewSharedSecretHandler,
	)
	s.Require().NoError(err)

	s.bob, err = New(
		bobDBPath.Name(),
		bobDBKey,
		"2",
		addedBundlesHandler,
		onNewSharedSecretHandler,
	)
	s.Require().NoError(err)
}

func (s *ProtocolServiceTestSuite) TestBuildPublicMessage() {
	aliceKey, err := crypto.GenerateKey()
	s.NoError(err)

	payload := []byte("test")
	s.NoError(err)

	msg, err := s.alice.BuildPublicMessage(aliceKey, payload)
	s.NoError(err)
	s.NotNil(msg, "It creates a message")

	s.NotNilf(msg.Message.GetBundles(), "It adds a bundle to the message")
}

func (s *ProtocolServiceTestSuite) TestBuildDirectMessage() {
	bobKey, err := crypto.GenerateKey()
	s.NoError(err)
	aliceKey, err := crypto.GenerateKey()
	s.NoError(err)

	payload := []byte("test")

	msgSpec, err := s.alice.BuildDirectMessage(aliceKey, &bobKey.PublicKey, payload)
	s.NoError(err)
	s.NotNil(msgSpec, "It creates a message spec")

	msg := msgSpec.Message
	s.NotNil(msg, "It creates a messages")

	s.NotNilf(msg.GetBundle(), "It adds a bundle to the message")

	directMessage := msg.GetDirectMessage()
	s.NotNilf(directMessage, "It sets the direct message")

	encryptedPayload := directMessage["none"].GetPayload()
	s.NotNilf(encryptedPayload, "It sets the payload of the message")

	s.NotEqualf(payload, encryptedPayload, "It encrypts the payload")
}

func (s *ProtocolServiceTestSuite) TestBuildAndReadDirectMessage() {
	bobKey, err := crypto.GenerateKey()
	s.Require().NoError(err)
	aliceKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	payload := []byte("test")

	// Message is sent with DH
	msgSpec, err := s.alice.BuildDirectMessage(aliceKey, &bobKey.PublicKey, payload)
	s.Require().NoError(err)
	s.Require().NotNil(msgSpec)

	msg := msgSpec.Message
	s.Require().NotNil(msg)

	// Bob is able to decrypt the message
	unmarshaledMsg, err := s.bob.HandleMessage(bobKey, &aliceKey.PublicKey, msg, []byte("message-id"))
	s.NoError(err)
	s.NotNil(unmarshaledMsg)

	recoveredPayload := []byte("test")
	s.Equalf(payload, recoveredPayload, "It successfully unmarshal the decrypted message")
}

func (s *ProtocolServiceTestSuite) TestSecretNegotiation() {
	var secretResponse []*sharedsecret.Secret
	bobKey, err := crypto.GenerateKey()
	s.NoError(err)
	aliceKey, err := crypto.GenerateKey()
	s.NoError(err)

	payload := []byte("test")

	s.bob.onNewSharedSecretHandler = func(secret []*sharedsecret.Secret) {
		secretResponse = secret
	}
	msgSpec, err := s.alice.BuildDirectMessage(aliceKey, &bobKey.PublicKey, payload)
	s.NoError(err)
	s.NotNil(msgSpec, "It creates a message spec")

	bundle := msgSpec.Message.GetBundle()
	s.Require().NotNil(bundle)

	signedPreKeys := bundle.GetSignedPreKeys()
	s.Require().NotNil(signedPreKeys)

	signedPreKey := signedPreKeys["1"]
	s.Require().NotNil(signedPreKey)

	s.Require().Equal(uint32(1), signedPreKey.GetProtocolVersion())

	_, err = s.bob.HandleMessage(bobKey, &aliceKey.PublicKey, msgSpec.Message, []byte("message-id"))
	s.NoError(err)

	s.Require().NotNil(secretResponse)
}
