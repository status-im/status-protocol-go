package sharedsecret

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	migrations "github.com/status-im/status-protocol-go/encryption/internal/sqlite"
	"github.com/status-im/status-protocol-go/sqlite"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(SharedSecretTestSuite))
}

type SharedSecretTestSuite struct {
	suite.Suite
	service *SharedSecret
	path    string
	logger  *zap.Logger
}

func (s *SharedSecretTestSuite) SetupTest() {
	logger, err := zap.NewDevelopment()
	s.Require().NoError(err)
	s.logger = logger

	dbFile, err := ioutil.TempFile(os.TempDir(), "sharedsecret")
	s.Require().NoError(err)
	s.path = dbFile.Name()

	db, err := sqlite.Open(s.path, "", sqlite.MigrationConfig{
		AssetNames: migrations.AssetNames(),
		AssetGetter: func(name string) ([]byte, error) {
			return migrations.Asset(name)
		},
	})
	s.Require().NoError(err)

	s.service = New(db, logger)
}

func (s *SharedSecretTestSuite) TearDownTest() {
	os.Remove(s.path)

	_ = s.logger.Sync()
}

func (s *SharedSecretTestSuite) TestSingleInstallationID() {
	ourInstallationID := "our"
	installationID1 := "1"
	installationID2 := "2"

	myKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	theirKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	// We receive a message from installationID1
	sharedKey1, err := s.service.Generate(myKey, &theirKey.PublicKey, installationID1)
	s.Require().NoError(err)
	s.Require().NotNil(sharedKey1, "it generates a shared key")

	// We want to send a message to installationID1
	sharedKey2, agreed2, err := s.service.Agreed(myKey, ourInstallationID, &theirKey.PublicKey, []string{installationID1})
	s.Require().NoError(err)
	s.Require().True(agreed2)
	s.Require().NotNil(sharedKey2, "We can retrieve a shared secret")
	s.Require().Equal(sharedKey1, sharedKey2, "The shared secret is the same as the one stored")

	// We want to send a message to multiple installationIDs, one of which we haven't never communicated with
	sharedKey3, agreed3, err := s.service.Agreed(myKey, ourInstallationID, &theirKey.PublicKey, []string{installationID1, installationID2})
	s.Require().NoError(err)
	s.Require().NotNil(sharedKey3, "A shared key is returned")
	s.Require().False(agreed3)

	// We receive a message from installationID2
	sharedKey4, err := s.service.Generate(myKey, &theirKey.PublicKey, installationID2)
	s.Require().NoError(err)
	s.Require().NotNil(sharedKey4, "it generates a shared key")
	s.Require().Equal(sharedKey1, sharedKey4, "It generates the same key")

	// We want to send a message to installationID 1 & 2, both have been
	sharedKey5, agreed5, err := s.service.Agreed(myKey, ourInstallationID, &theirKey.PublicKey, []string{installationID1, installationID2})
	s.Require().NoError(err)
	s.Require().NotNil(sharedKey5, "We can retrieve a shared secret")
	s.Require().True(agreed5)
	s.Require().Equal(sharedKey1, sharedKey5, "The shared secret is the same as the one stored")

}

func (s *SharedSecretTestSuite) TestAll() {
	installationID1 := "1"
	installationID2 := "2"

	myKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	theirKey1, err := crypto.GenerateKey()
	s.Require().NoError(err)

	theirKey2, err := crypto.GenerateKey()
	s.Require().NoError(err)

	// We receive a message from user 1
	sharedKey1, err := s.service.Generate(myKey, &theirKey1.PublicKey, installationID1)
	s.Require().NoError(err)
	s.Require().NotNil(sharedKey1, "it generates a shared key")

	// We receive a message from user 2
	sharedKey2, err := s.service.Generate(myKey, &theirKey2.PublicKey, installationID2)
	s.Require().NoError(err)
	s.Require().NotNil(sharedKey2, "it generates a shared key")

	// All the secrets are there
	secrets, err := s.service.All()
	s.Require().NoError(err)
	expected := []*Secret{
		sharedKey1,
		sharedKey2,
	}
	s.Require().Equal(expected, secrets)
}
