package publisher

import (
	"crypto/ecdsa"
	"database/sql"
	"io/ioutil"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/suite"
)

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(PublisherTestSuite))
}

type testKey struct {
	privateKey     *ecdsa.PrivateKey
	keyID          string
	publicKeyBytes hexutil.Bytes
}

type PublisherTestSuite struct {
	suite.Suite
	publisher *Publisher
}

func (p *PublisherTestSuite) SetupTest(installationID string) {
	dir, err := ioutil.TempDir("", "publisher-test")
	p.Require().NoError(err)

	db, err := sql.Open("sqlite3", dir)
	p.Require().NoError(err)

	p.publisher = New(db, nil)
}

// TODO(adam): provide more tests
