package publisher

import (
	"database/sql"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/suite"
)

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(PublisherTestSuite))
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

	p.publisher = New(db)
}

// TODO(adam): provide more tests
