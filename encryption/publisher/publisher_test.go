package publisher

import (
	"database/sql"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(PublisherTestSuite))
}

type PublisherTestSuite struct {
	suite.Suite
	publisher *Publisher
	logger    *zap.Logger
}

func (p *PublisherTestSuite) SetupTest(installationID string) {
	dir, err := ioutil.TempDir("", "publisher-test")
	p.Require().NoError(err)

	db, err := sql.Open("sqlite3", dir)
	p.Require().NoError(err)

	logger, err := zap.NewDevelopment()
	p.Require().NoError(err)
	p.logger = logger

	p.publisher = New(db, logger)
}

func (p *PublisherTestSuite) TearDownTest() {
	p.logger.Sync()
}

// TODO(adam): provide more tests
