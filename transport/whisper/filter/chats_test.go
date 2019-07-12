package filter

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	_ "github.com/mutecomm/go-sqlcipher"
	whisper "github.com/status-im/whisper/whisperv6"
	"github.com/stretchr/testify/suite"

	"github.com/status-im/status-protocol-go/transport/whisper/internal/sqlite"
)

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(ChatsTestSuite))
}

type ChatsTestSuite struct {
	suite.Suite
	chats  *ChatsManager
	dbPath string
	keys   []*testKey
}

type testKey struct {
	privateKey       *ecdsa.PrivateKey
	partitionedTopic int
}

func (t *testKey) publicKeyString() string {
	return hex.EncodeToString(crypto.FromECDSAPub(&t.privateKey.PublicKey))
}

func newTestKey(privateKey string, partitionedTopic int) (*testKey, error) {
	key, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return nil, err
	}

	return &testKey{
		privateKey:       key,
		partitionedTopic: partitionedTopic,
	}, nil
}

func (s *ChatsTestSuite) SetupTest() {
	keyStrs := []string{
		"c6cbd7d76bc5baca530c875663711b947efa6a86a900a9e8645ce32e5821484e",
		"d51dd64ad19ea84968a308dca246012c00d2b2101d41bce740acd1c650acc509",
	}
	keyTopics := []int{4490, 3991}

	dbFile, err := ioutil.TempFile(os.TempDir(), "filter")
	s.Require().NoError(err)
	s.dbPath = dbFile.Name()

	for i, k := range keyStrs {
		testKey, err := newTestKey(k, keyTopics[i])
		s.Require().NoError(err)
		s.keys = append(s.keys, testKey)
	}

	db, err := sqlite.Open(s.dbPath, "filter-key")
	s.Require().NoError(err)

	whisper := whisper.New(nil)
	_, err = whisper.AddKeyPair(s.keys[0].privateKey)
	s.Require().NoError(err)

	s.chats, err = New(db, whisper)
	s.Require().NoError(err)
}

func (s *ChatsTestSuite) TearDownTest() {
	os.Remove(s.dbPath)
}

func (s *ChatsTestSuite) TestDiscoveryAndPartitionedTopic() {
	partitionedTopic := fmt.Sprintf("contact-discovery-%d", s.keys[0].partitionedTopic)
	personalDiscoveryTopic := fmt.Sprintf("contact-discovery-%s", s.keys[0].publicKeyString())
	contactCodeTopic := contactCodeTopic(&s.keys[0].privateKey.PublicKey)

	_, err := s.chats.InitDeprecated(nil, nil)
	s.Require().NoError(err)

	s.Require().Equal(4, len(s.chats.chats), "It creates four filters")

	discoveryFilter := s.chats.chats[DiscoveryTopic]
	s.Require().NotNil(discoveryFilter, "It adds the discovery filter")
	s.Require().True(discoveryFilter.Listen)

	personalDiscoveryFilter := s.chats.chats[personalDiscoveryTopic]
	s.Require().NotNil(personalDiscoveryFilter, "It adds the discovery filter")
	s.Require().True(personalDiscoveryFilter.Listen)

	contactCodeFilter := s.chats.chats[contactCodeTopic]
	s.Require().NotNil(contactCodeFilter, "It adds the contact code filter")
	s.Require().True(contactCodeFilter.Listen)

	partitionedFilter := s.chats.chats[partitionedTopic]
	s.Require().NotNil(partitionedFilter, "It adds the partitioned filter")
	s.Require().True(partitionedFilter.Listen)
}
