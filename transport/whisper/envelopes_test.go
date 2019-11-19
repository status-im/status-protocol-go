package whisper

import (
	"testing"

	"go.uber.org/zap"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/status-im/status-eth-node/types"
	whispertypes "github.com/status-im/status-eth-node/types/whisper"
	"github.com/stretchr/testify/suite"
)

var (
	testHash = types.Hash{0x01}
	testIDs  = [][]byte{[]byte("id")}
)

type EnvelopesMonitorSuite struct {
	suite.Suite

	monitor *EnvelopesMonitor
}

func TestEnvelopesMonitorSuite(t *testing.T) {
	suite.Run(t, new(EnvelopesMonitorSuite))
}

func (s *EnvelopesMonitorSuite) SetupTest() {
	s.monitor = NewEnvelopesMonitor(
		nil,
		EnvelopesMonitorConfig{
			EnvelopeEventsHandler:          nil,
			MaxAttempts:                    0,
			MailserverConfirmationsEnabled: false,
			IsMailserver:                   func(types.EnodeID) bool { return false },
			Logger:                         zap.NewNop(),
		},
	)
}

func (s *EnvelopesMonitorSuite) TestConfirmed() {
	s.monitor.Add(testIDs, testHash, whispertypes.NewMessage{})
	s.Contains(s.monitor.envelopes, testHash)
	s.Equal(EnvelopePosted, s.monitor.envelopes[testHash])
	s.monitor.handleEvent(whispertypes.EnvelopeEvent{
		Event: whispertypes.EventEnvelopeSent,
		Hash:  testHash,
	})
	s.Contains(s.monitor.envelopes, testHash)
	s.Equal(EnvelopeSent, s.monitor.envelopes[testHash])
}

func (s *EnvelopesMonitorSuite) TestConfirmedWithAcknowledge() {
	testBatch := types.Hash{1}
	pkey, err := crypto.GenerateKey()
	s.Require().NoError(err)
	node := enode.NewV4(&pkey.PublicKey, nil, 0, 0)
	s.monitor.Add(testIDs, testHash, whispertypes.NewMessage{})
	s.Contains(s.monitor.envelopes, testHash)
	s.Equal(EnvelopePosted, s.monitor.envelopes[testHash])
	s.monitor.handleEvent(whispertypes.EnvelopeEvent{
		Event: whispertypes.EventEnvelopeSent,
		Hash:  testHash,
		Batch: testBatch,
	})
	s.Equal(EnvelopePosted, s.monitor.envelopes[testHash])
	s.monitor.handleEvent(whispertypes.EnvelopeEvent{
		Event: whispertypes.EventBatchAcknowledged,
		Batch: testBatch,
		Peer:  types.EnodeID(node.ID()),
	})
	s.Contains(s.monitor.envelopes, testHash)
	s.Equal(EnvelopeSent, s.monitor.envelopes[testHash])
}

func (s *EnvelopesMonitorSuite) TestIgnored() {
	s.monitor.handleEvent(whispertypes.EnvelopeEvent{
		Event: whispertypes.EventEnvelopeSent,
		Hash:  testHash,
	})
	s.NotContains(s.monitor.envelopes, testHash)
}

func (s *EnvelopesMonitorSuite) TestRemoved() {
	s.monitor.Add(testIDs, testHash, whispertypes.NewMessage{})
	s.Contains(s.monitor.envelopes, testHash)
	s.monitor.handleEvent(whispertypes.EnvelopeEvent{
		Event: whispertypes.EventEnvelopeExpired,
		Hash:  testHash,
	})
	s.NotContains(s.monitor.envelopes, testHash)
}

func (s *EnvelopesMonitorSuite) TestIgnoreNotFromMailserver() {
	// enables filter in the tracker to drop confirmations from non-mailserver peers
	s.monitor.mailServerConfirmation = true
	s.monitor.Add(testIDs, testHash, whispertypes.NewMessage{})
	s.monitor.handleEvent(whispertypes.EnvelopeEvent{
		Event: whispertypes.EventEnvelopeSent,
		Hash:  testHash,
		Peer:  types.EnodeID{1}, // could be empty, doesn't impact test behaviour
	})
	s.Require().Equal(EnvelopePosted, s.monitor.GetState(testHash))
}

func (s *EnvelopesMonitorSuite) TestReceived() {
	s.monitor.isMailserver = func(peer types.EnodeID) bool {
		return true
	}
	s.monitor.Add(testIDs, testHash, whispertypes.NewMessage{})
	s.Contains(s.monitor.envelopes, testHash)
	s.monitor.handleEvent(whispertypes.EnvelopeEvent{
		Event: whispertypes.EventEnvelopeReceived,
		Hash:  testHash,
	})
	s.Require().Equal(EnvelopeSent, s.monitor.GetState(testHash))
}
