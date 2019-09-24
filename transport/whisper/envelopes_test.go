package whisper

import (
	"testing"

	"go.uber.org/zap"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	whisper "github.com/status-im/whisper/whisperv6"
	"github.com/stretchr/testify/suite"
)

var (
	testHash = common.Hash{0x01}
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
			IsMailserver:                   func(enode.ID) bool { return false },
			Logger:                         zap.NewNop(),
		},
	)
}

func (s *EnvelopesMonitorSuite) TestConfirmed() {
	s.monitor.Add(testIDs, testHash, whisper.NewMessage{})
	s.Contains(s.monitor.envelopes, testHash)
	s.Equal(EnvelopePosted, s.monitor.envelopes[testHash])
	s.monitor.handleEvent(whisper.EnvelopeEvent{
		Event: whisper.EventEnvelopeSent,
		Hash:  testHash,
	})
	s.Contains(s.monitor.envelopes, testHash)
	s.Equal(EnvelopeSent, s.monitor.envelopes[testHash])
}

func (s *EnvelopesMonitorSuite) TestConfirmedWithAcknowledge() {
	testBatch := common.Hash{1}
	pkey, err := crypto.GenerateKey()
	s.Require().NoError(err)
	node := enode.NewV4(&pkey.PublicKey, nil, 0, 0)
	s.monitor.Add(testIDs, testHash, whisper.NewMessage{})
	s.Contains(s.monitor.envelopes, testHash)
	s.Equal(EnvelopePosted, s.monitor.envelopes[testHash])
	s.monitor.handleEvent(whisper.EnvelopeEvent{
		Event: whisper.EventEnvelopeSent,
		Hash:  testHash,
		Batch: testBatch,
	})
	s.Equal(EnvelopePosted, s.monitor.envelopes[testHash])
	s.monitor.handleEvent(whisper.EnvelopeEvent{
		Event: whisper.EventBatchAcknowledged,
		Batch: testBatch,
		Peer:  node.ID(),
	})
	s.Contains(s.monitor.envelopes, testHash)
	s.Equal(EnvelopeSent, s.monitor.envelopes[testHash])
}

func (s *EnvelopesMonitorSuite) TestIgnored() {
	s.monitor.handleEvent(whisper.EnvelopeEvent{
		Event: whisper.EventEnvelopeSent,
		Hash:  testHash,
	})
	s.NotContains(s.monitor.envelopes, testHash)
}

func (s *EnvelopesMonitorSuite) TestRemoved() {
	s.monitor.Add(testIDs, testHash, whisper.NewMessage{})
	s.Contains(s.monitor.envelopes, testHash)
	s.monitor.handleEvent(whisper.EnvelopeEvent{
		Event: whisper.EventEnvelopeExpired,
		Hash:  testHash,
	})
	s.NotContains(s.monitor.envelopes, testHash)
}

func (s *EnvelopesMonitorSuite) TestIgnoreNotFromMailserver() {
	// enables filter in the tracker to drop confirmations from non-mailserver peers
	s.monitor.mailServerConfirmation = true
	s.monitor.Add(testIDs, testHash, whisper.NewMessage{})
	s.monitor.handleEvent(whisper.EnvelopeEvent{
		Event: whisper.EventEnvelopeSent,
		Hash:  testHash,
		Peer:  enode.ID{1}, // could be empty, doesn't impact test behaviour
	})
	s.Require().Equal(EnvelopePosted, s.monitor.GetState(testHash))
}

func (s *EnvelopesMonitorSuite) TestReceived() {
	s.monitor.isMailserver = func(peer enode.ID) bool {
		return true
	}
	s.monitor.Add(testIDs, testHash, whisper.NewMessage{})
	s.Contains(s.monitor.envelopes, testHash)
	s.monitor.handleEvent(whisper.EnvelopeEvent{
		Event: whisper.EventEnvelopeReceived,
		Hash:  testHash,
	})
	s.Require().Equal(EnvelopeSent, s.monitor.GetState(testHash))
}
