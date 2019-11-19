package gethbridge

import (
	"github.com/status-im/status-eth-node/types"
	whispertypes "github.com/status-im/status-eth-node/types/whisper"
	whisper "github.com/status-im/whisper/whisperv6"
)

// NewGethMailServerResponseWrapper returns a whispertypes.MailServerResponse object that mimics Geth's MailServerResponse
func NewGethMailServerResponseWrapper(mailServerResponse *whisper.MailServerResponse) *whispertypes.MailServerResponse {
	if mailServerResponse == nil {
		panic("mailServerResponse should not be nil")
	}

	return &whispertypes.MailServerResponse{
		LastEnvelopeHash: types.Hash(mailServerResponse.LastEnvelopeHash),
		Cursor:           mailServerResponse.Cursor,
		Error:            mailServerResponse.Error,
	}
}
