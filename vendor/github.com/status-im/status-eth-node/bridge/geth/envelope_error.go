package gethbridge

import (
	"github.com/status-im/status-eth-node/types"
	whispertypes "github.com/status-im/status-eth-node/types/whisper"
	whisper "github.com/status-im/whisper/whisperv6"
)

// NewGethEnvelopeErrorWrapper returns a whispertypes.EnvelopeError object that mimics Geth's EnvelopeError
func NewGethEnvelopeErrorWrapper(envelopeError *whisper.EnvelopeError) *whispertypes.EnvelopeError {
	if envelopeError == nil {
		panic("envelopeError should not be nil")
	}

	return &whispertypes.EnvelopeError{
		Hash:        types.Hash(envelopeError.Hash),
		Code:        mapGethErrorCode(envelopeError.Code),
		Description: envelopeError.Description,
	}
}

func mapGethErrorCode(code uint) uint {
	switch code {
	case whisper.EnvelopeTimeNotSynced:
		return whispertypes.EnvelopeTimeNotSynced
	case whisper.EnvelopeOtherError:
		return whispertypes.EnvelopeOtherError
	}
	return whispertypes.EnvelopeOtherError
}
