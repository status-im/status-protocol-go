package gethbridge

import (
	whispertypes "github.com/status-im/status-eth-node/types/whisper"
	whisper "github.com/status-im/whisper/whisperv6"
)

// NewGethSyncEventResponseWrapper returns a whispertypes.SyncEventResponse object that mimics Geth's SyncEventResponse
func NewGethSyncEventResponseWrapper(syncEventResponse whisper.SyncEventResponse) whispertypes.SyncEventResponse {
	return whispertypes.SyncEventResponse{
		Cursor: syncEventResponse.Cursor,
		Error:  syncEventResponse.Error,
	}
}
