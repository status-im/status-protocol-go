package statusproto

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	statusproto "github.com/status-im/status-protocol-go/types"
	"github.com/stretchr/testify/require"
)

func TestMessageID(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	keyBytes := crypto.FromECDSAPub(&key.PublicKey)

	data := []byte("test")
	expectedID := statusproto.HexBytes(crypto.Keccak256(append(keyBytes, data...)))
	require.Equal(t, expectedID, MessageID(&key.PublicKey, data))
}

func TestTimestampInMs(t *testing.T) {
	ts := TimestampInMs(1555274502548) // random timestamp in milliseconds
	tt := ts.Time()
	require.Equal(t, tt.UnixNano(), 1555274502548*int64(time.Millisecond))
	require.Equal(t, ts, TimestampInMsFromTime(tt))
}
