package statusproto

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

var (
	testPairMessageBytes  = []byte(`["~#p2",["installation-id","desktop","name","token"]]`)
	testPairMessageStruct = PairMessage{
		Name:           "name",
		DeviceType:     "desktop",
		FCMToken:       "token",
		InstallationID: "installation-id",
	}
)

func TestDecodePairMessageMessage(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	val, err := DecodeMessage(&key.PublicKey, testPairMessageBytes)
	require.NoError(t, err)
	require.EqualValues(t, StatusMessage{
		Message:   testPairMessageStruct,
		SigPubKey: &key.PublicKey,
		ID:        MessageID(&key.PublicKey, testPairMessageBytes),
	}, val)
}

func TestEncodePairMessage(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	data, err := EncodePairMessage(testPairMessageStruct)
	require.NoError(t, err)
	// Decode it back to a struct because, for example, map encoding is non-deterministic
	// and it is not possible to compare bytes.
	val, err := DecodeMessage(&key.PublicKey, data)
	require.NoError(t, err)
	require.EqualValues(t, StatusMessage{
		Message:   testPairMessageStruct,
		SigPubKey: &key.PublicKey,
		ID:        MessageID(&key.PublicKey, data),
	}, val)
}
