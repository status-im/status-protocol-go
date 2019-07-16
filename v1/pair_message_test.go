package statusproto

import (
	"testing"

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
	val, err := DecodeMessage(testPairMessageBytes)
	require.NoError(t, err)
	require.EqualValues(t, StatusMessage{
		Message: testPairMessageStruct,
		ID:      MessageID(testPairMessageBytes),
	}, val)
}

func TestEncodePairMessage(t *testing.T) {
	data, err := EncodePairMessage(testPairMessageStruct)
	require.NoError(t, err)
	// Decode it back to a struct because, for example, map encoding is non-deterministic
	// and it is not possible to compare bytes.
	val, err := DecodeMessage(data)
	require.NoError(t, err)
	require.EqualValues(t, StatusMessage{
		Message: testPairMessageStruct,
		ID:      MessageID(data),
	}, val)
}
