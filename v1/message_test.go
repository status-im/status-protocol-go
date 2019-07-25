package statusproto

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

var (
	testMessageBytes  = []byte(`["~#c4",["abc123","text/plain","~:public-group-user-message",154593077368201,1545930773682,["^ ","~:chat-id","testing-adamb","~:text","abc123"]]]`)
	testMessageStruct = Message{
		Text:      "abc123",
		ContentT:  "text/plain",
		MessageT:  "public-group-user-message",
		Clock:     154593077368201,
		Timestamp: 1545930773682,
		Content:   Content{"testing-adamb", "abc123"},
	}
)

func TestDecodeMessage(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	val, err := DecodeMessage(&key.PublicKey, testMessageBytes)
	require.NoError(t, err)
	require.EqualValues(t, StatusMessage{
		Message:   testMessageStruct,
		SigPubKey: &key.PublicKey,
		ID:        MessageID(&key.PublicKey, testMessageBytes),
	}, val)
}

func BenchmarkDecodeMessage(b *testing.B) {
	key, err := crypto.GenerateKey()
	require.NoError(b, err)

	_, err = DecodeMessage(&key.PublicKey, testMessageBytes)
	if err != nil {
		b.Fatalf("failed to decode message: %v", err)
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_, _ = DecodeMessage(&key.PublicKey, testMessageBytes)
	}
}

func TestEncodeMessage(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	data, err := EncodeMessage(testMessageStruct)
	require.NoError(t, err)
	// Decode it back to a struct because, for example, map encoding is non-deterministic
	// and it is not possible to compare bytes.
	val, err := DecodeMessage(&key.PublicKey, data)
	require.NoError(t, err)
	require.EqualValues(t, StatusMessage{
		Message:   testMessageStruct,
		SigPubKey: &key.PublicKey,
		ID:        MessageID(&key.PublicKey, data),
	}, val)
}

func TestWrappedMessageWithSignature(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	transportKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	data, err := EncodeMessage(testMessageStruct)
	require.NoError(t, err)
	wrappedMessage, err := WrapMessageV1(data, key)
	require.NoError(t, err)
	// Decode it back to a struct because, for example, map encoding is non-deterministic
	// and it is not possible to compare bytes.
	val, err := DecodeMessage(&transportKey.PublicKey, wrappedMessage)
	require.NoError(t, err)
	require.EqualValues(t, StatusMessage{
		Message:   testMessageStruct,
		ID:        MessageID(&key.PublicKey, data),
		SigPubKey: &key.PublicKey,
	}, val)
}

func TestWrappedMessageWithoutSignature(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	data, err := EncodeMessage(testMessageStruct)
	require.NoError(t, err)
	wrappedMessage, err := WrapMessageV1(data, nil)
	require.NoError(t, err)
	// Decode it back to a struct because, for example, map encoding is non-deterministic
	// and it is not possible to compare bytes.
	val, err := DecodeMessage(&key.PublicKey, wrappedMessage)
	require.NoError(t, err)

	require.EqualValues(t, StatusMessage{
		Message:   testMessageStruct,
		SigPubKey: &key.PublicKey,
		ID:        MessageID(&key.PublicKey, data),
	}, val)
}

func TestMessageID(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	compressedKey := crypto.CompressPubkey(&key.PublicKey)

	data := []byte("test")
	expectedID := crypto.Keccak256(append(compressedKey, data...))
	require.Equal(t, expectedID, MessageID(&key.PublicKey, data))
}

func TestMessageWrongPublicKey(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	wrongKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	data, err := EncodeMessage(testMessageStruct)
	require.NoError(t, err)
	wrappedMessage, err := WrapMessageV1(data, key)
	require.NoError(t, err)
	// Decode it back to a struct because, for example, map encoding is non-deterministic
	// and it is not possible to compare bytes.
	val, err := DecodeMessage(&key.PublicKey, wrappedMessage)
	require.NoError(t, err)
	require.NotEqual(t, val.ID, MessageID(&wrongKey.PublicKey, data), val)
}

func TestTimestampInMs(t *testing.T) {
	ts := TimestampInMs(1555274502548) // random timestamp in milliseconds
	tt := ts.Time()
	require.Equal(t, tt.UnixNano(), 1555274502548*int64(time.Millisecond))
	require.Equal(t, ts, TimestampInMsFromTime(tt))
}
