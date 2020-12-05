package statusproto

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/status-im/status-protocol-go/protobuf"
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

func TestUnmarshalJSON(t *testing.T) {
	jsonString := `{
                         "text": "some-text",
			 "ensName": "ens-name",
			 "contentType": 1,
			 "chatId": "chat-id",
			 "sticker": {
			   "hash": "hash",
			   "pack": 1
			 },
			 "responseTo": "response-to"
		       }`
	messageJSON := []byte(jsonString)
	expected := &Message{}
	expected.Text = "some-text"
	expected.ResponseTo = "response-to"
	expected.EnsName = "ens-name"
	expected.ChatId = "chat-id"
	expected.ContentType = 1
	expected.Payload = &protobuf.ChatMessage_Sticker{Sticker: &protobuf.StickerMessage{Hash: "hash", Pack: 1}}
	actual := &Message{}
	err := json.Unmarshal(messageJSON, actual)
	require.NoError(t, err)

	require.Equal(t, expected, actual)

}
