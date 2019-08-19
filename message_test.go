package statusproto

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/stretchr/testify/require"

	"github.com/status-im/status-protocol-go/applicationmetadata"
	"github.com/status-im/status-protocol-go/encryption"
	protocol "github.com/status-im/status-protocol-go/v1"
	whisper "github.com/status-im/whisper/whisperv6"
)

func TestMessageAutomaton_Resolve(t *testing.T) {
	mock := &mockAutomaton{}
	automaton := messageProcessor{
		Encryptor:    mock,
		Encoder:      mock,
		Syncer:       mock,
		Wrapper:      mock,
		Sender:       mock,
		featureFlags: featureFlags{},
	}
	message := &Message{
		encryptedPayload: []byte("encrypted-payload"),
	}
	_, err := automaton.Resolve(message)
	require.NoError(t, err)
	require.Equal(t, []string{"decrypt", "desync", "unwrap", "decode"}, mock.calls)
}

func TestMessageAutomaton_Send(t *testing.T) {
	mock := &mockAutomaton{}
	automaton := messageProcessor{
		Encryptor: mock,
		Encoder:   mock,
		Syncer:    mock,
		Wrapper:   mock,
		Sender:    mock,
		featureFlags: featureFlags{
			sendV1Messages: true,
			datasync:       true,
		},
	}
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	protocolMessage := protocol.CreatePrivateTextMessage([]byte("data"), time.Now().Unix(), "some-chat-id")
	message, err := newPrivateMessage(&key.PublicKey, &key.PublicKey, protocolMessage)
	require.NoError(t, err)
	err = automaton.Send(message)
	require.NoError(t, err)
	require.Equal(t, []string{"encode", "wrap", "sync", "encrypt", "send-private"}, mock.calls)
}

func TestMessageAutomaton_SendEncoded(t *testing.T) {
	mock := &mockAutomaton{}
	automaton := messageProcessor{
		Encryptor: mock,
		Encoder:   mock,
		Syncer:    mock,
		Wrapper:   mock,
		Sender:    mock,
		featureFlags: featureFlags{
			sendV1Messages: true,
			datasync:       true,
		},
	}
	message := &Message{
		decryptedPayload: []byte("encoded-data"),
	}
	err := automaton.SendEncoded(message)
	require.NoError(t, err)
	require.Equal(t, []string{"wrap", "sync", "encrypt", "send-private"}, mock.calls)
}

type mockAutomaton struct {
	calls []string
}

func (m *mockAutomaton) Encrypt(recipientKey *ecdsa.PublicKey, data []byte) ([]byte, encryptionMeta, error) {
	m.calls = append(m.calls, "encrypt")
	return nil, encryptionMeta{spec: &encryption.ProtocolMessageSpec{}}, nil
}

func (m *mockAutomaton) Decrypt(senderKey *ecdsa.PublicKey, messageID []byte, data []byte) ([]byte, error) {
	m.calls = append(m.calls, "decrypt")
	return nil, nil
}

func (m *mockAutomaton) Encode(message interface{}) ([]byte, error) {
	m.calls = append(m.calls, "encode")
	return nil, nil
}

func (m *mockAutomaton) Decode(data []byte) (interface{}, error) {
	m.calls = append(m.calls, "decode")
	return nil, nil
}

func (m *mockAutomaton) Sync(recipeintKey *ecdsa.PublicKey, data []byte) error {
	m.calls = append(m.calls, "sync")
	return nil
}

func (m *mockAutomaton) Desync(senderKey *ecdsa.PublicKey, data []byte) [][]byte {
	m.calls = append(m.calls, "desync")
	return [][]byte{data} // return at least received payload to continue with the next states
}

func (m *mockAutomaton) Wrap(data []byte) ([]byte, error) {
	m.calls = append(m.calls, "wrap")
	return nil, nil
}

func (m *mockAutomaton) Unwrap(data []byte) (*applicationmetadata.Message, error) {
	m.calls = append(m.calls, "unwrap")
	return &applicationmetadata.Message{
		Signature: nil,
		Payload:   data,
	}, nil
}

func (m *mockAutomaton) SendPublic(string, *encryption.ProtocolMessageSpec) ([]byte, *whisper.NewMessage, error) {
	m.calls = append(m.calls, "send-public")
	return nil, nil, nil
}

func (m *mockAutomaton) SendPrivate(*ecdsa.PublicKey, *encryption.ProtocolMessageSpec) ([]byte, *whisper.NewMessage, error) {
	m.calls = append(m.calls, "send-private")
	return nil, nil, nil
}
func (m *mockAutomaton) SendPublicRaw(string, []byte) ([]byte, *whisper.NewMessage, error) {
	m.calls = append(m.calls, "send-public-raw")
	return nil, nil, nil
}

func TestNewMessageFromTransport(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	m, err := newMessageFromTransport(&whisper.Message{
		Sig:     crypto.FromECDSAPub(&key.PublicKey),
		Payload: []byte{0x0a, 0x0b, 0x0c},
		Hash:    []byte{0x01},
	}, "test-chat-id", true)
	require.NoError(t, err)
	require.Nil(t, m.ProtocolID())
	require.Equal(t, []byte{0x01}, m.AnyID())
	require.NotNil(t, m.SigPubKey())
	require.Equal(t, "test-chat-id", m.ChatID())

	// invalid signature
	_, err = newMessageFromTransport(&whisper.Message{
		Sig: nil,
	}, "test-chat-id", true)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "received a message with invalid signature")
}

func TestNewPrivateMessage_Failure(t *testing.T) {
	key, _ := crypto.GenerateKey()
	publicKey := &key.PublicKey
	testCases := []struct {
		Name      string
		SigPubKey *ecdsa.PublicKey
		Recipient *ecdsa.PublicKey
		Message   interface{}
		Error     error
	}{
		{
			Name:  "missing signature",
			Error: errMissingSigPubKey,
		},
		{
			Name:      "missing recipient",
			SigPubKey: publicKey,
			Error:     errMissingRecipient,
		},
		{
			Name:      "missing protocol message",
			SigPubKey: publicKey,
			Recipient: publicKey,
			Error:     errMissingProtocolMessage,
		},
		{
			Name:      "invalid protocol message",
			SigPubKey: publicKey,
			Recipient: publicKey,
			Message:   struct{}{},
			Error:     errNotUserMessage,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := newPrivateMessage(tc.SigPubKey, tc.Recipient, tc.Message)
			require.Equal(t, tc.Error, err)
		})
	}
}

func TestNewPrivateMessage_Success(t *testing.T) {
	key, _ := crypto.GenerateKey()
	publicKey := &key.PublicKey
	m, err := newPrivateMessage(publicKey, publicKey, protocol.CreatePrivateTextMessage(nil, 0, "chat-id"))
	require.NoError(t, err)
	// require.NotEmpty(t, m.ChatID()) // TODO
	require.NotNil(t, m.SigPubKey())
	require.Nil(t, m.ProtocolID())
	require.Nil(t, m.AnyID())
	require.NotNil(t, m.Interface())
	require.True(t, m.IsUserMessage())
	require.False(t, m.Public())
}

func TestNewPublicMessage(t *testing.T) {
	key, _ := crypto.GenerateKey()
	publicKey := &key.PublicKey
	testCases := []struct {
		Name      string
		SigPubKey *ecdsa.PublicKey
		Recipient *ecdsa.PublicKey
		Message   interface{}
		Error     error
	}{
		{
			Name:  "missing signature",
			Error: errMissingSigPubKey,
		},
		{
			Name:      "missing protocol message",
			SigPubKey: publicKey,
			Recipient: publicKey,
			Error:     errMissingProtocolMessage,
		},
		{
			Name:      "invalid protocol message",
			SigPubKey: publicKey,
			Recipient: publicKey,
			Message:   struct{}{},
			Error:     errNotUserMessage,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := newPublicMessage(tc.SigPubKey, "test-chat-id", tc.Message)
			require.Equal(t, tc.Error, err)
		})
	}
}

func TestNewPublicMessage_Success(t *testing.T) {
	key, _ := crypto.GenerateKey()
	publicKey := &key.PublicKey
	m, err := newPublicMessage(publicKey, "chat-id", protocol.CreatePublicTextMessage(nil, 0, "chat-id"))
	require.NoError(t, err)
	require.Equal(t, "chat-id", m.ChatID())
	require.NotNil(t, m.SigPubKey())
	require.Nil(t, m.ProtocolID())
	require.Nil(t, m.AnyID())
	require.NotNil(t, m.Interface())
	require.True(t, m.IsUserMessage())
	require.True(t, m.Public())
}
