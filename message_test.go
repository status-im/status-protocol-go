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
	message := newPrivateMessage(&key.PublicKey, &key.PublicKey, protocolMessage)
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
