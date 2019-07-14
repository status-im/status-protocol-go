package statusproto

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"io/ioutil"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	whisper "github.com/status-im/whisper/whisperv6"
	"github.com/stretchr/testify/require"
)

func TestNewMessenger(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "messenger-test")
	require.NoError(t, err)
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	shh := whisper.New(nil)

	_, err = NewMessenger(
		privateKey,
		nil,
		shh,
		tmpDir,
		"some-key",
		"installation-1",
		WithChats([]string{"status"}, nil, nil),
	)
	require.NoError(t, err)
}

type testChat struct {
	publicName string
	publicKey  *ecdsa.PublicKey
}

func (c testChat) ID() string {
	if c.publicKey != nil {
		return hex.EncodeToString(crypto.FromECDSAPub(c.publicKey))
	}
	// Deliberately use a different ID than public name.
	return hex.EncodeToString([]byte(c.publicName))
}

func (c testChat) PublicKey() *ecdsa.PublicKey {
	return c.publicKey
}

func (c testChat) PublicName() string {
	return c.publicName
}

func TestMessengerSend(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "messenger-test")
	require.NoError(t, err)
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	config := whisper.DefaultConfig
	config.MinimumAcceptedPOW = 0
	shh := whisper.New(&config)

	m, err := NewMessenger(
		privateKey,
		nil,
		shh,
		tmpDir,
		"some-key",
		"installation-1",
	)
	require.NoError(t, err)

	// Send public
	_, err = m.Send(context.Background(), testChat{publicName: "status"}, []byte("test"))
	require.NoError(t, err)

	// Send private
	recipientKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	_, err = m.Send(context.Background(), testChat{publicKey: &recipientKey.PublicKey}, []byte("test"))
	require.NoError(t, err)
}

func TestMessengerRetrieve(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "messenger-test")
	require.NoError(t, err)
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	config := whisper.DefaultConfig
	config.MinimumAcceptedPOW = 0
	shh := whisper.New(&config)
	err = shh.Start(nil)
	require.NoError(t, err)

	m, err := NewMessenger(
		privateKey,
		nil,
		shh,
		tmpDir,
		"some-key",
		"installation-1",
	)
	require.NoError(t, err)

	chat := testChat{publicName: "status"}

	// Join chat
	err = m.Join(chat)
	require.NoError(t, err)

	// Send public
	_, err = m.Send(context.Background(), chat, []byte("test"))
	require.NoError(t, err)

	// Give Whisper some time to propagate message to filters.
	time.Sleep(time.Millisecond * 500)

	// Retrieve chat
	messages, err := m.Retrieve(context.Background(), chat, RetrieveLatest)
	require.NoError(t, err)
	require.Len(t, messages, 1)
}
