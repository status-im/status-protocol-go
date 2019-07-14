package statusproto

import (
	"io/ioutil"
	"testing"

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
