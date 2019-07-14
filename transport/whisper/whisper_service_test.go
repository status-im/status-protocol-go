package whisper

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectAndAddNoMailservers(t *testing.T) {
	svc := &WhisperServiceTransport{}
	rst, err := svc.selectAndAddMailServer()
	require.Empty(t, rst)
	require.EqualError(t, ErrNoMailservers, err.Error())
}

func TestNewWhisperServiceTransport(t *testing.T) {
	dbDir, err := ioutil.TempDir("", "transport")
	require.NoError(t, err)
	defer os.Remove(dbDir)

	_, err = NewWhisperServiceTransport(nil, nil, nil, dbDir, "some-key", nil)
	require.NoError(t, err)
}
