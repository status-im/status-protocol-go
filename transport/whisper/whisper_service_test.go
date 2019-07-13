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
	dbPath, err := ioutil.TempFile("", "transport.sql")
	require.NoError(t, err)
	defer os.Remove(dbPath.Name())

	_, err = NewWhisperServiceTransport(nil, nil, nil, dbPath.Name(), "some-key", nil)
	require.NoError(t, err)
}
