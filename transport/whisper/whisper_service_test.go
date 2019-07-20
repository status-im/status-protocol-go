package whisper

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSelectAndAddNoMailservers(t *testing.T) {
	logger := zap.NewNop()
	svc := &WhisperServiceTransport{
		logger: logger,
	}
	rst, err := svc.selectAndAddMailServer()
	require.Empty(t, rst)
	require.EqualError(t, ErrNoMailservers, err.Error())
}

func TestNewWhisperServiceTransport(t *testing.T) {
	dbPath, err := ioutil.TempFile("", "transport.sql")
	require.NoError(t, err)
	defer os.Remove(dbPath.Name())

	logger, err := zap.NewDevelopment()
	require.NoError(t, err)
	defer require.NoError(t, logger.Sync())

	_, err = NewWhisperServiceTransport(nil, nil, nil, dbPath.Name(), "some-key", nil, logger)
	require.NoError(t, err)
}
