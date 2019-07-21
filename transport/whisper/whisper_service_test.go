package whisper

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSelectAndAddNoMailservers(t *testing.T) {
	dbDir, err := ioutil.TempDir("", "transport")
	require.NoError(t, err)
	defer os.Remove(dbDir)

	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	svc, err := NewWhisperServiceTransport(nil, nil, nil, dbDir, "some-key", nil, logger)
	require.NoError(t, err)

	rst, err := svc.selectAndAddMailServer()
	require.Empty(t, rst)
	require.EqualError(t, ErrNoMailservers, err.Error())
	_ = logger.Sync()
}

func TestNewWhisperServiceTransport(t *testing.T) {
	dbDir, err := ioutil.TempDir("", "transport")
	require.NoError(t, err)
	defer os.Remove(dbDir)

	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	_, err = NewWhisperServiceTransport(nil, nil, nil, dbDir, "some-key", nil, logger)
	require.NoError(t, err)
	_ = logger.Sync()
}
