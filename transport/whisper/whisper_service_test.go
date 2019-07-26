package whisper

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/status-im/status-protocol-go/sqlite"
	migrations "github.com/status-im/status-protocol-go/transport/whisper/migrations"

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
	_ = logger.Sync()
}

func TestNewWhisperServiceTransport(t *testing.T) {
	dbPath, err := ioutil.TempFile("", "transport.sql")
	require.NoError(t, err)
	defer os.Remove(dbPath.Name())
	db, err := sqlite.Open(dbPath.Name(), "some-key", sqlite.MigrationConfig{
		AssetNames:  migrations.AssetNames(),
		AssetGetter: migrations.Asset,
	})
	require.NoError(t, err)

	logger, err := zap.NewDevelopment()
	require.NoError(t, err)
	defer func() { _ = logger.Sync() }()

	_, err = NewWhisperServiceTransport(nil, nil, nil, db, nil, logger)
	require.NoError(t, err)
}
