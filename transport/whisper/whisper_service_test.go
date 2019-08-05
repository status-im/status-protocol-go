package whisper

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/status-im/status-protocol-go/sqlite"
	migrations "github.com/status-im/status-protocol-go/transport/whisper/migrations"

	"github.com/stretchr/testify/require"

	"github.com/status-im/status-protocol-go/tt"
)

func TestNewWhisperServiceTransport(t *testing.T) {
	dbPath, err := ioutil.TempFile("", "transport.sql")
	require.NoError(t, err)
	defer os.Remove(dbPath.Name())
	db, err := sqlite.Open(dbPath.Name(), "some-key", sqlite.MigrationConfig{
		AssetNames:  migrations.AssetNames(),
		AssetGetter: migrations.Asset,
	})
	require.NoError(t, err)

	logger := tt.MustCreateTestLogger()
	require.NoError(t, err)
	defer func() { _ = logger.Sync() }()

	_, err = NewWhisperServiceTransport(nil, nil, db, nil, nil, logger)
	require.NoError(t, err)
}
