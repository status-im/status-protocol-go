package sqlite

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	dir, err := ioutil.TempDir("", "test-open")
	require.NoError(t, err)
	defer os.Remove(dir)

	dbPath := filepath.Join(dir, "db.sql")

	// Open the db for the first time.
	db, err := open(dbPath, "some-key", reducedKdfIterationsNumber, MigrationConfig{})
	require.NoError(t, err)

	// Insert some data.
	_, err = db.Exec("CREATE TABLE test(name TEXT)")
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO test (name) VALUES ("abc")`)
	require.NoError(t, err)
	db.Close()

	// Open again with different key should fail
	// because the file already exists and it should not
	// be recreated.
	db, err = open(dbPath, "different-key", reducedKdfIterationsNumber, MigrationConfig{})
	require.NoError(t, err)

	row := db.QueryRow(`SELECT name FROM test WHERE name = 'abc'`)
	var name string
	err = row.Scan(&name)
	require.EqualError(t, err, "file is encrypted or is not a database")
}