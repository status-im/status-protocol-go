package publisher

import (
	"database/sql"
)

type sqlitePersistence struct {
	db *sql.DB
}

func newSQLitePersistence(db *sql.DB) *sqlitePersistence {
	return &sqlitePersistence{
		db: db,
	}
}

func (s *sqlitePersistence) lastPublished() (int64, error) {
	var lastPublished int64
	statement := "SELECT last_published FROM contact_code_config LIMIT 1"
	err := s.db.QueryRow(statement).Scan(&lastPublished)
	if err != nil {
		return 0, err
	}
	return lastPublished, nil
}

func (s *sqlitePersistence) setLastPublished(lastPublished int64) error {
	statement := "UPDATE contact_code_config SET last_published = ?"
	stmt, err := s.db.Prepare(statement)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(lastPublished)
	return err
}
