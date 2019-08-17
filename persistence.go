package statusproto

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pkg/errors"

	protocol "github.com/status-im/status-protocol-go/v1"
)

const (
	uniqueIDContstraint = "UNIQUE constraint failed: user_messages.id"
)

var (
	// ErrMsgAlreadyExist returned if msg already exist.
	ErrMsgAlreadyExist = errors.New("message with given ID already exist")
)

// sqlitePersistence wrapper around sql db with operations common for a client.
type sqlitePersistence struct {
	db *sql.DB
}

func (db sqlitePersistence) LastMessageClock(publicKey *ecdsa.PublicKey, chatID string) (int64, error) {
	if publicKey == nil {
		return 0, errors.New("public key is nil")
	}
	if chatID == "" {
		return 0, errors.New("chat ID is empty")
	}

	var last sql.NullInt64
	err := db.db.QueryRow(
		"SELECT max(clock) FROM user_messages WHERE sig_public_key =? AND chat_id = ?",
		crypto.FromECDSAPub(publicKey),
		chatID,
	).Scan(&last)
	if err != nil {
		return 0, err
	}
	return last.Int64, nil
}

// Messages returns messages for a given contact, in a given period.
// Ordered by a timestamp. ChatID is optional.
func (db sqlitePersistence) Messages(publicKey *ecdsa.PublicKey, from, to time.Time, chatID string) ([]*Message, error) {
	q := `SELECT
			recipient,
			data
		FROM user_messages
		WHERE
			sig_public_key = ? AND
			timestamp >= ? AND timestamp <= ?`
	args := []interface{}{
		crypto.FromECDSAPub(publicKey),
		protocol.TimestampInMsFromTime(from),
		protocol.TimestampInMsFromTime(to),
	}
	if chatID != "" {
		q = q + ` AND chat_id = ?`
		args = append(args, chatID)
	}
	rows, err := db.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*Message

	for rows.Next() {
		var (
			recipientBytes     []byte
			recipientPublicKey *ecdsa.PublicKey
			data               []byte
		)
		if err := rows.Scan(
			&recipientBytes,
			&data,
		); err != nil {
			return nil, err
		}

		if len(recipientBytes) > 0 {
			recipientPublicKey, err = crypto.UnmarshalPubkey(recipientBytes)
			if err != nil {
				return nil, err
			}
		}

		message := Message{
			sigPubKey:        publicKey,
			decryptedPayload: data,
			recipient:        recipientPublicKey,
		}
		result = append(result, &message)
	}

	return result, nil
}

func (db sqlitePersistence) SaveMessages(publicKey *ecdsa.PublicKey, messages ...*Message) error {
	tx, err := db.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO user_messages(
			id, sig_public_key, chat_id, recipient, clock, timestamp, data)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}

	for _, m := range messages {
		var recipientBytes []byte

		if m.recipient != nil {
			recipientBytes = crypto.FromECDSAPub(m.recipient)
		}

		if _, err := stmt.Exec(
			m.ID(),
			crypto.FromECDSAPub(publicKey),
			m.ChatID(),
			recipientBytes,
			m.Clock(),
			m.Timestamp(),
			m.RawMessage(),
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}
