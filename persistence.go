package statusproto

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pkg/errors"

	protocol "github.com/status-im/status-protocol-go/v1"
)

// sqlitePersistence wrapper around sql db with operations common for a client.
type sqlitePersistence struct {
	db *sql.DB
}

func (db sqlitePersistence) LastMessageClock(chatID string) (int64, error) {
	if chatID == "" {
		return 0, errors.New("chat ID is empty")
	}

	var last sql.NullInt64
	err := db.db.QueryRow(
		"SELECT max(clock) FROM user_messages WHERE chat_id = ?",
		chatID,
	).Scan(&last)
	if err != nil {
		return 0, err
	}
	return last.Int64, nil
}

var selectFields = []string{
	"id",
	"sig_public_key",
	"recipient",
	"chat_id",
	"content_type",
	"message_type",
	"text",
	"clock",
	"timestamp",
	"content_chat_id",
	"content_text",
}

// Messages returns messages for a given contact, in a given period.
// Ordered by a timestamp. ChatID is optional.
// TODO: implement flags to get only unread messages.
// TODO: implement pagination.
func (db sqlitePersistence) Messages(from, to time.Time) ([]*Message, error) {
	q := fmt.Sprintf(
		`SELECT
			%s
		FROM user_messages
		WHERE
			timestamp >= ? AND timestamp < ?`,
		strings.Join(selectFields, ", "),
	)
	args := []interface{}{
		protocol.TimestampInMsFromTime(from),
		protocol.TimestampInMsFromTime(to),
	}
	rows, err := db.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*Message

	for rows.Next() {
		var (
			m                 Message
			protocolMessage   protocol.Message
			sigPublicKeyBytes []byte
			recipientBytes    []byte
		)
		if err := rows.Scan(
			&m.id,
			&sigPublicKeyBytes,
			&recipientBytes,
			&m.chatID,
			&protocolMessage.ContentT,
			&protocolMessage.MessageT,
			&protocolMessage.Text,
			&protocolMessage.Clock,
			&protocolMessage.Timestamp,
			&protocolMessage.Content.ChatID,
			&protocolMessage.Content.Text,
		); err != nil {
			return nil, err
		}

		protocolMessage.ID = m.id

		m.sigPubKey, err = crypto.UnmarshalPubkey(sigPublicKeyBytes)
		if err != nil {
			return nil, err
		}

		if len(recipientBytes) > 0 {
			m.recipient, err = crypto.UnmarshalPubkey(recipientBytes)
			if err != nil {
				return nil, err
			}
		}

		result = append(result, &m)
	}

	return result, nil
}

var insertFields = []string{
	"id",
	"sig_public_key",
	"recipient",
	"chat_id",
	"content_type",
	"message_type",
	"text",
	"clock",
	"timestamp",
	"content_chat_id",
	"content_text",
	// "flags", // TODO: add support
}

func insertValues(m *Message) ([]interface{}, error) {
	var recipientBytes []byte
	if m.recipient != nil {
		recipientBytes = crypto.FromECDSAPub(m.recipient)
	}

	protocolMessage, ok := m.Interface().(protocol.Message)
	if !ok {
		return nil, errors.New("message does not contain a supported protocol message")
	}

	return []interface{}{
		m.ProtocolID(),
		crypto.FromECDSAPub(m.SigPubKey()),
		recipientBytes,
		m.ChatID(),
		protocolMessage.ContentT,
		protocolMessage.MessageT,
		protocolMessage.Text,
		m.Clock(),
		m.Timestamp(),
		protocolMessage.Content.ChatID,
		protocolMessage.Content.Text,
	}, nil
}

func (db sqlitePersistence) SaveMessages(messages ...*Message) (err error) {
	tx, err := db.db.BeginTx(context.Background(), &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	stmt, err := tx.Prepare(
		fmt.Sprintf(
			`INSERT INTO user_messages(%s) VALUES (%s)`,
			strings.Join(insertFields, ", "),
			strings.Repeat("?, ", len(insertFields)-1)+"?",
		),
	)
	if err != nil {
		return err
	}

	for _, m := range messages {
		if !m.IsUserMessage() {
			return errors.New("not a user message")
		}

		args, err := insertValues(m)
		if err != nil {
			return err
		}
		if _, err := stmt.Exec(args...); err != nil {
			return err
		}
	}

	return
}
