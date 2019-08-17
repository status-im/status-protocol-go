package statusproto

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

func formatChatID(chatID string, chatType ChatType) string {
	return fmt.Sprintf("%s-%d", chatID, chatType)
}

func (db sqlitePersistence) SaveChat(chat Chat) error {
	var err error
	// We build the db chatID using the type, so that we have no clashes
	chatID := formatChatID(chat.ID, chat.ChatType)

	pkey := []byte{}
	// For one to one chatID is an encoded public key
	if chat.ChatType == ChatTypeOneToOne {
		pkey, err = hex.DecodeString(chat.ID[2:])
		if err != nil {
			return err
		}
		// Safety check, make sure is well formed
		_, err := crypto.UnmarshalPubkey(pkey)
		if err != nil {
			return err
		}

	}

	// Encode members
	var encodedMembers bytes.Buffer
	memberEncoder := gob.NewEncoder(&encodedMembers)

	if err := memberEncoder.Encode(chat.Members); err != nil {
		return err
	}

	// Encode membership updates
	var encodedMembershipUpdates bytes.Buffer
	membershipUpdatesEncoder := gob.NewEncoder(&encodedMembershipUpdates)

	if err := membershipUpdatesEncoder.Encode(chat.MembershipUpdates); err != nil {
		return err
	}

	// Insert record
	stmt, err := db.db.Prepare(`INSERT INTO chats(id, name, color, active, type, timestamp,  deleted_at_clock_value, public_key, unviewed_message_count, last_clock_value, last_message_content_type, last_message_content, members, membership_updates)
	    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(
		chatID,
		chat.Name,
		chat.Color,
		chat.Active,
		chat.ChatType,
		chat.Timestamp,
		chat.DeletedAtClockValue,
		pkey,
		chat.UnviewedMessagesCount,
		chat.LastClockValue,
		chat.LastMessageContentType,
		chat.LastMessageContent,
		encodedMembers.Bytes(),
		encodedMembershipUpdates.Bytes(),
	)
	if err != nil {
		return err
	}

	return err
}

func (db sqlitePersistence) DeleteChat(chatID string, chatType ChatType) error {
	dbChatID := formatChatID(chatID, chatType)
	_, err := db.db.Exec("DELETE FROM chats WHERE id = ?", dbChatID)
	return err
}

func (db sqlitePersistence) Chats(from, to int) ([]*Chat, error) {

	rows, err := db.db.Query(`SELECT
	id,
	name,
	color,
	active,
	type,
	timestamp,
	deleted_at_clock_value,
	public_key,
	unviewed_message_count,
	last_clock_value,
	last_message_content_type,
	last_message_content,
	members,
	membership_updates
	FROM chats
	ORDER BY chats.timestamp DESC LIMIT ? OFFSET ?`, to, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var response []*Chat

	for rows.Next() {
		chat := &Chat{}
		encodedMembers := []byte{}
		encodedMembershipUpdates := []byte{}
		pkey := []byte{}
		err := rows.Scan(
			&chat.ID,
			&chat.Name,
			&chat.Color,
			&chat.Active,
			&chat.ChatType,
			&chat.Timestamp,
			&chat.DeletedAtClockValue,
			&pkey,
			&chat.UnviewedMessagesCount,
			&chat.LastClockValue,
			&chat.LastMessageContentType,
			&chat.LastMessageContent,
			&encodedMembers,
			&encodedMembershipUpdates,
		)
		if err != nil {
			return nil, err
		}

		// Restore the backward compatible ID
		chat.ID = chat.ID[:len(chat.ID)-2]

		// Restore members
		membersDecoder := gob.NewDecoder(bytes.NewBuffer(encodedMembers))
		if err := membersDecoder.Decode(&chat.Members); err != nil {
			return nil, err
		}

		// Restore membership updates
		membershipUpdatesDecoder := gob.NewDecoder(bytes.NewBuffer(encodedMembershipUpdates))
		if err := membershipUpdatesDecoder.Decode(&chat.MembershipUpdates); err != nil {
			return nil, err
		}

		if len(pkey) != 0 {
			chat.PublicKey, err = crypto.UnmarshalPubkey(pkey)
			if err != nil {
				return nil, err
			}
		}
		response = append(response, chat)
	}

	return response, nil
}
