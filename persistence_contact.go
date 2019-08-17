package statusproto

import (
	"bytes"
	"encoding/gob"
)

func (db sqlitePersistence) Contacts() ([]*Contact, error) {
	rows, err := db.db.Query(`SELECT
	id,
	address,
	name,
	photo,
	last_updated,
	system_tags,
	device_info,
	tribute_to_talk
	FROM contacts`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var response []*Contact

	for rows.Next() {
		contact := &Contact{}
		encodedDeviceInfo := []byte{}
		encodedSystemTags := []byte{}
		err := rows.Scan(
			&contact.ID,
			&contact.Address,
			&contact.Name,
			&contact.Photo,
			&contact.LastUpdated,
			&encodedSystemTags,
			&encodedDeviceInfo,
			&contact.TributeToTalk,
		)
		if err != nil {
			return nil, err
		}

		// Restore device info
		deviceInfoDecoder := gob.NewDecoder(bytes.NewBuffer(encodedDeviceInfo))
		if err := deviceInfoDecoder.Decode(&contact.DeviceInfo); err != nil {
			return nil, err
		}

		// Restore system tags
		systemTagsDecoder := gob.NewDecoder(bytes.NewBuffer(encodedSystemTags))
		if err := systemTagsDecoder.Decode(&contact.SystemTags); err != nil {
			return nil, err
		}

		response = append(response, contact)
	}

	return response, nil
}

func (db sqlitePersistence) SaveContact(contact Contact) error {
	// Encode device info
	var encodedDeviceInfo bytes.Buffer
	deviceInfoEncoder := gob.NewEncoder(&encodedDeviceInfo)

	if err := deviceInfoEncoder.Encode(contact.DeviceInfo); err != nil {
		return err
	}

	// Encoded system tags
	var encodedSystemTags bytes.Buffer
	systemTagsEncoder := gob.NewEncoder(&encodedSystemTags)

	if err := systemTagsEncoder.Encode(contact.SystemTags); err != nil {
		return err
	}

	// Insert record
	stmt, err := db.db.Prepare(`INSERT INTO contacts(
	  id,
	  address,
	  name,
	  photo,
	  last_updated,
	  system_tags,
	  device_info,
	  tribute_to_talk
	)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(
		contact.ID,
		contact.Address,
		contact.Name,
		contact.Photo,
		contact.LastUpdated,
		encodedSystemTags.Bytes(),
		encodedDeviceInfo.Bytes(),
		contact.TributeToTalk,
	)
	return err
}
