package statusproto

import (
	"crypto/ecdsa"
	"fmt"
)

//go:generate stringer -type=ContactType

// ContactType defines a type of a contact.
type ContactType int

func (c ContactType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%d"`, c)), nil
}

func (c *ContactType) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case fmt.Sprintf(`"%s"`, ContactPublicRoom):
		*c = ContactPublicRoom
	case fmt.Sprintf(`"%s"`, ContactPrivate):
		*c = ContactPrivate
	default:
		return fmt.Errorf("invalid ContactType: %s", data)
	}

	return nil
}

// Types of contacts.
const (
	ContactPublicRoom ContactType = iota + 1
	ContactPrivate
)

// ContactState defines state of the contact.
type ContactState int

const (
	// ContactAdded default level. Added or confirmed by user.
	ContactAdded ContactState = iota + 1
	// ContactNew contact got connected to us and waits for being added or blocked.
	ContactNew
	// ContactBlocked means that all incoming messages from it will be discarded.
	ContactBlocked
)

// Contact is a single contact which has a type and name.
type Contact struct {
	Name      string           `json:"name"`
	Type      ContactType      `json:"type"`
	State     ContactState     `json:"state"`
	Topic     string           `json:"topic"`
	PublicKey *ecdsa.PublicKey `json:"-"`
}
