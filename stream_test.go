package statusproto

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	protocol "github.com/status-im/status-protocol-go/v1"
)

func TestStreamHandlerForContact(t *testing.T) {
	db, err := initializeTmpDB()
	require.NoError(t, err)
	defer db.Close()

	contact := Contact{Name: "test", Type: ContactPublicRoom}
	handler := StreamStoreHandlerForContact(db, contact)
	msg := protocol.Message{
		ID: []byte{1},
	}

	require.NoError(t, handler(&msg))

	msgs, err := db.NewMessages(contact, 0)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.Equal(t, msg.ID, msgs[0].ID)
}

func TestPrivateStreamSavesNewContactsAndMessages(t *testing.T) {
	db, err := initializeTmpDB()
	require.NoError(t, err)
	defer db.Close()
	pkey, err := crypto.GenerateKey()
	require.NoError(t, err)
	handler := StreamStoreHandlerMultiplexed(db)
	msg := protocol.Message{
		ID:        []byte{1},
		SigPubKey: &pkey.PublicKey,
	}

	require.NoError(t, handler(&msg))

	// assert a new contact with proper state
	contacts, err := db.Contacts()
	require.NoError(t, err)
	require.Len(t, contacts, 1)
	require.Equal(t, &pkey.PublicKey, contacts[0].PublicKey)
	require.Equal(t, ContactNew, contacts[0].State)

	// aassert saved messages
	msgs, err := db.NewMessages(contacts[0], 0)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.Equal(t, &pkey.PublicKey, msgs[0].SigPubKey)
}
