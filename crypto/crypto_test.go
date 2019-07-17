package crypto

import (
	"encoding/hex"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSymmetricEncryption(t *testing.T) {
	const rawKey = "0000000000000000000000000000000000000000000000000000000000000000"
	expectedPlaintext := []byte("test")
	key, err := hex.DecodeString(rawKey)
	require.Nil(t, err, "Key should be generated without errors")

	cyphertext1, err := EncryptSymmetric(key, expectedPlaintext)
	require.Nil(t, err, "Cyphertext should be generated without errors")

	cyphertext2, err := EncryptSymmetric(key, expectedPlaintext)
	require.Nil(t, err, "Cyphertext should be generated without errors")

	require.Equalf(
		t,
		32,
		len(cyphertext1),
		"Cyphertext with the correct length should be generated")

	require.NotEqualf(
		t,
		cyphertext1,
		cyphertext2,
		"Same plaintext should not be encrypted in the same way")

	plaintext, err := DecryptSymmetric(key, cyphertext1)
	require.Nil(t, err, "Cyphertext should be decrypted without errors")

	require.Equalf(
		t,
		expectedPlaintext,
		plaintext,
		"Cypther text should be decrypted successfully")
}
