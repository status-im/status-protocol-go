package statusproto

import "crypto/ecdsa"

type Chat interface {
	ID() []byte
	PublicName() string
	PublicKey() *ecdsa.PublicKey
}
