package statusproto

import "crypto/ecdsa"

type Chat interface {
	ID() string
	PublicKey() *ecdsa.PublicKey
}
