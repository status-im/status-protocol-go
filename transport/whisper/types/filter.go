package whispertypes

import (
	"crypto/ecdsa"
)

// Filter represents a Whisper message filter
type Filter interface {
	KeyAsym() *ecdsa.PrivateKey // Private Key of recipient
	KeySym() []byte             // Key associated with the Topic
}
