package statusproto

import (
	"crypto/ecdsa"

	"github.com/status-im/status-protocol-go/applicationmetadata"

	protocol "github.com/status-im/status-protocol-go/v1"
)

type Wrapper interface {
	Wrap([]byte) ([]byte, error)
	Unwrap([]byte) (*applicationmetadata.Message, error)
}

type wrapperV1 struct {
	privateKey *ecdsa.PrivateKey
}

func (w wrapperV1) Wrap(data []byte) ([]byte, error) {
	return protocol.WrapMessageV1(data, w.privateKey)
}

func (wrapperV1) Unwrap(data []byte) (*applicationmetadata.Message, error) {
	return applicationmetadata.Unmarshal(data)
}
