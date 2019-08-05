package statusproto

import (
	"github.com/pkg/errors"
	protocol "github.com/status-im/status-protocol-go/v1"
)

type Encoder interface {
	Encode(message interface{}) ([]byte, error)
	Decode([]byte) (interface{}, error)
}

type protocolV1Encoder struct{}

func (protocolV1Encoder) Encode(message interface{}) ([]byte, error) {
	switch v := message.(type) {
	case protocol.Message:
		return protocol.EncodeMessage(v)
	case protocol.PairMessage:
		return protocol.EncodePairMessage(v)
	default:
		return nil, errors.New("encode error: unknown message type")
	}
}

func (protocolV1Encoder) Decode(data []byte) (interface{}, error) {
	return protocol.DecodeMessage(data)
}
