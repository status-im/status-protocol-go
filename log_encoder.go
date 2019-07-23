package statusproto

import (
	"encoding/hex"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type jsonHexEncoder struct {
	zapcore.Encoder
}

func NewJSONHexEncoder(cfg zapcore.EncoderConfig) zapcore.Encoder {
	jsonEncoder := zapcore.NewJSONEncoder(cfg)
	return &jsonHexEncoder{
		Encoder: jsonEncoder,
	}
}

func (enc *jsonHexEncoder) AddBinary(key string, val []byte) {
	enc.AddString(key, "0x"+hex.EncodeToString(val))
}

func registerJSONHexEncoder() error {
	return zap.RegisterEncoder("json-hex", func(cfg zapcore.EncoderConfig) (zapcore.Encoder, error) {
		return NewJSONHexEncoder(cfg), nil
	})
}
