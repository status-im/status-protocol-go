package statusproto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestJSONHexEncoder(t *testing.T) {
	encoder := NewJSONHexEncoder(zap.NewDevelopmentEncoderConfig())
	encoder.AddBinary("test-key", []byte{0x01, 0x02, 0x03})
	buf, err := encoder.EncodeEntry(zapcore.Entry{
		LoggerName: "",
		Time:       time.Now(),
		Level:      zapcore.DebugLevel,
		Message:    "",
	}, nil)
	require.NoError(t, err)
	require.Contains(t, buf.String(), `"test-key":"0x010203"`)
}
