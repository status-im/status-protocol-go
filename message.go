package statusproto

import (
	"database/sql/driver"
	"encoding/json"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/ast"
	"github.com/pkg/errors"
	"github.com/status-im/status-protocol-go/protobuf"
	statusproto "github.com/status-im/status-protocol-go/types"
	sendmessage "github.com/status-im/status-protocol-go/v1"
	"strings"
	"unicode"
	"unicode/utf8"
)

type hexutilSQL statusproto.HexBytes

func (h hexutilSQL) Value() (driver.Value, error) {
	return []byte(h), nil
}

func (h hexutilSQL) String() string {
	return statusproto.EncodeHex(h)
}

func (h *hexutilSQL) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	if b, ok := value.([]byte); ok {
		*h = hexutilSQL(b)
		return nil
	}
	return errors.New("failed to scan hexutilSQL")
}

// QuotedMessage contains the original text of the message replied to
type QuotedMessage struct {
	// From is a public key of the author of the message.
	From    string `json:"from"`
	Content string `json:"content"`
}

// Message represents a message record in the database,
// more specifically in user_messages_legacy table.
// Encoding and decoding of byte blobs should be performed
// using hexutil package.
type Message struct {
	*sendmessage.Message

	// ID calculated as keccak256(compressedAuthorPubKey, data) where data is unencrypted payload.
	ID string `json:"id"`
	// WhisperTimestamp is a timestamp of a Whisper envelope.
	WhisperTimestamp uint64 `json:"whisperTimestamp"`
	// From is a public key of the author of the message.
	From string `json:"from"`
	// Random 3 words name
	Alias string `json:"alias"`
	// Identicon of the author
	Identicon string `json:"identicon"`
	// To is a public key of the recipient unless it's a public message then it's empty.
	To hexutilSQL `json:"to,omitempty"`

	RetryCount     int    `json:"retryCount"`
	Seen           bool   `json:"seen"`
	OutgoingStatus string `json:"outgoingStatus,omitempty"`

	QuotedMessage *QuotedMessage `json:"quotedMessage"`

	// Computed fields
	RTL        bool     `json:"rtl"`
	ParsedText ast.Node `json:"parsedText"`
	LineCount  int      `json:"lineCount"`
}

func (m *Message) MarshalJSON() ([]byte, error) {
	type MessageAlias Message
	item := struct {
		*MessageAlias
		ChatId      string                           `json:"chatId"`
		ResponseTo  string                           `json:"responseTo"`
		EnsName     string                           `json:"ensName"`
		Sticker     *protobuf.StickerMessage         `json:"sticker"`
		ContentType protobuf.ChatMessage_ContentType `json:"contentType"`
	}{
		MessageAlias: (*MessageAlias)(m),
		ChatId:       m.ChatId,
		ResponseTo:   m.ResponseTo,
		EnsName:      m.EnsName,
		Sticker:      m.GetSticker(),
		ContentType:  m.ContentType,
	}

	return json.Marshal(item)
}

// Check if the first character is Hebrew or Arabic or the RTL character
func isRTL(s string) bool {
	first, _ := utf8.DecodeRuneInString(s)
	return unicode.Is(unicode.Hebrew, first) ||
		unicode.Is(unicode.Arabic, first) ||
		// RTL character
		first == '\u200f'
}

// PrepareContent return the parsed content of the message, the line-count and whether
// is a right-to-left message
func (m *Message) PrepareContent() {
	m.ParsedText = markdown.Parse([]byte(m.Text), nil)
	m.LineCount = strings.Count(m.Text, "\n")
	m.RTL = isRTL(m.Text)
}
