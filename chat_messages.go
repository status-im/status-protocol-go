package statusproto

import protocol "github.com/status-im/status-protocol-go/v1"

// ChatMessages holds the retrieved messages for a given chat, as well as information about that chat
type ChatMessages struct {
	ChatID   string
	Public   bool
	Messages []*protocol.Message
}
