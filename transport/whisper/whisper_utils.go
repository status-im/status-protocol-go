package whisper

import (
	"github.com/ethereum/go-ethereum/crypto"
	shh "github.com/status-im/whisper/whisperv6"
)

var discoveryTopic = "contact-discovery"
var DiscoveryTopicBytes = ToTopic(discoveryTopic)

func ToTopic(s string) shh.TopicType {
	return shh.BytesToTopic(crypto.Keccak256([]byte(s)))
}

func DefaultWhisperMessage() shh.NewMessage {
	msg := shh.NewMessage{}

	msg.TTL = 10
	msg.PowTarget = 0.002
	msg.PowTime = 1

	return msg
}
