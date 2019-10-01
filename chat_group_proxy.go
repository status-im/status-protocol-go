package statusproto

import (
	protocol "github.com/status-im/status-protocol-go/v1"
)

type chatGroupProxy struct {
	group *protocol.Group
	chat  Chat
}

func newChatGroupProxy(chat Chat) *chatGroupProxy {
	return &chatGroupProxy{
		group: protocol.NewGroup(chatToProtocolMembershipUpdate(chat)),
		chat:  chat,
	}
}

func chatToProtocolMembershipUpdate(chat Chat) []protocol.MembershipUpdateFlat {
	result := make([]protocol.MembershipUpdateFlat, len(chat.MembershipUpdates))
	for idx, update := range chat.MembershipUpdates {
		result[idx] = protocol.MembershipUpdateFlat{
			From:      update.From,
			Signature: update.Signature,
			MembershipUpdateEvent: protocol.MembershipUpdateEvent{
				Name:       update.Name,
				Type:       update.Type,
				ClockValue: int64(update.ClockValue), // TODO: remove type difference
				Member:     update.Member,
				Members:    update.Members,
			},
		}
	}
	return result
}
