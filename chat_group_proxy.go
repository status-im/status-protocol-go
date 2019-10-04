package statusproto

import (
	protocol "github.com/status-im/status-protocol-go/v1"
)

func newProtocolGroupFromChat(chat *Chat) (*protocol.Group, error) {
	return protocol.NewGroup(chat.ID, chatToFlattenMembershipUpdate(chat))
}

func chatToFlattenMembershipUpdate(chat *Chat) []protocol.MembershipUpdateFlat {
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

func updateChatFromProtocolGroup(chat *Chat, g *protocol.Group) {
	// ID
	chat.ID = g.ChatID()

	// Name
	chat.Name = g.Name()

	// Members
	members := g.Members()
	admins := g.Admins()
	joined := g.Joined()
	chatMembers := make([]ChatMember, 0, len(members))
	for _, m := range members {
		chatMember := ChatMember{
			ID: m,
		}
		chatMember.Admin = stringSliceContains(admins, m)
		chatMember.Joined = stringSliceContains(joined, m)
		chatMembers = append(chatMembers, chatMember)
	}
	chat.Members = chatMembers

	// MembershipUpdates
	updates := g.Updates()
	membershipUpdates := make([]ChatMembershipUpdate, 0, len(updates))
	for _, update := range updates {
		membershipUpdate := ChatMembershipUpdate{
			Type:       update.Type,
			Name:       update.Name,
			ClockValue: uint64(update.ClockValue), // TODO: get rid of type casting
			Signature:  update.Signature,
			From:       update.From,
			Member:     update.Member,
			Members:    update.Members,
		}
		membershipUpdate.setID()
		membershipUpdates = append(membershipUpdates, membershipUpdate)
	}
	chat.MembershipUpdates = membershipUpdates
}

func stringSliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
