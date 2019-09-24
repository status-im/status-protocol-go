package statusproto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testMembershipUpdateMessageBytes  = []byte(`["~#g5",["072ea460-84d3-53c5-9979-1ca36fb5d1020x0424a68f89ba5fcd5e0640c1e1f591d561fa4125ca4e2a43592bc4123eca10ce064e522c254bb83079ba404327f6eafc01ec90a1444331fe769d3f3a7f90b0dde1",["~#list",[["^ ","~:chat-id","072ea460-84d3-53c5-9979-1ca36fb5d1020x0424a68f89ba5fcd5e0640c1e1f591d561fa4125ca4e2a43592bc4123eca10ce064e522c254bb83079ba404327f6eafc01ec90a1444331fe769d3f3a7f90b0dde1","~:from","0x0424a68f89ba5fcd5e0640c1e1f591d561fa4125ca4e2a43592bc4123eca10ce064e522c254bb83079ba404327f6eafc01ec90a1444331fe769d3f3a7f90b0dde1","~:events",[["^ ","~:type","chat-created","~:name","thathata","~:clock-value",156897373998501],["^ ","^5","members-added","^7",156897373998502,"~:members",["~#set",["0x04aebe2bb01a988abe7d978662f21de7760486119876c680e5a559e38e086a2df6dad41c4e4d9079c03db3bced6cb70fca76afc5650e50ea19b81572046a813534"]]]],"~:signature","7fca3d614cf55bc6cdf9c17fd1e65d1688673322bf1f004c58c78e0927edefea3d1053bf6a9d2e058ae88079f588105dccf2a2f9f330f6035cd47c715ee5950601"]]],null]]`)
	testMembershipUpdateMessageStruct = MembershipUpdateMessage{
		ChatID: "072ea460-84d3-53c5-9979-1ca36fb5d1020x0424a68f89ba5fcd5e0640c1e1f591d561fa4125ca4e2a43592bc4123eca10ce064e522c254bb83079ba404327f6eafc01ec90a1444331fe769d3f3a7f90b0dde1",
		Updates: []MembershipUpdate{
			{
				ChatID:    "072ea460-84d3-53c5-9979-1ca36fb5d1020x0424a68f89ba5fcd5e0640c1e1f591d561fa4125ca4e2a43592bc4123eca10ce064e522c254bb83079ba404327f6eafc01ec90a1444331fe769d3f3a7f90b0dde1",
				Signature: "7fca3d614cf55bc6cdf9c17fd1e65d1688673322bf1f004c58c78e0927edefea3d1053bf6a9d2e058ae88079f588105dccf2a2f9f330f6035cd47c715ee5950601",
				From:      "0x0424a68f89ba5fcd5e0640c1e1f591d561fa4125ca4e2a43592bc4123eca10ce064e522c254bb83079ba404327f6eafc01ec90a1444331fe769d3f3a7f90b0dde1",
				Events: []MembershipUpdateEvent{
					{
						Type:       "chat-created",
						Name:       "thathata",
						ClockValue: 156897373998501,
					},
					{
						Type:       "members-added",
						Members:    []string{"0x04aebe2bb01a988abe7d978662f21de7760486119876c680e5a559e38e086a2df6dad41c4e4d9079c03db3bced6cb70fca76afc5650e50ea19b81572046a813534"},
						ClockValue: 156897373998502,
					},
				},
			},
		},
		Message: nil,
	}
)

func TestDecodeMembershipUpdateMessage(t *testing.T) {
	val, err := decodeTransitMessage(testMembershipUpdateMessageBytes)
	require.NoError(t, err)
	require.EqualValues(t, testMembershipUpdateMessageStruct, val)
}

func TestEncodeMembershipUpdateMessage(t *testing.T) {
	data, err := EncodeMembershipUpdateMessage(testMembershipUpdateMessageStruct)
	require.NoError(t, err)
	// Decode it back to a struct and compare. Comparing bytes is not an option because,
	// for example, map encoding is non-deterministic.
	val, err := decodeTransitMessage(data)
	require.NoError(t, err)
	require.EqualValues(t, testMembershipUpdateMessageStruct, val)
}
