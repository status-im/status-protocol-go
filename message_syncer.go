package statusproto

import (
	"crypto/ecdsa"

	"github.com/pkg/errors"
	"github.com/status-im/status-protocol-go/datasync"
	datasyncpeer "github.com/status-im/status-protocol-go/datasync/peer"
)

type Syncer interface {
	Sync(recipeintKey *ecdsa.PublicKey, data []byte) error
	Desync(senderKey *ecdsa.PublicKey, data []byte) [][]byte
}

type dataSyncer struct {
	datasync   *datasync.DataSync
	privateKey *ecdsa.PrivateKey
}

func (s *dataSyncer) Sync(recipientKey *ecdsa.PublicKey, data []byte) error {
	groupID := datasync.ToOneToOneGroupID(&s.privateKey.PublicKey, recipientKey)
	peerID := datasyncpeer.PublicKeyToPeerID(*recipientKey)
	exist, err := s.datasync.IsPeerInGroup(groupID, peerID)
	if err != nil {
		return errors.Wrap(err, "failed to check if peer is in group")
	}
	if !exist {
		if err := s.datasync.AddPeer(groupID, peerID); err != nil {
			return errors.Wrap(err, "failed to add peer")
		}
	}
	_, err = s.datasync.AppendMessage(groupID, data)
	if err != nil {
		return errors.Wrap(err, "failed to append message to datasync")
	}
	return nil
}

func (s *dataSyncer) Desync(senderKey *ecdsa.PublicKey, data []byte) [][]byte {
	return s.datasync.Handle(senderKey, data)
}
