package statusproto

import (
	"crypto/ecdsa"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/status-im/status-protocol-go/encryption"
)

type Encryptor interface {
	Encrypt(recipientKey *ecdsa.PublicKey, data []byte) ([]byte, encryptionMeta, error)
	Decrypt(senderKey *ecdsa.PublicKey, messageID []byte, data []byte) ([]byte, error)
}

type protocolEncryptor struct {
	encryptionProtocol *encryption.Protocol
	privateKey         *ecdsa.PrivateKey
}

func (e *protocolEncryptor) Encrypt(recipientKey *ecdsa.PublicKey, data []byte) ([]byte, encryptionMeta, error) {
	var (
		err  error
		meta encryptionMeta
		spec *encryption.ProtocolMessageSpec
	)

	if recipientKey != nil && len(data) > 0 {
		spec, err = e.encryptionProtocol.BuildDirectMessage(e.privateKey, recipientKey, data)
	} else if recipientKey != nil && len(data) == 0 {
		spec, err = e.encryptionProtocol.BuildBundleAdvertiseMessage(e.privateKey, recipientKey)
	} else if recipientKey == nil {
		spec, err = e.encryptionProtocol.BuildPublicMessage(e.privateKey, data)
	} else {
		err = errors.New("encryptor: invalid arguments to encrypt")
	}
	if err != nil {
		return nil, meta, err
	}

	payload, err := proto.Marshal(spec.Message)
	if err != nil {
		return nil, meta, err
	}
	return payload, encryptionMeta{spec: spec}, nil
}

// TODO: get rid of messageID which should be calculated by the encryption package based on the other arguments.
func (e *protocolEncryptor) Decrypt(senderKey *ecdsa.PublicKey, messageID []byte, data []byte) ([]byte, error) {
	var protocolMessage encryption.ProtocolMessage
	err := proto.Unmarshal(data, &protocolMessage)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal ProtocolMessage")
	}

	payload, err := e.encryptionProtocol.HandleMessage(
		e.privateKey,
		senderKey,
		&protocolMessage,
		messageID,
	)
	if err != nil {
		err = errors.Wrap(err, "failed to handle Encryption message")
	}
	return payload, err
}
