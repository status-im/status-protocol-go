package statusproto

import (
	"crypto/ecdsa"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/status-im/status-protocol-go/encryption"
)

type Encryptor interface {
	Encrypt(recipientKey *ecdsa.PublicKey, data []byte) ([]byte, encryptionMeta, error)
}

type Decryptor interface {
	Decrypt(senderKey *ecdsa.PublicKey, messageID []byte, data []byte) ([]byte, error)
}

type privateEncryptor struct {
	encryptionProtocol *encryption.Protocol
	privateKey         *ecdsa.PrivateKey
}

func (e *privateEncryptor) Encrypt(recipientKey *ecdsa.PublicKey, data []byte) ([]byte, encryptionMeta, error) {
	var meta encryptionMeta

	spec, err := e.encryptionProtocol.BuildDirectMessage(e.privateKey, recipientKey, data)
	if err != nil {
		return nil, meta, err
	}

	payload, err := proto.Marshal(spec.Message)
	if err != nil {
		return nil, meta, err
	}
	return payload, encryptionMeta{spec: spec}, nil
}

type publicEncryptor struct {
	encryptionProtocol *encryption.Protocol
	privateKey         *ecdsa.PrivateKey
}

func (e *publicEncryptor) Encrypt(_ *ecdsa.PublicKey, data []byte) ([]byte, encryptionMeta, error) {
	var meta encryptionMeta

	spec, err := e.encryptionProtocol.BuildPublicMessage(e.privateKey, data)
	if err != nil {
		return nil, meta, err
	}

	payload, err := proto.Marshal(spec.Message)
	if err != nil {
		return nil, meta, err
	}
	return payload, encryptionMeta{spec: spec}, nil
}

type advertiseBundleEncryptor struct {
	encryptionProtocol *encryption.Protocol
	privateKey         *ecdsa.PrivateKey
}

func (e *advertiseBundleEncryptor) Encrypt(recipientKey *ecdsa.PublicKey, data []byte) ([]byte, encryptionMeta, error) {
	var meta encryptionMeta
	spec, err := e.encryptionProtocol.BuildBundleAdvertiseMessage(e.privateKey, recipientKey)
	payload, err := proto.Marshal(spec.Message)
	if err != nil {
		return nil, meta, err
	}
	return payload, encryptionMeta{spec: spec}, nil
}

type decryptor struct {
	encryptionProtocol *encryption.Protocol
	privateKey         *ecdsa.PrivateKey
}

// TODO: get rid of messageID which should be calculated by the encryption package based on the other arguments.
func (e *decryptor) Decrypt(senderKey *ecdsa.PublicKey, messageID []byte, data []byte) ([]byte, error) {
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
