package statusproto

import (
	"crypto/ecdsa"

	"github.com/pkg/errors"
	whisper "github.com/status-im/whisper/whisperv6"

	"github.com/status-im/status-protocol-go/encryption"
	"github.com/status-im/status-protocol-go/encryption/multidevice"
	"github.com/status-im/status-protocol-go/encryption/sharedsecret"
	transport "github.com/status-im/status-protocol-go/transport/whisper"
)

// Messenger is a entity managing chats and messages.
// It acts as a bridge between the application and encryption
// layers.
type Messenger struct {
	adapter *whisperAdapter
}

type config struct {
	onAddedBundlesHandler    func([]*multidevice.Installation)
	onNewSharedSecretHandler func([]*sharedsecret.Secret)
}

type Option func (*config) error

func WithOnAddedBundlesHandler(h func([]*multidevice.Installation)) func(c *config) error {
	return func(c *config) error {
		c.onAddedBundlesHandler = h
		return nil
	}
}

func WithOnNewSharedSecret(h func([]*sharedsecret.Secret)) func(c *config) error {
	return func(c *config) error {
		c.onNewSharedSecretHandler = h
		return nil
	}
}

func NewMessenger(
	identity *ecdsa.PrivateKey,
	server transport.Server,
	shh *whisper.Whisper,
	dataDir string,
	dbKey string,
	installationID string,
	opts ...Option,
) (*Messenger, error) {
	var c config

	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return nil, err
		}
	}

	t, err := transport.NewWhisperServiceTransport(
		server,
		shh,
		identity,
		nil,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a WhisperServiceTransport")
	}

	p, err := encryption.New(
		dataDir,
		dbKey,
		installationID,
		c.onAddedBundlesHandler,
		c.onNewSharedSecretHandler,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create the encryption layer")
	}

	return &Messenger{
		adapter: newWhisperAdapter(identity, t, p),
	}, nil
}
