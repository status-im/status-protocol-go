package gethbridge

import (
	"github.com/ethereum/go-ethereum/node"
	gethens "github.com/status-im/status-eth-node/bridge/geth/ens"
	"github.com/status-im/status-eth-node/types"
	enstypes "github.com/status-im/status-eth-node/types/ens"
	whisper "github.com/status-im/whisper/whisperv6"
	"go.uber.org/zap"
)

type gethNodeWrapper struct {
	stack *node.Node
}

func NewNodeBridge(stack *node.Node) types.Node {
	return &gethNodeWrapper{stack: stack}
}

func (w *gethNodeWrapper) NewENSVerifier(logger *zap.Logger) enstypes.ENSVerifier {
	return gethens.NewVerifier(logger)
}

func (w *gethNodeWrapper) NewWhisper() (types.Whisper, error) {
	var nativeWhisper *whisper.Whisper
	err := w.stack.Service(&nativeWhisper)
	if err != nil {
		return nil, err
	}
	if nativeWhisper == nil {
		panic("Whisper service is not available")
	}

	return NewGethWhisperWrapper(nativeWhisper), nil
}
