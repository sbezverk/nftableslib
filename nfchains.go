package nftableslib

import (
	"sync"

	"github.com/google/nftables"
)

// ChainsInterface defines third level interface operating with nf chains
type ChainsInterface interface {
	Chains() ChainFuncs
}

// ChainFuncs defines funcations to operate with chains
type ChainFuncs interface {
	Chain(name string) RulesInterface
	Create(name string, hookNum nftables.ChainHook, priority nftables.ChainPriority, chainType nftables.ChainType)
}

type nfChains struct {
	conn  *nftables.Conn
	table *nftables.Table
	sync.Mutex
	chains map[string]*nfChain
}

type nfChain struct {
	chainType nftables.ChainType
	chain     *nftables.Chain
	RulesInterface
}

func (nfc *nfChains) Chain(name string) RulesInterface {
	return nfc.chains[name].RulesInterface
}

func (nfc *nfChains) Chains() ChainFuncs {
	return nfc
}

func (nfc *nfChains) Create(name string, hookNum nftables.ChainHook, priority nftables.ChainPriority, chainType nftables.ChainType) {
	if _, ok := nfc.chains[name]; ok {
		delete(nfc.chains, name)
	}
	nfc.chains[name] = &nfChain{
		chain: nfc.conn.AddChain(&nftables.Chain{
			Name:     name,
			Hooknum:  hookNum,
			Priority: priority,
			Table:    nfc.table,
			Type:     chainType,
		}),
		chainType: chainType,
	}
}

func newChains(conn *nftables.Conn, t *nftables.Table) ChainsInterface {
	return &nfChains{
		conn:   conn,
		table:  t,
		chains: make(map[string]*nfChain),
	}
}
