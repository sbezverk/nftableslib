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
	Add()
}

type nfChains struct {
	tableName string
	tableType nftables.TableFamily
	sync.Mutex
	chains map[string]*nftables.Chain
}

func (nfc *nfChains) Chains() ChainFuncs {
	return nfc
}

func (nfc *nfChains) Add() {
}

func newChains(name string, familyType nftables.TableFamily) ChainsInterface {
	return &nfChains{
		tableName: name,
		tableType: familyType,
		chains:    make(map[string]*nftables.Chain),
	}
}
