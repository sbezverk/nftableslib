package nftableslib

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/google/nftables"
)

// ChainsInterface defines third level interface operating with nf chains
type ChainsInterface interface {
	Chains() ChainFuncs
}

// ChainPolicy defines type for chain policies
type ChainPolicy string

const (
	// ChainPolicyAccept defines "accept" chain policy
	ChainPolicyAccept ChainPolicy = "accept"
	// ChainPolicyDrop defines "drop" chain policy
	ChainPolicyDrop ChainPolicy = "drop"
)

// ChainAttributes defines attributes which can be apply to a chain of BASE type
type ChainAttributes struct {
	Type     nftables.ChainType
	Hook     nftables.ChainHook
	Priority nftables.ChainPriority
	Device   string
	Policy   ChainPolicy
}

// Validate validate attributes passed for a base chain creation
func (cha *ChainAttributes) Validate() error {
	if cha.Type == "" {
		return fmt.Errorf("base chain must have type set")
	}
	// TODO Add additional attributes validation

	return nil
}

// ChainFuncs defines funcations to operate with chains
type ChainFuncs interface {
	Chain(name string) (RulesInterface, error)
	Create(name string, attributes *ChainAttributes) error
	CreateImm(name string, attributes *ChainAttributes) error
	Delete(name string) error
	DeleteImm(name string) error
	Dump() ([]byte, error)
	// TODO figure out what other methods are needed and them
}

type nfChains struct {
	conn  NetNS
	table *nftables.Table
	sync.Mutex
	chains map[string]*nfChain
}

type nfChain struct {
	baseChain bool
	chain     *nftables.Chain
	RulesInterface
}

// Chain return Rules Interface for a specified chain
func (nfc *nfChains) Chain(name string) (RulesInterface, error) {
	nfc.Lock()
	defer nfc.Unlock()
	// Check if nf table with the same family type and name  already exists
	if c, ok := nfc.chains[name]; ok {
		return c.RulesInterface, nil

	}
	return nil, fmt.Errorf("chain %s does not exist", name)
}

// Chains return a list of methods available for Chain operations
func (nfc *nfChains) Chains() ChainFuncs {
	return nfc
}

func (nfc *nfChains) Create(name string, attributes *ChainAttributes) error {
	nfc.Lock()
	defer nfc.Unlock()
	if _, ok := nfc.chains[name]; ok {
		return fmt.Errorf("chain %s already exist in table %s", name, nfc.table.Name)
	}
	var baseChain bool
	var c *nftables.Chain
	if attributes != nil {
		if err := attributes.Validate(); err != nil {
			return err
		}
		baseChain = true
		c = nfc.conn.AddChain(&nftables.Chain{
			Name:     name,
			Hooknum:  attributes.Hook,
			Priority: attributes.Priority,
			Table:    nfc.table,
			Type:     attributes.Type,
		})
	} else {
		baseChain = false
		c = nfc.conn.AddChain(&nftables.Chain{
			Name:  name,
			Table: nfc.table,
		})
	}
	nfc.chains[name] = &nfChain{
		chain:          c,
		baseChain:      baseChain,
		RulesInterface: newRules(nfc.conn, nfc.table, c),
	}

	return nil
}

func (nfc *nfChains) CreateImm(name string, attributes *ChainAttributes) error {
	if err := nfc.Create(name, attributes); err != nil {
		return err
	}

	return nfc.conn.Flush()
}

func (nfc *nfChains) Delete(name string) error {
	nfc.Lock()
	defer nfc.Unlock()
	if ch, ok := nfc.chains[name]; ok {
		nfc.conn.DelChain(ch.chain)
		delete(nfc.chains, name)
	}

	return nil
}

func (nfc *nfChains) DeleteImm(name string) error {
	if err := nfc.Delete(name); err != nil {
		return err
	}

	return nfc.conn.Flush()
}

func (nfc *nfChains) Dump() ([]byte, error) {
	nfc.Lock()
	defer nfc.Unlock()
	var data []byte

	for _, c := range nfc.chains {
		if b, err := json.Marshal(&c.chain); err != nil {
			return nil, err
		} else {
			data = append(data, b...)
		}
		if b, err := c.Rules().Dump(); err != nil {
			return nil, err
		} else {
			data = append(data, b...)
		}
	}

	return data, nil
}

func newChains(conn NetNS, t *nftables.Table) ChainsInterface {
	return &nfChains{
		conn:   conn,
		table:  t,
		chains: make(map[string]*nfChain),
	}
}
