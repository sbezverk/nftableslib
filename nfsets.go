package nftableslib

import (
	"math/rand"
	"sync"

	"github.com/google/nftables"
)

// SetAttributes  defines parameters of a nftables Set
type SetAttributes struct {
	Name     string
	Constant bool
	IsMap    bool
	KeyType  nftables.SetDatatype
	DataType nftables.SetDatatype
}

// SetsInterface defines third level interface operating with nf maps
type SetsInterface interface {
	Sets() SetFuncs
}

// SetFuncs defines funcations to operate with nftables Sets
type SetFuncs interface {
	CreateSet(*SetAttributes, []nftables.SetElement) (*nftables.Set, error)
	DelSet(*nftables.Set) error
	GetSets() ([]*nftables.Set, error)
	GetSetElements(*nftables.Set) ([]nftables.SetElement, error)
	SetAddElements(*nftables.Set, []nftables.SetElement) error
	SetDelElements(*nftables.Set, []nftables.SetElement) error
}

type nfSets struct {
	conn  NetNS
	table *nftables.Table
	sync.Mutex
	sets map[string]*nftables.Set
}

// Sets return a list of methods available for Sets operations
func (nfs *nfSets) Sets() SetFuncs {
	return nfs
}

func (nfs *nfSets) CreateSet(attrs *SetAttributes, elements []nftables.SetElement) (*nftables.Set, error) {
	var err error

	// TODO Add parameters validation

	s := &nftables.Set{
		Table:     nfs.table,
		ID:        uint32(rand.Intn(0xffff)),
		Name:      attrs.Name,
		Anonymous: false,
		Constant:  attrs.Constant,
		Interval:  false,
		IsMap:     attrs.IsMap,
		KeyType:   attrs.KeyType,
		DataType:  attrs.DataType,
	}

	if err = nfs.conn.AddSet(s, elements); err != nil {
		return nil, err
	}
	if err := nfs.conn.Flush(); err != nil {
		return nil, err
	}

	return s, nil
}

func (nfs *nfSets) DelSet(set *nftables.Set) error {
	nfs.conn.DelSet(set)
	if err := nfs.conn.Flush(); err != nil {
		return err
	}

	return nil
}

func (nfs *nfSets) GetSets() ([]*nftables.Set, error) {
	sets, err := nfs.conn.GetSets(nfs.table)
	if err != nil {
		return nil, err
	}
	if err := nfs.conn.Flush(); err != nil {
		return nil, err
	}

	return sets, nil
}

func (nfs *nfSets) GetSetElements(set *nftables.Set) ([]nftables.SetElement, error) {
	elements, err := nfs.conn.GetSetElements(set)
	if err != nil {
		return nil, err
	}
	if err := nfs.conn.Flush(); err != nil {
		return nil, err
	}

	return elements, nil
}

func (nfs *nfSets) SetAddElements(set *nftables.Set, elements []nftables.SetElement) error {
	if err := nfs.conn.SetAddElements(set, elements); err != nil {
		return err
	}
	if err := nfs.conn.Flush(); err != nil {
		return err
	}
	return nil
}

func (nfs *nfSets) SetDelElements(set *nftables.Set, elements []nftables.SetElement) error {
	if err := nfs.conn.SetDeleteElements(set, elements); err != nil {
		return err
	}
	if err := nfs.conn.Flush(); err != nil {
		return err
	}
	return nil
}

func newSets(conn NetNS, t *nftables.Table) SetsInterface {
	return &nfSets{
		conn:  conn,
		table: t,
		sets:  make(map[string]*nftables.Set),
	}
}
