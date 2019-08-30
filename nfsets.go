package nftableslib

import (
	"bytes"
	"fmt"
	"math/rand"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// SetAttributes  defines parameters of a nftables Set
type SetAttributes struct {
	Name     string
	Constant bool
	IsMap    bool
	KeyType  nftables.SetDatatype
	DataType nftables.SetDatatype
}

type IPAddrElement struct {
	Addr    string
	Port    *uint16
	AddrIP  *string
	Verdict *expr.Verdict
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
	var fe []nftables.SetElement
	// TODO Add parameters validation
	setInterval := false
	fe = elements
	if attrs.KeyType == nftables.TypeIPAddr || attrs.KeyType == nftables.TypeIP6Addr {
		// Since Key type is IPv4 or IPv6 address, the final elements needs to be processed
		// to support IPv4/IPv6 ranges.

		// Add processing here and then assign fe, new processed set of elements
		fe = elements
		setInterval = true
	}
	s := &nftables.Set{
		Table:     nfs.table,
		ID:        uint32(rand.Intn(0xffff)),
		Name:      attrs.Name,
		Anonymous: false,
		Constant:  attrs.Constant,
		Interval:  setInterval,
		IsMap:     attrs.IsMap,
		KeyType:   attrs.KeyType,
		DataType:  attrs.DataType,
	}
	// Adding to new Set, provided elements if any provided
	if err = nfs.conn.AddSet(s, fe); err != nil {
		return nil, err
	}
	// Requesting Netfilter to programm it.
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

// MakeIPAddrElement creates a list of Elements for IPv4 or IPv6 address, slice of IPAddrElement
// carries IP address which will be used as a key in the element, and 3 possible values depending on the
// type of a set. Value could be IP address as a string, Port as uint16 and a nftables.Verdict
// For IPv4 addresses ipv4 bool should be set to true, otherwise IPv6 addresses are expected.
func MakeIPAddrElement(input []*IPAddrElement, ipv4 bool) ([]nftables.SetElement, error) {
	var addrs []*IPAddr
	var orgElements []nftables.SetElement
	for _, i := range input {
		addr, err := NewIPAddr(i.Addr)
		if err != nil {
			return nil, err
		}
		if ipv4 {
			if addr.IsIPv6() {
				return nil, fmt.Errorf("cannot mix ipv4 and ipv6 addresses in the same set")
			}
		} else {
			if !addr.IsIPv6() {
				return nil, fmt.Errorf("cannot mix ipv4 and ipv6 addresses in the same set")
			}
		}
		addrs = append(addrs, addr)
		s := nftables.SetElement{
			Key: addr.IP,
		}
		switch {
		case i.AddrIP != nil:
			valAddr, err := NewIPAddr(*i.AddrIP)
			if err != nil {
				return nil, err
			}
			if valAddr.IsIPv6() {
				return nil, fmt.Errorf("cannot mix ipv4 and ipv6 addresses in the same set")
			}
			s.Val = valAddr.IP
		case i.Port != nil:
			s.Val = binaryutil.BigEndian.PutUint16(*i.Port)
		case i.Verdict != nil:
			s.VerdictData = i.Verdict
		}
		orgElements = append(orgElements, s)
	}
	elements := buildElementRanges(addrs)
	for i := 0; i < len(elements); i++ {
		for j := 0; j < len(orgElements); j++ {
			if bytes.Compare(elements[i].Key, orgElements[j].Key) == 0 {
				p := &elements[i]
				p.Val = orgElements[j].Val
				p.VerdictData = orgElements[j].VerdictData
			}
		}
	}

	return elements, nil
}
