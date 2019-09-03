package nftableslib

import (
	"fmt"
	"math/rand"
	"net"
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

// IPAddrElement defines key:value of the element of the type nftables.TypeIPAddr
// if IPAddrElement is element of a basic set, then only Addr will be specified,
// if it is element of a map then either Port or AddrIP and if it is element of a vmap, then
// Verdict.
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
	DelSet(string) error
	GetSets() ([]*nftables.Set, error)
	GetSetElements(string) ([]nftables.SetElement, error)
	SetAddElements(string, []nftables.SetElement) error
	SetDelElements(string, []nftables.SetElement) error
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
	setInterval := false
	if attrs.KeyType == nftables.TypeIPAddr || attrs.KeyType == nftables.TypeIP6Addr {
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
	se := []nftables.SetElement{}
	if nfs.table.Family == nftables.TableFamilyIPv4 {
		se = append(se, nftables.SetElement{Key: net.ParseIP("0.0.0.0").To4(), IntervalEnd: true})
	} else {
		se = append(se, nftables.SetElement{Key: net.ParseIP("::").To16(), IntervalEnd: true})
	}
	se = append(se, elements...)
	if err = nfs.conn.AddSet(s, elements); err != nil {
		return nil, err
	}
	// Requesting Netfilter to programm it.
	if err := nfs.conn.Flush(); err != nil {
		return nil, err
	}
	nfs.Lock()
	defer nfs.Unlock()
	nfs.sets[attrs.Name] = s

	return s, nil
}

// Exist check if the set with name exists in the store and programmed on the host,
// if both checks succeed, true is returned, otherwise false is returned.
func (nfs *nfSets) Exist(name string) bool {
	nfs.Lock()
	_, ok := nfs.sets[name]
	nfs.Unlock()
	if !ok {
		return false
	}
	sets, err := nfs.GetSets()
	if err != nil {
		return false
	}
	for _, s := range sets {
		if s.Name == name {
			return true
		}
	}
	return false
}

func (nfs *nfSets) DelSet(name string) error {
	if nfs.Exist(name) {
		nfs.conn.DelSet(nfs.sets[name])
	}
	// Returning nil for either case, if set does not exist ot it  was successfully deleted
	return nil
}

// GetSets returns a slice programmed on the host for a specific table.
func (nfs *nfSets) GetSets() ([]*nftables.Set, error) {
	return nfs.conn.GetSets(nfs.table)
}

func (nfs *nfSets) GetSetElements(name string) ([]nftables.SetElement, error) {
	if nfs.Exist(name) {
		return nfs.conn.GetSetElements(nfs.sets[name])
	}
	return nil, fmt.Errorf("set %s does not exist", name)
}

func (nfs *nfSets) SetAddElements(name string, elements []nftables.SetElement) error {
	if nfs.Exist(name) {
		if err := nfs.conn.SetAddElements(nfs.sets[name], elements); err != nil {
			return err
		}
		if err := nfs.conn.Flush(); err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("set %s does not exist", name)
}

func (nfs *nfSets) SetDelElements(name string, elements []nftables.SetElement) error {
	if nfs.Exist(name) {
		set := nfs.sets[name]
		if err := nfs.conn.SetDeleteElements(set, elements); err != nil {
			return err
		}
		if err := nfs.conn.Flush(); err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("set %s does not exist", name)
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
func MakeIPAddrElement(input *IPAddrElement) ([]nftables.SetElement, error) {
	addr, err := NewIPAddr(input.Addr)
	if err != nil {
		return nil, err
	}

	// TODO Figure out if overlapping and possibility of collapsing needs to be checked.
	elements := buildElementRanges([]*IPAddr{addr})
	p := &elements[0]
	switch {
	case input.AddrIP != nil:
		valAddr, err := NewIPAddr(*input.AddrIP)
		if err != nil {
			return nil, err
		}
		// Checking that both key and value were of the same Family ether IPv4 or IPv6
		if addr.IsIPv6() {
			if !valAddr.IsIPv6() {
				return nil, fmt.Errorf("cannot mix ipv4 and ipv6 addresses in the same element")
			}
		}
		if !addr.IsIPv6() {
			if valAddr.IsIPv6() {
				return nil, fmt.Errorf("cannot mix ipv4 and ipv6 addresses in the same element")
			}
		}
		p.Val = valAddr.IP
	case input.Port != nil:
		p.Val = binaryutil.BigEndian.PutUint16(*input.Port)
	case input.Verdict != nil:
		p.VerdictData = input.Verdict
	}

	return elements, nil
}
