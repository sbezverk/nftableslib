package nftableslib

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// RulesInterface defines third level interface operating with nf Rules
type RulesInterface interface {
	Rules() RuleFuncs
}

// RuleFuncs defines funcations to operate with Rules
type RuleFuncs interface {
	Create(string, *Rule) error
	Dump() ([]byte, error)
}

type nfRules struct {
	conn  NetNS
	table *nftables.Table
	chain *nftables.Chain
	sync.Mutex
	rules map[string]*nfRule
}

type nfRule struct {
	rule *nftables.Rule
	set  *nftables.Set
}

func (nfr *nfRules) Rules() RuleFuncs {
	return nfr
}

func (nfr *nfRules) Create(name string, rule *Rule) error {
	// Validating passed rule parameters
	if err := rule.Validate(); err != nil {
		return err
	}
	set := nftables.Set{
		Anonymous: false,
		Constant:  true,
		Name:      name,
		ID:        uint32(rand.Intn(0xffff)),
		KeyType:   nftables.TypeInetService,
		Table:     nfr.table,
	}
	var r *nftables.Rule
	var se []nftables.SetElement
	var err error
	if rule.L3 != nil {
		r, se, err = createL3(nfr.table.Family, rule.L3, set)
	}
	if rule.L4 != nil {
		r, se, err = createL4(rule.L4, set)
	}
	if err != nil {
		return err
	}
	r.Table = nfr.table
	r.Chain = nfr.chain

	nfr.Lock()
	defer nfr.Unlock()
	if _, ok := nfr.rules[name]; ok {
		delete(nfr.rules, name)
	}
	if len(se) != 0 {
		nfr.conn.AddSet(&set, se)
	}
	nfr.conn.AddRule(r)
	nfr.rules[name] = &nfRule{
		rule: r,
		set:  &set,
	}

	return nil
}

func (nfr *nfRules) Dump() ([]byte, error) {
	nfr.Lock()
	defer nfr.Unlock()
	var data []byte

	for _, r := range nfr.rules {
		b, err := json.Marshal(&r)
		if err != nil {
			return nil, err
		}
		data = append(data, b...)
	}

	return data, nil
}

func newRules(conn NetNS, t *nftables.Table, c *nftables.Chain) RulesInterface {
	return &nfRules{
		conn:  conn,
		table: t,
		chain: c,
		rules: make(map[string]*nfRule),
	}
}

// IPAddr defines a type of ip address, if it is host address with mask of 32 for ipv4 and mask of 128 for ipv6
// then CIDR should be false, if it is a network address, then CIDR should be true and Mask set to a number of bits
// in the address' mask. Mask value is from 0 to 32 for ipv4 and from 0 to 128 for ipv6 addresses.
type IPAddr struct {
	*net.IPAddr
	CIDR bool
	Mask *uint8
}

// Validate checks validity of ip address and its parameters
func (ip *IPAddr) Validate() error {
	// If CIDR is not specified, there is nothing to validate
	if !ip.CIDR {
		return nil
	}
	if ip.CIDR && ip.Mask == nil {
		return fmt.Errorf("mask length must be specified when CIDR is true")
	}
	return nil
}

// IPAddrSpec lists possible flavours if specifying ip address, either List or Range can be specified
type IPAddrSpec struct {
	List  []*IPAddr
	Range [2]*IPAddr
}

// Validate checks IPAddrSpec struct
func (ip *IPAddrSpec) Validate() error {
	if len(ip.List) != 0 && (ip.Range[0] != nil || ip.Range[1] != nil) {
		return fmt.Errorf("either List or Range but not both can be specified")
	}
	if len(ip.List) == 0 && (ip.Range[0] == nil || ip.Range[1] == nil) {
		return fmt.Errorf("neither List nor Range is specified")
	}
	if len(ip.List) != 0 {
		for i := 0; i < len(ip.List); i++ {
			fmt.Printf("i: %d ip: %+v\n", i, ip.List[i])
			if err := ip.List[i].Validate(); err != nil {
				return err
			}
		}
	}
	if ip.Range[0] != nil && ip.Range[1] != nil {
		for i := 0; i < len(ip.Range); i++ {
			fmt.Printf("i: %d ip: %+v\n", i, ip.Range[i])
			if err := ip.Range[i].Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

// L3Rule contains parameters for L3 based rule, either Source or Destination can be specified
type L3Rule struct {
	Src     *IPAddrSpec
	Dst     *IPAddrSpec
	Exclude bool
	Verdict *expr.Verdict
}

// Validate checks parameters of L3Rule struct
func (l3 *L3Rule) Validate() error {
	if l3.Src != nil && l3.Dst != nil {
		return fmt.Errorf("either L3 Src or L3 Dst but not both can be specified")
	}
	if l3.Src == nil && l3.Dst == nil {
		return fmt.Errorf("neither L3 Src nor L3 is specified")
	}
	if l3.Verdict == nil {
		return fmt.Errorf("L3 does not have Verdict specified")
	}
	if l3.Src != nil {
		if err := l3.Src.Validate(); err != nil {
			return err
		}
	}
	if l3.Dst != nil {
		if err := l3.Dst.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Port lists possible flavours of specifying port information
type Port struct {
	List  []*uint32
	Range [2]*uint32
}

// Validate check parameters of Port struct
func (p *Port) Validate() error {
	if len(p.List) != 0 && (p.Range[0] != nil || p.Range[1] != nil) {
		return fmt.Errorf("either List or Range but not both can be specified")
	}
	if len(p.List) == 0 && (p.Range[0] == nil || p.Range[1] == nil) {
		return fmt.Errorf("neither List nor Range is specified")
	}

	return nil
}

// L4Rule contains parameters for L4 based rule
type L4Rule struct {
	L4Proto int
	Src     *Port
	Dst     *Port
	// TODO Does validation needed for Exclude?
	Exclude  bool
	Redirect *uint32
	Verdict  *expr.Verdict
}

// Validate checks parameters of L4Rule struct
func (l4 *L4Rule) Validate() error {
	if l4.L4Proto == 0 {
		return fmt.Errorf("L4Proto cannot be 0")
	}
	if l4.Src != nil && l4.Dst != nil {
		return fmt.Errorf("either L3 Src or L3 Dst but not both can be specified")
	}
	if l4.Src == nil && l4.Dst == nil {
		return fmt.Errorf("neither L3 Src nor L3 is specified")
	}
	if l4.Src != nil {
		if err := l4.Src.Validate(); err != nil {
			return err
		}
	}
	if l4.Dst != nil {
		if err := l4.Dst.Validate(); err != nil {
			return err
		}
	}
	if l4.Redirect != nil && l4.Verdict != nil {
		return fmt.Errorf("either Verdict or Redirect but not both can be specified")
	}
	if l4.Redirect == nil && l4.Verdict == nil {
		return fmt.Errorf("neither Verdict nor Redirect is specified")
	}
	return nil
}

// Rule contains parameters for a rule to configure, only L3 OR L4 parameters can be specified
type Rule struct {
	L3 *L3Rule
	L4 *L4Rule
}

// Validate checks parameters passed in struct and returns error if inconsistency is found
func (r Rule) Validate() error {
	if r.L3 != nil && r.L4 != nil {
		return fmt.Errorf("either L3 or L4 but not both can be specified")
	}
	if r.L3 != nil {
		return r.L3.Validate()
	}
	if r.L4 != nil {
		return r.L4.Validate()
	}

	return fmt.Errorf("L3 or L4 parameters must be specified")
}
