package nftableslib

import (
	"encoding/json"
	"fmt"
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
	Create(string, []expr.Any, ...*nftables.SetElement) error
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

func (nfr *nfRules) Create(name string, ruleExpressions []expr.Any, elements ...*nftables.SetElement) error {
	nfr.Lock()
	defer nfr.Unlock()

	if _, ok := nfr.rules[name]; ok {
		delete(nfr.rules, name)
	}
	r := nftables.Rule{
		Table: nfr.table,
		Chain: nfr.chain,
		Exprs: ruleExpressions,
	}
	s := nftables.Set{
		Table:     nfr.table,
		Anonymous: true,
		Constant:  true,
		KeyType:   nftables.TypeInetService,
	}

	nfr.conn.AddRule(&r)
	nfr.rules[name] = &nfRule{
		rule: &r,
		set:  &s,
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

func (nfr *nfRule) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, '[')

	for i := 0; i < len(nfr.rule.Exprs); i++ {
		e, err := marshalExpression(nfr.rule.Exprs[i])
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, e...)
		if i < len(nfr.rule.Exprs)-1 {
			jsonData = append(jsonData, ',')
		}
	}
	jsonData = append(jsonData, ']')

	return jsonData, nil
}

func marshalExpression(exp expr.Any) ([]byte, error) {
	var b []byte

	if e, ok := exp.(*expr.Meta); ok {
		b = append(b, []byte("{\"Key\":")...)
		switch e.Key {
		case expr.MetaKeyLEN:
			b = append(b, []byte("\"expr.MetaKeyLEN\"")...)
		case expr.MetaKeyPROTOCOL:
			b = append(b, []byte("\"expr.MetaKeyPROTOCOL\"")...)
		case expr.MetaKeyPRIORITY:
			b = append(b, []byte("\"expr.MetaKeyPRIORITY\"")...)
		case expr.MetaKeyMARK:
			b = append(b, []byte("\"expr.MetaKeyMARK\"")...)
		case expr.MetaKeyIIF:
			b = append(b, []byte("\"expr.MetaKeyIIF\"")...)
		case expr.MetaKeyOIF:
			b = append(b, []byte("\"expr.MetaKeyOIF\"")...)
		case expr.MetaKeyIIFNAME:
			b = append(b, []byte("\"expr.MetaKeyIIFNAME\"")...)
		case expr.MetaKeyOIFNAME:
			b = append(b, []byte("\"expr.MetaKeyOIFNAME\"")...)
		case expr.MetaKeyIIFTYPE:
			b = append(b, []byte("\"expr.MetaKeyIIFTYPE\"")...)
		case expr.MetaKeyOIFTYPE:
			b = append(b, []byte("\"expr.MetaKeyOIFTYPE\"")...)
		case expr.MetaKeySKUID:
			b = append(b, []byte("\"expr.MetaKeySKUID\"")...)
		case expr.MetaKeySKGID:
			b = append(b, []byte("\"expr.MetaKeySKGID\"")...)
		case expr.MetaKeyNFTRACE:
			b = append(b, []byte("\"expr.MetaKeyNFTRACE\"")...)
		case expr.MetaKeyRTCLASSID:
			b = append(b, []byte("\"expr.MetaKeyRTCLASSID\"")...)
		case expr.MetaKeySECMARK:
			b = append(b, []byte("\"expr.MetaKeySECMARK\"")...)
		case expr.MetaKeyNFPROTO:
			b = append(b, []byte("\"expr.MetaKeyNFPROTO\"")...)
		case expr.MetaKeyL4PROTO:
			b = append(b, []byte("\"expr.MetaKeyL4PROTO\"")...)
		case expr.MetaKeyBRIIIFNAME:
			b = append(b, []byte("\"expr.MetaKeyBRIIIFNAME\"")...)
		case expr.MetaKeyBRIOIFNAME:
			b = append(b, []byte("\"expr.MetaKeyBRIOIFNAME\"")...)
		case expr.MetaKeyPKTTYPE:
			b = append(b, []byte("\"expr.MetaKeyPKTTYPE\"")...)
		case expr.MetaKeyCPU:
			b = append(b, []byte("\"expr.MetaKeyCPU\"")...)
		case expr.MetaKeyIIFGROUP:
			b = append(b, []byte("\"expr.MetaKeyIIFGROUP\"")...)
		case expr.MetaKeyOIFGROUP:
			b = append(b, []byte("\"expr.MetaKeyOIFGROUP\"")...)
		case expr.MetaKeyCGROUP:
			b = append(b, []byte("\"expr.MetaKeyCGROUP\"")...)
		case expr.MetaKeyPRANDOM:
			b = append(b, []byte("\"expr.MetaKeyPRANDOM\"")...)
		default:
			b = append(b, []byte("\"Unknown key\"")...)
		}
		b = append(b, []byte(",\"Register\":")...)
		b = append(b, []byte(fmt.Sprintf("%d}", e.Register))...)

		return b, nil
	}
	if e, ok := exp.(*expr.Cmp); ok {
		b = append(b, []byte("{\"Op\":")...)
		switch e.Op {
		case expr.CmpOpEq:
			b = append(b, []byte("\"expr.CmpOpEq\"")...)
		case expr.CmpOpNeq:
			b = append(b, []byte("\"expr.CmpOpNeq\"")...)
		case expr.CmpOpLt:
			b = append(b, []byte("\"expr.CmpOpLt\"")...)
		case expr.CmpOpLte:
			b = append(b, []byte("\"expr.CmpOpLte\"")...)
		case expr.CmpOpGt:
			b = append(b, []byte("\"expr.CmpOpGt\"")...)
		case expr.CmpOpGte:
			b = append(b, []byte("\"expr.CmpOpGte\"")...)
		default:
			b = append(b, []byte("\"Unknown Op\"")...)
		}
		b = append(b, []byte(",\"Register\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.Register))...)

		b = append(b, []byte(",\"Data\":")...)
		b = append(b, '[')
		for i := 0; i < len(e.Data); i++ {
			b = append(b, fmt.Sprintf("\"%#x\"", e.Data[i])...)
			if i < len(e.Data)-1 {
				b = append(b, ',')
			}
		}
		b = append(b, ']')
		b = append(b, '}')
		return b, nil
	}
	if e, ok := exp.(*expr.Payload); ok {
		b = append(b, []byte("{\"DestRegister\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.DestRegister))...)
		b = append(b, []byte(",\"Base\":")...)
		switch e.Base {
		case expr.PayloadBaseLLHeader:
			b = append(b, []byte("\"expr.PayloadBaseLLHeader\"")...)
		case expr.PayloadBaseNetworkHeader:
			b = append(b, []byte("\"expr.PayloadBaseNetworkHeader\"")...)
		case expr.PayloadBaseTransportHeader:
			b = append(b, []byte("\"expr.PayloadBaseTransportHeader\"")...)
		default:
			b = append(b, []byte("\"Unknown Base\"")...)
		}
		b = append(b, []byte(",\"Len\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.Len))...)
		b = append(b, []byte(",\"Offset\":")...)
		b = append(b, []byte(fmt.Sprintf("%d}", e.Offset))...)
		return b, nil
	}
	if e, ok := exp.(*expr.Immediate); ok {
		b = append(b, []byte("{\"Register\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.Register))...)
		b = append(b, []byte(",\"Data\":")...)
		b = append(b, '[')
		for i := 0; i < len(e.Data); i++ {
			b = append(b, fmt.Sprintf("\"%#x\"", e.Data[i])...)
			if i < len(e.Data)-1 {
				b = append(b, ',')
			}
		}
		b = append(b, ']')
		b = append(b, '}')
		return b, nil
	}
	if e, ok := exp.(*expr.Verdict); ok {
		b = append(b, []byte("{\"Kind\":")...)
		b = append(b, []byte(fmt.Sprintf("\"%#x\"", uint32(e.Kind)))...)
		if e.Chain != "" {
			b = append(b, []byte(",\"Chain\":")...)
			b = append(b, []byte(fmt.Sprintf("\"%s\"", e.Chain))...)
		}
		b = append(b, []byte("}")...)
		return b, nil
	}
	if e, ok := exp.(*expr.Redir); ok {
		b = append(b, []byte("{\"RegisterProtoMin\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.RegisterProtoMin))...)
		b = append(b, []byte(",\"RegisterProtoMax\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.RegisterProtoMax))...)
		b = append(b, []byte(",\"Flags\":")...)
		b = append(b, []byte(fmt.Sprintf("\"%#x\"}", e.Flags))...)
		return b, nil
	}
	/*

		TODO: (sbezverk)

			expr.Lookup:

			expr.Masq:

			expr.NAT:

			expr.Objref:

			expr.Queue:

			expr.Rt:
	*/

	return nil, fmt.Errorf("unknown expression type %T", exp)
}

// IPAddr lists possible flavours if specifying ip address, either List or Range can be specified
type IPAddr struct {
	List  []*net.IPAddr
	Range [2]*net.IPAddr
}

// Validate checks IPAddr struct
func (ip *IPAddr) Validate() error {
	if len(ip.List) != 0 && (ip.Range[0] != nil || ip.Range[1] != nil) {
		return fmt.Errorf("either List or Range but not both can be specified")
	}
	if len(ip.List) == 0 && (ip.Range[0] == nil || ip.Range[1] == nil) {
		return fmt.Errorf("neither List nor Range is specified")
	}
	return nil
}

// L3Rule contains parameters for L3 based rule, either Source or Destination can be specified
type L3Rule struct {
	Src     *IPAddr
	Dst     *IPAddr
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
		if err := l3.Src.Validate(); err != nil {
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
	L4Proto  int
	Src      *Port
	Dst      *Port
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
		if err := l4.Src.Validate(); err != nil {
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
