package nftableslib

import (
	"encoding/json"
	"fmt"
	"log"
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
	Create(string, []expr.Any)
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
	rule nftables.Rule
}

func (nfr *nfRules) Rules() RuleFuncs {
	return nfr
}

func (nfr *nfRules) Create(name string, ruleExpressions []expr.Any) {
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
	nfr.conn.AddRule(&r)
	nfr.rules[name] = &nfRule{
		rule: r,
	}
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
	log.Printf("Custom JSON rule encoder was called")
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
	log.Printf("jsonData: %s", jsonData)

	return jsonData, nil
}

func marshalExpression(exp expr.Any) ([]byte, error) {
	var jsonData []byte

	if e, ok := exp.(*expr.Meta); ok {
		var b []byte
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

		log.Printf("%s", b)
		return b, nil
	}
	/*	case expr.Cmp:
			log.Printf("type: %v", v)
		case expr.Payload:
			log.Printf("type: %v", v)
		case expr.Immediate:
			log.Printf("type: %v", v)
		case expr.Lookup:
			log.Printf("type: %v", v)
		case expr.Masq:
			log.Printf("type: %v", v)
		case expr.NAT:
			log.Printf("type: %v", v)
		case expr.Objref:
			log.Printf("type: %v", v)
		case expr.Queue:
			log.Printf("type: %v", v)
		case expr.Redir:
			log.Printf("type: %v", v)
		case expr.Rt:
			log.Printf("type: %v", v)
		case expr.Verdict:
			log.Printf("type: %v", v)
		default:
			log.Printf("type: %v", v)
		}
	*/
	b, err := json.Marshal(&exp)
	if err != nil {
		return nil, err
	}
	log.Printf("Unknown")
	jsonData = append(jsonData, b...)

	return jsonData, nil
}
