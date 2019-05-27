package nftableslib

import (
	"encoding/json"
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
		b, err := json.Marshal(&r.rule)
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
