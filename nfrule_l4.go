package nftableslib

import (
	"fmt"

	"github.com/google/nftables/expr"

	"github.com/google/nftables"
)

func createL4(rule *L4Rule, set nftables.Set) (*nftables.Rule, []nftables.SetElement, error) {
	r := nftables.Rule{}
	s := make([]nftables.SetElement, 0)

	var rulePort *Port
	var offset uint32

	if rule.Src != nil {
		rulePort = rule.Src
		offset = 0
	}
	if rule.Dst != nil {
		rulePort = rule.Dst
		offset = 2
	}
	if rulePort == nil {
		return nil, nil, fmt.Errorf("both source and destination ports are nil")
	}

	if rule.Redirect != nil {
		return processPortRedirect(rule.L4Proto, offset, rulePort, *rule.Redirect)
	}
	if rule.Verdict != nil {
		return processL4Port(rule.L4Proto, offset, rulePort, rule.Exclude, rule.Verdict)
	}
	return &r, s, nil
}

func processPortRedirect(l4proto int, offset uint32, port *Port, redicrect uint32) (*nftables.Rule, []nftables.SetElement, error) {

	return nil, nil, fmt.Errorf("not implemented")
}

func processL4Port(l4proto int, offset uint32, port *Port, exclude bool, verdict *expr.Verdict) (*nftables.Rule, []nftables.SetElement, error) {

	return nil, nil, fmt.Errorf("not implemented")
}
