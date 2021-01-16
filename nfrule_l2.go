package nftableslib

import (
	"github.com/google/nftables/expr"
)

func createL2(rule *Rule) ([]expr.Any, []*nfSet, error) {
	var re []expr.Any
	if rule.L2.IIf != nil && rule.L2.IIf.Name != "" {
		re = append(re, getExprForInputIntfByName(rule.L2.IIf.Name, rule.L2.IIf.RelOp)...)
	}
	if rule.L2.OIf != nil && rule.L2.OIf.Name != "" {
		re = append(re, getExprForOutputIntfByName(rule.L2.OIf.Name, rule.L2.OIf.RelOp)...)
	}
	return re, nil, nil
}
