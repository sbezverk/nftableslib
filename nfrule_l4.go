package nftableslib

import (
	"fmt"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"

	"github.com/google/nftables"
)

func createL4(rule *L4Rule, set *nftables.Set) (*nftables.Rule, []nftables.SetElement, error) {
	var rulePort *Port
	var offset uint32

	set.KeyType = nftables.TypeInetService
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
		return processPortRedirect(rule.L4Proto, offset, rulePort, *rule.Redirect, rule.Exclude, set)
	}

	return processL4Port(rule.L4Proto, offset, rulePort, rule.Exclude, set)
}

func processPortRedirect(l4proto uint8, offset uint32, port *Port, redirect uint16, excl bool, set *nftables.Set) (*nftables.Rule, []nftables.SetElement, error) {
	if len(port.List) != 0 {
		re, se, err := processPortList(l4proto, offset, port.List, excl, set)
		if err != nil {
			return nil, nil, err
		}
		re = append(re, getExprForRedirectPort(redirect)...)
		return &nftables.Rule{
			Exprs: re,
		}, se, nil
	}
	if port.Range[0] != nil && port.Range[1] != nil {
		re, _, err := processPortRange(l4proto, offset, port.Range, excl)
		if err != nil {
			return nil, nil, err
		}
		re = append(re, getExprForRedirectPort(redirect)...)
		return &nftables.Rule{
			Exprs: re,
		}, nil, nil
	}

	return nil, nil, fmt.Errorf("both port list and port range are nil")
}

func processL4Port(l4proto uint8, offset uint32, port *Port, exclude bool, set *nftables.Set) (*nftables.Rule, []nftables.SetElement, error) {
	if len(port.List) != 0 {
		re, se, err := processPortList(l4proto, offset, port.List, exclude, set)
		if err != nil {
			return nil, nil, err
		}

		return &nftables.Rule{
			Exprs: re,
		}, se, nil
	}
	if port.Range[0] != nil && port.Range[1] != nil {
		re, _, err := processPortRange(l4proto, offset, port.Range, exclude)
		if err != nil {
			return nil, nil, err
		}

		return &nftables.Rule{
			Exprs: re,
		}, nil, nil
	}

	return nil, nil, fmt.Errorf("both port list and port range are nil")
}

func processPortList(l4proto uint8, offset uint32, port []*uint16, excl bool, set *nftables.Set) ([]expr.Any, []nftables.SetElement, error) {
	// Processing multiple ports case
	re := []expr.Any{}
	// Normal case, more than 1 entry in the port list need to build SetElement slice
	setElements := make([]nftables.SetElement, len(port))
	for i := 0; i < len(port); i++ {
		setElements[i].Key = binaryutil.BigEndian.PutUint16(*port[i])
	}

	re, err := getExprForListPort(l4proto, offset, port, excl, set)
	if err != nil {
		return nil, nil, err
	}

	return re, setElements, nil
}

func processPortRange(l4proto uint8, offset uint32, port [2]*uint16, excl bool) ([]expr.Any, []nftables.SetElement, error) {
	re, err := getExprForRangePort(l4proto, offset, port, excl)
	if err != nil {
		return nil, nil, err
	}
	return re, nil, nil
}
