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
	if rule.Verdict != nil {
		return processL4Port(rule.L4Proto, offset, rulePort, rule.Exclude, rule.Verdict, set)
	}

	return nil, nil, fmt.Errorf("both verdict and redirect are nil")
}

func processPortRedirect(l4proto int, offset uint32, port *Port, redirect uint32, excl bool, set *nftables.Set) (*nftables.Rule, []nftables.SetElement, error) {
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

func processL4Port(l4proto int, offset uint32, port *Port, exclude bool, verdict *expr.Verdict, set *nftables.Set) (*nftables.Rule, []nftables.SetElement, error) {
	if len(port.List) != 0 {
		re, se, err := processPortList(l4proto, offset, port.List, exclude, set)
		if err != nil {
			return nil, nil, err
		}
		re = append(re, verdict)
		return &nftables.Rule{
			Exprs: re,
		}, se, nil
	}
	if port.Range[0] != nil && port.Range[1] != nil {
		re, _, err := processPortRange(l4proto, offset, port.Range, exclude)
		if err != nil {
			return nil, nil, err
		}
		re = append(re, verdict)
		return &nftables.Rule{
			Exprs: re,
		}, nil, nil
	}

	return nil, nil, fmt.Errorf("both port list and port range are nil")
}

func processPortList(l4proto int, offset uint32, port []*uint32, excl bool, set *nftables.Set) ([]expr.Any, []nftables.SetElement, error) {
	// Processing special case of 1 port in the list
	if len(port) == 1 {
		re := []expr.Any{}
		re, err := getExprForSinglePort(l4proto, offset, port, excl)
		if err != nil {
			return nil, nil, err
		}
		return re, nil, nil
	}
	// Processing multiple ports case
	re := []expr.Any{}
	setElements := make([]nftables.SetElement, len(port))
	for _, p := range port {
		setElements = append(setElements,
			nftables.SetElement{
				Key: binaryutil.BigEndian.PutUint16(uint16(*p)),
			})
	}
	re, err := getExprForListPort(l4proto, offset, port, excl, set)
	if err != nil {
		return nil, nil, err
	}

	return re, setElements, nil
}

func processPortRange(l4proto int, offset uint32, port [2]*uint32, excl bool) ([]expr.Any, []nftables.SetElement, error) {
	re, err := getExprForRangePort(l4proto, offset, port, excl)
	if err != nil {
		return nil, nil, err
	}
	return re, nil, nil
}
