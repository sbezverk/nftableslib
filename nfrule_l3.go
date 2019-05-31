package nftableslib

import (
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func createL3(l3proto nftables.TableFamily, rule *L3Rule, set nftables.Set) (*nftables.Rule, []nftables.SetElement, error) {
	// IPv4 source address offset - 12, destination address offset - 16
	// IPv6 source address offset - 8, destination address offset - 24
	var ruleAddr *IPAddr
	var addrOffset uint32
	if rule.Src != nil {
		ruleAddr = rule.Src
		switch l3proto {
		case nftables.TableFamilyIPv4:
			addrOffset = 12
		case nftables.TableFamilyIPv6:
			addrOffset = 8
		default:
			return nil, nil, fmt.Errorf("unknown nftables.TableFamily %#02x", l3proto)
		}
	}
	if rule.Dst != nil {
		ruleAddr = rule.Dst
		switch l3proto {
		case nftables.TableFamilyIPv4:
			addrOffset = 16
		case nftables.TableFamilyIPv6:
			addrOffset = 24
		default:
			return nil, nil, fmt.Errorf("unknown nftables.TableFamily %#02x", l3proto)
		}
	}
	if ruleAddr == nil {
		return nil, nil, fmt.Errorf("both source and destination are nil")
	}
	if len(ruleAddr.List) != 0 {
		return processAddrList(l3proto, addrOffset, ruleAddr.List, rule.Exclude, rule.Verdict, set)
	}
	if ruleAddr.Range[0] != nil && ruleAddr.Range[1] != nil {
		return processAddrRange(l3proto, addrOffset, ruleAddr.Range, rule.Exclude, rule.Verdict)
	}
	return nil, nil, fmt.Errorf("both address list and address range is empry")
}

func processAddrList(l3proto nftables.TableFamily, offset uint32, list []*net.IPAddr,
	excl bool, verdict *expr.Verdict, set nftables.Set) (*nftables.Rule, []nftables.SetElement, error) {
	if len(list) == 1 {
		// Special case with a single entry in the list, as a result it does not require to build SetElement
		expr, err := getExprForSingleIP(l3proto, offset, list[0], excl)
		if err != nil {
			return nil, nil, err
		}
		expr = append(expr, verdict)
		return &nftables.Rule{
			Exprs: expr,
		}, nil, nil
	}
	// Normal case, more than 1 entry in the list, need to build SetElement slice
	setElements := make([]nftables.SetElement, len(list))
	if l3proto == nftables.TableFamilyIPv4 {
		for i := 0; i < len(list); i++ {
			setElements[i].Key = swapBytes(list[i].IP.To4())
		}
	}
	if l3proto == nftables.TableFamilyIPv6 {
		for i := 0; i < len(list); i++ {
			setElements[i].Key = swapBytes(list[i].IP.To16())
		}
	}
	if len(setElements) == 0 {
		return nil, nil, fmt.Errorf("unknown nftables.TableFamily %#02x", l3proto)
	}

	expr, err := getExprForListIP(l3proto, set, offset, excl)
	if err != nil {
		return nil, nil, err
	}
	expr = append(expr, verdict)

	return &nftables.Rule{
		Exprs: expr,
	}, setElements, nil
}

func processAddrRange(l3proto nftables.TableFamily, offset uint32, rng [2]*net.IPAddr, excl bool, verdict *expr.Verdict) (*nftables.Rule, []nftables.SetElement, error) {
	expr, err := getExprForRangeIP(l3proto, offset, rng, excl)
	if err != nil {
		return nil, nil, err
	}
	expr = append(expr, verdict)
	return &nftables.Rule{
		Exprs: expr,
	}, nil, nil
}
