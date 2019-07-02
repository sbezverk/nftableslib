package nftableslib

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func createL3(l3proto nftables.TableFamily, rule *Rule, set *nftables.Set) (*nftables.Rule, []nftables.SetElement, error) {
	l3 := rule.L3
	re := []expr.Any{}
	se := []nftables.SetElement{}
	processed := false
	var err error
	if l3.Version != nil {
		re, se, err = processVersion(*l3.Version, rule.Exclude)
		if err != nil {
			return nil, nil, err
		}
		if rule.Redirect != nil && rule.Redirect.TProxy {
			re = append(re, getExprForTProxyRedirect(rule.Redirect.Port, l3proto)...)
		} else if rule.Verdict != nil {
			re = append(re, rule.Verdict)
		}

		return &nftables.Rule{Exprs: re}, se, nil
	}
	// IPv4 source address offset - 12, destination address offset - 16
	// IPv6 source address offset - 8, destination address offset - 24
	var ruleAddr *IPAddrSpec
	var addrOffset uint32
	if l3.Src != nil {
		ruleAddr = l3.Src
		switch l3proto {
		case nftables.TableFamilyIPv4:
			addrOffset = 12
			set.KeyType = nftables.TypeIPAddr
		case nftables.TableFamilyIPv6:
			addrOffset = 8
			set.KeyType = nftables.TypeIP6Addr
		default:
			return nil, nil, fmt.Errorf("unknown nftables.TableFamily %#02x", l3proto)
		}
	}
	if l3.Dst != nil {
		ruleAddr = l3.Dst
		switch l3proto {
		case nftables.TableFamilyIPv4:
			addrOffset = 16
			set.KeyType = nftables.TypeIPAddr
		case nftables.TableFamilyIPv6:
			addrOffset = 24
			set.KeyType = nftables.TypeIP6Addr
		default:
			return nil, nil, fmt.Errorf("unknown nftables.TableFamily %#02x", l3proto)
		}
	}
	if ruleAddr == nil {
		return nil, nil, fmt.Errorf("both source and destination are nil")
	}
	if len(ruleAddr.List) != 0 {
		re, se, err = processAddrList(l3proto, addrOffset, ruleAddr.List, rule.Exclude, set)
		if err != nil {
			return nil, nil, err
		}
		processed = true
	}
	if ruleAddr.Range[0] != nil && ruleAddr.Range[1] != nil {
		re, se, err = processAddrRange(l3proto, addrOffset, ruleAddr.Range, rule.Exclude)
		if err != nil {
			return nil, nil, err
		}
		processed = true
	}
	if !processed {
		return nil, nil, fmt.Errorf("address list, address range are empry")
	}
	if rule.Redirect != nil && rule.Redirect.TProxy {
		re = append(re, getExprForTProxyRedirect(rule.Redirect.Port, l3proto)...)
	} else if rule.Verdict != nil {
		re = append(re, rule.Verdict)
	}

	return &nftables.Rule{Exprs: re}, se, nil
}

func processAddrList(l3proto nftables.TableFamily, offset uint32, list []*IPAddr,
	excl bool, set *nftables.Set) ([]expr.Any, []nftables.SetElement, error) {
	if len(list) == 1 {
		// Special case with a single entry in the list, as a result it does not require to build SetElement
		re, err := getExprForSingleIP(l3proto, offset, list[0], excl)
		if err != nil {
			return nil, nil, err
		}

		return re, nil, nil
	}
	// Normal case, more than 1 entry in the list, need to build SetElement slice
	setElements := make([]nftables.SetElement, len(list))
	if l3proto == nftables.TableFamilyIPv4 {
		for i := 0; i < len(list); i++ {
			setElements[i].Key = list[i].IP.To4()
		}
	}
	if l3proto == nftables.TableFamilyIPv6 {
		for i := 0; i < len(list); i++ {
			setElements[i].Key = list[i].IP.To16()
		}
	}
	if len(setElements) == 0 {
		return nil, nil, fmt.Errorf("unknown nftables.TableFamily %#02x", l3proto)
	}

	re, err := getExprForListIP(l3proto, set, offset, excl)
	if err != nil {
		return nil, nil, err
	}

	return re, setElements, nil
}

func processAddrRange(l3proto nftables.TableFamily, offset uint32, rng [2]*IPAddr, excl bool) ([]expr.Any, []nftables.SetElement, error) {
	re, err := getExprForRangeIP(l3proto, offset, rng, excl)
	if err != nil {
		return nil, nil, err
	}

	return re, nil, nil
}

func processVersion(version byte, excl bool) ([]expr.Any, []nftables.SetElement, error) {
	re, err := getExprForIPVersion(version, excl)
	if err != nil {
		return nil, nil, err
	}

	return re, nil, nil
}
