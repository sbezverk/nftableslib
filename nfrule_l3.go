package nftableslib

import (
	"fmt"
	"net"

	"github.com/google/nftables"
)

func createL3(l3proto nftables.TableFamily, rule *L3Rule) (*nftables.Rule, []nftables.SetElement, error) {

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
		return processAddrList(l3proto, addrOffset, ruleAddr.List)
	}
	if ruleAddr.Range[0] != nil && ruleAddr.Range[1] != nil {
		return processAddrRange(l3proto, addrOffset, ruleAddr.Range)
	}
	return nil, nil, fmt.Errorf("both address list and address range is empry")
}

func processAddrList(l3proto nftables.TableFamily, offset uint32, list []*net.IPAddr) (*nftables.Rule, []nftables.SetElement, error) {
	return &nftables.Rule{}, nil, nil
}

func processAddrRange(l3proto nftables.TableFamily, offset uint32, rng [2]*net.IPAddr) (*nftables.Rule, []nftables.SetElement, error) {
	return &nftables.Rule{}, nil, nil
}
