package nftableslib

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

func getExprForMatchAct(nfr *nfRules, l3proto nftables.TableFamily, matchAct *MatchAct) ([]expr.Any, error) {
	if matchAct == nil {
		return nil, fmt.Errorf("MatchAct is nil")
	}
	// If MatchAct does not specify Map, return error
	if matchAct.MatchRef == nil {
		return nil, fmt.Errorf("reference to match map cannot be nil")
	}
	if len(matchAct.ActElement) == 0 {
		return nil, fmt.Errorf("number of elements in action vmap cannot be 0")
	}

	var elements []nftables.SetElement
	for key, v := range matchAct.ActElement {
		if v.verdict == nil {
			return nil, fmt.Errorf("rule action has nil verdict for element %d", key)
		}
		elements = append(elements, nftables.SetElement{
			Key:         binaryutil.BigEndian.PutUint32(uint32(key)),
			VerdictData: v.verdict,
		})
	}

	var l3OffsetSrc, l3OffsetDst, l3AddrLen /*, l4ProtoOffset*/ uint32
	l4OffsetSrc := uint32(0)
	l4OffsetDst := uint32(2)
	re := []expr.Any{}

	switch l3proto {
	case nftables.TableFamilyIPv4:
		l3OffsetSrc = 12
		l3OffsetDst = 16
		l3AddrLen = 4
		// l4ProtoOffset = 9
	case nftables.TableFamilyIPv6:
		l3OffsetSrc = 8
		l3OffsetDst = 24
		l3AddrLen = 16
		// l4ProtoOffset = 6
	default:
		return nil, fmt.Errorf("unsupported table family %d", l3proto)
	}

	switch matchAct.Match {
	case MatchTypeL3Src:
		re = append(re, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       l3OffsetSrc,       // Offset ip address in network header
			Len:          uint32(l3AddrLen), // length bytes for ip address
		})
	case MatchTypeL3Dst:
		re = append(re, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       l3OffsetDst,       // Offset ip address in network header
			Len:          uint32(l3AddrLen), // length bytes for ip address
		})
	case MatchTypeL4Src:
		re = append(re, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       l4OffsetSrc, // Offset for a transport protocol header
			Len:          2,           // 2 bytes for port
		})
	case MatchTypeL4Dst:
		re = append(re, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       l4OffsetDst, // Offset for a transport protocol header
			Len:          2,           // 2 bytes for port
		})
	default:
		return nil, fmt.Errorf("unsupported matching criteria %+v", matchAct.Match)
	}
	if len(re) == 0 {
		return nil, fmt.Errorf("no valid matching criteria was found")
	}

	match := &expr.Lookup{
		SourceRegister: 1,
		DestRegister:   1,
		IsDestRegSet:   true,
		SetID:          matchAct.MatchRef.ID,
		SetName:        matchAct.MatchRef.Name,
	}
	re = append(re, match)
	s, err := makeActSet(nfr, elements)
	if err != nil {
		return nil, err
	}
	act := &expr.Lookup{
		SourceRegister: 1,
		DestRegister:   0,
		IsDestRegSet:   true,
		SetID:          s.ID,
		SetName:        s.Name,
	}
	re = append(re, act)

	return re, nil
}

func makeActSet(nfr *nfRules, elements []nftables.SetElement) (*nftables.Set, error) {
	var set *nftables.Set

	set = &nftables.Set{
		Table:     nfr.table,
		Anonymous: true,
		Constant:  true,
		IsMap:     true,
		KeyType:   nftables.TypeInteger,
		DataType:  nftables.TypeVerdict,
	}
	if err := nfr.conn.AddSet(set, elements); err != nil {
		return nil, err
	}

	return set, nil
}
