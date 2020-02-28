package nftableslib

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// ConcatElement defines 1 element of Concatination rule
type ConcatElement struct {
	// Etype defines an element type as defined in github.com/google/nftables
	// example nftables.InetService or nftables.IPAddr
	EType nftables.SetDatatype
	// EProto defines a protocol as defined in golang.org/x/sys/unix
	EProto byte
	// ESource defines a direction, if true then element is saddr or sport,
	// if false then daddr or dport
	ESource bool
	// EMask defines mask of the element, mostly used along with IPAddr
	EMask []byte
}

// Concat defines parameters of Concatination rule
type Concat struct {
	Elements []*ConcatElement
	// VMap defines if concatination is used with verdict map, if set to true
	// Rule's Action will be ignored as the action is stored in the verdict of the map.
	VMap bool
	// SetRef defines name and id of map for
	SetRef *SetRef
}

func getExprForConcat(l3proto nftables.TableFamily, concat *Concat) ([]expr.Any, error) {
	var l3OffsetSrc, l3OffsetDst, l3AddrLen, l4ProtoOffset uint32
	l4OffsetSrc := uint32(0)
	l4OffsetDst := uint32(2)
	re := []expr.Any{}
	switch l3proto {
	case nftables.TableFamilyIPv4:
		l3OffsetSrc = 12
		l3OffsetDst = 16
		l3AddrLen = 4
		l4ProtoOffset = 9
	case nftables.TableFamilyIPv6:
		l3OffsetSrc = 8
		l3OffsetDst = 24
		l3AddrLen = 16
		l4ProtoOffset = 6
	default:
		return nil, fmt.Errorf("unsupported table family %d", l3proto)
	}
	register := uint32(1)
	for _, e := range concat.Elements {
		switch e.EType {
		case nftables.TypeIPAddr:
			// [ payload load length of address in bytes @ network header + l3OffsetSrc or l3OffsetDst => reg 1 ]
			var offset uint32
			if e.ESource {
				offset = l3OffsetSrc
			} else {
				offset = l3OffsetDst
			}
			re = append(re, &expr.Payload{
				DestRegister: register,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          l3AddrLen,
			})
		case nftables.TypeIP6Addr:
			// [ payload load length of address in bytes @ network header + l3OffsetSrc or l3OffsetDst => reg 1 ]
			var offset uint32
			if e.ESource {
				offset = l3OffsetSrc
			} else {
				offset = l3OffsetDst
			}
			re = append(re, &expr.Payload{
				DestRegister: register,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          l3AddrLen,
			})
			// Since IPv6 takes 16 bytes, need to increment register counter by 3.
			register += 3
		case nftables.TypeEtherAddr:
		case nftables.TypeInetProto:
			// [ payload load 1b @ network header + 9 => reg 1 ]
			re = append(re, &expr.Payload{
				DestRegister: register,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       l4ProtoOffset,
				Len:          1,
			})
		case nftables.TypeInetService:
			// [ payload load 2b @ transport header + l4OffsetSrc or l4OffsetDst => reg X ]
			var offset uint32
			if e.ESource {
				offset = l4OffsetSrc
			} else {
				offset = l4OffsetDst
			}
			re = append(re, &expr.Payload{
				DestRegister: register,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       offset,
				Len:          2,
			})
		default:
			return nil, fmt.Errorf("unsupported element type %+v", e.EType)
		}
		if register == 1 {
			register = 9
		} else {
			register++
		}
	}
	// If Concat refers to map, add lookup expression
	if concat.SetRef != nil {
		re = append(re, &expr.Lookup{
			SourceRegister: 1,
			DestRegister:   0,
			IsDestRegSet:   true,
			SetID:          concat.SetRef.ID,
			SetName:        concat.SetRef.Name,
		})
	}

	return re, nil
}
