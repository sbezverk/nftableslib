package nftableslib

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func getExprForDynamic(l3proto nftables.TableFamily, dynamic *Dynamic) ([]expr.Any, error) {
	// If dynamic does not carry a populated Set or Map, return error
	if dynamic.SetRef == nil {
		return nil, fmt.Errorf("reference to set or map cannot be nil")
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

	switch dynamic.Match {
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
		return nil, fmt.Errorf("unsupported matching criteria %+v", dynamic.Match)
	}
	if len(re) == 0 {
		return nil, fmt.Errorf("no valid matching criteria was found")
	}
	re = append(re, &expr.Immediate{
		// Value of register must match to the value of SrcRegData
		Register: 2,
		Data:     binaryutil.BigEndian.PutUint32(dynamic.Key),
	})
	de := &expr.Dynset{
		SrcRegKey: 1,
		// Value of SrcRegData must match to the value of expr.Immediate's Register
		SrcRegData: 2,
		Operation:  dynamic.Op,
		SetID:      dynamic.SetRef.ID,
		SetName:    dynamic.SetRef.Name,
		Invert:     dynamic.Invert,
	}
	// Entry timeout only makes sense only if  Operation is Update
	if dynamic.Op == unix.NFT_DYNSET_OP_UPDATE {
		de.Timeout = dynamic.Timeout
	}
	re = append(re, de)

	return re, nil
}
