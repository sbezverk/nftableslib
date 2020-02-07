package nftableslib

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func getExprForDynamic(l3proto nftables.TableFamily, dynamic *Dynamic) ([]expr.Any, error) {
	var l3OffsetSrc, l3OffsetDst, l3AddrLen, l4ProtoOffset uint32
	l4OffsetSrc := uint32(0)
	l4OffsetDst := uint32(2)
	re := []expr.Any{}
	switch l3proto {
	case nftables.TableFamilyIPv4:
		//		l3OffsetSrc = 12
		//		l3OffsetDst = 16
		//		l3AddrLen = 4
		l4ProtoOffset = 9
	case nftables.TableFamilyIPv6:
		l3OffsetSrc = 8
		l3OffsetDst = 24
		l3AddrLen = 16
		l4ProtoOffset = 6
	default:
		return nil, fmt.Errorf("unsupported table family %d", l3proto)
	}

	if dynamic.SetRef != nil {
		re = append(re, &expr.Dynset{
			//			SourceRegister: 1,
			//			DestRegister:   0,
			//			IsDestRegSet:   true,
			SetID:   dynamic.SetRef.ID,
			SetName: dynamic.SetRef.Name,
		})
	}

	return re, nil
}
