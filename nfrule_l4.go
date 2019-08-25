package nftableslib

import (
	"math/rand"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"

	"github.com/google/nftables"
)

func createL4(family nftables.TableFamily, rule *Rule) ([]expr.Any, []*nfSet, error) {
	var offset uint32
	re := []expr.Any{}
	e := []expr.Any{}
	sets := make([]*nfSet, 0)
	var set *nfSet
	var err error

	l4 := rule.L4
	if l4.Src != nil {
		offset = 0
		if len(l4.Src.List) != 0 {
			e, set, err = processPortList(l4.L4Proto, offset, l4.Src.List, l4.Src.RelOp)
			if err != nil {
				return nil, nil, err
			}
		}
		if l4.Src.Range[0] != nil && l4.Src.Range[1] != nil {
			e, set, err = processPortRange(l4.L4Proto, offset, l4.Src.Range, l4.Src.RelOp)
			if err != nil {
				return nil, nil, err
			}
		}
		if set != nil {
			set.set.KeyType = nftables.TypeInetService
			sets = append(sets, set)
		}
		re = append(re, e...)
	}
	if l4.Dst != nil {
		offset = 2
		if len(l4.Dst.List) != 0 {
			e, set, err = processPortList(l4.L4Proto, offset, l4.Dst.List, l4.Dst.RelOp)
			if err != nil {
				return nil, nil, err
			}
		}
		if l4.Dst.Range[0] != nil && l4.Dst.Range[1] != nil {
			e, set, err = processPortRange(l4.L4Proto, offset, l4.Dst.Range, l4.Dst.RelOp)
			if err != nil {
				return nil, nil, err
			}
		}
		if set != nil {
			set.set.KeyType = nftables.TypeInetService
			sets = append(sets, set)
		}
		re = append(re, e...)
	}

	return re, sets, nil
}

func processPortList(l4proto uint8, offset uint32, port []*uint16, op Operator) ([]expr.Any, *nfSet, error) {
	// Processing multiple ports case
	re := []expr.Any{}
	var nfset *nfSet
	var set *nftables.Set
	if len(port) > 1 {
		nfset = &nfSet{}
		set = &nftables.Set{}
		set.Anonymous = false
		set.Constant = true
		set.Name = getSetName()
		set.ID = uint32(rand.Intn(0xffff))

		se := make([]nftables.SetElement, len(port))
		// Normal case, more than 1 entry in the port list need to build SetElement slice
		for i := 0; i < len(port); i++ {
			se[i].Key = binaryutil.BigEndian.PutUint16(*port[i])
		}
		nfset.set = set
		nfset.elements = se
	}
	re, err := getExprForListPort(l4proto, offset, port, op, set)
	if err != nil {
		return nil, nil, err
	}

	return re, nfset, nil
}

func processPortRange(l4proto uint8, offset uint32, port [2]*uint16, op Operator) ([]expr.Any, *nfSet, error) {
	re, err := getExprForRangePort(l4proto, offset, port, op)
	if err != nil {
		return nil, nil, err
	}
	return re, nil, nil
}
