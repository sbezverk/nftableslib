package nftableslib

import (
	"fmt"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"

	"github.com/google/nftables"
)

func createL4(family nftables.TableFamily, rule *Rule, set *nftables.Set) (*nftables.Rule, []nftables.SetElement, error) {
	var rulePort *Port
	var offset uint32
	l4 := rule.L4
	set.KeyType = nftables.TypeInetService
	if l4.Src != nil {
		rulePort = l4.Src
		offset = 0
	}
	if l4.Dst != nil {
		rulePort = l4.Dst
		offset = 2
	}

	re := []expr.Any{}
	se := []nftables.SetElement{}
	var err error
	processed := false
	if len(rulePort.List) != 0 {
		re, se, err = processPortList(l4.L4Proto, offset, rulePort.List, rule.Exclude, set)
		if err != nil {
			return nil, nil, err
		}
		processed = true
	}
	if rulePort.Range[0] != nil && rulePort.Range[1] != nil {
		re, _, err = processPortRange(l4.L4Proto, offset, rulePort.Range, rule.Exclude)
		if err != nil {
			return nil, nil, err
		}
		processed = true
	}
	if !processed {
		return nil, nil, fmt.Errorf("both port list and port range are nil")
	}

	return &nftables.Rule{Exprs: re}, se, nil
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
