package nftableslib

import "github.com/google/nftables"

func createL4(rule *L4Rule, set nftables.Set) (*nftables.Rule, []nftables.SetElement, error) {
	r := nftables.Rule{}
	s := make([]nftables.SetElement, 0)
	return &r, s, nil
}
