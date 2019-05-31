package nftableslib

import "github.com/google/nftables"

func createL4(rule *Rule) (*nftables.Rule, []nftables.SetElement) {
	r := nftables.Rule{}
	s := make([]nftables.SetElement, 0)
	return &r, s
}
