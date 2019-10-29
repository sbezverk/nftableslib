package main

import (
	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"github.com/sbezverk/nftableslib/pkg/e2e/setenv"
	"golang.org/x/sys/unix"
)

// Testing Sync feature, in a namespace a set of rules will be created and programmed, then tables/chains/rules in
// memory removed, Sync is supposed to learn and rebuild in-memory data structures based on discovered in the namesapce
// nftables information.
func testSync() error {

	test := setenv.NFTablesTest{

		Name:      "Sync rules test",
		TableName: "nftables_ipv4",
		Version:   nftables.TableFamilyIPv4,
		DstNFRules: map[setenv.TestChain][]nftableslib.Rule{
			setenv.TestChain{
				"chain-1",
				&nftableslib.ChainAttributes{
					Type:     nftables.ChainTypeFilter,
					Priority: 0,
					Hook:     nftables.ChainHookInput,
					Policy:   nftableslib.ChainPolicyAccept,
				},
			}: []nftableslib.Rule{
				{
					L3: &nftableslib.L3Rule{
						Protocol: nftableslib.L3Protocol(unix.IPPROTO_ICMP),
						Dst: &nftableslib.IPAddrSpec{
							List: []*nftableslib.IPAddr{setIPAddr("1.1.1.2")},
						},
					},
					Action: setActionVerdict(nftableslib.NFT_DROP),
				},
			},
		},
	}

	ns, err := setenv.NewNS("namespace_1")
	if err != nil {
		return err
	}

	if err := setenv.NFTablesSet(ns, test.Version, test.DstNFRules, true, test.TableName); err != nil {
		return err
	}
	return nil
}
