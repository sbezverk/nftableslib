package main

import (
	"fmt"

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

	ti, err := setenv.NFTablesSet(ns, test.Version, test.DstNFRules, false, test.TableName)
	if err != nil {
		return err
	}
	org, err := ti.Tables().Dump()
	if err != nil {
		return err
	}
	fmt.Printf("Initial programmed tables/chains/rules: %s\n", string(org))
	ns.Close()

	// Reinitializing connection to the namespace
	newNS, err := setenv.NewNS("namespace_1")
	if err != nil {
		return err
	}
	defer newNS.Close()
	newConn := nftableslib.InitConn(int(newNS))
	newTI := nftableslib.InitNFTables(newConn)
	//	learned, err := newTI.Tables().Dump()
	//	if err != nil {
	//		return err
	//	}
	//	fmt.Printf("Learned  before Sync() tables/chains/rules: %s\n", string(learned))
	// Attempting to Sync with already existing tables/chains/rules
	if err := newTI.Tables().Sync(test.Version); err != nil {
		return err
	}
	//	learned, err = newTI.Tables().Dump()
	//	if err != nil {
	//		return err
	//	}
	//	fmt.Printf("Learned  after Sync() tables/chains/rules: %s\n", string(learned))

	_, err = newTI.Tables().TableChains(test.TableName, test.Version)
	if err != nil {
		return err
	}
	//	newRI, err := newCI.Chains().Chain(test.)

	return nil
}
