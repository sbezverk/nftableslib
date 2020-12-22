package main

import (
	"fmt"
	"reflect"

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
		DstNFRules: []setenv.TestChain{
			{
				Name: "chain-1",
				Attr: nil,
				Rules: []nftableslib.Rule{
					{
						// This rule will block ALL TCP traffic with the exception of traffic destined to port 8888
						L4: &nftableslib.L4Rule{
							L4Proto: unix.IPPROTO_TCP,
							Dst: &nftableslib.Port{
								List:  nftableslib.SetPortList([]int{8888}),
								RelOp: nftableslib.NEQ,
							},
						},
						Action: setActionVerdict(nftableslib.NFT_DROP),
					},
					{
						// Allowed TCP traffic to port 8888 will be redirected to port 9999
						L4: &nftableslib.L4Rule{
							L4Proto: unix.IPPROTO_TCP,
							Dst: &nftableslib.Port{
								List: nftableslib.SetPortList([]int{8888}),
							},
						},
						Action: setActionRedirect(9999, false),
					},
				},
			},
			{
				Name: "chain-2",
				Attr: &nftableslib.ChainAttributes{
					Type:     nftables.ChainTypeFilter,
					Priority: 0,
					Hook:     nftables.ChainHookInput,
					Policy:   &accept,
				},
				Rules: []nftableslib.Rule{
					{
						L3: &nftableslib.L3Rule{
							Protocol: nftableslib.L3Protocol(unix.IPPROTO_ICMP),
							Dst: &nftableslib.IPAddrSpec{
								List: []*nftableslib.IPAddr{setIPAddr("1.1.0.0/16")},
							},
						},
						Action: setActionVerdict(nftableslib.NFT_DROP),
					},
				},
			},
		},
		SrcNFRules: []setenv.TestChain{
			{
				Name: "chain-3",
				Attr: &nftableslib.ChainAttributes{
					Type:     nftables.ChainTypeNAT,
					Priority: 0,
					Hook:     nftables.ChainHookPostrouting,
				},
				Rules: []nftableslib.Rule{
					{
						L3: &nftableslib.L3Rule{
							Protocol: nftableslib.L3Protocol(unix.IPPROTO_TCP),
						},
						Action: setSNAT(&nftableslib.NATAttributes{
							L3Addr: [2]*nftableslib.IPAddr{setIPAddr("5.5.5.5")},
							Port:   [2]uint16{7777},
						}),
					},
				},
			},
		},
	}

	ns, err := setenv.NewNS()
	if err != nil {
		return err
	}
	defer ns.Close()
	ti := setenv.MakeTablesInterface(ns)
	if err := ti.Tables().CreateImm(test.TableName, test.Version); err != nil {
		return fmt.Errorf("fail to create table %s with error: %+v", test.TableName, err)
	}
	if test.DstNFRules != nil {
		if err := setenv.ProgramTestRules(ti, test.TableName, test.Version, test.DstNFRules); err != nil {
			return fmt.Errorf("fail to create destination test rules table %s with error: %+v", test.TableName, err)
		}
	}
	if test.SrcNFRules != nil {
		if err := setenv.ProgramTestRules(ti, test.TableName, test.Version, test.SrcNFRules); err != nil {
			return fmt.Errorf("fail to create destination test rules table %s with error: %+v", test.TableName, err)
		}
	}

	ci, err := ti.Tables().TableChains(test.TableName, test.Version)
	if err != nil {
		return fmt.Errorf("fail to get Chains interface for table %s with error: %+v", test.TableName, err)
	}
	chains, err := ci.Chains().Get()
	if err != nil {
		return fmt.Errorf("fail to get Chains list for table %s with error: %+v", test.TableName, err)
	}
	// printChainRules(chains, ci, test.TableName)
	orgRules, _ := rulesToBytes(chains, ci, test.TableName)

	// Creating New TablesInterface
	newTI := setenv.MakeTablesInterface(ns)

	// Attempting to Sync with already existing tables/chains/rules
	if err := newTI.Tables().Sync(test.Version); err != nil {
		return fmt.Errorf("fail to Sync with error: %+v", err)
	}

	newCI, err := newTI.Tables().TableChains(test.TableName, test.Version)
	if err != nil {
		return fmt.Errorf("fail to get new Chains interface for table %s with error: %+v", test.TableName, err)
	}

	chains, err = newCI.Chains().Get()
	if err != nil {
		return fmt.Errorf("fail to get new Chains list with error: %+v", err)
	}
	if len(chains) == 0 {
		return fmt.Errorf("no chains discovered")
	}

	// printChainRules(chains, newCI, test.TableName)
	newRules, _ := rulesToBytes(chains, ci, test.TableName)

	if !reflect.DeepEqual(orgRules, newRules) {
		return fmt.Errorf("discovered rules do not match original")
	}

	return nil
}

func printChainRules(chains []string, ci nftableslib.ChainsInterface, tableName string) error {
	for _, chain := range chains {
		ri, err := ci.Chains().Chain(chain)
		if err != nil {
			return err
		}

		lr, err := ri.Rules().Dump()
		if err != nil {
			return err
		}
		fmt.Printf("Table: %s, Chain: %s Rules: %s\n\n", tableName, chain, string(lr))
	}
	return nil
}

func rulesToBytes(chains []string, ci nftableslib.ChainsInterface, tableName string) ([][]byte, error) {
	data := make([][]byte, len(chains))
	i := 0
	for _, chain := range chains {
		ri, err := ci.Chains().Chain(chain)
		if err != nil {
			return nil, err
		}

		lr, err := ri.Rules().Dump()
		if err != nil {
			return nil, err
		}
		data[i] = append(data[i], lr...)
		i++
	}
	return data, nil
}
