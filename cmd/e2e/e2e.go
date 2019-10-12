package main

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"github.com/sbezverk/nftableslib/pkg/e2e/setenv"
	"github.com/sbezverk/nftableslib/pkg/e2e/validations"
)

func init() {
	runtime.LockOSThread()
}

func main() {
	tests := []setenv.NFTablesTest{
		{
			Name:    "IPV4 ICMP Drop",
			Version: nftables.TableFamilyIPv4,
			DstNSRules: map[setenv.TestChain][]nftableslib.Rule{
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
			Saddr:      "1.1.1.1/24",
			Daddr:      "1.1.1.2/24",
			Validation: validations.ICMPDropTestValidation,
		},
		{
			Name:    "IPV4 Redirecting TCP port 8888 to 9999",
			Version: nftables.TableFamilyIPv4,
			DstNSRules: map[setenv.TestChain][]nftableslib.Rule{
				setenv.TestChain{
					"chain-1",
					nil,
				}: []nftableslib.Rule{
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
				setenv.TestChain{
					"chain-2",
					&nftableslib.ChainAttributes{
						Type:     nftables.ChainTypeNAT,
						Priority: 0,
						Hook:     nftables.ChainHookPrerouting,
					},
				}: []nftableslib.Rule{
					{
						L3: &nftableslib.L3Rule{
							Protocol: nftableslib.L3Protocol(unix.IPPROTO_TCP),
						},
						Action: setActionVerdict(unix.NFT_JUMP, "chain-1"),
					},
				},
			},
			Saddr:      "1.1.1.1/24",
			Daddr:      "1.1.1.2/24",
			Validation: validations.TCPPortRedirectValidation,
		},
		/* Currently by some unknown reasons, IPv6 refuses to bind to namespace's interface
		   This test will be re-enabled after the solution is found.
		{
			name:    "IPV6 ICMP Drop",
			version: nftables.TableFamilyIPv6,
			dstNSRules: map[testChain][]nftableslib.Rule{
				testChain{
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
							Protocol: nftableslib.L3Protocol(unix.IPPROTO_ICMPV6),
							Dst: &nftableslib.IPAddrSpec{
								List: []*nftableslib.IPAddr{setIPAddr("2001:1::2")},
							},
						},
						Action: setActionVerdict(nftableslib.NFT_DROP),
					},
				},
			},
			saddr: "2001:1::1",
			daddr: "2001:1::2",
		},
		*/
	}

	for _, tt := range tests {
		fmt.Printf("+++ Starting test: \"%s\" \n", tt.Name)
		t, err := setenv.NewP2PTestEnv(tt.Version, tt.Saddr, tt.Daddr)
		if err != nil {
			fmt.Printf("--- Test: \"%s\" failed with error: %+v\n", tt.Name, err)
			os.Exit(1)
		}
		defer t.Cleanup()
		// Get allocated namesapces and prepared ip addresses
		ns := t.GetNamespace()
		ip := t.GetIPs()

		// Initial connectivity test before applying any nftables rules are applied
		if err := setenv.TestICMP(ns[0], tt.Version, ip[0], ip[1]); err != nil {
			fmt.Printf("--- Test: \"%s\" failed during initial connectivity test with error: %+v\n", tt.Name, err)
			os.Exit(1)
		}
		if tt.SrcNSRules != nil {
			if err := setenv.NFTablesSet(ns[0], tt.Version, tt.SrcNSRules); err != nil {
				fmt.Printf("--- Test: \"%s\" failed to setup nftables table/chain/rule in a source namespace with error: %+v\n", tt.Name, err)
				os.Exit(1)
			}
		}
		if tt.DstNSRules != nil {
			if err := setenv.NFTablesSet(ns[1], tt.Version, tt.DstNSRules); err != nil {
				fmt.Printf("--- Test: \"%s\" failed to setup nftables table/chain/rule in a destination namespace with error: %+v\n", tt.Name, err)
				os.Exit(1)
			}
		}
		// Check if test's validation is set and execute validation.
		if tt.Validation != nil {
			if err := tt.Validation(tt.Version, ns, ip); err != nil {
				fmt.Printf("--- Test: \"%s\" failed validation error: %+v\n", tt.Name, err)
				os.Exit(1)
			}
		} else {
			fmt.Printf("--- Test: \"%s\" has no validation, test without validation is not allowed\n", tt.Name)
			os.Exit(1)
		}
		fmt.Printf("+++ Finished test: \"%s\" successfully.\n", tt.Name)
	}
}

func setActionVerdict(key int, chain ...string) *nftableslib.RuleAction {
	ra, err := nftableslib.SetVerdict(key, chain...)
	if err != nil {
		fmt.Printf("failed to SetVerdict with error: %+v\n", err)
		return nil
	}
	return ra
}

func setActionRedirect(port int, tproxy bool) *nftableslib.RuleAction {
	ra, err := nftableslib.SetRedirect(port, tproxy)
	if err != nil {
		fmt.Printf("failed to SetRedirect with error: %+v", err)
		return nil
	}
	return ra
}

func setIPAddr(addr string) *nftableslib.IPAddr {
	a, err := nftableslib.NewIPAddr(addr)
	if err != nil {
		fmt.Printf("error %+v return from NewIPAddr for address: %s\n", err, addr)
		return nil
	}
	return a
}