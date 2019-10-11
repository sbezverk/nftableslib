package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"

	"github.com/google/nftables"
	"github.com/google/uuid"
	"github.com/sbezverk/nftableslib"
	"github.com/sbezverk/nftableslib/e2e/setenv"
	"github.com/vishvananda/netns"
)

type testChain struct {
	name string
	attr *nftableslib.ChainAttributes
}

type nftablesTest struct {
	name       string
	version    nftables.TableFamily
	srcNSRules map[testChain][]nftableslib.Rule
	dstNSRules map[testChain][]nftableslib.Rule
	saddr      string
	daddr      string
	validation func(nftables.TableFamily, []netns.NsHandle, []*nftableslib.IPAddr) error
}

func init() {
	runtime.LockOSThread()
}

func main() {
	tests := []nftablesTest{
		/*		{
					name:    "IPV4 ICMP Drop",
					version: nftables.TableFamilyIPv4,
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
									Protocol: nftableslib.L3Protocol(unix.IPPROTO_ICMP),
									Dst: &nftableslib.IPAddrSpec{
										List: []*nftableslib.IPAddr{setIPAddr("1.1.1.2")},
									},
								},
								Action: setActionVerdict(nftableslib.NFT_DROP),
							},
						},
					},
					saddr:      "1.1.1.1/24",
					daddr:      "1.1.1.2/24",
					validation: icmpDropTestValidation,
				},
		*/
		{
			name:    "IPV4 Redirecting TCP port 8888 to 9999",
			version: nftables.TableFamilyIPv4,
			dstNSRules: map[testChain][]nftableslib.Rule{
				testChain{
					"chain-1",
					nil,
				}: []nftableslib.Rule{
					{
						L4: &nftableslib.L4Rule{
							L4Proto: unix.IPPROTO_TCP,
							Dst: &nftableslib.Port{
								List: nftableslib.SetPortList([]int{8888}),
							},
						},
						Action: setActionRedirect(9999, false),
					},
				},
				testChain{
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
			saddr:      "1.1.1.1/24",
			daddr:      "1.1.1.2/24",
			validation: tcpPortRedirectValidation,
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
		t, err := setenv.NewP2PTestEnv(tt.version, tt.saddr, tt.daddr)
		if err != nil {
			fmt.Printf("test: \"%s\" failed with error: %+v\n", tt.name, err)
			os.Exit(1)
		}
		defer t.Cleanup()
		// Get allocated namesapces and prepared ip addresses
		ns := t.GetNamespace()
		ip := t.GetIPs()

		// Initial connectivity test before applying any nftables rules are applied
		if err := setenv.TestICMP(ns[0], tt.version, ip[0], ip[1]); err != nil {
			fmt.Printf("test: \"%s\" failed during initial connectivity test with error: %+v\n", tt.name, err)
			os.Exit(1)
		}
		if tt.srcNSRules != nil {
			if err := nftablesSet(ns[0], tt.version, tt.srcNSRules); err != nil {
				fmt.Printf("test: \"%s\" failed to setup nftables table/chain/rule in a source namespace with error: %+v\n", tt.name, err)
				os.Exit(1)
			}
		}
		// for debugging
		time.Sleep(time.Second * 10)
		if tt.dstNSRules != nil {
			if err := nftablesSet(ns[1], tt.version, tt.dstNSRules); err != nil {
				fmt.Printf("test: \"%s\" failed to setup nftables table/chain/rule in a destination namespace with error: %+v\n", tt.name, err)
				os.Exit(1)
			}
		}
		// for debugging
		time.Sleep(time.Second * 10)
		if tt.validation != nil {
			if err := tt.validation(tt.version, ns, ip); err != nil {
				fmt.Printf("test: \"%s\" failed validation error: %+v\n", tt.name, err)
				os.Exit(1)
			}
		} else {
			fmt.Printf("test: \"%s\" has no validation, test without validation is not allowed\n", tt.name)
			os.Exit(1)
		}
	}
	fmt.Printf("All tests succeeded...\n")
}

func nftablesSet(ns netns.NsHandle, version nftables.TableFamily, nfrules map[testChain][]nftableslib.Rule) error {
	conn := nftableslib.InitConn(int(ns))
	ti := nftableslib.InitNFTables(conn)

	tn := uuid.New().String()[:8]
	if err := ti.Tables().CreateImm(tn, version); err != nil {
		return fmt.Errorf("failed to create table with error: %+v", err)
	}
	ci, err := ti.Tables().Table(tn, version)
	if err != nil {
		return fmt.Errorf("failed to get chains interface for table %s with error: %+v", tn, err)
	}

	for chain, rules := range nfrules {
		if err := ci.Chains().CreateImm(chain.name, chain.attr); err != nil {
			return fmt.Errorf("failed to create chain with error: %+v", err)
		}
		ri, err := ci.Chains().Chain(chain.name)
		if err != nil {
			return fmt.Errorf("failed to get rules interface for chain with error: %+v", err)
		}
		for _, rule := range rules {
			if _, err = ri.Rules().CreateImm(&rule); err != nil {
				return fmt.Errorf("failed to create rule with error: %+v", err)
			}
		}
	}

	return nil
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
