package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"

	"net/http"
	_ "net/http/pprof"

	"golang.org/x/sys/unix"

	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"github.com/sbezverk/nftableslib/pkg/e2e/setenv"
)

var (
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	accept     = nftableslib.ChainPolicyAccept
)

var tests = []setenv.NFTablesTest{
	{
		Name:    "IPV4 ICMP Drop",
		Version: nftables.TableFamilyIPv4,
		DstNFRules: []setenv.TestChain{
			{
				Name: "chain-1",
				Attr: &nftableslib.ChainAttributes{
					Type:     nftables.ChainTypeFilter,
					Priority: nftables.ChainPriorityFirst,
					Hook:     nftables.ChainHookInput,
					Policy:   &accept,
				},
				Rules: []nftableslib.Rule{
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
		},
	},
	{
		Name:    "IPV4 Redirecting TCP port 8888 to 9999",
		Version: nftables.TableFamilyIPv4,
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
					Type:     nftables.ChainTypeNAT,
					Priority: nftables.ChainPriorityFirst,
					Hook:     nftables.ChainHookPrerouting,
				},
				Rules: []nftableslib.Rule{
					{
						L3: &nftableslib.L3Rule{
							Protocol: nftableslib.L3Protocol(unix.IPPROTO_TCP),
						},
						Action: setActionVerdict(unix.NFT_JUMP, "chain-1"),
					},
				},
			},
		},
	},
	{
		Name:    "IPV6 Redirecting TCP port 8888 to 9999",
		Version: nftables.TableFamilyIPv6,
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
					Type:     nftables.ChainTypeNAT,
					Priority: nftables.ChainPriorityFirst,
					Hook:     nftables.ChainHookPrerouting,
				},
				Rules: []nftableslib.Rule{
					{
						L3: &nftableslib.L3Rule{
							Protocol: nftableslib.L3Protocol(unix.IPPROTO_TCP),
						},
						Action: setActionVerdict(unix.NFT_JUMP, "chain-1"),
					},
				},
			},
		},
	},
	{
		Name:    "IPV4 TCP SNAT",
		Version: nftables.TableFamilyIPv4,
		SrcNFRules: []setenv.TestChain{
			{
				Name: "chain-1",
				Attr: &nftableslib.ChainAttributes{
					Type:     nftables.ChainTypeNAT,
					Priority: nftables.ChainPriorityFirst,
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
	},
	{
		Name:    "IPV6 TCP SNAT",
		Version: nftables.TableFamilyIPv6,
		SrcNFRules: []setenv.TestChain{
			{
				Name: "chain-1",
				Attr: &nftableslib.ChainAttributes{
					Type:     nftables.ChainTypeNAT,
					Priority: nftables.ChainPriorityFirst,
					Hook:     nftables.ChainHookPostrouting,
				},
				Rules: []nftableslib.Rule{
					{
						L3: &nftableslib.L3Rule{
							Protocol: nftableslib.L3Protocol(unix.IPPROTO_TCP),
						},
						Action: setSNAT(&nftableslib.NATAttributes{
							L3Addr: [2]*nftableslib.IPAddr{setIPAddr("2001:1234::1")},
							Port:   [2]uint16{7777},
						})},
				},
			},
		},
	},
	{
		Name:    "IPV4 UDP SNAT",
		Version: nftables.TableFamilyIPv4,
		SrcNFRules: []setenv.TestChain{
			{
				Name: "chain-1",
				Attr: &nftableslib.ChainAttributes{
					Type:     nftables.ChainTypeNAT,
					Priority: nftables.ChainPriorityFirst,
					Hook:     nftables.ChainHookPostrouting,
				},
				Rules: []nftableslib.Rule{
					{
						L3: &nftableslib.L3Rule{
							Protocol: nftableslib.L3Protocol(unix.IPPROTO_UDP),
						},
						Action: setSNAT(&nftableslib.NATAttributes{
							L3Addr: [2]*nftableslib.IPAddr{setIPAddr("5.5.5.5")},
							Port:   [2]uint16{7777},
						}),
					},
				},
			},
		},
	},
	{
		Name:    "IPV6 UDP SNAT",
		Version: nftables.TableFamilyIPv6,
		SrcNFRules: []setenv.TestChain{
			{
				Name: "chain-1",
				Attr: &nftableslib.ChainAttributes{
					Type:     nftables.ChainTypeNAT,
					Priority: nftables.ChainPriorityFirst,
					Hook:     nftables.ChainHookPostrouting,
				},
				Rules: []nftableslib.Rule{
					{
						L3: &nftableslib.L3Rule{
							Protocol: nftableslib.L3Protocol(unix.IPPROTO_UDP),
						},
						Action: setSNAT(&nftableslib.NATAttributes{
							L3Addr: [2]*nftableslib.IPAddr{setIPAddr("2001:1234::1")},
							Port:   [2]uint16{7777},
						})},
				},
			},
		},
	},
	{
		Name:    "IPV6 ICMP Drop",
		Version: nftables.TableFamilyIPv6,
		DstNFRules: []setenv.TestChain{
			{
				Name: "chain-1",
				Attr: &nftableslib.ChainAttributes{
					Type:     nftables.ChainTypeFilter,
					Priority: nftables.ChainPriorityFirst,
					Hook:     nftables.ChainHookInput,
					Policy:   &accept,
				},
				Rules: []nftableslib.Rule{
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
		},
	},
}

func init() {
	runtime.LockOSThread()
}

func main() {
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fmt.Printf("failed to create cpu profiling file with error: %+v\n", err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	// Starting web server to make available performance characteristics
	go func() {
		fmt.Println("Starting web server", http.ListenAndServe("localhost:6060", nil))
	}()

	ns, err := setenv.NewNS()
	if err != nil {
		fmt.Printf("failed to create test namespace with error: %+v\n", err)
		os.Exit(1)
	}
	stopIPv4 := make(chan struct{})
	errIPv4 := make(chan struct{})
	stopIPv6 := make(chan struct{})
	errIPv6 := make(chan struct{})
	ti := setenv.MakeTablesInterface(ns)

	// Go routine concurrently programming IPv4 chains and rules, upon success
	// it removes created artifacts.
	go func() {
		err := runTests(ti, nftables.TableFamilyIPv4, tests, stopIPv4, errIPv4)
		if err != nil {
			fmt.Printf("failed to start ipv4 tester with error: %+v\n", err)
			ns.Close()
			os.Exit(1)
		}
	}()

	// Go routine concurrently programming IPv6 chains and rules, upon success
	// it removes created artifacts.
	go func() {
		err := runTests(ti, nftables.TableFamilyIPv6, tests, stopIPv6, errIPv6)
		if err != nil {
			fmt.Printf("failed to start ipv6 tester with error: %+v\n", err)
			ns.Close()
			os.Exit(1)
		}
	}()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	fmt.Printf("Waiting for Ctrl-C\n")
	select {
	case <-c:
		stopIPv4 <- struct{}{}
		stopIPv6 <- struct{}{}
		fmt.Printf("Waiting on stop to close\n")
		<-stopIPv4
		<-stopIPv6
	case <-errIPv4:
		fmt.Printf("ipv4 test error recieved, stop testing\n")
		stopIPv6 <- struct{}{}
	case <-errIPv6:
		fmt.Printf("ipv6 test error recieved, stop testing\n")
		stopIPv4 <- struct{}{}
	}

	ns.Close()
	fmt.Printf("Finished\n")
}

func runTests(ti nftableslib.TablesInterface, family nftables.TableFamily, tests []setenv.NFTablesTest, stopCh chan struct{}, errCh chan struct{}) error {
	tn := "tableipv4"
	fm := "IPv4"
	if family == nftables.TableFamilyIPv6 {
		tn = "tableipv6"
		fm = "IPv6"
	}
	fmt.Printf("Running tests for family: %+v\n", fm)
	if err := ti.Tables().CreateImm(tn, family); err != nil {
		return fmt.Errorf("failed to create table %s with error: %+v", tn, err)
	}
	ci, err := ti.Tables().Table(tn, family)
	if err != nil {
		return fmt.Errorf("failed to get chains interface for table %s with error: %+v", tn, err)
	}

	for {
		for _, test := range tests {
			if test.Version != family {
				continue
			}
			chainRH, err := programTest(ci, test)
			if err != nil {
				fmt.Printf("failed to program test %s with error: %+v\n", test.Name, err)
				errCh <- struct{}{}
				return err
			}
			if err := cleanupTest(ci, test, chainRH); err != nil {
				fmt.Printf("failed to cleanup for test %s with error: %+v\n", test.Name, err)
				errCh <- struct{}{}
				return err
			}
			select {
			case <-stopCh:
				fmt.Printf("\nStop received\n")
				close(errCh)
				close(stopCh)
				return nil
			default:
			}
		}
	}
}

func programTest(ci nftableslib.ChainsInterface, test setenv.NFTablesTest) (map[string][]uint64, error) {
	chains := test.DstNFRules
	if test.SrcNFRules != nil {
		chains = test.SrcNFRules
	}
	chainRH := make(map[string][]uint64)
	for _, chain := range chains {
		if err := ci.Chains().CreateImm(chain.Name, chain.Attr); err != nil {
			return nil, fmt.Errorf("failed to create chain with error: %+v", err)
		}
		ri, err := ci.Chains().Chain(chain.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to get rules interface for chain with error: %+v", err)
		}
		rhs := make([]uint64, 0)
		for _, rule := range chain.Rules {
			rh, err := ri.Rules().CreateImm(&rule)
			if err != nil {
				return nil, fmt.Errorf("failed to create rule with error: %+v", err)
			}
			rhs = append(rhs, rh)
		}
		chainRH[chain.Name] = rhs
	}
	return chainRH, nil
}

func cleanupTest(ci nftableslib.ChainsInterface, test setenv.NFTablesTest, chainRH map[string][]uint64) error {
	for chain, rhs := range chainRH {
		ri, err := ci.Chains().Chain(chain)
		if err != nil {
			return fmt.Errorf("failed to get rules interface for chain with error: %+v", err)
		}
		for i := len(rhs) - 1; i >= 0; i-- {
			if err = ri.Rules().DeleteImm(rhs[i]); err != nil {
				return fmt.Errorf("failed to delete rule with error: %+v", err)
			}
		}
	}
	for chain := range chainRH {
		if err := ci.Chains().DeleteImm(chain); err != nil {
			return fmt.Errorf("failed to delete chain with error: %+v", err)
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
		fmt.Printf("failed to SetRedirect with error: %+v\n", err)
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

func setSNAT(attrs *nftableslib.NATAttributes) *nftableslib.RuleAction {
	ra, err := nftableslib.SetSNAT(attrs)
	if err != nil {
		fmt.Printf("error %+v return from SetSNAT call\n", err)
		return nil
	}
	return ra
}

func setDNAT(attrs *nftableslib.NATAttributes) *nftableslib.RuleAction {
	ra, err := nftableslib.SetDNAT(attrs)
	if err != nil {
		fmt.Printf("error %+v return from SetSNAT call\n", err)
		return nil
	}
	return ra
}
