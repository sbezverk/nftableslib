package mock

import (
	"net"
	"strconv"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/sbezverk/nftableslib"
	"golang.org/x/sys/unix"
)

func TestMock(t *testing.T) {
	ipv4Mask := uint8(12)
	ipv6Mask := uint8(64)
	port1 := uint16(8080)
	port2 := uint16(9090)
	port3 := uint16(8989)
	portRedirect := uint16(15001)

	ipv4Tests := []struct {
		name    string
		rule    nftableslib.Rule
		success bool
	}{
		{
			name: "Single IPv4 in list, source, no exclusion, with subnet mask",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Src: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{
							{
								&net.IPAddr{
									IP: net.ParseIP("192.0.2.0"),
								},
								true,
								&ipv4Mask,
							},
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_JUMP),
				},
				Exclude: false,
			},
			success: true,
		},
		{
			name: "Single IPv4 in list, source, no exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Src: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{
							{
								&net.IPAddr{
									IP: net.ParseIP("192.0.2.1"),
								},
								false,
								nil,
							},
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_JUMP),
				},
				Exclude: false,
			},
			success: true,
		},
		{
			name: "Single IPv4 in list, destination, exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{
							{
								&net.IPAddr{
									IP: net.ParseIP("192.0.2.1"),
								},
								false,
								nil,
							},
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_JUMP),
				},
				Exclude: true,
			},
			success: true,
		},
		{
			name: "Multiple IPv4s in list, source, exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{
							{
								&net.IPAddr{
									IP: net.ParseIP("192.0.2.1"),
								},
								false,
								nil,
							}, {
								&net.IPAddr{
									IP: net.ParseIP("192.0.3.1"),
								},
								false,
								nil,
							}, {
								&net.IPAddr{
									IP: net.ParseIP("192.0.4.1"),
								},
								false,
								nil,
							},
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_JUMP),
				},
				Exclude: true,
			},
			success: true,
		},
		{
			name: "Multiple IPv4s in list, destination, no exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{
							{
								&net.IPAddr{
									IP: net.ParseIP("192.0.2.1"),
								},
								false,
								nil,
							}, {
								&net.IPAddr{
									IP: net.ParseIP("192.0.3.1"),
								},
								false,
								nil,
							}, {
								&net.IPAddr{
									IP: net.ParseIP("192.0.4.1"),
								},
								false,
								nil,
							},
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_JUMP),
				},
				Exclude: false,
			},
			success: true,
		},
		{
			name: "IPv4 Range, destination, no exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Src: &nftableslib.IPAddrSpec{
						Range: [2]*nftableslib.IPAddr{
							{
								&net.IPAddr{
									IP: net.ParseIP("1.1.1.0"),
								},
								false,
								nil,
							}, {
								&net.IPAddr{
									IP: net.ParseIP("2.2.2.0"),
								},
								false,
								nil,
							},
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_JUMP),
				},
				Exclude: false,
			},
			success: true,
		},
	}
	ipv6Tests := []struct {
		name    string
		rule    nftableslib.Rule
		success bool
	}{
		{
			name: "Single IPv6 in list, source, no exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Src: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{
							{
								&net.IPAddr{
									IP: net.ParseIP("2001:0101::1"),
								},
								false,
								nil,
							},
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_JUMP),
				},
				Exclude: false,
			},
			success: true,
		},
		{
			name: "Single IPv6 in list, source, no exclusion, with subnet mask ",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Src: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{
							{
								&net.IPAddr{
									IP: net.ParseIP("2001:0101::"),
								},
								true,
								&ipv6Mask,
							},
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_JUMP),
				},
				Exclude: false,
			},
			success: true,
		},
		{
			name: "Single IPv6 in list, destination, exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{
							{
								&net.IPAddr{
									IP: net.ParseIP("fe80::1852:15be:a31d:5d2f"),
								},
								false,
								nil,
							},
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_JUMP),
				},
				Exclude: true,
			},
			success: true,
		},
		{
			name: "Multiple IPv6s in list, source, exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{
							{
								&net.IPAddr{
									IP: net.ParseIP("2001:0101::1"),
								},
								false,
								nil,
							}, {
								&net.IPAddr{
									IP: net.ParseIP("fe80::1852:15be:a31d:5d2f"),
								},
								false,
								nil,
							},
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_JUMP),
				},
				Exclude: true,
			},
			success: true,
		},
		{
			name: "Multiple IPv6s in list, destination, no exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{
							{
								&net.IPAddr{
									IP: net.ParseIP("2001:470:b87e:81::11"),
								},
								false,
								nil,
							}, {
								&net.IPAddr{
									IP: net.ParseIP("fe80::5054:ff:fe6c:1c4d"),
								},
								false,
								nil,
							}, {
								&net.IPAddr{
									IP: net.ParseIP("fe80::5054:ff:fecd:2379"),
								},
								false,
								nil,
							},
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_JUMP),
				},
				Exclude: false,
			},
			success: true,
		},
		{
			name: "IPv6 Range, destination, no exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddrSpec{
						Range: [2]*nftableslib.IPAddr{
							{
								&net.IPAddr{
									IP: net.ParseIP("2001:470:b87e:81::11"),
								},
								false,
								nil,
							}, {
								&net.IPAddr{
									IP: net.ParseIP("2001:470:b87e:89::11"),
								},
								false,
								nil,
							},
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind:  expr.VerdictKind(unix.NFT_JUMP),
					Chain: "fake_chain_1",
				},
				Exclude: false,
			},
			success: true,
		},
	}

	l4PortTests := []struct {
		name    string
		rule    nftableslib.Rule
		success bool
	}{
		{
			name: "L4 Single source port with verdict",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Src: &nftableslib.Port{
						List: []*uint16{
							&port1,
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind:  expr.VerdictKind(unix.NFT_JUMP),
					Chain: "fake_chain_1",
				},
			},
			success: true,
		},
		{
			name: "L4 Single destination port with verdict",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_UDP,
					Src: &nftableslib.Port{
						List: []*uint16{
							&port2,
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_RETURN),
				},
			},
			success: true,
		},
		{
			name: "L4 Single destination port with verdict and exclusion",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						List: []*uint16{
							&port1,
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_RETURN),
				},
				Exclude: true,
			},
			success: true,
		},
		{
			name: "L4 Single source port with redirect",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Src: &nftableslib.Port{
						List: []*uint16{
							&port1,
						},
					},
				},
				Redirect: &nftableslib.Redirect{
					Port: portRedirect,
				},
			},
			success: true,
		},
		{
			name: "L4 Single destination port with redirect",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_UDP,
					Dst: &nftableslib.Port{
						List: []*uint16{
							&port1,
						},
					},
				},
				Redirect: &nftableslib.Redirect{
					Port: portRedirect,
				},
			},
			success: true,
		},
		{
			name: "L4 Single destination port with redirect and exclusion",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						List: []*uint16{
							&port1,
						},
					},
				},
				Redirect: &nftableslib.Redirect{
					Port: portRedirect,
				},
				Exclude: true,
			},
			success: true,
		},
		{
			name: "L4 list of destination ports with redirects",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						List: []*uint16{
							&port1,
							&port2,
							&port3,
						},
					},
				},
				Redirect: &nftableslib.Redirect{
					Port: portRedirect,
				},
				Exclude: false,
			},
			success: true,
		},
		{
			name: "L4 list of destination ports with verdicts",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						List: []*uint16{
							&port1,
							&port2,
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_RETURN),
				},
				Exclude: false,
			},
			success: true,
		},
		{
			name: "L4 list of destination ports with redirects with exclude",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						List: []*uint16{
							&port1,
							&port2,
						},
					},
				},
				Redirect: &nftableslib.Redirect{
					Port: portRedirect,
				},
				Exclude: true,
			},
			success: true,
		},
		{
			name: "L4 list of destination ports with verdicts with exclude",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						List: []*uint16{
							&port1,
							&port2,
						},
					},
				},
				Exclude: true,
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_RETURN),
				},
			},
			success: true,
		},
		{
			name: "L4 Range of destination ports with redirects",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						Range: [2]*uint16{
							&port1,
							&port2,
						},
					},
				},
				Redirect: &nftableslib.Redirect{
					Port: portRedirect,
				},
				Exclude: false,
			},
			success: true,
		},
		{
			name: "L4 Range of destination ports with verdicts",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						Range: [2]*uint16{
							&port1,
							&port2,
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_RETURN),
				},
				Exclude: false,
			},
			success: true,
		},
		{
			name: "L4 range of destination ports with redirects with exclude",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						Range: [2]*uint16{
							&port1,
							&port2,
						},
					},
				},
				Redirect: &nftableslib.Redirect{
					Port: portRedirect,
				},
				Exclude: true,
			},
			success: true,
		},
		{
			name: "L4 Range of destination ports with verdicts with exclude",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						Range: [2]*uint16{
							&port1,
							&port2,
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_RETURN),
				},
				Exclude: true,
			},
			success: true,
		},
	}
	m := InitMockConn()
	m.ti.Tables().Create("filter-v4", nftables.TableFamilyIPv4)
	tblV4, err := m.ti.Tables().Table("filter-v4", nftables.TableFamilyIPv4)
	if err != nil {
		t.Fatalf("failed to get chain interface for table filter-v4")
	}
	chainAttrs := nftableslib.ChainAttributes{
		Hook:     nftables.ChainHookInput,
		Type:     nftables.ChainTypeFilter,
		Priority: nftables.ChainPriorityFilter,
	}
	tblV4.Chains().Create("chain-1-v4", &chainAttrs)

	m.ti.Tables().Create("filter-v6", nftables.TableFamilyIPv6)
	tblV6, err := m.ti.Tables().Table("filter-v6", nftables.TableFamilyIPv6)
	if err != nil {
		t.Fatalf("failed to get chain interface for table filter-v6")
	}
	tblV6.Chains().Create("chain-1-v6", &chainAttrs)

	for i, tt := range ipv4Tests {
		ri, err := tblV4.Chains().Chain("chain-1-v4")
		if err != nil {
			t.Fatalf("failed to get rules interface for chain chain-1-v4")
		}
		_, err = ri.Rules().Create("rule-00-v4-"+strconv.Itoa(i), &tt.rule)
		if err == nil && !tt.success {
			t.Errorf("Test: %s should fail but succeeded", tt.name)
		}
		if err != nil && tt.success {
			t.Errorf("Test: %s should succeed but fail with error: %v", tt.name, err)
		}
	}

	for i, tt := range ipv6Tests {
		ri, err := tblV6.Chains().Chain("chain-1-v6")
		if err != nil {
			t.Fatalf("failed to get rules interface for chain chain-1-v6")
		}
		_, err = ri.Rules().Create("rule-00-v6-"+strconv.Itoa(i), &tt.rule)
		if err == nil && !tt.success {
			t.Errorf("Test: %s should fail but succeeded", tt.name)
		}
		if err != nil && tt.success {
			t.Errorf("Test: %s should succeed but fail with error: %v", tt.name, err)
		}
	}

	for i, tt := range l4PortTests {
		ri, err := tblV4.Chains().Chain("chain-1-v4")
		if err != nil {
			t.Fatalf("failed to get rules interface for chain chain-1-v4")
		}
		_, err = ri.Rules().Create("rule-00-v4-"+strconv.Itoa(i), &tt.rule)
		if err == nil && !tt.success {
			t.Errorf("Test: %s should fail but succeeded", tt.name)
		}
		if err != nil && tt.success {
			t.Errorf("Test: %s should succeed but fail with error: %v", tt.name, err)
		}
	}

	if err := m.Flush(); err != nil {
		t.Errorf("Failed Flushing Tables with error: %v", err)
	}

	nft, _ := m.ti.Tables().Dump()

	t.Logf("Resulting tables: %s", string(nft))

}
