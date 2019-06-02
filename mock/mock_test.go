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
	ipv4Tests := []struct {
		name    string
		rule    nftableslib.Rule
		success bool
	}{
		{
			name: "Single IPv4 in list, source, no exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Src: &nftableslib.IPAddr{
						List: []*net.IPAddr{
							&net.IPAddr{
								IP: net.ParseIP("192.0.2.1"),
							},
						},
					},
					Exclude: false,
					Verdict: &expr.Verdict{
						Kind: expr.VerdictKind(unix.NFT_JUMP),
					},
				},
			},
			success: true,
		},
		{
			name: "Single IPv4 in list, destination, exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddr{
						List: []*net.IPAddr{
							&net.IPAddr{
								IP: net.ParseIP("192.0.2.1"),
							},
						},
					},
					Exclude: true,
					Verdict: &expr.Verdict{
						Kind: expr.VerdictKind(unix.NFT_JUMP),
					},
				},
			},
			success: true,
		},
		{
			name: "Multiple IPv4s in list, source, exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddr{
						List: []*net.IPAddr{
							&net.IPAddr{
								IP: net.ParseIP("192.0.2.1"),
							},
							&net.IPAddr{
								IP: net.ParseIP("192.0.3.1"),
							},
							&net.IPAddr{
								IP: net.ParseIP("192.0.4.1"),
							},
						},
					},
					Exclude: true,
					Verdict: &expr.Verdict{
						Kind: expr.VerdictKind(unix.NFT_JUMP),
					},
				},
			},
			success: true,
		},
		{
			name: "Multiple IPv4s in list, destination, no exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddr{
						List: []*net.IPAddr{
							&net.IPAddr{
								IP: net.ParseIP("192.0.2.1"),
							},
							&net.IPAddr{
								IP: net.ParseIP("192.0.3.1"),
							},
							&net.IPAddr{
								IP: net.ParseIP("192.0.4.1"),
							},
						},
					},
					Exclude: false,
					Verdict: &expr.Verdict{
						Kind: expr.VerdictKind(unix.NFT_JUMP),
					},
				},
			},
			success: true,
		},
		{
			name: "IPv4 Range, destination, no exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Src: &nftableslib.IPAddr{
						Range: [2]*net.IPAddr{
							&net.IPAddr{
								IP: net.ParseIP("1.1.1.0"),
							},
							&net.IPAddr{
								IP: net.ParseIP("2.2.2.0"),
							},
						},
					},
					Exclude: false,
					Verdict: &expr.Verdict{
						Kind: expr.VerdictKind(unix.NFT_JUMP),
					},
				},
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
					Src: &nftableslib.IPAddr{
						List: []*net.IPAddr{
							&net.IPAddr{
								IP: net.ParseIP("2001:0101::1"),
							},
						},
					},
					Exclude: false,
					Verdict: &expr.Verdict{
						Kind: expr.VerdictKind(unix.NFT_JUMP),
					},
				},
			},
			success: true,
		},
		{
			name: "Single IPv6 in list, destination, exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddr{
						List: []*net.IPAddr{
							&net.IPAddr{
								IP: net.ParseIP("fe80::1852:15be:a31d:5d2f"),
							},
						},
					},
					Exclude: true,
					Verdict: &expr.Verdict{
						Kind: expr.VerdictKind(unix.NFT_JUMP),
					},
				},
			},
			success: true,
		},
		{
			name: "Multiple IPv6s in list, source, exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddr{
						List: []*net.IPAddr{
							&net.IPAddr{
								IP: net.ParseIP("2001:0101::1"),
							},
							&net.IPAddr{
								IP: net.ParseIP("fe80::1852:15be:a31d:5d2f"),
							},
						},
					},
					Exclude: true,
					Verdict: &expr.Verdict{
						Kind: expr.VerdictKind(unix.NFT_JUMP),
					},
				},
			},
			success: true,
		},
		{
			name: "Multiple IPv6s in list, destination, no exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddr{
						List: []*net.IPAddr{
							&net.IPAddr{
								IP: net.ParseIP("2001:470:b87e:81::11"),
							},
							&net.IPAddr{
								IP: net.ParseIP("fe80::5054:ff:fe6c:1c4d"),
							},
							&net.IPAddr{
								IP: net.ParseIP("fe80::5054:ff:fecd:2379"),
							},
						},
					},
					Exclude: false,
					Verdict: &expr.Verdict{
						Kind: expr.VerdictKind(unix.NFT_JUMP),
					},
				},
			},
			success: true,
		},
		{
			name: "IPv6 Range, destination, no exclusion",
			rule: nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddr{
						Range: [2]*net.IPAddr{
							&net.IPAddr{
								IP: net.ParseIP("2001:470:b87e:81::11"),
							},
							&net.IPAddr{
								IP: net.ParseIP("2001:470:b87e:89::11"),
							},
						},
					},
					Exclude: false,
					Verdict: &expr.Verdict{
						Kind:  expr.VerdictKind(unix.NFT_JUMP),
						Chain: "fake_chain_1",
					},
				},
			},
			success: true,
		},
	}

	port1 := uint32(8080)
	port2 := uint32(9090)
	portRedirect := uint32(15001)

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
						List: []*uint32{
							&port1,
						},
					},
					Verdict: &expr.Verdict{
						Kind:  expr.VerdictKind(unix.NFT_JUMP),
						Chain: "fake_chain_1",
					},
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
						List: []*uint32{
							&port2,
						},
					},
					Verdict: &expr.Verdict{
						Kind: expr.VerdictKind(unix.NFT_RETURN),
					},
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
						List: []*uint32{
							&port1,
						},
					},
					Verdict: &expr.Verdict{
						Kind: expr.VerdictKind(unix.NFT_RETURN),
					},
					Exclude: true,
				},
			},
			success: true,
		},
		{
			name: "L4 Single source port with redirect",
			rule: nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Src: &nftableslib.Port{
						List: []*uint32{
							&port1,
						},
					},
					Redirect: &portRedirect,
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
						List: []*uint32{
							&port1,
						},
					},
					Redirect: &portRedirect,
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
						List: []*uint32{
							&port1,
						},
					},
					Redirect: &portRedirect,
					Exclude:  true,
				},
			},
			success: true,
		},
	}
	m := InitMockConn()
	m.ti.Tables().Create("filter-v4", nftables.TableFamilyIPv4)
	m.ti.Tables().Table("filter-v4", nftables.TableFamilyIPv4).Chains().Create(
		"chain-1-v4",
		nftables.ChainHookInput,
		nftables.ChainPriorityFilter,
		nftables.ChainTypeFilter)

	m.ti.Tables().Create("filter-v6", nftables.TableFamilyIPv6)
	m.ti.Tables().Table("filter-v6", nftables.TableFamilyIPv6).Chains().Create(
		"chain-1-v6",
		nftables.ChainHookInput,
		nftables.ChainPriorityFilter,
		nftables.ChainTypeFilter)

	for i, tt := range ipv4Tests {
		if err := m.ti.Tables().Table("filter-v4", nftables.TableFamilyIPv4).Chains().Chain("chain-1-v4").Rules().Create("rule-00-v4-"+strconv.Itoa(i), &tt.rule); err != nil {
			t.Errorf("Test: %s failed with error: %v", tt.name, err)
		}
	}

	for i, tt := range ipv6Tests {
		if err := m.ti.Tables().Table("filter-v6", nftables.TableFamilyIPv6).Chains().Chain("chain-1-v6").Rules().Create("rule-00-v6-"+strconv.Itoa(i), &tt.rule); err != nil {
			t.Errorf("Test: %s failed with error: %v", tt.name, err)
		}
	}

	for i, tt := range l4PortTests {
		if err := m.ti.Tables().Table("filter-v4", nftables.TableFamilyIPv4).Chains().Chain("chain-1-v4").Rules().Create("rule-00-v4-"+strconv.Itoa(i), &tt.rule); err != nil {
			t.Errorf("Test: %s failed with error: %v", tt.name, err)
		}
	}

	if err := m.Flush(); err != nil {
		t.Errorf("Failed Flushing Tables with error: %v", err)
	}

	nft, _ := m.ti.Tables().Dump()

	t.Logf("Resulting tables: %s", string(nft))

}
