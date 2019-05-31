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

	/*
		p1 := nftableslib.Rule{
			L3: &nftableslib.L3Rule{
				Src: &nftableslib.IPAddr{
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
		}
	*/

	if err := m.Flush(); err != nil {
		t.Errorf("Failed Flushing Tables with error: %v", err)
	}

	nft, _ := m.ti.Tables().Dump()

	t.Logf("Resulting tables: %s", string(nft))

}
