package mock

import (
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/sbezverk/nftableslib"
	"golang.org/x/sys/unix"
)

func TestMock(t *testing.T) {
	m := InitMockConn()
	m.ti.Tables().Create("filter-v4", nftables.TableFamilyIPv4)
	m.ti.Tables().Table("filter-v4", nftables.TableFamilyIPv4).Chains().Create(
		"chain-1-v4",
		nftables.ChainHookInput,
		nftables.ChainPriorityFilter,
		nftables.ChainTypeFilter)

	p1 := nftableslib.Rule{
		L3: &nftableslib.L3Rule{
			Src: &nftableslib.IPAddr{
				Exclude: false,
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
			Verdict: &expr.Verdict{
				Kind: expr.VerdictKind(unix.NFT_JUMP),
			},
		},
	}

	if err := m.ti.Tables().Table("filter-v4", nftables.TableFamilyIPv4).Chains().Chain("chain-1-v4").Rules().Create("rule-1-v4", &p1); err != nil {
		t.Errorf("Fail to create rule: %+v with error: %+v", p1, err)
	}

	/*
		m.ti.Tables().Table("filter-v4", nftables.TableFamilyIPv4).Chains().Chain("chain-1-v4").Rules().Create("rule-2-v4", nftableslib.ProcessL4Packet(p2))

		m.ti.Tables().Create("filter-v6", nftables.TableFamilyIPv6)
		m.ti.Tables().Table("filter-v6", nftables.TableFamilyIPv6).Chains().Create(
			"chain-1-v6",
			nftables.ChainHookInput,
			nftables.ChainPriorityFilter,
			nftables.ChainTypeFilter)

		m.ti.Tables().Table("filter-v6", nftables.TableFamilyIPv6).Chains().Chain("chain-1-v6").Rules().Create("rule-1-v6", nftableslib.ProcessL4Packet(p1))
		m.ti.Tables().Table("filter-v6", nftables.TableFamilyIPv6).Chains().Chain("chain-1-v6").Rules().Create("rule-2-v6", nftableslib.ProcessL4Packet(p2))
	*/
	if err := m.Flush(); err != nil {
		t.Errorf("Failed Flushing Tables with error: %v", err)
	}

	nft, _ := m.ti.Tables().Dump()

	t.Logf("Resulting tables: %s", string(nft))

}
