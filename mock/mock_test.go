package mock

import (
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

	p1 := nftableslib.L4PortList{
		L4Proto: unix.IPPROTO_TCP,
		Port:    []uint32{50705},
		Src:     true,
		Verdict: expr.Verdict{
			Kind:  unix.NFT_GOTO,
			Chain: "fake_chain_1",
		},
	}

	p2 := nftableslib.L4PortList{
		L4Proto: unix.IPPROTO_TCP,
		Port:    []uint32{12030},
		Src:     false,
	}

	m.ti.Tables().Table("filter-v4", nftables.TableFamilyIPv4).Chains().Chain("chain-1-v4").Rules().Create("rule-1-v4", nftableslib.ProcessL4Packet(p1))

	m.ti.Tables().Table("filter-v4", nftables.TableFamilyIPv4).Chains().Chain("chain-1-v4").Rules().Create("rule-2-v4", nftableslib.ProcessL4Packet(p2))

	m.ti.Tables().Create("filter-v6", nftables.TableFamilyIPv6)
	m.ti.Tables().Table("filter-v6", nftables.TableFamilyIPv6).Chains().Create(
		"chain-1-v6",
		nftables.ChainHookInput,
		nftables.ChainPriorityFilter,
		nftables.ChainTypeFilter)

	m.ti.Tables().Table("filter-v6", nftables.TableFamilyIPv6).Chains().Chain("chain-1-v6").Rules().Create("rule-1-v6", nftableslib.ProcessL4Packet(p1))
	m.ti.Tables().Table("filter-v6", nftables.TableFamilyIPv6).Chains().Chain("chain-1-v6").Rules().Create("rule-2-v6", nftableslib.ProcessL4Packet(p2))

	if err := m.Flush(); err != nil {
		t.Errorf("Failed Flushing Tables with error: %v", err)
	}

	nft, _ := m.ti.Tables().Dump()

	t.Logf("Resulting tables: %s", string(nft))

}
