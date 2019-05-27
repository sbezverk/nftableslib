package mock

import (
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"golang.org/x/sys/unix"
)

func TestMock(t *testing.T) {
	m := InitMockConn()
	m.ti.Tables().Create("filter", nftables.TableFamilyIPv4)
	m.ti.Tables().Table("filter", nftables.TableFamilyIPv4).Chains().Create(
		"chain-1",
		nftables.ChainHookInput,
		nftables.ChainPriorityFilter,
		nftables.ChainTypeFilter)

	p := nftableslib.Packet{
		L4Proto: unix.IPPROTO_TCP,
		SrcPort: uint32(50705),
		DstAddr: net.ParseIP("127.0.0.1"),
	}

	m.ti.Tables().Table("filter", nftables.TableFamilyIPv4).Chains().Chain("chain-1").Rules().Create("rule-1", nftableslib.ProcessIPv4Packet(p))

	if err := m.Flush(); err != nil {
		t.Errorf("Failed Flushing Tables with error: %v", err)
	}

	nft, _ := m.ti.Tables().Dump()

	t.Logf("Resulting tables: %s", string(nft))

}
