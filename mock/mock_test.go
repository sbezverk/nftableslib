package mock

import (
	"testing"
	// "github.com/sbezverk/nftableslib"
	"github.com/google/nftables"
)

func TestMock(t *testing.T) {
	m := InitMockConn()
	m.ti.Tables().Create("filter", nftables.TableFamilyIPv4)
	m.ti.Tables().Table("filter", nftables.TableFamilyIPv4).Chains().Create(
		"chain-1",
		nftables.ChainHookInput,
		nftables.ChainPriorityFilter,
		nftables.ChainTypeFilter)
	if err := m.Flush(); err != nil {
		t.Errorf("Failed Flushing Tables with error: %v", err)
	}

	nft, _ := m.ti.Tables().Dump()

	t.Logf("Resulting tables: %s", string(nft))

}
