package nftableslib

import (
	"testing"

	"github.com/google/nftables"
)

func TestChains(t *testing.T) {
	conn := InitConn()
	if conn == nil {
		t.Fatal("initialization of netlink connection failed")
	}
	conn.Tables().Create("test", nftables.TableFamilyIPv4)
	conn.Tables().Table("test", nftables.TableFamilyIPv4).Chains().Create(
		"chain-1",
		nftables.ChainHookInput,
		nftables.ChainPriorityFilter,
		nftables.ChainTypeFilter)
}
