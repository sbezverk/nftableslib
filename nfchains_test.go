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
	nft := InitNFTables(conn)
	nft.Tables().Create("test", nftables.TableFamilyIPv4)
	tbl, err := nft.Tables().Table("test", nftables.TableFamilyIPv4)
	if err != nil {
		t.Fatalf("failed to get chain interface for table test of type nftables.TableFamilyIPv4")
	}
	tbl.Chains().Create(
		"chain-1",
		nftables.ChainHookInput,
		nftables.ChainPriorityFilter,
		nftables.ChainTypeFilter)
}
