package nftableslib

import (
	"testing"

	"github.com/google/nftables"
)

func TestChains(t *testing.T) {
	tests := []struct {
		name       string
		chain      string
		attributes *ChainAttributes
		success    bool
	}{
		{
			name:  "Base chain, correct attributes",
			chain: "chain-1",
			attributes: &ChainAttributes{
				Hook:     nftables.ChainHookInput,
				Priority: nftables.ChainPriorityFilter,
				Type:     nftables.ChainTypeFilter,
			},
			success: true,
		},
		{
			name:  "Base chain, missing type",
			chain: "chain-2",
			attributes: &ChainAttributes{
				Hook:     nftables.ChainHookInput,
				Priority: nftables.ChainPriorityFilter,
				Type:     "",
			},
			success: false,
		},
		{
			name:       "Regular chain",
			chain:      "chain-3",
			attributes: nil,
			success:    true,
		},
	}
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
	defer nft.Tables().Delete("test", nftables.TableFamilyIPv4)
	for _, tt := range tests {
		err := tbl.Chains().Create(tt.chain, tt.attributes)
		if err != nil && tt.success {
			t.Errorf("test: %s failed with error: %+v but supposed to succeed", tt.name, err)
			continue
		}
		if err == nil && !tt.success {
			t.Errorf("test: \"%s\" succeed but supposed to fail", tt.name)
			continue
		}
	}
}
