package nftableslib

import (
	"testing"

	"github.com/google/nftables"
)

func TestCreateTable(t *testing.T) {
	conn := InitConn()
	if conn == nil {
		t.Fatal("initialization of netlink connection failed")
	}
	nft := InitNFTables(conn)
	nft.Tables().Create("filter", nftables.TableFamilyIPv4)
	if !nft.Tables().Exist("filter", nftables.TableFamilyIPv4) {
		t.Fatalf("expected table %s of type %v to exist, but it does not", "filter", nftables.TableFamilyIPv4)
	}
}

func TestCreateMultipleTable(t *testing.T) {
	conn := InitConn()
	if conn == nil {
		t.Fatal("initialization of netlink connection failed")
	}
	nft := InitNFTables(conn)
	nft.Tables().Create("filter-1", nftables.TableFamilyIPv4)
	nft.Tables().Create("filter-2", nftables.TableFamilyIPv4)
	nft.Tables().Create("filter-1", nftables.TableFamilyIPv6)
	nft.Tables().Create("filter-2", nftables.TableFamilyIPv6)
	if !nft.Tables().Exist("filter-1", nftables.TableFamilyIPv4) {
		t.Fatalf("expected table %s of type %v to exist, but it does not", "filter", nftables.TableFamilyIPv4)
	}
	if !nft.Tables().Exist("filter-2", nftables.TableFamilyIPv4) {
		t.Fatalf("expected table %s of type %v to exist, but it does not", "filter", nftables.TableFamilyIPv4)
	}
	if !nft.Tables().Exist("filter-1", nftables.TableFamilyIPv6) {
		t.Fatalf("expected table %s of type %v to exist, but it does not", "filter", nftables.TableFamilyIPv4)
	}
	if !nft.Tables().Exist("filter-2", nftables.TableFamilyIPv6) {
		t.Fatalf("expected table %s of type %v to exist, but it does not", "filter", nftables.TableFamilyIPv4)
	}
	b, _ := nft.Tables().Dump()
	t.Logf("Resulting tables: %s", string(b))
}

func TestDeleteNFTable(t *testing.T) {
	conn := InitConn()
	if conn == nil {
		t.Fatal("initialization of netlink connection failed")
	}
	nft := InitNFTables(conn)
	nft.Tables().Create("filter", nftables.TableFamilyIPv4)
	nft.Tables().DeleteImm("filter", nftables.TableFamilyIPv4)
	exist := nft.Tables().Exist("filter", nftables.TableFamilyIPv4)
	if exist {
		t.Fatalf("expected table %s of type %v not exist, but it does", "filter", nftables.TableFamilyIPv4)
	}
}

func BenchmarkCreateTable(b *testing.B) {
	conn := InitConn()
	if conn == nil {
		b.Fatal("initialization of netlink connection failed")
	}
	nft := InitNFTables(conn)
	for i := 0; i < b.N; i++ {
		if err := nft.Tables().Create("filter", nftables.TableFamilyIPv4); err != nil {
			b.Fatalf("test \"TestCreateExistingNFTable\" failed to create table filter with error: %+v", err)
		}
		if err := nft.Tables().Delete("filter", nftables.TableFamilyIPv4); err != nil {
			b.Fatalf("test \"TestCreateExistingNFTable\" failed to delete table filter with error: %+v", err)
		}
	}
}
