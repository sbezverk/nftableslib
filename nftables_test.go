package nftableslib

import (
	"testing"

	"github.com/google/nftables"
)

func TestAddNFTable(t *testing.T) {
	conn := InitConn()
	if conn == nil {
		t.Fatal("initialization of netlink connection failed")
	}
	conn.AddNFTable("filter", nftables.TableFamilyIPv4)
	exist, programmed := conn.NFTableExistAndProgrammed("filter", nftables.TableFamilyIPv4)
	if !exist {
		t.Fatalf("expected table %s of type %v to exist, but it does not", "filter", nftables.TableFamilyIPv4)
	}
	if programmed {
		t.Fatalf("expected table %s of type %v to be not programmed, but it does", "filter", nftables.TableFamilyIPv4)
	}
}
