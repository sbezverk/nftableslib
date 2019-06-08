package main

import (
	"fmt"
	"net"
	"os"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/sbezverk/nftableslib"
	"golang.org/x/sys/unix"
)

func main() {
	// Initializing netlink connecrtion
	conn := nftableslib.InitConn()
	ti := nftableslib.InitNFTables(conn)
	fmt.Printf("Cleaning nftable...\n")
	conn.FlushRuleset()

	ti.Tables().Create("ipv4table", nftables.TableFamilyIPv4)
	fmt.Printf("Programming nftable...\n")
	if err := conn.Flush(); err != nil {
		fmt.Printf("Failed to programm nftable with error: %+v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Programming nftable succeeded.\n")

	ti.Tables().Table("ipv4table", nftables.TableFamilyIPv4).Chains().Create("ipv4chain-1", nftables.ChainHookPrerouting,
		nftables.ChainPriorityFirst, nftables.ChainTypeFilter)
	fmt.Printf("Programming chain...\n")
	if err := conn.Flush(); err != nil {
		fmt.Printf("Failed to programm nftable with error: %+v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Programming chain succeeded.\n")
	port1 := uint32(8182)
	// rule1Mask := uint8(25)
	rule1 := nftableslib.Rule{
		L3: &nftableslib.L3Rule{
			Dst: &nftableslib.IPAddrSpec{
				List: []*nftableslib.IPAddr{
					{
						&net.IPAddr{
							IP: net.ParseIP("192.168.20.1"),
						},
						false,
						nil, // &rule1Mask,
					},
				},
			},
			Verdict: &expr.Verdict{
				Kind: expr.VerdictKind(unix.NFT_JUMP),
			},
		},
	}

	rule2 := nftableslib.Rule{
		L4: &nftableslib.L4Rule{
			L4Proto: unix.IPPROTO_TCP,
			Src: &nftableslib.Port{
				List: []*uint32{
					&port1,
				},
			},
			Verdict: &expr.Verdict{
				Kind: expr.VerdictKind(unix.NFT_RETURN),
			},
		},
	}
	if err := ti.Tables().Table("ipv4table", nftables.TableFamilyIPv4).Chains().Chain("ipv4chain-1").Rules().Create("ipv4rule-2", &rule2); err != nil {
		fmt.Printf("failed to create chain with error: %+v, exiting...\n", err)
		os.Exit(1)
	}
	fmt.Printf("Programming nftable...\n")
	if err := conn.Flush(); err != nil {
		fmt.Printf("Failed to programm nftable with error: %+v\n", err)
		os.Exit(1)
	}
	if err := ti.Tables().Table("ipv4table", nftables.TableFamilyIPv4).Chains().Chain("ipv4chain-1").Rules().Create("ipv4rule-1", &rule1); err != nil {
		fmt.Printf("failed to create chain with error: %+v, exiting...\n", err)
		os.Exit(1)
	}
	jsontables, err := ti.Tables().Dump()
	if err != nil {
		fmt.Printf("failed to dump tables content with error: %+v\n", err)
	}
	fmt.Printf("Internal dump: %s\n", string(jsontables))

	fmt.Printf("Programming nftable...\n")
	if err := conn.Flush(); err != nil {
		fmt.Printf("Failed to programm nftable with error: %+v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Programming nftable succeeded.\n")

	tables, err := conn.ListTables()
	if err != nil {
		fmt.Printf("failed to list tables with error: %+v\n", err)
	}
	fmt.Printf("netlink tables list: %+v\n", tables)
}
