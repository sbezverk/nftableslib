# wip nftableslib

nftableslib is a library offering an interface to nf tables. It is based on "github.com/google/nftables" and offers a higher level abstruction level. 
It allows to create tables, chains and rules. Once table is create a caller can request this table's Chains interface which will allow to create chains which belong to a specific table.
Similarly, once chain is create a caller can request this chain's Rules interface. 

A rule is defined by means of a Rule type. 

Rule contains parameters for a rule to configure, only L3 OR L4 parameters can be specified. 

**TODO** Add description of cases for Verdict, Redirect and Exclude
```
type Rule struct {
	L3      *L3Rule
	L4      *L4Rule
    Verdict *expr.Verdict
    Redirect *uint32
    Exclude bool
}
```

A single rule can only carry L3 OR L4 parameteres. 

L4 parameters are defined by L4 type:
```
type L4Rule struct {
	L4Proto int
	Src     *Port
	Dst     *Port
}
```

L3 parameters are defined by L3 type:
```
type L3Rule struct {
	Src *IPAddrSpec
	Dst *IPAddrSpec
	Version *uint32
}
```
Rule type offers Validation method which checks all parameters provided in Rule structure for consistency.

Here is example of programming a simple L3 rule:

```
package main

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/sbezverk/nftableslib"
)

func main() {
	// Initializing netlink connection for a global namespace,
    // if non-global namespace is needed, namespace id must be specified in InitConn
	conn := nftableslib.InitConn()
    // Initializing nftableslib
	ti := nftableslib.InitNFTables(conn)

	// Clean up previously defined nf tables
	conn.FlushRuleset()

    // Creating nf table for IPv4 family
	ti.Tables().Create("ipv4table", nftables.TableFamilyIPv4)

	// Pushing table config to nf tables module
    // Pushing config after each create is not mandatory, it is done for debugging purposes.
	if err := conn.Flush(); err != nil {
		fmt.Printf("Failed to programm nftable with error: %+v\n", err)
		os.Exit(1)
	}

    // Getting Chains Interface for just created table
	ci, err := ti.Tables().Table("ipv4table", nftables.TableFamilyIPv4)
	if err != nil {
		fmt.Printf("Failed to get chains interface for table ipv4table with error: %+v\n", err)
		os.Exit(1)
	}

    // Creating new chain
	ci.Chains().Create("ipv4chain-1", nftables.ChainHookPrerouting,
		nftables.ChainPriorityFirst, nftables.ChainTypeFilter)
	
	if err := conn.Flush(); err != nil {
		fmt.Printf("Failed to programm nftable with error: %+v\n", err)
		os.Exit(1)
	}
	// Specifying L3 rule if ipv4 traffic is source from one of these ip addresses
    // stiop processing.
	rule1 := nftableslib.Rule{
		L3: &nftableslib.L3Rule{
			Src: &nftableslib.IPAddrSpec{
				List: []*nftableslib.IPAddr{
					{
						&net.IPAddr{
							IP: net.ParseIP("1.2.3.4"),
						},
						fasse,
						nil,
					},
					{
						&net.IPAddr{
							IP: net.ParseIP("2.3.4.5"),
						},
						false,
						nil,
					},
				},
			},
			Verdict: &expr.Verdict{
				Kind: expr.VerdictKind(unix.NFT_RETURN),
			},
			Exclude: false,
		},
	}
    // Getting Rules interface from chain ipv4chain-1
	ri, err := ci.Chains().Chain("ipv4chain-1")
	if err != nil {
		fmt.Printf("Failed to get rules interface for chain ipv4chain-1 with error: %+v\n", err)
		os.Exit(1)
	}
    // Creating rule
	if err := ri.Rules().Create("ipv4rule-1", &rule1); err != nil {
		fmt.Printf("failed to create chain with error: %+v, exiting...\n", err)
		os.Exit(1)
	}
	// Final programming
	if err := conn.Flush(); err != nil {
		fmt.Printf("Failed to programm nftable with error: %+v\n", err)
		os.Exit(1)
	}
}

```

As a result of execution of this program, nft client displays the following configuration:

```
sudo nft list table ip ipv4table
table ip ipv4table {
	set ipv4rule-1 {
		type ipv4_addr
		flags constant
		elements = { 1.2.3.4, 2.3.4.5 }
	}

	chain ipv4chain-1 {
		type filter hook prerouting priority -2147483648; policy accept;
		ip saddr == @ipv4rule-1 return
	}
}

```