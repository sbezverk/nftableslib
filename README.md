[![Build Status](https://travis-ci.org/sbezverk/nftableslib.svg?branch=master)](https://travis-ci.org/sbezverk/nftableslib)
# **nftableslib** - a library for Golang to talk to Netfilter 

nftableslib is a library offering an interface to Netfilter tables. It is based on "github.com/google/nftables" and offers a higher level of abstruction. 
It allows to create tables, chains and rules. Once table is creates, a caller can request this table's Chains interface to create chains within this table.
Similarly, once chain is created, a caller can request this chain's Rules interface to create rules for this chain.

A caller defines netfilter rule by means of a Rule struct. 

Rule contains parameters for a rule to configure L3(ip/ipv6), L4(tcp/udp/port) parameters can be specified. 

```
type Rule struct {
    L3      *L3Rule
    L4      *L4Rule
    Verdict *expr.Verdict
    Redirect *uint32
    Exclude bool
}
```

**Verdict** defines an action to take when condition is met. In some cases **Verdict** can be used without any conditions to be the last action in the chain. Example, when chain has default policy of Accept, but you want the traffic which did not match any condition to be dropped.

**Exclude** flag is true when the condition specified by the rules should be inverted. Example, L4 condition specifies match on tcp traffic for a range of ports 1025-1028, setting **Exclude** to *true* will match every tcp port with the exception of the ports specified in the range. 

**Redirect** struct defines a port where the traffic matching condition should be fowarded to. If transparent proxy is required, **TProxy** variable should be set to *true*
```
type Redirect struct {
	Port   uint16
	TProxy bool
}
```

A single rule can carry either L3 or L4 parameteres. L3 and L4 cannot be combined in the same rule. 
Redirect requires either L3 or L4, if there is no condition to match some traffic validation of a rule will fail.

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
**Version** parameter is used to match against a particular IP protocol version. Example, all IPv4 or all IPv6 traffic.

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
		},
        Verdict: &expr.Verdict{
			Kind: expr.VerdictKind(unix.NFT_RETURN),
		},
		Exclude: false,
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