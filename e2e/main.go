package main

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"

	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"github.com/sbezverk/nftableslib/e2e/setenv"
	"github.com/vishvananda/netns"
)

func main() {
	t, err := setenv.NewP2PTestEnv("1.1.1.1", "1.1.1.2")
	if err != nil {
		fmt.Printf("Failed with error: %+v\n", err)
		os.Exit(1)
	}
	defer t.Cleanup()
	ns := t.GetNamespace()
	ips := t.GetIPs()
	if err := setenv.TestICMP(t.GetNamespace()[0], unix.IPPROTO_ICMP, ips[0], ips[1]); err != nil {
		fmt.Printf("Connectivity test supposed to succeed, but failed with error: %+v\n", err)
		os.Exit(1)
	}
	if err := nftablesSet(ns[1], ips[1]); err != nil {
		fmt.Printf("Failed with error: %+v\n", err)
		os.Exit(1)
	}
	if err := setenv.TestICMP(t.GetNamespace()[0], unix.IPPROTO_ICMP, ips[0], ips[1]); err == nil {
		fmt.Printf("Connectivity test supposed to fail, but succeeded\n")
		os.Exit(1)
	}

	fmt.Printf("Test succeeded!\n")
}

func nftablesSet(ns netns.NsHandle, dip *net.IPNet) error {
	// Initializing netlink connection
	conn := nftableslib.InitConn(int(ns))
	ti := nftableslib.InitNFTables(conn)

	if err := ti.Tables().CreateImm("table", nftables.TableFamilyIPv4); err != nil {
		return fmt.Errorf("failed to create table with error: %+v", err)
	}
	ci, err := ti.Tables().Table("table", nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("failed to get chains interface for table with error: %+v", err)
	}
	ch1Attr := nftableslib.ChainAttributes{
		Type:     nftables.ChainTypeFilter,
		Priority: 0,
		Hook:     nftables.ChainHookInput,
		Policy:   nftableslib.ChainPolicyAccept,
	}
	if err := ci.Chains().CreateImm("chain-1", &ch1Attr); err != nil {
		return fmt.Errorf("failed to create chain with error: %+v", err)
	}

	c1ri, err := ci.Chains().Chain("chain-1")
	if err != nil {
		return fmt.Errorf("failed to get rules interface for chain with error: %+v", err)
	}
	addr, err := nftableslib.NewIPAddr(dip.IP.String())
	if err != nil {
		return err
	}
	action, err := nftableslib.SetVerdict(nftableslib.NFT_DROP)
	if err != nil {
		return err
	}
	rule := nftableslib.Rule{
		L3: &nftableslib.L3Rule{
			Protocol: nftableslib.L3Protocol(unix.IPPROTO_ICMP),
			Dst: &nftableslib.IPAddrSpec{
				List: []*nftableslib.IPAddr{addr},
			},
		},
		Action: action,
	}
	if _, err = c1ri.Rules().CreateImm(&rule); err != nil {
		return fmt.Errorf("failed to create rule with error: %+v", err)
	}
	return nil
}
