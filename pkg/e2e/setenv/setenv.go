package setenv

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"time"

	"github.com/google/nftables"
	"github.com/google/uuid"
	"github.com/sbezverk/nftableslib"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// TestChain defines a key in NFTablesTes map
type TestChain struct {
	Name string
	Attr *nftableslib.ChainAttributes
}

// NFTablesTest defines structure used for tests
type NFTablesTest struct {
	Name       string
	Version    nftables.TableFamily
	SrcNFRules map[TestChain][]nftableslib.Rule
	DstNFRules map[TestChain][]nftableslib.Rule
	Saddr      string
	Daddr      string
	Validation func(nftables.TableFamily, []netns.NsHandle, []*nftableslib.IPAddr) error
}

// P2PTestEnv defines methods to interact with an instantiated p2p test environment
type P2PTestEnv interface {
	Cleanup()
	GetNamespace() []netns.NsHandle
	GetIPs() []*nftableslib.IPAddr
}

// p2pEnv contains variables and functions for an instantiated test environment
type p2pEnv struct {
	ns1   netns.NsHandle
	ns2   netns.NsHandle
	ip1   *nftableslib.IPAddr
	ip2   *nftableslib.IPAddr
	link1 netlink.Link
	link2 netlink.Link
}

func (e *p2pEnv) GetNamespace() []netns.NsHandle {
	return []netns.NsHandle{e.ns1, e.ns2}
}

func (e *p2pEnv) GetIPs() []*nftableslib.IPAddr {
	return []*nftableslib.IPAddr{e.ip1, e.ip2}
}

// NewP2PTestEnv sets up two new net namespaces, builds a link between them and assigns
// ip addresses to each end of the link. It also checks connectivity by using ping.
func NewP2PTestEnv(version nftables.TableFamily, ip1s, ip2s string) (P2PTestEnv, error) {
	var err error
	e := p2pEnv{}
	// Validate and normilize IPs
	e.ip1, e.ip2, err = normalizeIP(ip1s, ip2s)
	if err != nil {
		return nil, err
	}
	// Storing original net namespace to restore it before exiting
	ns, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get current process namespace")
	}
	defer netns.Set(ns)
	// Creating 2 new net namespaces
	e.ns1, e.ns2, err = twoNewNS()
	if err != nil {
		return nil, err
	}
	// Validating that new namespaces are available
	if err := netns.Set(e.ns1); err != nil {
		return nil, fmt.Errorf("failed to switch to namespace %s with error: %+v", e.ns1, err)
	}
	if err := netns.Set(e.ns2); err != nil {
		return nil, fmt.Errorf("failed to switch to namespace %s with error: %+v", e.ns2, err)
	}

	// Creating two names for each end of veth interfaces
	intf1 := newIntfName(1)
	intf2 := newIntfName(2)
	// Creating attributes struct for veth interface
	linkAttr := netlink.NewLinkAttrs()
	linkAttr.Name = intf1
	veth := &netlink.Veth{
		LinkAttrs: linkAttr,
		PeerName:  intf2,
	}
	e.link1, e.link2, err = addVethToNS(e.ns1, e.ns2, veth)
	if err != nil {
		return nil, err
	}
	if err := setVethIPAddr(e); err != nil {
		return nil, err
	}

	// Test connectivity between
	if err := TestICMP(e.ns1, version, e.ip1, e.ip2); err != nil {
		return nil, err
	}
	if err := TestICMP(e.ns2, version, e.ip2, e.ip1); err != nil {
		return nil, err
	}
	return &e, nil
}

func (e *p2pEnv) Cleanup() {
	e.ns1.Close()
	e.ns2.Close()
}

func normalizeIP(ip1s, ip2s string) (*nftableslib.IPAddr, *nftableslib.IPAddr, error) {
	ip1, err := newIPAddr(ip1s)
	if err != nil {
		return nil, nil, err
	}
	ip2, err := newIPAddr(ip2s)
	if err != nil {
		return nil, nil, err
	}
	// TODO add check that both IPs are IPv4 or IPv6, no mixing allowed

	return ip1, ip2, nil
}

// newAddr checks and converts into CIDR formated IPv4 or IPv6 address
func newIPAddr(addr string) (*nftableslib.IPAddr, error) {
	if ip, ipnet, err := net.ParseCIDR(addr); err == nil {
		// Found a valid CIDR address
		ones, _ := ipnet.Mask.Size()
		mask := uint8(ones)
		return &nftableslib.IPAddr{
			&net.IPAddr{
				IP: ip,
			},
			true,
			&mask,
		}, nil
	}
	// Check if addr is just ip address in a non CIDR format
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("%s is invalid ip address", addr)
	}
	mask := uint8(32)
	if ip.To4() == nil {
		mask = uint8(128)
	}
	ip, _, err := net.ParseCIDR(addr + "/" + fmt.Sprintf("%d", mask))
	if err != nil {
		return nil, err
	}
	return &nftableslib.IPAddr{
		&net.IPAddr{
			IP: ip,
		},
		true,
		&mask,
	}, nil
}

func newIntfName(id int) string {
	s := uuid.New().String()
	intf := "veth-" + strconv.Itoa(id) + "-"
	intf += s[:15-len(intf)]
	return intf
}

func twoNewNS() (netns.NsHandle, netns.NsHandle, error) {
	ns1, err := netns.New()
	if err != nil {
		return -1, -1, err
	}
	ns2, err := netns.New()
	if err != nil {
		return -1, -1, err
	}

	return ns1, ns2, err
}

func addVethToNS(ns1, ns2 netns.NsHandle, veth *netlink.Veth) (netlink.Link, netlink.Link, error) {
	if err := netns.Set(ns1); err != nil {
		return nil, nil, fmt.Errorf("failureto switch to namespace %s with error: %+v", ns1, err)
	}
	nsh1, err := netlink.NewHandleAt(ns1)
	if err != nil {
		return nil, nil, fmt.Errorf("failure to handle with error: %+v", err)
	}
	if err = nsh1.LinkAdd(veth); err != nil {
		return nil, nil, fmt.Errorf("failure to add veth to pod with error: %+v", err)
	}
	l1, err := waitForLink(ns1, veth.Name)
	if err != nil {
		return nil, nil, err
	}
	l2, err := waitForLink(ns1, veth.PeerName)
	if err != nil {
		return nil, nil, err
	}

	if err := netlink.LinkSetUp(l1); err != nil {
		return nil, nil, fmt.Errorf("failure setting link %s up with error: %+v", l1.Attrs().Name, err)
	}

	if err := moveLinkIntoNS(l2, ns2); err != nil {
		return nil, nil, fmt.Errorf("failure to place veth into the namespace with error: %+v", err)
	}

	// Switching to peer's namespace
	if err := netns.Set(ns2); err != nil {
		return nil, nil, fmt.Errorf("failed to switch to namespace %s with error: %+v", ns2, err)
	}
	_, err = waitForLink(ns2, veth.PeerName)
	if err != nil {
		return nil, nil, fmt.Errorf("failure to get link with error: %+v", err)
	}
	if err := netlink.LinkSetUp(l2); err != nil {
		return nil, nil, fmt.Errorf("failure setting link %s up with error: %+v", l2.Attrs().Name, err)
	}
	// Waiting for both links to become Operationally Up
	l1, err = waitForLinkUp(ns1, l1)
	if err != nil {
		return nil, nil, err
	}
	l2, err = waitForLinkUp(ns2, l2)
	if err != nil {
		return nil, nil, err
	}

	return l1, l2, nil
}

func waitForLink(ns netns.NsHandle, linkName string) (netlink.Link, error) {
	org, err := netns.Get()
	if err != nil {
		return nil, err
	}
	defer netns.Set(org)
	nsh, err := netlink.NewHandleAt(ns)
	if err != nil {
		return nil, fmt.Errorf("failure to get namespace's handle with error: %+v", err)
	}
	ticker := time.NewTicker(time.Second * 1)
	timeout := time.NewTimer(time.Second * 10)
	for {
		links, _ := nsh.LinkList()
		for _, link := range links {
			if link.Attrs().Name == linkName {
				return link, nil
			}
		}
		select {
		case <-ticker.C:
			continue
		case <-timeout.C:
			return nil, fmt.Errorf("timeout waiting for the link to appear in the namespace")
		}
	}
}

func waitForLinkUp(ns netns.NsHandle, link netlink.Link) (netlink.Link, error) {
	org, err := netns.Get()
	if err != nil {
		return nil, err
	}
	defer netns.Set(org)
	nsh, err := netlink.NewHandleAt(ns)
	if err != nil {
		return nil, fmt.Errorf("failure to get namespace's handle with error: %+v", err)
	}
	ticker := time.NewTicker(time.Second * 1)
	timeout := time.NewTimer(time.Second * 10)
	ln := link.Attrs().Name
	for {
		if link, err := nsh.LinkByName(ln); err == nil {
			if link.Attrs().OperState == netlink.OperUp {
				return link, nil
			}
		}
		select {
		case <-ticker.C:
			continue
		case <-timeout.C:
			return nil, fmt.Errorf("timeout waiting for the link to become operational")
		}
	}
}

func moveLinkIntoNS(link netlink.Link, ns netns.NsHandle) error {
	ticker := time.NewTicker(time.Second * 1)
	timeout := time.NewTimer(time.Second * 10)
	for {
		err := netlink.LinkSetNsFd(link, int(ns))
		if err == nil {
			return nil
		}
		select {
		case <-ticker.C:
			continue
		case <-timeout.C:
			return fmt.Errorf("failure to place veth into a namespace with error: %+v", err)
		}
	}
}

func setVethIPAddr(e p2pEnv) error {
	var addr1, addr2, lo *net.IPNet
	if e.ip1.IP.To4() != nil {
		addr1 = &net.IPNet{IP: e.ip1.IP.To4(), Mask: net.CIDRMask(int(*e.ip1.Mask), 32)}
		addr2 = &net.IPNet{IP: e.ip2.IP.To4(), Mask: net.CIDRMask(int(*e.ip2.Mask), 32)}
		lo = &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(32, 32)}
	} else {
		addr1 = &net.IPNet{IP: e.ip1.IP.To16(), Mask: net.CIDRMask(int(*e.ip1.Mask), 128)}
		addr2 = &net.IPNet{IP: e.ip2.IP.To16(), Mask: net.CIDRMask(int(*e.ip2.Mask), 128)}
		lo = &net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)}
	}

	var vethAddr1 = &netlink.Addr{IPNet: addr1, Peer: addr2}
	var vethAddr2 = &netlink.Addr{IPNet: addr2, Peer: addr1}
	var loAddr = &netlink.Addr{IPNet: lo}

	ns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get current process namespace")
	}
	defer netns.Set(ns)

	if err := netns.Set(e.ns1); err != nil {
		return fmt.Errorf("failed to switch to namespace %s with error: %+v", e.ns1, err)
	}

	if _, ok := e.link1.(*netlink.Veth); !ok {
		return fmt.Errorf("failure, got unexpected interface type: %+v", reflect.TypeOf(e.link1))
	}
	if err := netlink.AddrAdd(e.link1, vethAddr1); err != nil {
		return fmt.Errorf("failure to assign IP to veth interface with error: %+v", err)
	}
	if err := setLoopbackIP(e.ns1, loAddr); err != nil {
		return fmt.Errorf("failure to assign IP to loopback interface with error: %+v", err)
	}
	if err := netns.Set(e.ns2); err != nil {
		return fmt.Errorf("failed to switch to namespace %s with error: %+v", e.ns2, err)
	}
	if _, ok := e.link2.(*netlink.Veth); !ok {
		return fmt.Errorf("failure, got unexpected interface type: %+v", reflect.TypeOf(e.link2))
	}
	if err := netlink.AddrAdd(e.link2, vethAddr2); err != nil {
		return fmt.Errorf("failure to assign IP to veth interface with error: %+v", err)
	}
	if err := setLoopbackIP(e.ns2, loAddr); err != nil {
		return fmt.Errorf("failure to assign IP to loopback interface with error: %+v", err)
	}
	// printNSLink(e.ns1)
	// printNSLink(e.ns2)

	return nil
}

func setLoopbackIP(ns netns.NsHandle, lo *netlink.Addr) error {
	nsh, err := netlink.NewHandleAt(ns)
	if err != nil {
		return fmt.Errorf("failure to get namespace's handle with error: %+v", err)
	}
	links, _ := nsh.LinkList()
	found := false
	var link netlink.Link
	for _, link = range links {
		if link.Attrs().Name == "lo" {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("loopback is not found")
	}
	if err := netlink.AddrAdd(link, lo); err != nil {
		return fmt.Errorf("failure to assign IP to loopback interface with error: %+v", err)
	}

	return nil
}

// TestICMP tests icmp connectivity between two namespaces, ping is initiated in source namespace
// and destination namespace is expected to reply with echo reply packets
func TestICMP(sourceNS netns.NsHandle, protocol nftables.TableFamily, saddr, daddr *nftableslib.IPAddr) error {
	// Preserving original net namespace
	org, err := netns.Get()
	if err != nil {
		return err
	}
	defer netns.Set(org)
	if err := netns.Set(sourceNS); err != nil {
		return err
	}
	var proto string
	var protoStart int
	var src, dst string
	var wm icmp.Message
	switch protocol {
	case nftables.TableFamilyIPv4:
		proto = "ip4:icmp"
		protoStart = unix.IPPROTO_ICMP
		wm = icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
		}
		src = saddr.IP.To4().String()
		dst = daddr.IP.To4().String()
	case nftables.TableFamilyIPv6:
		proto = "ip6:ipv6-icmp"
		protoStart = unix.IPPROTO_ICMPV6
		wm = icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest, Code: 0,
		}
		src = saddr.IP.To16().String()
		dst = daddr.IP.To16().String()
	default:
		return fmt.Errorf("unsupported table family %+v", protocol)
	}
	// Starting listener
	c, err := icmpListenPacket(proto, src)
	if err != nil {
		return fmt.Errorf("call ListenPacket failed with error: %+v", err)
	}
	defer c.Close()

	wm.Body = &icmp.Echo{
		ID: os.Getpid() & 0xffff, Seq: 1,
		Data: []byte("ping"),
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return err
	}

	for i := 0; i < 1; i++ {
		fmt.Printf("")
		if _, err := c.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(dst)}); err != nil {
			return err
		}
		if err := waitForICMPReply(c, protoStart); err != nil {
			return err
		}
	}

	return nil
}

func icmpListenPacket(proto string, src string) (*icmp.PacketConn, error) {
	ticker := time.NewTicker(time.Second * 1)
	timeout := time.NewTimer(time.Second * 10)
	for {
		c, err := icmp.ListenPacket(proto, src)
		if err == nil {
			return c, nil
		}
		select {
		case <-ticker.C:
			continue
		case <-timeout.C:
			return nil, fmt.Errorf("failure to open icmp socket with error: %+v", err)
		}
	}
}

func waitForICMPReply(c *icmp.PacketConn, protoStart int) error {
	ticker := time.NewTicker(time.Second * 1)
	timeout := time.NewTimer(time.Second * 2)
	for {
		rb := make([]byte, 1500)
		c.SetReadDeadline(time.Now().Add(time.Second * 1))
		n, _, err := c.ReadFrom(rb)
		if err == nil {
			rm, err := icmp.ParseMessage(protoStart, rb[:n])
			if err != nil {
				return err
			}
			switch rm.Type {
			case ipv4.ICMPTypeEchoReply:
				return nil
			case ipv6.ICMPTypeEchoReply:
				return nil
			}
		}
		select {
		case <-ticker.C:
			continue
		case <-timeout.C:
			return fmt.Errorf("timeout to receive ICMP reply")
		}
	}
}

func printNSLink(ns netns.NsHandle) error {
	org, err := netns.Get()
	if err != nil {
		return err
	}
	defer netns.Set(org)
	if err := netns.Set(ns); err != nil {
		return fmt.Errorf("failed to switch to namespace %s with error: %+v", ns, err)
	}
	nsh, err := netlink.NewHandleAt(ns)
	if err != nil {
		return fmt.Errorf("failure to get namespace's handle with error: %+v", err)
	}
	links, err := nsh.LinkList()
	if err != nil {
		return fmt.Errorf("failure to get a list of links from the namespace %s with error: %+v", ns.String(), err)
	}
	for _, link := range links {
		fmt.Printf("Link: %s\n", link.Attrs().Name)
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			fmt.Printf("- %s\n", addr.IPNet.IP.String())
		}
	}
	return nil
}

// NFTablesSet sets up nftables rules in the namespace
func NFTablesSet(ns netns.NsHandle, version nftables.TableFamily, nfrules map[TestChain][]nftableslib.Rule) error {
	conn := nftableslib.InitConn(int(ns))
	ti := nftableslib.InitNFTables(conn)

	tn := uuid.New().String()[:8]
	if err := ti.Tables().CreateImm(tn, version); err != nil {
		return fmt.Errorf("failed to create table with error: %+v", err)
	}
	ci, err := ti.Tables().Table(tn, version)
	if err != nil {
		return fmt.Errorf("failed to get chains interface for table %s with error: %+v", tn, err)
	}

	for chain, rules := range nfrules {
		if err := ci.Chains().CreateImm(chain.Name, chain.Attr); err != nil {
			return fmt.Errorf("failed to create chain with error: %+v", err)
		}
		ri, err := ci.Chains().Chain(chain.Name)
		if err != nil {
			return fmt.Errorf("failed to get rules interface for chain with error: %+v", err)
		}
		for _, rule := range rules {
			if _, err = ri.Rules().CreateImm(&rule); err != nil {
				return fmt.Errorf("failed to create rule with error: %+v", err)
			}
		}
	}
	b, _ := ti.Tables().Dump()
	fmt.Printf("Resulting nftables rule: %s\n", string(b))

	return nil
}
