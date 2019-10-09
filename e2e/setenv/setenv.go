package setenv

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/google/uuid"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// ProtocolICMP defines offset in bytes for IPv4 ICMP
	ProtocolICMP = 1
	// ProtocolIPv6ICMP defines offset in bytes for IPv6 ICMP
	ProtocolIPv6ICMP = 58
)

// P2PTestEnv defines methods to interact with an instantiated p2p test environment
type P2PTestEnv interface {
	Cleanup()
	GetNamespace() []netns.NsHandle
	GetIPs() []*net.IPNet
}

// p2pEnv contains variables and functions for an instantiated test environment
type p2pEnv struct {
	ns1   netns.NsHandle
	ns2   netns.NsHandle
	ip1   *net.IPNet
	ip2   *net.IPNet
	link1 netlink.Link
	link2 netlink.Link
}

func (e *p2pEnv) GetNamespace() []netns.NsHandle {
	return []netns.NsHandle{e.ns1, e.ns2}
}

func (e *p2pEnv) GetIPs() []*net.IPNet {
	return []*net.IPNet{e.ip1, e.ip2}
}

// NewP2PTestEnv sets up two new net namespaces, builds a link between them and assigns
// ip addresses to each end of the link. It also checks connectivity by using ping.
func NewP2PTestEnv(ip1s, ip2s string) (P2PTestEnv, error) {
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
	if err := TestICMP(e.ns1, unix.IPPROTO_ICMP, e.ip1, e.ip2); err != nil {
		return nil, err
	}
	if err := TestICMP(e.ns2, unix.IPPROTO_ICMP, e.ip2, e.ip1); err != nil {
		return nil, err
	}
	return &e, nil
}

func (e *p2pEnv) Cleanup() {
	e.ns1.Close()
	e.ns2.Close()
}

func normalizeIP(ip1s, ip2s string) (*net.IPNet, *net.IPNet, error) {
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
func newIPAddr(addr string) (*net.IPNet, error) {
	if _, ipnet, err := net.ParseCIDR(addr); err == nil {
		// Found a valid CIDR address
		return ipnet, nil
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
	_, ipnet, err := net.ParseCIDR(addr + "/" + fmt.Sprintf("%d", mask))
	if err != nil {
		return nil, err
	}
	return ipnet, nil
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
	var addr1, addr2 *net.IPNet
	if e.ip1.IP.To4() != nil {
		addr1 = &net.IPNet{IP: e.ip1.IP.To4(), Mask: net.CIDRMask(e.ip1.Mask.Size())}
		addr2 = &net.IPNet{IP: e.ip2.IP.To4(), Mask: net.CIDRMask(e.ip2.Mask.Size())}
	} else {
		addr1 = &net.IPNet{IP: e.ip1.IP.To16(), Mask: net.CIDRMask(e.ip1.Mask.Size())}
		addr2 = &net.IPNet{IP: e.ip2.IP.To16(), Mask: net.CIDRMask(e.ip2.Mask.Size())}
	}

	var vethAddr1 = &netlink.Addr{IPNet: addr1, Peer: addr2}
	var vethAddr2 = &netlink.Addr{IPNet: addr2, Peer: addr1}

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
	if err := netns.Set(e.ns2); err != nil {
		return fmt.Errorf("failed to switch to namespace %s with error: %+v", e.ns2, err)
	}
	if _, ok := e.link2.(*netlink.Veth); !ok {
		return fmt.Errorf("failure, got unexpected interface type: %+v", reflect.TypeOf(e.link2))
	}
	if err := netlink.AddrAdd(e.link2, vethAddr2); err != nil {
		return fmt.Errorf("failure to assign IP to veth interface with error: %+v", err)
	}

	// printNSLink(e.ns1)
	// printNSLink(e.ns2)

	return nil
}

// TestICMP tests icmp connectivity between two namespaces, ping is initiated in source namespace
// and destination namespace is expected to reply with echo reply packets
func TestICMP(sourceNS netns.NsHandle, protocol int, saddr, daddr *net.IPNet) error {
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
	var wm icmp.Message
	switch protocol {
	case unix.IPPROTO_ICMP:
		proto = "ip4:icmp"
		protoStart = ProtocolICMP
		wm = icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
		}
	case unix.IPPROTO_ICMPV6:
		proto = "ip6:ipv6-icmp"
		protoStart = ProtocolIPv6ICMP
		wm = icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest, Code: 0,
		}
	default:
		return fmt.Errorf("Unknown ICMP protocol %+v", protocol)
	}
	// Starting listener
	c, err := icmp.ListenPacket(proto, saddr.IP.String())
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

	for i := 0; i < 5; i++ {
		if _, err := c.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(daddr.IP.String())}); err != nil {
			return err
		}
		rb := make([]byte, 1500)
		c.SetReadDeadline(time.Now().Add(time.Second * 2))
		n, peer, err := c.ReadFrom(rb)
		if err != nil {
			return err
		}
		rm, err := icmp.ParseMessage(protoStart, rb[:n])
		if err != nil {
			return err
		}
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
		case ipv6.ICMPTypeEchoReply:
		default:
			return fmt.Errorf("Unexpected reply during connectivity test from peer: %s", peer.String())
		}
	}

	return nil
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
