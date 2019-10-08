package setenv

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// P2PTestEnv defines methods to interact with an instantiated p2p test environment
type P2PTestEnv interface {
	Cleanup()
}

// p2pEnv contains variables and functions for an instantiated test environment
type p2pEnv struct {
	ns1 netns.NsHandle
	ns2 netns.NsHandle
	ip1 *net.IPNet
	ip2 *net.IPNet
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
	link1, link2, err := addVethToNS(e.ns1, e.ns2, veth)
	if err != nil {
		return nil, err
	}
	if err := setVethIPAddr(e.ns1, e.ns2, link1, link2, e.ip1, e.ip2); err != nil {
		return nil, err
	}
	// Test connectivity between

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
	l1, err := waitForLink(nsh1, veth.Name)
	if err != nil {
		return nil, nil, err
	}
	l2, err := waitForLink(nsh1, veth.PeerName)
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

	nsh2, err := netlink.NewHandleAt(ns2)
	if err != nil {
		return nil, nil, fmt.Errorf("failure to get handle with error: %+v", err)
	}

	_, err = waitForLink(nsh2, veth.PeerName)
	if err != nil {
		return nil, nil, fmt.Errorf("failure to get link with error: %+v", err)
	}
	if err := netlink.LinkSetUp(l2); err != nil {
		return nil, nil, fmt.Errorf("failure setting link %s up with error: %+v", l2.Attrs().Name, err)
	}

	return l1, l2, nil
}

func waitForLink(namespaceHandle *netlink.Handle, linkName string) (netlink.Link, error) {
	ticker := time.NewTicker(time.Second * 1)
	timeout := time.NewTimer(time.Second * 10)
	for {
		links, _ := namespaceHandle.LinkList()
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

func setVethIPAddr(ns1, ns2 netns.NsHandle, link1, link2 netlink.Link, ip1, ip2 *net.IPNet) error {
	var addr1, addr2 *net.IPNet
	if ip1.IP.To4() != nil {
		addr1 = &net.IPNet{IP: ip1.IP.To4(), Mask: net.CIDRMask(ip1.Mask.Size())}
		addr2 = &net.IPNet{IP: ip2.IP.To4(), Mask: net.CIDRMask(ip2.Mask.Size())}
	} else {
		addr1 = &net.IPNet{IP: ip1.IP.To16(), Mask: net.CIDRMask(ip1.Mask.Size())}
		addr2 = &net.IPNet{IP: ip2.IP.To16(), Mask: net.CIDRMask(ip2.Mask.Size())}
	}

	var vethAddr1 = &netlink.Addr{IPNet: addr1, Peer: addr2}
	var vethAddr2 = &netlink.Addr{IPNet: addr2, Peer: addr1}

	ns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get current process namespace")
	}
	defer netns.Set(ns)

	if err := netns.Set(ns1); err != nil {
		return fmt.Errorf("failed to switch to namespace %s with error: %+v", ns1, err)
	}

	if _, ok := link1.(*netlink.Veth); !ok {
		return fmt.Errorf("failure, got unexpected interface type: %+v", reflect.TypeOf(link1))
	}
	if err := netlink.AddrAdd(link1, vethAddr1); err != nil {
		return fmt.Errorf("failure to assign IP to veth interface with error: %+v", err)
	}
	if err := netns.Set(ns2); err != nil {
		return fmt.Errorf("failed to switch to namespace %s with error: %+v", ns1, err)
	}
	if _, ok := link2.(*netlink.Veth); !ok {
		return fmt.Errorf("failure, got unexpected interface type: %+v", reflect.TypeOf(link2))
	}
	if err := netlink.AddrAdd(link2, vethAddr2); err != nil {
		return fmt.Errorf("failure to assign IP to veth interface with error: %+v", err)
	}

	return nil
}
