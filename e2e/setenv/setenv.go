package setenv

import (
	"fmt"
	"net"

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
	ip1 *net.IPAddr
	ip2 *net.IPAddr
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

	e.ns1, err = netns.New()
	if err != nil {
		return nil, err
	}
	e.ns2, err = netns.New()
	if err != nil {
		return nil, err
	}
	fmt.Printf("ns1: %+v ns2: %+v\n", e.ns1, e.ns2)

	return &e, nil
}

func (e *p2pEnv) Cleanup() {
	e.ns1.Close()
	e.ns2.Close()
}

func normalizeIP(ip1s, ip2s string) (*net.IPAddr, *net.IPAddr, error) {
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
func newIPAddr(addr string) (*net.IPAddr, error) {
	if _, ipnet, err := net.ParseCIDR(addr); err == nil {
		// Found a valid CIDR address
		return &net.IPAddr{
			IP: ipnet.IP,
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
	_, ipnet, err := net.ParseCIDR(addr + "/" + fmt.Sprintf("%d", mask))
	if err != nil {
		return nil, err
	}
	return &net.IPAddr{
		IP: ipnet.IP,
	}, nil
}
