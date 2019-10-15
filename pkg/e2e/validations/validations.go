package validations

import (
	"fmt"
	"net"
	"time"

	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"github.com/sbezverk/nftableslib/pkg/e2e/setenv"
	"github.com/vishvananda/netns"
)

type resultMsg struct {
	addr net.Addr
}

func tcpListener(c *net.TCPListener, stopch chan struct{}, resultch chan resultMsg) error {
	fmt.Printf("tcp listener listens for connections on: %s\n", c.Addr())
	for {
		c.SetDeadline(time.Now().Add(time.Second * 10))
		conn, err := c.Accept()
		if err == nil {
			resultch <- resultMsg{
				addr: conn.RemoteAddr(),
			}
		}
		select {
		case <-stopch:
			c.Close()
			close(stopch)
			return nil
		default:
		}
	}
}

func setupTCPListener(version nftables.TableFamily, ns netns.NsHandle, ip *nftableslib.IPAddr,
	port string, stopch chan struct{}, resultch chan resultMsg) (*net.TCPListener, error) {
	// Switching to destination namespace to setup and start tcpListener
	if err := netns.Set(ns); err != nil {
		return nil, err
	}
	// Testing redirect by sending packet to destination ip port 8888 and then receiving it
	// over the packet channel, destination port should be 9999
	var daddr, proto string
	switch version {
	case nftables.TableFamilyIPv4:
		daddr = ip.IP.To4().String()
		proto = "tcp4"
	case nftables.TableFamilyIPv6:
		daddr = "[" + ip.IP.To16().String() + "]"
		proto = "tcp6"
	default:
		return nil, fmt.Errorf("%+v unknown protocol version", version)
	}

	addr, err := net.ResolveTCPAddr(proto, daddr+":"+port)
	if err != nil {
		return nil, fmt.Errorf("call ResolveTCPAddr failed with error: %+v", err)

	}
	cl, err := net.ListenTCP(proto, addr)
	if err != nil {
		return nil, fmt.Errorf("call ListenTCP failed with error: %+v", err)
	}
	// Starting tcp listener go routine and defining cleanup deferred call.
	go tcpListener(cl, stopch, resultch)

	return cl, nil
}

func dialTCP(version nftables.TableFamily, ns netns.NsHandle, ip *nftableslib.IPAddr, port string, laddr ...net.Addr) error {
	// Switching to the source namespace to make a call
	if err := netns.Set(ns); err != nil {
		return err
	}
	var daddr, proto string
	switch version {
	case nftables.TableFamilyIPv4:
		daddr = ip.IP.To4().String()
		proto = "tcp4"
	case nftables.TableFamilyIPv6:
		daddr = "[" + ip.IP.To16().String() + "]"
		proto = "tcp6"
	default:
		return fmt.Errorf("%+v unknown protocol version", version)
	}
	// Setting Dial timeout to 30 seconds, as default timeout is too long.
	d := net.Dialer{Timeout: time.Second * 10}
	if laddr != nil {
		d.LocalAddr = laddr[0]
	}
	cd, err := d.Dial(proto, daddr+":"+port)
	if err != nil {
		return fmt.Errorf("call Dial failed with error: %+v", err)
	}
	defer cd.Close()

	return nil
}

// TCPPortRedirectValidation validation function for test: "IPV4 and IPV6 Redirecting TCP port 8888 to 9999"
func TCPPortRedirectValidation(version nftables.TableFamily, ns []netns.NsHandle, ip []*nftableslib.IPAddr) error {
	org, err := netns.Get()
	if err != nil {
		return err
	}

	defer netns.Set(org)
	// stop channel for shutting down the listener
	stopch := make(chan struct{})
	// packet channel to transfer received by the listener packets back to the sender for analysis
	resultch := make(chan resultMsg)
	cl, err := setupTCPListener(version, ns[1], ip[1], "9999", stopch, resultch)
	if err != nil {
		return err
	}
	// Closing TCP Listener
	defer cl.Close()
	// Informing TCP Listener to shut down
	defer func() {
		stopch <- struct{}{}
		<-stopch
	}()
	// Attempting to dial Listener's IP and Good port
	if err := dialTCP(version, ns[0], ip[1], "8888"); err != nil {
		return err
	}
	// Attempting to dial Listener's IP and Wrong port
	if err := dialTCP(version, ns[0], ip[1], "9999"); err == nil {
		return fmt.Errorf("dial to port 9999 succeeded but supposed to fail")
	}
	// Get results
	if err := getResult(resultch); err != nil {
		return fmt.Errorf("getPacket failed with error: %+v", err)
	}

	return nil
}

func getResult(resultch chan resultMsg) error {
	ticker := time.NewTicker(time.Second * 1)
	timeout := time.NewTimer(time.Second * 10)
	for {
		select {
		case result := <-resultch:
			fmt.Printf("result from the listener: %+v network: %+v\n", result.addr, result.addr.Network())
			return nil
		case <-ticker.C:
			continue
		case <-timeout.C:
			return fmt.Errorf("timeout getting connection")
		default:
		}
	}
}

// ICMPDropTestValidation validation function for test: "IPV4 ICMP Drop"
func ICMPDropTestValidation(version nftables.TableFamily, ns []netns.NsHandle, ip []*nftableslib.IPAddr) error {
	if err := setenv.TestICMP(ns[0], version, ip[0], ip[1]); err == nil {
		return fmt.Errorf("failed as the connectivity test supposed to fail, but succeeded")
	}

	return nil
}

// IPv4SNATValidation validation function for test: "IPV4 SNAT"
func IPv4SNATValidation(version nftables.TableFamily, ns []netns.NsHandle, ip []*nftableslib.IPAddr) error {
	org, err := netns.Get()
	if err != nil {
		return err
	}

	defer netns.Set(org)
	// stop channel for shutting down the listener
	stopch := make(chan struct{})
	// packet channel to transfer received by the listener packets back to the sender for analysis
	resultch := make(chan resultMsg)
	cl, err := setupTCPListener(version, ns[1], ip[1], "9999", stopch, resultch)
	if err != nil {
		return err
	}
	// Closing TCP Listener
	defer cl.Close()
	// Informing TCP Listener to shut down
	defer func() {
		stopch <- struct{}{}
		<-stopch
	}()
	// Attempting to dial Listener's IP and Good port
	var laddr *net.TCPAddr
	switch version {
	case nftables.TableFamilyIPv4:
		laddr, _ = net.ResolveTCPAddr("ip4:tcp", "127.0.0.1:0")
	case nftables.TableFamilyIPv6:
		laddr, _ = net.ResolveTCPAddr("ip6:tcp", "[::1]:0")
	}

	if err := dialTCP(version, ns[0], ip[1], "9999", laddr); err != nil {
		return err
	}
	// Get results
	if err := getResult(resultch); err != nil {
		return fmt.Errorf("getPacket failed with error: %+v", err)
	}

	return nil
}
