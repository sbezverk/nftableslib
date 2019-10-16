package validations

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"github.com/sbezverk/nftableslib/pkg/e2e/setenv"
	"github.com/vishvananda/netns"
)

type resultMsg struct {
	addr net.Addr
}

func ipPacketListener(port int, pc *net.IPConn, stopch chan struct{}, resultch chan resultMsg) {
	fmt.Printf("ip listener listens for a packet on: %s\n", pc.LocalAddr().String())
	p := make([]byte, 1500)
	for {
		p = p[:]
		pc.SetReadDeadline(time.Now().Add(time.Second * 2))
		n, addr, err := pc.ReadFrom(p)
		if err == nil {
			// If no error, shipping addr and packet content over packetch
			fmt.Printf("Got packet from address: %+v\n", addr)

			// Decode a packet
			packet := gopacket.NewPacket(p[:n], layers.LayerTypeTCP, gopacket.Default)
			// Get the TCP layer from this packet
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				// Get actual TCP data from this layer
				tcp, _ := tcpLayer.(*layers.TCP)
				fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
				if layers.TCPPort(port) == tcp.DstPort {
					resultch <- resultMsg{
						addr: addr,
					}
				}
			}
		}
		select {
		case <-stopch:
			pc.Close()
			close(stopch)
			return
		default:
		}
	}
}

func tcpListener(c *net.TCPListener, stopch chan struct{}, resultch chan resultMsg) error {
	fmt.Printf("tcp listener listens for a connections on: %s\n", c.Addr())
	for {
		c.SetDeadline(time.Now().Add(time.Second * 2))
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

func setupIPListener(version nftables.TableFamily, ns netns.NsHandle, ip *nftableslib.IPAddr,
	port string, stopch chan struct{}, resultch chan resultMsg) (*net.IPConn, error) {
	// Switching to destination namespace to setup and start tcpListener
	if err := netns.Set(ns); err != nil {
		return nil, err
	}
	// Testing redirect by sending packet to destination ip port 8888 and then receiving it
	// over the packet channel, destination port should be 9999
	var daddr, proto, network string
	switch version {
	case nftables.TableFamilyIPv4:
		daddr = ip.IP.To4().String()
		proto = "tcp4"
		network = "ip4:"
	case nftables.TableFamilyIPv6:
		daddr = "[" + ip.IP.To16().String() + "]"
		proto = "tcp6"
		network = "ip6:"
	default:
		return nil, fmt.Errorf("%+v unknown protocol version", version)
	}

	addr, err := net.ResolveTCPAddr(proto, daddr+":"+port)
	if err != nil {
		return nil, fmt.Errorf("call ResolveTCPAddr failed with error: %+v", err)

	}

	laddr := net.IPAddr{IP: addr.IP}
	pc, err := net.ListenIP(network+"tcp", &laddr)
	if err != nil {
		return nil, fmt.Errorf("call to ListenPacket failed with error: %+v", err)
	}

	// Starting tcp listener go routine and defining cleanup deferred call.
	p, _ := strconv.Atoi(port)
	go ipPacketListener(p, pc, stopch, resultch)

	return pc, nil
}

func dialTCP(version nftables.TableFamily, ns netns.NsHandle, ip *nftableslib.IPAddr, port string) error {
	// Switching to the source namespace to make a call
	if err := netns.Set(ns); err != nil {
		return err
	}
	proto := "tcp"
	var daddr string
	switch version {
	case nftables.TableFamilyIPv4:
		daddr = ip.IP.To4().String()
	case nftables.TableFamilyIPv6:
		daddr = "[" + ip.IP.To16().String() + "]"
	default:
		return fmt.Errorf("%+v unknown protocol version", version)
	}
	// Setting Dial timeout to 30 seconds, as default timeout is too long.
	d := net.Dialer{Timeout: time.Second * 10}
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
	if _, err := getResult(resultch); err != nil {
		return fmt.Errorf("getPacket failed with error: %+v", err)
	}

	return nil
}

func getResult(resultch chan resultMsg) (*resultMsg, error) {
	ticker := time.NewTicker(time.Second * 1)
	timeout := time.NewTimer(time.Second * 10)
	for {
		select {
		case result := <-resultch:
			fmt.Printf("result from the listener: %+v network: %+v\n", result.addr, result.addr.Network())
			return &result, nil
		case <-ticker.C:
			continue
		case <-timeout.C:
			return nil, fmt.Errorf("timeout getting connection")
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
	cl, err := setupIPListener(version, ns[1], ip[1], "9999", stopch, resultch)
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

	// Just sending first Sync packet should be sufficient, as long as it comes with SNATed address,
	// no need to complete 3 way handshake.
	dialTCP(version, ns[0], ip[1], "9999")

	// Get results
	result, err := getResult(resultch)
	if err != nil {
		return fmt.Errorf("getPacket failed with error: %+v", err)
	}
	if result.addr.String() != "5.5.5.5" {
		return fmt.Errorf("Unexpected source address: %s, expected address: 5.5.5.5", result.addr.String())
	}
	return nil
}

// IPv4SNATValidation validation function for test: "IPV4 SNAT"
func IPv6SNATValidation(version nftables.TableFamily, ns []netns.NsHandle, ip []*nftableslib.IPAddr) error {
	org, err := netns.Get()
	if err != nil {
		return err
	}

	defer netns.Set(org)
	// stop channel for shutting down the listener
	stopch := make(chan struct{})
	// packet channel to transfer received by the listener packets back to the sender for analysis
	resultch := make(chan resultMsg)
	cl, err := setupIPListener(version, ns[1], ip[1], "9999", stopch, resultch)
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

	// Just sending first Sync packet should be sufficient, as long as it comes with SNATed address,
	// no need to complete 3 way handshake.
	dialTCP(version, ns[0], ip[1], "9999")

	// Get results
	result, err := getResult(resultch)
	if err != nil {
		return fmt.Errorf("getPacket failed with error: %+v", err)
	}
	if result.addr.String() != "2001:1234::1" {
		return fmt.Errorf("Unexpected source address: %s, expected address: 2001:1234::1", result.addr.String())
	}
	return nil
}
