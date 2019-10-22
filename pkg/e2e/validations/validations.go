package validations

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

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

func ipPacketListener(port int, proto int, pc *net.IPConn, stopch chan struct{}, resultch chan resultMsg) {
	fmt.Printf("ip listener listens for a packet on: %s\n", pc.LocalAddr().String())
	p := make([]byte, 1500)
	for {
		p = p[:]
		pc.SetReadDeadline(time.Now().Add(time.Second * 20))
		n, addr, err := pc.ReadFrom(p)
		if err == nil {
			// If no error, shipping addr and packet content over packetch
			switch proto {
			case unix.IPPROTO_TCP:
				// Decode a packet
				packet := gopacket.NewPacket(p[:n], layers.LayerTypeTCP, gopacket.Default)
				// Get the TCP layer from this packet
				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					// Get actual TCP data from this layer
					tcp, _ := tcpLayer.(*layers.TCP)
					if layers.TCPPort(port) == tcp.DstPort {
						resultch <- resultMsg{
							addr: addr,
						}
					}
				}
			case unix.IPPROTO_UDP:
				// Decode a packet
				packet := gopacket.NewPacket(p[:n], layers.LayerTypeUDP, gopacket.Default)
				// Get the UDP layer from this packet
				if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					// Get actual UDP data from this layer
					udp, _ := udpLayer.(*layers.UDP)
					if layers.UDPPort(port) == udp.DstPort {
						resultch <- resultMsg{
							addr: addr,
						}
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

func getNetProtoStr(version nftables.TableFamily, proto int) (string, string, error) {
	var protoStr, netStr string
	switch proto {
	case unix.IPPROTO_TCP:
		protoStr = "tcp"
	case unix.IPPROTO_UDP:
		protoStr = "udp"
	case unix.IPPROTO_ICMP:
		protoStr = "icmp"
	case unix.IPPROTO_ICMPV6:
		protoStr = "icmp"
	default:
		return "", "", fmt.Errorf("%d unknown protocol number", proto)
	}
	switch version {
	case nftables.TableFamilyIPv4:
		protoStr += "4"
		netStr = "ip4:"
	case nftables.TableFamilyIPv6:
		protoStr += "6"
		netStr = "ip6:"
	default:
		return "", "", fmt.Errorf("%+v unknown IP protocol version", version)
	}

	return netStr, protoStr, nil
}

func setupIPListener(version nftables.TableFamily, ns netns.NsHandle, ip *nftableslib.IPAddr,
	port string, proto int, stopch chan struct{}, resultch chan resultMsg) (*net.IPConn, error) {
	// Switching to destination namespace to setup and start tcpListener
	if err := netns.Set(ns); err != nil {
		return nil, err
	}
	// Testing redirect by sending packet to destination ip port 8888 and then receiving it
	// over the packet channel, destination port should be 9999

	netStr, protoStr, err := getNetProtoStr(version, proto)
	if err != nil {
		return nil, err
	}
	var daddr string

	switch version {
	case nftables.TableFamilyIPv4:
		daddr = ip.IP.To4().String()
	case nftables.TableFamilyIPv6:
		daddr = "[" + ip.IP.To16().String() + "]"
	default:
		return nil, fmt.Errorf("%+v unknown IP protocol version", version)
	}
	var laddr net.IPAddr
	switch proto {
	case unix.IPPROTO_TCP:
		tcpAddr, err := net.ResolveTCPAddr(protoStr, daddr+":"+port)
		if err != nil {
			return nil, fmt.Errorf("call ResolveTCPAddr failed with error: %+v", err)
		}
		netStr += "tcp"
		laddr = net.IPAddr{IP: tcpAddr.IP}
	case unix.IPPROTO_UDP:
		udpAddr, err := net.ResolveUDPAddr(protoStr, daddr+":"+port)
		if err != nil {
			return nil, fmt.Errorf("call ResolveUdpAddr failed with error: %+v", err)
		}
		netStr += "udp"
		laddr = net.IPAddr{IP: udpAddr.IP}

	}
	pc, err := net.ListenIP(netStr, &laddr)
	if err != nil {
		return nil, fmt.Errorf("call to ListenPacket failed with error: %+v", err)
	}

	// Starting tcp listener go routine and defining cleanup deferred call.
	p, _ := strconv.Atoi(port)
	go ipPacketListener(p, proto, pc, stopch, resultch)

	return pc, nil
}

func dial(version nftables.TableFamily, ns netns.NsHandle, ip *nftableslib.IPAddr, port string, proto int) error {
	// Switching to the source namespace to make a call
	if err := netns.Set(ns); err != nil {
		return err
	}

	_, protoStr, err := getNetProtoStr(version, proto)
	if err != nil {
		return nil
	}

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
	cd, err := d.Dial(protoStr, daddr+":"+port)
	if err != nil {
		return fmt.Errorf("call Dial failed with error: %+v", err)
	}
	defer cd.Close()
	// Since Dial for UDP does not send any Data, as opposed to Dail for TCP sending SYN packet
	// sending a small packet out.
	if proto == unix.IPPROTO_UDP {
		cd.Write([]byte("UDP test"))
	}
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
	if err := dial(version, ns[0], ip[1], "8888", unix.IPPROTO_TCP); err != nil {
		return err
	}
	// Attempting to dial Listener's IP and Wrong port
	if err := dial(version, ns[0], ip[1], "9999", unix.IPPROTO_TCP); err == nil {
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

// SNATValidation validation function for test: "IPV4 SNAT"
func getPacketFromDestination(version nftables.TableFamily, ns []netns.NsHandle, ip []*nftableslib.IPAddr,
	proto int, srcPort, dstPort string) (net.Addr, error) {
	org, err := netns.Get()
	if err != nil {
		return nil, err
	}

	defer netns.Set(org)
	// stop channel for shutting down the listener
	stopch := make(chan struct{})
	// packet channel to transfer received by the listener packets back to the sender for analysis
	resultch := make(chan resultMsg)
	cl, err := setupIPListener(version, ns[1], ip[1], dstPort, proto, stopch, resultch)
	if err != nil {
		return nil, err
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
	var result *resultMsg

	dial(version, ns[0], ip[1], srcPort, proto)

	// Get results
	result, err = getResult(resultch)
	if err != nil {
		return nil, fmt.Errorf("getPacket failed with error: %+v", err)
	}

	return result.addr, nil
}

// IPv4TCPSNATValidation validation function for test: "IPV4 TCP SNAT"
func IPv4TCPSNATValidation(version nftables.TableFamily, ns []netns.NsHandle, ip []*nftableslib.IPAddr) error {
	addr, err := getPacketFromDestination(version, ns, ip, unix.IPPROTO_TCP, "9999", "9999")
	if err != nil {
		return err
	}
	if addr.String() != "5.5.5.5" {
		return fmt.Errorf("Unexpected source address: %s, expected address: 5.5.5.5", addr.String())
	}
	return nil
}

// IPv4UDPSNATValidation validation function for test: "IPV4 UDP SNAT"
func IPv4UDPSNATValidation(version nftables.TableFamily, ns []netns.NsHandle, ip []*nftableslib.IPAddr) error {
	addr, err := getPacketFromDestination(version, ns, ip, unix.IPPROTO_UDP, "9999", "9999")
	if err != nil {
		return err
	}

	if addr.String() != "5.5.5.5" {
		return fmt.Errorf("Unexpected source address: %s, expected address: 5.5.5.5", addr.String())
	}
	return nil
}

// IPv6TCPSNATValidation validation function for test: "IPV6 TCP SNAT"
func IPv6TCPSNATValidation(version nftables.TableFamily, ns []netns.NsHandle, ip []*nftableslib.IPAddr) error {
	addr, err := getPacketFromDestination(version, ns, ip, unix.IPPROTO_TCP, "9999", "9999")
	if err != nil {
		return err
	}
	if addr.String() != "2001:1234::1" {
		return fmt.Errorf("Unexpected source address: %s, expected address: 2001:1234::1", addr.String())
	}
	return nil
}
