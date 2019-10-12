package validations

import (
	"fmt"
	"net"
	"time"

	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"github.com/sbezverk/nftableslib/e2e/setenv"
	"github.com/vishvananda/netns"
)

func tcpListener(c *net.TCPListener, stopch chan struct{}, resultch chan struct{}) error {
	fmt.Printf("tcp listener listens for connections on: %s\n", c.Addr())
	for {
		c.SetDeadline(time.Now().Add(time.Second * 10))
		conn, err := c.Accept()
		if err == nil {
			fmt.Printf("Connection from: %s\n", conn.RemoteAddr())
			resultch <- struct{}{}
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

// TCPPortRedirectValidation validation function for test: "IPV4 Redirecting TCP port 8888 to 9999"
func TCPPortRedirectValidation(version nftables.TableFamily, ns []netns.NsHandle, ip []*nftableslib.IPAddr) error {
	org, err := netns.Get()
	if err != nil {
		return err
	}
	// Switching to destination namespace to setup and start tcpListener
	if err := netns.Set(ns[1]); err != nil {
		return err
	}
	defer netns.Set(org)
	// stop channel for shutting down the listener
	stopch := make(chan struct{})
	// packet channel to transfer received by the listener packets back to the sender for analysis
	resultch := make(chan struct{})

	// Testing redirect by sending packet to destination ip port 8888 and then receiving it
	// over the packet channel, destination port should be 9999
	var daddr, proto string
	switch version {
	case nftables.TableFamilyIPv4:
		daddr = ip[1].IP.To4().String()
		proto = "tcp4"
	case nftables.TableFamilyIPv6:
		daddr = "[" + ip[1].IP.To16().String() + "]"
		proto = "tcp6"
	default:
		return fmt.Errorf("%+v unknown protocol version", version)
	}

	addr, err := net.ResolveTCPAddr(proto, daddr+":9999")
	if err != nil {
		return fmt.Errorf("call ResolveTCPAddr failed with error: %+v", err)

	}
	cl, err := net.ListenTCP(proto, addr)
	if err != nil {
		return fmt.Errorf("call ListenTCP failed with error: %+v", err)
	}
	defer cl.Close()
	// Starting tcp listener go routine and defining cleanup deferred call.
	go tcpListener(cl, stopch, resultch)
	defer func() {
		stopch <- struct{}{}
		<-stopch
	}()

	// Switching to the source namespace to make a call
	if err := netns.Set(ns[0]); err != nil {
		return err
	}
	// Setting Dial timeout to 30 seconds, as default timeout is too long.
	d := net.Dialer{Timeout: time.Second * 30}
	cd, err := d.Dial(proto, daddr+":8888")
	if err != nil {
		return fmt.Errorf("call Dial failed with error: %+v", err)
	}
	defer cd.Close()

	if err := getResult(resultch); err != nil {
		return fmt.Errorf("getPacket failed with error: %+v", err)
	}

	return nil
}

func getResult(resultch chan struct{}) error {
	ticker := time.NewTicker(time.Second * 1)
	timeout := time.NewTimer(time.Second * 10)
	for {
		select {
		case <-resultch:
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
