package nftableslib

import (
	"fmt"
	"net"

	"github.com/google/nftables"

	"golang.org/x/sys/unix"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// L3Packet defines parameters of Layer 3 packet processing
type L3Packet struct {
	Addr net.IP
	Src  bool
}

// L4PortList defines parameters of Layer 4 packet processing
type L4PortList struct {
	L4Proto uint32
	Port    []uint32
	Src     bool
	expr.Verdict
}

// L4PortRange defines parameters of Layer 4 packet processing
type L4PortRange struct {
	L4Proto  uint32
	FromPort uint32
	ToPort   uint32
	Src      bool
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

func inputIntfByName(intf string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(intf),
		},
	}
}

func outputIntfByName(intf string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(intf),
		},
	}
}

// proto example: unix.IPPROTO_TCP
func redirect(proto uint32, rp uint32, ports ...uint32) []expr.Any {
	/*
	  [ meta load l4proto => reg 1 ]
	  [ cmp eq reg 1 0x00000006 ]
	  [ payload load 2b @ transport header + 2 => reg 1 ]
	  [ cmp gte reg 1 0x00000100 ]
	  [ cmp lte reg 1 0x0000ffff ]
	  [ immediate reg 1 0x0000993a ]
	  [ redir proto_min reg 1 ]
	*/

	re := []expr.Any{}
	re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint32(proto),
	})

	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       2, // Offset for a transport protocol header
		Len:          2, // 2 bytes for port
	})
	var fp, lp uint32

	switch len(ports) {
	case 0: // No ports specified redirecting whole range 1-65535
		fp, lp = 1, 65535
	case 1:
		fp = ports[0]
	case 2:
		fp, lp = ports[0], ports[1]
	default:
		fp, lp = ports[0], ports[1]
	}
	if lp == 0 {
		// Single port was passed, then expression is for a single port match
		re = append(re, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint32(fp),
		})

	} else {
		// range of ports was specified, then expression for range is added
		re = append(re, &expr.Cmp{
			Op:       expr.CmpOpGte,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint32(fp),
		})
		re = append(re, &expr.Cmp{
			Op:       expr.CmpOpLte,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint32(lp),
		})
	}
	re = append(re, &expr.Immediate{
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint32(rp),
	})

	re = append(re, &expr.Redir{
		RegisterProtoMin: 1,
	})

	return re
}

func processPortInChain(proto uint32, port uint32, chain string) []expr.Any {
	/*
	  [ meta load l4proto => reg 1 ]
	  [ cmp eq reg 1 0x00000006 ]
	  [ payload load 2b @ transport header + 2 => reg 1 ]
	  [ cmp eq reg 1 0x000011c6 ]
	  [ immediate reg 0 jump -> istio_redirect ]
	*/
	re := []expr.Any{}
	re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint32(proto),
	})

	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       2, // Offset for a transport protocol header
		Len:          2, // 2 bytes for port
	})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint32(port),
	})

	re = append(re, &expr.Verdict{
		Kind:  expr.VerdictKind(unix.NFT_JUMP),
		Chain: chain,
	})

	return re
}

// ProcessL4Packet matches a packet based on the passed parameter and returns
// to the calling chain
func ProcessL4Packet(data L4PortList) []expr.Any {
	re := []expr.Any{}

	// Match for L4 protocol if specified
	if data.L4Proto == 0 {
		return re
	}
	re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint32(data.L4Proto),
	})
	// If port is specified, then add condition for the port
	if len(data.Port) != 0 {
		re = append(re, getExprForL4Port(data)...)
	}
	kind := data.Verdict.Kind
	if kind == 0 {
		kind = unix.NFT_RETURN
	}
	re = append(re, &expr.Verdict{
		Kind:  kind,
		Chain: data.Verdict.Chain,
	})

	return re
}

/*
// ProcessIPv4Packet matches a packet based on the passed parameter and returns
// to the calling chain
func ProcessIPv4Packet(data Packet) []expr.Any {
	re := []expr.Any{}

	// if IP address specified, get the expression to match
	if data.Addr != nil {
		re = append(re, getExprForIPv4(data)...)
	}
	// Match for L4 protocol if specified
	if data.L4Proto == 0 {
		return re
	}
	re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint32(data.L4Proto),
	})
	// If port is specified, then add condition for the port
	if data.Port != 0 {
		re = append(re, getExprForIPv4Port(data)...)
	}
	re = append(re, &expr.Verdict{
		Kind: expr.VerdictKind(unix.NFT_RETURN),
	})

	return re
}
*/

// getExptForIPv4
func getExprForIPv4(data L3Packet) []expr.Any {
	re := []expr.Any{}
	offset := uint32(16)
	if data.Src {
		offset = uint32(12)
	}
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset, // Offset ipv4 address in network header
		Len:          4,      // length bytes for ipv4 address
	})
	baddr := swapBytes([]byte(data.Addr.To4()))
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     baddr,
	})

	return re
}

// getExprForIPv4SrcPort returns expression to match by ipv4 TCP source port
func getExprForL4Port(data L4PortList) []expr.Any {
	re := []expr.Any{}
	offset := uint32(2)
	if data.Src {
		offset = 0
	}
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       offset, // Offset for a transport protocol header
		Len:          2,      // 2 bytes for port
	})
	port := make([]byte, 2, 4)
	port = append(port, binaryutil.NativeEndian.PutUint16(uint16(data.Port[0]))...)
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     port,
	})

	return re
}

// New calls

func swapBytes(addr []byte) []byte {
	l := len(addr)
	r := make([]byte, l)
	for i := 0; i < len(addr); i++ {
		r[l-1-i] = addr[i]
	}
	return r
}

// getExprForSingleIP returns expression to match a single IPv4 or IPv6 address
func getExprForSingleIP(l3proto nftables.TableFamily, offset uint32, addr *net.IPAddr, excl bool) ([]expr.Any, error) {
	re := []expr.Any{}

	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset, // Offset ipv4 address in network header
		Len:          4,      // length bytes for ipv4 address
	})
	var baddr []byte
	if l3proto == nftables.TableFamilyIPv4 {
		baddr = swapBytes([]byte(addr.IP.To4()))
	}
	if l3proto == nftables.TableFamilyIPv6 {
		baddr = swapBytes([]byte(addr.IP.To16()))
	}
	if baddr == nil {
		return nil, fmt.Errorf("invalid ip %s", addr.String())
	}
	op := expr.CmpOpEq
	if excl {
		op = expr.CmpOpNeq
	}
	re = append(re, &expr.Cmp{
		Op:       op,
		Register: 1,
		Data:     baddr,
	})

	return re, nil
}

// getExprForListIP returns expression to match a list of IPv4 or IPv6 addresses
func getExprForListIP(set nftables.Set, offset uint32, excl bool) ([]expr.Any, error) {
	re := []expr.Any{}

	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset, // Offset ipv4 address in network header
		Len:          4,      // length bytes for ipv4 address
	})

	re = append(re, &expr.Lookup{
		SourceRegister: 1,
		Invert:         excl,
		SetID:          set.ID,
		SetName:        set.Name,
	})

	return re, nil
}
