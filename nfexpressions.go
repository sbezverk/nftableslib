package nftableslib

import (
	"net"

	"golang.org/x/sys/unix"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// Packet is used to pass L4 protocol, source/destination address and
// source/destination ports to build matching expression, only L4 protocol
// is required.
type Packet struct {
	L4Proto uint32
	Addr    net.IP
	Port    uint32
	Src     bool
}

/*
	List of available keys:

    MetaKeyLEN        MetaKey = unix.NFT_META_LEN
    MetaKeyPROTOCOL   MetaKey = unix.NFT_META_PROTOCOL
    MetaKeyPRIORITY   MetaKey = unix.NFT_META_PRIORITY
    MetaKeyMARK       MetaKey = unix.NFT_META_MARK
    MetaKeyIIF        MetaKey = unix.NFT_META_IIF
    MetaKeyOIF        MetaKey = unix.NFT_META_OIF
    MetaKeyIIFNAME    MetaKey = unix.NFT_META_IIFNAME
    MetaKeyOIFNAME    MetaKey = unix.NFT_META_OIFNAME
    MetaKeyIIFTYPE    MetaKey = unix.NFT_META_IIFTYPE
    MetaKeyOIFTYPE    MetaKey = unix.NFT_META_OIFTYPE
    MetaKeySKUID      MetaKey = unix.NFT_META_SKUID
    MetaKeySKGID      MetaKey = unix.NFT_META_SKGID
    MetaKeyNFTRACE    MetaKey = unix.NFT_META_NFTRACE
    MetaKeyRTCLASSID  MetaKey = unix.NFT_META_RTCLASSID
    MetaKeySECMARK    MetaKey = unix.NFT_META_SECMARK
    MetaKeyNFPROTO    MetaKey = unix.NFT_META_NFPROTO
    MetaKeyL4PROTO    MetaKey = unix.NFT_META_L4PROTO
    MetaKeyBRIIIFNAME MetaKey = unix.NFT_META_BRI_IIFNAME
    MetaKeyBRIOIFNAME MetaKey = unix.NFT_META_BRI_OIFNAME
    MetaKeyPKTTYPE    MetaKey = unix.NFT_META_PKTTYPE
    MetaKeyCPU        MetaKey = unix.NFT_META_CPU
    MetaKeyIIFGROUP   MetaKey = unix.NFT_META_IIFGROUP
    MetaKeyOIFGROUP   MetaKey = unix.NFT_META_OIFGROUP
    MetaKeyCGROUP     MetaKey = unix.NFT_META_CGROUP
    MetaKeyPRANDOM    MetaKey = unix.NFT_META_PRANDOM
*/

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

// getExptForIPv4
func getExprForIPv4(data Packet) []expr.Any {
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
	baddr := bigEndianIPv4([]byte(data.Addr.To4()))
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     baddr,
	})

	return re
}

// getExprForIPv4SrcPort returns expression to match by ipv4 TCP source port
func getExprForIPv4Port(data Packet) []expr.Any {
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
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint32(data.Port),
	})

	return re
}

func bigEndianIPv4(addr []byte) []byte {
	return []byte{addr[3], addr[2], addr[1], addr[0]}
}
