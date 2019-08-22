package nftableslib

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/google/nftables"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

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

// getExprForSingleIP returns expression to match a single IPv4 or IPv6 address
func getExprForSingleIP(l3proto nftables.TableFamily, offset uint32, addr *IPAddr, op Operator) ([]expr.Any, error) {
	re := []expr.Any{}
	addrLen := 4
	if l3proto == nftables.TableFamilyIPv6 {
		addrLen = 16
	}
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,          // Offset ipv4 address in network header
		Len:          uint32(addrLen), // length bytes for ipv4 address
	})
	var baddr, xor []byte
	if l3proto == nftables.TableFamilyIPv4 {
		baddr = []byte(addr.IP.To4())
	}
	if l3proto == nftables.TableFamilyIPv6 {
		baddr = []byte(addr.IP.To16())
	}
	if len(baddr) == 0 {
		return nil, fmt.Errorf("invalid ip %s", addr.IP.String())
	}
	xor = make([]byte, addrLen)
	re = append(re, &expr.Bitwise{
		SourceRegister: 1,
		DestRegister:   1,
		Len:            uint32(addrLen),
		Mask:           buildMask(addrLen, *addr.Mask),
		Xor:            xor,
	})
	cmpOp := expr.CmpOpEq
	if op == NEQ {
		cmpOp = expr.CmpOpNeq
	}
	re = append(re, &expr.Cmp{
		Op:       cmpOp,
		Register: 1,
		Data:     baddr,
	})

	return re, nil
}

// getExprForListIP returns expression to match a list of IPv4 or IPv6 addresses
func getExprForListIP(l3proto nftables.TableFamily, set *nftables.Set, offset uint32, op Operator) ([]expr.Any, error) {
	re := []expr.Any{}

	addrLen := 4
	if l3proto == nftables.TableFamilyIPv6 {
		addrLen = 16
	}
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,          // Offset ip address in network header
		Len:          uint32(addrLen), // length bytes for ip address
	})
	excl := false
	if op == NEQ {
		excl = true
	}
	re = append(re, &expr.Lookup{
		SourceRegister: 1,
		Invert:         excl,
		SetID:          set.ID,
		SetName:        set.Name,
	})

	return re, nil
}

// getExprForRangeIP returns expression to match a range of IPv4 or IPv6 addresses
func getExprForRangeIP(l3proto nftables.TableFamily, offset uint32, rng [2]*IPAddr, op Operator) ([]expr.Any, error) {
	re := []expr.Any{}

	addrLen := 4
	if l3proto == nftables.TableFamilyIPv6 {
		addrLen = 16
	}
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,          // Offset ipv4 address in network header
		Len:          uint32(addrLen), // length bytes for ipv4 address
	})
	var fromAddr, toAddr []byte
	if l3proto == nftables.TableFamilyIPv4 {
		fromAddr = []byte(rng[0].IP.To4())
		toAddr = []byte(rng[1].IP.To4())
	}
	if l3proto == nftables.TableFamilyIPv6 {
		fromAddr = []byte(rng[0].IP.To16())
		toAddr = []byte(rng[1].IP.To16())
	}
	if len(fromAddr) == 0 {
		return nil, fmt.Errorf("invalid ip %s", rng[0].IP.String())
	}
	if len(toAddr) == 0 {
		return nil, fmt.Errorf("invalid ip %s", rng[1].IP.String())
	}
	if op == NEQ {
		re = append(re, &expr.Range{
			Op:       expr.CmpOpNeq,
			Register: 1,
			FromData: fromAddr,
			ToData:   toAddr,
		})
		return re, nil
	}
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpGte,
		Register: 1,
		Data:     fromAddr,
	})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpLte,
		Register: 1,
		Data:     toAddr,
	})

	return re, nil
}

func getExprForRedirectPort(portToRedirect uint16) []expr.Any {
	// [ immediate reg 1 {port to Redirect} ]
	//  [ redir proto_min reg 1 ]
	re := []expr.Any{}
	re = append(re, &expr.Immediate{
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint16(portToRedirect),
	})

	re = append(re, &expr.Redir{
		RegisterProtoMin: 1,
	})

	return re
}

func getExprForListPort(l4proto uint8, offset uint32, port []*uint16, op Operator, set *nftables.Set) ([]expr.Any, error) {
	if l4proto == 0 {
		return nil, fmt.Errorf("l4 protocol is 0")
	}
	re := []expr.Any{}
	re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte{l4proto},
	})
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       offset, // Offset for a transport protocol header
		Len:          2,      // 2 bytes for port
	})
	excl := false
	if op == NEQ {
		excl = true
	}
	if len(port) > 1 {
		// Multi port is accomplished as a lookup
		re = append(re, &expr.Lookup{
			SourceRegister: 1,
			Invert:         excl,
			SetID:          set.ID,
			SetName:        set.Name,
		})
	} else {
		// Case for a single port list
		cmpOp := expr.CmpOpEq
		if excl {
			cmpOp = expr.CmpOpNeq
		}
		re = append(re, &expr.Cmp{
			Op:       cmpOp,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(*port[0]),
		})

	}
	return re, nil
}

func getExprForTProxyRedirect(port uint16, family nftables.TableFamily) []expr.Any {
	re := []expr.Any{}
	re = append(re, &expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(port)})
	re = append(re,
		&expr.TProxy{
			Family:      byte(family),
			TableFamily: byte(family),
			RegPort:     1,
		})

	return re
}

func getExprForRedirect(port uint16, family nftables.TableFamily) []expr.Any {
	re := []expr.Any{}
	re = append(re, &expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(port)})
	re = append(re,
		&expr.Redir{
			RegisterProtoMin: 1,
			RegisterProtoMax: 1,
		})

	return re
}

func getExprForRangePort(l4proto uint8, offset uint32, port [2]*uint16, op Operator) ([]expr.Any, error) {
	// [ meta load l4proto => reg 1 ]
	// [ cmp eq reg 1 0x00000006 ]
	// [ payload load 2b @ transport header + 0 => reg 1 ]
	// [ cmp gte reg 1 0x00003930 ]
	// [ cmp lte reg 1 0x000031d4 ]

	if l4proto == 0 {
		return nil, fmt.Errorf("l4 protocol is 0")
	}
	re := []expr.Any{}
	re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte{l4proto},
	})
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       offset, // Offset for a transport protocol header
		Len:          2,      // 2 bytes for port
	})
	if op == NEQ {
		re = append(re, &expr.Range{
			Op:       expr.CmpOpNeq,
			Register: 1,
			FromData: binaryutil.NativeEndian.PutUint16(*port[0]),
			ToData:   binaryutil.NativeEndian.PutUint16(*port[1]),
		})
		return re, nil
	}
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpGte,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint16(*port[0]),
	})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpLte,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint16(*port[1]),
	})

	return re, nil
}

func getExprForIPVersion(version byte, op Operator) ([]expr.Any, error) {
	re := []expr.Any{}
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       0, // Offset for a version of IP
		Len:          1, // 1 byte for IP version
	})
	if op != EQ {
		// TODO sbezverk
		return re, nil
	}
	re = append(re, &expr.Bitwise{
		SourceRegister: 1,
		DestRegister:   1,
		Len:            1,
		Mask:           []byte{0xf0},
		Xor:            []byte{0x0},
	})

	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte{(version << 4)},
	})

	return re, nil
}

func getExprForProtocol(l3proto nftables.TableFamily, proto uint32, op Operator) ([]expr.Any, error) {
	re := []expr.Any{}
	if l3proto == nftables.TableFamilyIPv4 {
		// IPv4
		// [ payload load 1b @ network header + 9 => reg 1 ]
		re = append(re, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       9, // Offset for a L4 protocol
			Len:          1, // 1 byte for L4 protocol
		})
	} else {
		// IPv6
		//	[ payload load 1b @ network header + 6 => reg 1 ]
		re = append(re, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       6, // Offset for a L4 protocol
			Len:          1, // 1 byte for L4 protocol
		})
	}

	if op != EQ {
		// TODO sbezverk
		return re, nil
	}
	// [ cmp eq reg 1 0x00000006 ]
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binaryutil.NativeEndian.PutUint32(proto),
	})

	return re, nil
}

func getExprForMetaMark(mark *MetaMark) []expr.Any {
	re := []expr.Any{}
	if mark.Set {
		// [ immediate reg 1 0x0000dead ]
		// [ meta set mark with reg 1 ]
		re = append(re, &expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(mark.Value))})
		re = append(re, &expr.Meta{Key: expr.MetaKey(unix.NFT_META_MARK), Register: 1, SourceRegister: true})
	} else {
		// [ meta load mark => reg 1 ]
		// [ cmp eq reg 1 0x0000dead ]
		re = append(re, &expr.Meta{Key: expr.MetaKey(unix.NFT_META_MARK), Register: 1, SourceRegister: false})
		re = append(re, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(uint32(mark.Value)),
		})
	}

	return re
}

func getExprForMasq(masq *masquerade) []expr.Any {
	re := []expr.Any{}
	// Since masquerade flags and toPort are mutually exclusive, each case will generate different sequence of
	// expressions
	if masq.toPort[0] != nil {
		m := &expr.Masq{ToPorts: true}
		// Case  at least 1 toPort specified
		//  [ immediate reg 1 0x00000004 ]
		re = append(re, &expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(*masq.toPort[0]))})
		m.RegProtoMin = 1
		m.RegProtoMax = 0
		if masq.toPort[1] != nil {
			// If second port is specified, then range of ports will be used.
			// [ immediate reg 2 0x00000008 ]
			re = append(re, &expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint32(uint32(*masq.toPort[1]))})
			m.RegProtoMax = 2
		}
		// [ masq proto_min reg 1 proto_max reg 2 ]
		re = append(re, m)
	} else {
		// Since toPort[0] is nil, checking flags
		//  [ masq flags value ]
		var random, fullyRandom, persistent bool
		if masq.random != nil {
			random = *masq.random
		}
		if masq.fullyRandom != nil {
			fullyRandom = *masq.fullyRandom
		}
		if masq.persistent != nil {
			persistent = *masq.persistent
		}
		re = append(re, &expr.Masq{Random: random, FullyRandom: fullyRandom, Persistent: persistent, ToPorts: false})
	}

	return re
}

func getExprForLog(log *Log) []expr.Any {
	re := []expr.Any{}
	re = append(re, &expr.Log{Key: log.Key, Data: log.Value})

	return re
}

func getExprForReject(r *reject) []expr.Any {
	re := []expr.Any{}
	re = append(re, &expr.Reject{Type: r.rejectType, Code: r.rejectCode})

	return re
}

func getExprForConntracks(cts []*Conntrack) []expr.Any {
	re := []expr.Any{}
	for _, ct := range cts {
		switch ct.Key {
		// List of supported conntrack keys
		case unix.NFT_CT_STATE:
			//	[ ct load state => reg 1 ]
			//	[ bitwise reg 1 = (reg=1 & 0x00000008 ) ^ 0x00000000 ]
			//	[ cmp neq reg 1 0x00000000 ]
			re = append(re, &expr.Ct{Key: unix.NFT_CT_STATE, Register: 1})
			re = append(re, &expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           ct.Value,
				Xor:            []byte{0x0, 0x0, 0x0, 0x0},
			})
			re = append(re, &expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x0, 0x0, 0x0, 0x0},
			})
		case unix.NFT_CT_DIRECTION:
		case unix.NFT_CT_STATUS:
		case unix.NFT_CT_LABELS:
		case unix.NFT_CT_EVENTMASK:
		}
	}

	return re
}

func buildMask(length int, maskLength uint8) []byte {
	mask := make([]byte, length)
	fullBytes := maskLength / 8
	leftBits := maskLength % 8
	for i := 0; i < int(fullBytes); i++ {
		mask[i] = 0xff
	}
	if leftBits != 0 {
		m := uint8(0x80)
		v := uint8(0x00)
		for i := 0; i < int(leftBits); i++ {
			v += m
			m = (m >> 1)
		}
		mask[fullBytes] ^= v
	}
	return mask
}
