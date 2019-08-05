package nftableslib

import (
	"fmt"

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
func getExprForSingleIP(l3proto nftables.TableFamily, offset uint32, addr *IPAddr, excl bool) ([]expr.Any, error) {
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
	if addr.CIDR {
		// Check specified subnet mask length so it would not exceed 32 for ipv4 and 128 for ipv6
		if l3proto == nftables.TableFamilyIPv4 && *addr.Mask > uint8(32) {
			return nil, fmt.Errorf("invalid mask length of %d for ipv4 address %s", *addr.Mask, addr.IP.String())
		}
		if l3proto == nftables.TableFamilyIPv6 && *addr.Mask > uint8(128) {
			return nil, fmt.Errorf("invalid mask length of %d for ipv4 address %s", *addr.Mask, addr.IP.String())
		}
		xor = make([]byte, addrLen)
		re = append(re, &expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            uint32(addrLen),
			Mask:           buildMask(addrLen, *addr.Mask),
			Xor:            xor,
		})
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
func getExprForListIP(l3proto nftables.TableFamily, set *nftables.Set, offset uint32, excl bool) ([]expr.Any, error) {
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

	re = append(re, &expr.Lookup{
		SourceRegister: 1,
		Invert:         excl,
		SetID:          set.ID,
		SetName:        set.Name,
	})

	return re, nil
}

// getExprForListIP returns expression to match a list of IPv4 or IPv6 addresses
func getExprForListIPV2(l3proto nftables.TableFamily, set *nftables.Set, offset uint32, excl bool) ([]expr.Any, error) {
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

	re = append(re, &expr.Lookup{
		SourceRegister: 1,
		Invert:         excl,
		SetID:          set.ID,
		SetName:        set.Name,
	})

	return re, nil
}

// getExprForRangeIP returns expression to match a range of IPv4 or IPv6 addresses
func getExprForRangeIP(l3proto nftables.TableFamily, offset uint32, rng [2]*IPAddr, excl bool) ([]expr.Any, error) {
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
	if excl {
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
	/*
	  [ immediate reg 1 {port to Redirect} ]
	  [ redir proto_min reg 1 ]
	*/

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

func getExprForSinglePort(l4proto uint8, offset uint32, port []*uint16, excl bool) ([]expr.Any, error) {
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
	op := expr.CmpOpEq
	if excl {
		op = expr.CmpOpNeq
	}
	re = append(re, &expr.Cmp{
		Op:       op,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint16(*port[0]),
	})

	return re, nil
}

func getExprForListPort(l4proto uint8, offset uint32, port []*uint16, excl bool, set *nftables.Set) ([]expr.Any, error) {
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
	re = append(re, &expr.Lookup{
		SourceRegister: 1,
		Invert:         excl,
		SetID:          set.ID,
		SetName:        set.Name,
	})

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

func getExprForRangePort(l4proto uint8, offset uint32, port [2]*uint16, excl bool) ([]expr.Any, error) {
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
	if excl {
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

func getExprForIPVersion(version byte, excl bool) ([]expr.Any, error) {
	re := []expr.Any{}
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       0, // Offset for a version of IP
		Len:          1, // 1 byte for IP version
	})
	if excl {
		// TODO
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

func getExprForProtocol(l3proto nftables.TableFamily, proto uint32, excl bool) ([]expr.Any, error) {
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

	if excl {
		// TODO
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

func getExprForMeta(meta *Meta) []expr.Any {
	re := []expr.Any{}
	re = append(re, &expr.Meta{Key: expr.MetaKey(meta.Key), Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     meta.Value,
	})

	return re
}

func getExprForLog(log *Log) []expr.Any {
	re := []expr.Any{}
	re = append(re, &expr.Log{Key: log.Key, Data: log.Value})

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
