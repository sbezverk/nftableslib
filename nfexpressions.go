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

func swapBytes(addr []byte) []byte {
	l := len(addr)
	r := make([]byte, l)
	for i := 0; i < len(addr); i++ {
		r[l-1-i] = addr[i]
	}
	return r
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
	var baddr []byte
	if l3proto == nftables.TableFamilyIPv4 {
		baddr = swapBytes([]byte(addr.IP.To4()))
	}
	if l3proto == nftables.TableFamilyIPv6 {
		baddr = swapBytes([]byte(addr.IP.To16()))
	}
	if len(baddr) == 0 {
		return nil, fmt.Errorf("invalid ip %s", addr.IP.String())
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
func getExprForListIP(l3proto nftables.TableFamily, set nftables.Set, offset uint32, excl bool) ([]expr.Any, error) {
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
		fromAddr = swapBytes([]byte(rng[0].IP.To4()))
		toAddr = swapBytes([]byte(rng[1].IP.To4()))
	}
	if l3proto == nftables.TableFamilyIPv6 {
		fromAddr = swapBytes([]byte(rng[0].IP.To16()))
		toAddr = swapBytes([]byte(rng[1].IP.To16()))
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

//
func getExprForRedirectPort(portToRedirect uint32) []expr.Any {
	/*
	  [ immediate reg 1 {port to Redirect} ]
	  [ redir proto_min reg 1 ]
	*/

	re := []expr.Any{}
	re = append(re, &expr.Immediate{
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint32(portToRedirect),
	})

	re = append(re, &expr.Redir{
		RegisterProtoMin: 1,
	})

	return re
}

func getExprForSinglePort(l4proto int, offset uint32, port []*uint32, excl bool) ([]expr.Any, error) {
	if l4proto == 0 {
		return nil, fmt.Errorf("l4 protocol is 0")
	}
	re := []expr.Any{}
	re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint32(uint32(l4proto)),
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
		Data:     binaryutil.BigEndian.PutUint16(uint16(*port[0])),
	})

	return re, nil
}

func getExprForListPort(l4proto int, offset uint32, port []*uint32, excl bool, set nftables.Set) ([]expr.Any, error) {
	if l4proto == 0 {
		return nil, fmt.Errorf("l4 protocol is 0")
	}
	re := []expr.Any{}
	re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint32(uint32(l4proto)),
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

func getExprForRangePort(l4proto int, offset uint32, port [2]*uint32, excl bool) ([]expr.Any, error) {
	if l4proto == 0 {
		return nil, fmt.Errorf("l4 protocol is 0")
	}
	re := []expr.Any{}
	re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint32(uint32(l4proto)),
	})
	if excl {
		re = append(re, &expr.Range{
			Op:       expr.CmpOpNeq,
			Register: 1,
			FromData: binaryutil.BigEndian.PutUint16(uint16(*port[0])),
			ToData:   binaryutil.BigEndian.PutUint16(uint16(*port[1])),
		})
		return re, nil
	}
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpGte,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint16(uint16(*port[0])),
	})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpLte,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint16(uint16(*port[1])),
	})

	return re, nil
}
