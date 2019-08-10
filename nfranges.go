package nftableslib

import (
	"net"
	"sort"

	"github.com/google/nftables"
)

type ByIP struct {
	byIP []*IPAddr
}

func (a *ByIP) Len() int {
	return len(a.byIP)
}

func (a *ByIP) Swap(i, j int) {
	a.byIP[i], a.byIP[j] = a.byIP[j], a.byIP[i]
}

func (a *ByIP) Less(i, j int) bool {
	a1 := a.byIP[i].IPAddr.IP
	a2 := a.byIP[j].IPAddr.IP
	for i := 0; i < len(a1); i++ {
		if a1[i] < a2[i] {
			return true
		} else {
			return false
		}
	}
	return false
}

type ByMask struct {
	byMask []*IPAddr
}

func (m *ByMask) Len() int {
	return len(m.byMask)
}

func (m *ByMask) Swap(i, j int) {
	m.byMask[i], m.byMask[j] = m.byMask[j], m.byMask[i]
}

func (m *ByMask) Less(i, j int) bool {
	return *m.byMask[i].Mask < *m.byMask[j].Mask
}

func getNetworks(list []*IPAddr) [][]*IPAddr {
	result := make([][]*IPAddr, 0)
	for i := 0; i < len(list); i++ {
		b1 := list[i].IPAddr.IP
		networks := make([]*IPAddr, 0)
		networks = append(networks, list[i])
		j := i + 1
		for ; j < len(list); j++ {
			b2 := list[j].IPAddr.IP
			if b1[0] == b2[0] {
				networks = append(networks, list[j])
				i++
			}
		}
		if len(networks) != 0 {
			result = append(result, networks)
		}
	}

	return result
}

func buildElementRanges(list []*IPAddr) []nftables.SetElement {
	a := ByIP{
		byIP: list,
	}
	sort.Sort(&a)
	networks := getNetworks(a.byIP)
	fl := make([]*IPAddr, 0)
	for _, nets := range networks {
		m := ByMask{
			byMask: nets,
		}
		sort.Sort(&m)
		if len(m.byMask) > 1 {
			fl = append(fl, tryCollapse(m.byMask)...)
			continue
		}
		fl = append(fl, m.byMask...)
	}
	se := buildElements(fl)

	return se
}

func buildElements(list []*IPAddr) []nftables.SetElement {
	se := make([]nftables.SetElement, 0)

	if !list[0].IsIPv6() {
		se = append(se, nftables.SetElement{Key: net.ParseIP("0.0.0.0").To4(), IntervalEnd: true})
	} else {
		se = append(se, nftables.SetElement{Key: net.ParseIP("::").To16(), IntervalEnd: true})
	}
	for i := 0; i < len(list); i++ {
		se = append(se, nftables.SetElement{Key: list[i].IPAddr.IP})
		se = append(se, nftables.SetElement{Key: computeGapRange(list[i]), IntervalEnd: true})
	}

	return se
}

func computeGapRange(e1 *IPAddr) net.IP {
	imask1 := getInverseMask(getMask(*e1.Mask, len(e1.IP)))
	bip1 := addInverseMaskPlusOne(getIP(e1), imask1)

	return net.IP(bip1)
}

func tryCollapse(org []*IPAddr) []*IPAddr {
	res := make([]*IPAddr, 0)
	collapsed := make([]int, len(org))
	for i := 0; i < len(org); i++ {
		if collapsed[i] == 1 {
			continue
		}
		res = append(res, org[i])
		for j := 0; j < len(org); j++ {
			if i == j {
				continue
			}
			if isSubnet(org[i], org[j]) {
				collapsed[j] = 1
				continue
			}
		}
	}

	return res
}

func isSubnet(ip1, ip2 *IPAddr) bool {
	mask1 := getMask(*ip1.Mask, len(ip1.IP))
	mask2 := getMask(*ip2.Mask, len(ip2.IP))
	bip1 := getIP(ip1)
	bip2 := getIP(ip2)
	for i := range bip1 {
		if bip1[i]&mask1[i] != bip2[i]&mask2[i]&mask1[i] {
			return false
		}
	}
	return true
}

func getIP(ip *IPAddr) []byte {
	if !ip.IsIPv6() {
		return ip.IP.To4()
	}
	return ip.IP.To16()
}

func getMask(ml uint8, l int) []byte {
	mask := make([]byte, l)
	fullBytes := ml / 8
	leftBits := ml % 8
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

func getInverseMask(mask []byte) []byte {
	inv := make([]byte, len(mask))
	for i := 0; i < len(mask); i++ {
		inv[i] = ^mask[i]
	}

	return inv
}

func addInverseMaskPlusOne(ip, mask []byte) []byte {
	r := make([]byte, len(ip))
	for i := 0; i < len(mask); i++ {
		r[i] = ip[i] | mask[i]
	}
	for i := len(r) - 1; i >= 0; i-- {
		r[i]++
		if r[i] != 0 {
			return r
		}
	}

	return r
}
