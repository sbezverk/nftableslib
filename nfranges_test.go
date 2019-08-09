package nftableslib

import (
	"net"
	"reflect"
	"sort"
	"testing"
)

func TestGetMask(t *testing.T) {
	tests := []struct {
		name   string
		mask   uint8
		want   []byte
		length int
	}{
		{
			name:   "2bits",
			mask:   uint8(2),
			want:   []byte{0xc0, 0x00, 0x00, 0x00},
			length: 4,
		},
		{
			name:   "8bits",
			mask:   uint8(8),
			want:   []byte{0xff, 0x00, 0x00, 0x00},
			length: 4,
		},
		{
			name:   "10bits",
			mask:   uint8(10),
			want:   []byte{0xff, 0xc0, 0x00, 0x00},
			length: 4,
		},
		{
			name:   "16bits",
			mask:   uint8(16),
			want:   []byte{0xff, 0xff, 0x00, 0x00},
			length: 4,
		},
		{
			name:   "19bits",
			mask:   uint8(19),
			want:   []byte{0xff, 0xff, 0xe0, 0x00},
			length: 4,
		},
		{
			name:   "24bits",
			mask:   uint8(24),
			want:   []byte{0xff, 0xff, 0xff, 0x00},
			length: 4,
		},
		{
			name:   "28bits",
			mask:   uint8(28),
			want:   []byte{0xff, 0xff, 0xff, 0xf0},
			length: 4,
		},
	}

	for _, tt := range tests {
		got := getMask(tt.mask, tt.length)
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("Test \"%s\" failed, got: %+v want: %+v", tt.name, got, tt.want)
		}
	}
}

func TestIsSubnet(t *testing.T) {
	//	mask2 := uint8(2)
	mask8 := uint8(8)
	//	mask10 := uint8(10)
	mask16 := uint8(16)
	mask19 := uint8(19)
	mask24 := uint8(24)
	//	mask28 := uint8(28)

	tests := []struct {
		name   string
		ip1    *IPAddr
		ip2    *IPAddr
		subnet bool
	}{
		{
			name: "ipv4 subnet",
			ip1: &IPAddr{
				&net.IPAddr{
					IP: net.ParseIP("4.0.0.0"),
				},
				true,
				&mask8,
			},
			ip2: &IPAddr{
				&net.IPAddr{
					IP: net.ParseIP("4.4.0.0"),
				},
				true,
				&mask16,
			},
			subnet: true,
		},
		{
			name: "ipv4 not subnet",
			ip1: &IPAddr{
				&net.IPAddr{
					IP: net.ParseIP("4.0.0.0"),
				},
				true,
				&mask16,
			},
			ip2: &IPAddr{
				&net.IPAddr{
					IP: net.ParseIP("4.4.0.0"),
				},
				true,
				&mask19,
			},
			subnet: false,
		},
		{
			name: "ipv4 not subnet",
			ip1: &IPAddr{
				&net.IPAddr{
					IP: net.ParseIP("4.0.0.0"),
				},
				true,
				&mask8,
			},
			ip2: &IPAddr{
				&net.IPAddr{
					IP: net.ParseIP("4.0.4.0"),
				},
				true,
				&mask24,
			},
			subnet: true,
		},
	}
	for _, tt := range tests {
		if isSubnet(tt.ip1, tt.ip2) && !tt.subnet {
			t.Fatalf("Test \"%s\" failed, expected to be not subnet", tt.name)
		}
		if !isSubnet(tt.ip1, tt.ip2) && tt.subnet {
			t.Fatalf("Test \"%s\" failed, expected to be a subnet", tt.name)
		}
	}
}

func TestTryCollapse(t *testing.T) {
	addr1, _ := NewIPAddr("4.4.4.0/24")
	addr2, _ := NewIPAddr("4.4.0.0/16")
	addr3, _ := NewIPAddr("4.0.0.0/8")
	addr4, _ := NewIPAddr("4.0.4.0/25")
	addr5, _ := NewIPAddr("4.0.0.0/16")
	tests := []struct {
		name string
		list []*IPAddr
		want []*IPAddr
	}{
		{
			name: "1 entry left",
			list: []*IPAddr{addr1, addr2, addr3, addr4},
			want: []*IPAddr{addr3},
		},
		{
			name: "2 entry left",
			list: []*IPAddr{addr1, addr2, addr4, addr5},
			want: []*IPAddr{addr2, addr5},
		},
	}
	for _, tt := range tests {
		networks := ByMask{
			byMask: tt.list,
		}
		sort.Sort(&networks)
		got := tryCollapse(networks.byMask)
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("Test \"%s\" failed, got: %+v want: %+v", tt.name, got, tt.want)
		}
	}
}

func TestComputeGapRange(t *testing.T) {
	tests := []struct {
		name string
		cidr *IPAddr
		want net.IP
	}{
		{
			name: "test_1",
			cidr: setIPAddr(t, "1.0.0.0/8"),
			want: net.IP([]byte{2, 0, 0, 0}),
		},
		{
			name: "test_2",
			cidr: setIPAddr(t, "35.254.0.0/16"),
			want: net.IP([]byte{35, 255, 0, 0}),
		},
	}
	for _, tt := range tests {
		got := computeGapRange(tt.cidr)
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("Test \"%s\" failed, got: %+v want: %+v", tt.name, got, tt.want)
		}
	}
}
