package nftableslib

import (
	"testing"

	"golang.org/x/sys/unix"
)

func setActionRedirect(t *testing.T, port int, tproxy bool) *RuleAction {
	ra, err := SetRedirect(port, tproxy)
	if err != nil {
		t.Fatalf("failed to SetRedirect with error: %+v", err)
	}
	return ra
}

func setActionVerdict(t *testing.T, key int, chain ...string) *RuleAction {
	ra, err := SetVerdict(key, chain...)
	if err != nil {
		t.Fatalf("failed to SetVerdict with error: %+v", err)
	}
	return ra
}

func setIPAddr(t *testing.T, addr string) *IPAddr {
	a, err := NewIPAddr(addr)
	if err != nil {
		t.Fatalf("error %+v return from NewIPAddr for address: %s", err, addr)
	}
	return a
}

func TestRule(t *testing.T) {
	//	ipv4Mask := uint8(24)
	ipVersion := byte(4)

	tests := []struct {
		name    string
		rule    *Rule
		success bool
	}{
		// TODO add more tests
		{
			name:    "Empty rule",
			rule:    &Rule{},
			success: false,
		},
		{
			name: "Good L3",
			rule: &Rule{
				L3: &L3Rule{
					Src: &IPAddrSpec{
						List: []*IPAddr{setIPAddr(t, "192.0.2.0/24")},
					},
				},
				Action: setActionVerdict(t, unix.NFT_RETURN),
			},
			success: true,
		},
		{
			name: "Good L3 Version Only",
			rule: &Rule{
				L3: &L3Rule{
					Version: &ipVersion,
				},
				Action: setActionVerdict(t, unix.NFT_RETURN),
			},
			success: true,
		},
		{
			name: "Good L3 Protocol with Redirect TProxy",
			rule: &Rule{
				L3: &L3Rule{
					Protocol: L3Protocol(unix.IPPROTO_TCP),
				},
				Action: setActionRedirect(t, 15001, true),
			},
			success: true,
		},
		{
			name: "Good L3 Protocol with Redicrect non TProxy",
			rule: &Rule{
				L3: &L3Rule{
					Protocol: L3Protocol(unix.IPPROTO_TCP),
				},
				Action: setActionRedirect(t, 50000, false),
			},
			success: true,
		},
		{
			name: "Redirect Only",
			rule: &Rule{
				Action: setActionRedirect(t, 50000, false),
			},
			success: false,
		},
		{
			name: "Verdict Only",
			rule: &Rule{
				Action: setActionVerdict(t, unix.NFT_JUMP, "fake-chain-1"),
			},
			success: true,
		},
	}

	for _, tt := range tests {
		err := tt.rule.Validate()
		if tt.success && err != nil {
			t.Errorf("Test \"%s\" failed with error: \"%+v\" but supposed to succeed", tt.name, err)
			continue
		}
		if !tt.success && err == nil {
			t.Errorf("Test \"%s\" succeeded but supposed to fail", tt.name)
		}
	}
}
