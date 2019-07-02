package nftableslib

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/google/nftables/expr"
)

func TestRule(t *testing.T) {
	ipv4Mask := uint8(24)
	ipVersion := byte(4)
	ipProtocol := uint32(unix.IPPROTO_TCP)
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
						List: []*IPAddr{
							{
								&net.IPAddr{
									IP: net.ParseIP("192.0.2.0"),
								},
								true,
								&ipv4Mask,
							},
						},
					},
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_RETURN),
				},
			},
			success: true,
		},
		{
			name: "Good L3 Version Only",
			rule: &Rule{
				L3: &L3Rule{
					Version: &ipVersion,
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_RETURN),
				},
			},
			success: true,
		},
		{
			name: "Good L3 Protocol with Redicrect",
			rule: &Rule{
				L3: &L3Rule{
					Protocol: &ipProtocol,
				},
				Redirect: &Redirect{
					Port:   uint16(50000),
					TProxy: true,
				},
			},
			success: true,
		},
		{
			name: "Redirect Only",
			rule: &Rule{
				Redirect: &Redirect{
					Port:   uint16(50000),
					TProxy: true,
				},
			},
			success: false,
		},
		{
			name: "Verdict Only",
			rule: &Rule{

				Verdict: &expr.Verdict{
					Kind:  expr.VerdictKind(unix.NFT_JUMP),
					Chain: "test-chain",
				},
			},
			success: true,
		},

		{
			name: "Redirect and Verdict",
			rule: &Rule{
				Redirect: &Redirect{
					Port:   uint16(50000),
					TProxy: true,
				},
				Verdict: &expr.Verdict{
					Kind: expr.VerdictKind(unix.NFT_RETURN),
				},
			},
			success: false,
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
