package nftableslib

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/google/nftables/expr"
)

func TestRule(t *testing.T) {
	ipv4Mask := uint8(24)
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
			name: "Rule with just Verdict",
			rule: &Rule{

				Verdict: &expr.Verdict{
					Kind:  expr.VerdictKind(unix.NFT_JUMP),
					Chain: "test-chain",
				},
			},
			success: true,
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
			},
			success: true,
		},
	}

	for _, tt := range tests {
		err := tt.rule.Validate()
		if tt.success && err != nil {
			t.Errorf("Test \"%s\" failed with error: %+v but supposed to succeed", tt.name, err)
			continue
		}
		if !tt.success && err == nil {
			t.Errorf("Test \"%s\" succeeded but supposed to fail", tt.name)
		}
	}
}
