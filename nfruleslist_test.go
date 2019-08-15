package nftableslib

import (
	"testing"

	"github.com/google/nftables"
)

func TestAddRule(t *testing.T) {
	r := nfRules{
		rules: nil,
	}

	for i := 0; i < 10; i++ {
		r.addRule(&nfRule{
			id:   uint32(i),
			rule: &nftables.Rule{},
		})
	}

	if n := r.countRules(); n != 10 {
		t.Fatalf("Expected 10 rules but found %d", n)
	}

}

func TestRemoveRule(t *testing.T) {

	tests := []struct {
		name     string
		number   int
		removeID uint32
		expect   int
		success  bool
	}{
		{
			name:     "Single element",
			number:   1,
			removeID: 10,
			expect:   0,
			success:  true,
		},
		{
			name:     "2 elements, deleting first",
			number:   2,
			removeID: 10,
			expect:   1,
			success:  true,
		},
		{
			name:     "2 elements, deleting last",
			number:   2,
			removeID: 20,
			expect:   1,
			success:  true,
		},
		{
			name:     "3 elements, deleting middle",
			number:   3,
			removeID: 20,
			expect:   2,
			success:  true,
		},
		{
			name:     "3 elements, deleting nonexisting",
			number:   3,
			removeID: 50,
			expect:   3,
			success:  false,
		},
	}

	for _, tt := range tests {
		r := nfRules{
			rules: nil,
		}
		for i := 0; i < tt.number; i++ {
			r.addRule(&nfRule{
				id:   uint32((i + 1) * 10),
				rule: &nftables.Rule{},
			})
		}
		err := r.removeRule(tt.removeID)
		if err != nil && tt.success {
			t.Fatalf("test \"%s\" failed to remove Rule with error: %+v but expected to succeed", tt.name, err)
		}
		if err == nil && !tt.success {
			t.Fatalf("test \"%s\" expected to fail but succeeded", tt.name)
		}
		if n := r.countRules(); n != tt.expect {
			t.Fatalf("test \"%s\" failed, expected %d rule but found %d", tt.name, tt.expect, n)
		}
	}
}

func TestInsertRule(t *testing.T) {
	// TODO Add test after insertRule is implemented
}
