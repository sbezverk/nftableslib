package nftableslib

import (
	"testing"

	"github.com/google/nftables"
)

func TestGenSetKeyType(t *testing.T) {
	tests := []struct {
		name      string
		types     []nftables.SetDatatype
		wantBytes uint32
	}{
		{
			name:      "No concat types provided",
			types:     nil,
			wantBytes: 0,
		},
		{
			name:      "Single TypeInetProto",
			types:     []nftables.SetDatatype{nftables.TypeInetProto},
			wantBytes: 4,
		},
		{
			name:      "Single TypeInetService",
			types:     []nftables.SetDatatype{nftables.TypeInetService},
			wantBytes: 4,
		},
		{
			name:      "Single TypeIPAddr",
			types:     []nftables.SetDatatype{nftables.TypeIPAddr},
			wantBytes: 4,
		},
		{
			name:      "Single TypeIP6Addr",
			types:     []nftables.SetDatatype{nftables.TypeIP6Addr},
			wantBytes: 16,
		},
		{
			name:      "Single TypeEtherAddr",
			types:     []nftables.SetDatatype{nftables.TypeEtherAddr},
			wantBytes: 8,
		},
		{
			name:      "Concat TypeInetProto & TypeInetService",
			types:     []nftables.SetDatatype{nftables.TypeInetProto, nftables.TypeInetService},
			wantBytes: 8,
		},
		{
			name:      "Concat TypeInetProto & TypeIPAddr",
			types:     []nftables.SetDatatype{nftables.TypeInetProto, nftables.TypeIPAddr},
			wantBytes: 8,
		},
		{
			name:      "Concat TypeIPAddr & TypeInetService",
			types:     []nftables.SetDatatype{nftables.TypeIPAddr, nftables.TypeInetService},
			wantBytes: 8,
		},
		{
			name:      "Concat TypeInetProto & TypeIPAddr & TypeInetService",
			types:     []nftables.SetDatatype{nftables.TypeInetProto, nftables.TypeIPAddr, nftables.TypeInetService},
			wantBytes: 12,
		},
	}

	for _, tt := range tests {
		gotType := GenSetKeyType(tt.types...)
		if gotType.Bytes != tt.wantBytes {
			t.Errorf("Test \"%s\" failed, expected %d bytes but got %d bytes", tt.name, tt.wantBytes, gotType.Bytes)
		}
	}
}
