package mitm

import "testing"

func TestPinMatches(t *testing.T) {
	cases := []struct {
		name string
		pin  Pin
		snap tlsSnapshot
		want bool
	}{
		{
			name: "exact_leaf_match",
			pin:  Pin{LeafSPKI: "abc", IssuerSPKI: "ca1"},
			snap: tlsSnapshot{LeafSPKI: "abc", IssuerSPKI: "ca1"},
			want: true,
		},
		{
			name: "leaf_rotated_same_issuer_passes",
			pin:  Pin{LeafSPKI: "abc", IssuerSPKI: "ca1"},
			snap: tlsSnapshot{LeafSPKI: "xyz", IssuerSPKI: "ca1"},
			want: true,
		},
		{
			name: "strict_mismatch_both_differ",
			pin:  Pin{LeafSPKI: "abc", IssuerSPKI: "ca1"},
			snap: tlsSnapshot{LeafSPKI: "xyz", IssuerSPKI: "ca2"},
			want: false,
		},
		{
			name: "empty_snapshot_fails",
			pin:  Pin{LeafSPKI: "abc", IssuerSPKI: "ca1"},
			snap: tlsSnapshot{},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pinMatches(c.pin, c.snap)
			if got != c.want {
				t.Errorf("pinMatches(pin=%+v, snap=%+v) = %v; want %v",
					c.pin, c.snap, got, c.want)
			}
		})
	}
}
