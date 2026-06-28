package mitm

type Pin struct {
	LeafSPKI   string
	IssuerSPKI string
}

func pinMatches(p Pin, snap tlsSnapshot) bool {
	if snap.LeafSPKI == "" || snap.IssuerSPKI == "" {
		return false
	}
	if p.LeafSPKI == snap.LeafSPKI {
		return true
	}
	return p.IssuerSPKI == snap.IssuerSPKI
}
