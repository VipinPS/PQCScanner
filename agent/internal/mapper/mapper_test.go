package mapper

import "testing"

func TestProbeIDsAreUnique(t *testing.T) {
	seen := map[uint64]bool{}
	for _, p := range Probes {
		if seen[p.ID] {
			t.Fatalf("duplicate probe ID %d (symbol %s)", p.ID, p.Symbol)
		}
		seen[p.ID] = true
	}
}

func TestByID(t *testing.T) {
	p, ok := ByID(0)
	if !ok || p.Symbol != "MD5_Init" {
		t.Fatalf("ByID(0) = %+v, %v; want MD5_Init, true", p, ok)
	}

	if _, ok := ByID(9999); ok {
		t.Fatal("ByID(9999) should not exist")
	}
}

func TestBySymbol(t *testing.T) {
	p, ok := BySymbol("ECDH_compute_key")
	if !ok || p.Algorithm != "ECDH" {
		t.Fatalf("BySymbol(ECDH_compute_key) = %+v, %v; want algorithm ECDH", p, ok)
	}

	if _, ok := BySymbol("does_not_exist"); ok {
		t.Fatal("BySymbol(does_not_exist) should not exist")
	}
}

func TestLibrariesAndForLibrary(t *testing.T) {
	libs := Libraries()
	if len(libs) == 0 {
		t.Fatal("Libraries() returned no libraries")
	}

	total := 0
	for _, lib := range libs {
		probes := ForLibrary(lib)
		if len(probes) == 0 {
			t.Fatalf("ForLibrary(%s) returned no probes", lib)
		}
		for _, p := range probes {
			if p.Library != lib {
				t.Fatalf("ForLibrary(%s) returned probe for %s", lib, p.Library)
			}
		}
		total += len(probes)
	}
	if total != len(Probes) {
		t.Fatalf("sum of ForLibrary() = %d, want %d", total, len(Probes))
	}
}
