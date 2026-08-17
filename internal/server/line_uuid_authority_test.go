package server

import (
	"fmt"
	"testing"
)

func TestLineUUIDAuthorityTenThousandMappingsIsSingleScan(t *testing.T) {
	const count = 10_000
	scans := 0
	visits := 0
	resolver := newLineUUIDAuthorityResolver(func(yield func(hash, uuid, ownerNodeID string)) {
		scans++
		for i := 0; i < count; i++ {
			visits++
			yield(fmt.Sprintf("line_%05d", i), fmt.Sprintf("00000000-0000-4000-8000-%012d", i), fmt.Sprintf("node-%05d", i))
		}
		// This UUID is deliberately ambiguous and must never resolve.
		yield("line_duplicate_a", "ffffffff-ffff-4fff-8fff-ffffffffffff", "node-a")
		yield("line_duplicate_b", "ffffffff-ffff-4fff-8fff-ffffffffffff", "node-b")
		visits += 2
	})
	if scans != 1 || visits != count+2 {
		t.Fatalf("constructor scans=%d visits=%d, want 1/%d", scans, visits, count+2)
	}

	fallbacks := 0
	resolutions := 0
	for i := 0; i < count; i++ {
		resolutions++
		uuid := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		want := fmt.Sprintf("line_%05d", i)
		if got := resolver.resolve(fmt.Sprintf("node-%05d", i), "", uuid, func() string { fallbacks++; return "fallback" }); got != want {
			t.Fatalf("resolve %d=%q want %q", i, got, want)
		}
	}
	resolutions++
	if got := resolver.resolve("node-a", "", "ffffffff-ffff-4fff-8fff-ffffffffffff", func() string { fallbacks++; return "ambiguous" }); got != "ambiguous" {
		t.Fatalf("ambiguous resolve=%q", got)
	}
	resolutions++
	if got := resolver.resolve("node-a", "", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", func() string { fallbacks++; return "unknown" }); got != "unknown" {
		t.Fatalf("unknown resolve=%q", got)
	}
	resolutions++
	if got := resolver.resolve("node-a", "explicit", "ffffffff-ffff-4fff-8fff-ffffffffffff", func() string { fallbacks++; return "wrong" }); got != "line_explicit" {
		t.Fatalf("explicit resolve=%q", got)
	}
	if resolutions != count+3 || fallbacks != 2 {
		t.Fatalf("resolutions=%d fallbacks=%d, want %d/2", resolutions, fallbacks, count+3)
	}
	if _, ok := resolver.uuid("line_duplicate_a"); ok {
		t.Fatal("ambiguous UUID passed unique round trip")
	}
}
