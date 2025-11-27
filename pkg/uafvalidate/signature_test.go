package uafvalidate

import (
	"testing"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
)

func TestSignatureFromPair(t *testing.T) {
	pair := &ddrd.MayUAFPair{
		FreeAccessName: 0x1,
		UseAccessName:  0x2,
		FreeCallStack:  0x3,
		UseCallStack:   0x4,
	}
	sig := SignatureFromPair(pair)
	want := fuzzer.UAFPairProfile{FreeAccessName: 0x1, UseAccessName: 0x2, FreeCallStack: 0x3, UseCallStack: 0x4}
	if sig != want {
		t.Fatalf("signature mismatch: got=%+v want=%+v", sig, want)
	}
}

func TestIntersectProfiles(t *testing.T) {
	p1 := fuzzer.UAFPairProfile{FreeAccessName: 1}
	p2 := fuzzer.UAFPairProfile{FreeAccessName: 2}
	counts := IntersectProfiles([]fuzzer.UAFPairProfile{p1, p2, p1})
	if counts[p1] != 2 {
		t.Fatalf("expected 2 for p1, got %d", counts[p1])
	}
	if counts[p2] != 1 {
		t.Fatalf("expected 1 for p2, got %d", counts[p2])
	}
}
