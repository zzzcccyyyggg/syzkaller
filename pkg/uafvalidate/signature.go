package uafvalidate

import (
	"fmt"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
)

// SignatureFromPair converts a MayUAFPair into a reusable validation signature.
func SignatureFromPair(pair *ddrd.MayUAFPair) fuzzer.UAFPairProfile {
	if pair == nil {
		return fuzzer.UAFPairProfile{}
	}
	return fuzzer.UAFPairProfile{
		FreeAccessName: pair.FreeAccessName,
		UseAccessName:  pair.UseAccessName,
		FreeCallStack:  pair.FreeCallStack,
		UseCallStack:   pair.UseCallStack,
	}
}

// SignatureKey converts the signature into a stable textual key.
func SignatureKey(profile fuzzer.UAFPairProfile) string {
	return fmt.Sprintf("%016x-%016x-%016x-%016x",
		profile.FreeAccessName,
		profile.UseAccessName,
		profile.FreeCallStack,
		profile.UseCallStack,
	)
}

// IntersectProfiles groups identical signatures and returns their counts.
func IntersectProfiles(profiles []fuzzer.UAFPairProfile) map[fuzzer.UAFPairProfile]int {
	result := make(map[fuzzer.UAFPairProfile]int)
	for _, profile := range profiles {
		result[profile]++
	}
	return result
}

// IsZeroSignature reports whether the signature is empty.
func IsZeroSignature(profile fuzzer.UAFPairProfile) bool {
	return profile.FreeAccessName == 0 && profile.UseAccessName == 0 &&
		profile.FreeCallStack == 0 && profile.UseCallStack == 0
}
