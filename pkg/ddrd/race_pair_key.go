package ddrd

import (
	"fmt"
	"math/bits"
)

// RacePairKey is the lightweight two-level key used by the race corpus model.
// VarHash is the first-level key for the directed variable/access-name pair.
// StackHash is the second-level key for the directed call-stack pair.
type RacePairKey struct {
	VarHash   uint64 `json:"var_hash"`
	StackHash uint64 `json:"stack_hash"`
}

// OrderedStackPairID computes a direction-sensitive ID for a stack pair.
func OrderedStackPairID(stack1, stack2 uint64) uint64 {
	return stack1 ^ bits.RotateLeft64(stack2, 32)
}

// RacePairKeyFromUAFPair builds the canonical race pair key from a MayUAFPair.
func RacePairKeyFromUAFPair(pair *MayUAFPair) RacePairKey {
	if pair == nil {
		return RacePairKey{}
	}
	return RacePairKey{
		VarHash:   OrderedVarNamePairID(pair.FreeAccessName, pair.UseAccessName),
		StackHash: OrderedStackPairID(pair.FreeCallStack, pair.UseCallStack),
	}
}

func (key RacePairKey) IsZero() bool {
	return key.VarHash == 0 && key.StackHash == 0
}

func (key RacePairKey) String() string {
	if key.IsZero() {
		return ""
	}
	return fmt.Sprintf("%016x-%016x", key.VarHash, key.StackHash)
}

func RacePairKeyString(pair *MayUAFPair) string {
	return RacePairKeyFromUAFPair(pair).String()
}
