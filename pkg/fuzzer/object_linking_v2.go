// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sort"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// LinkProgramsV2 aligns semantic object references between two programs.
//
// The target partner is expected to have been namespace-isolated before this
// pass when running the fsobj experiments. The linker then explicitly rewrites
// a small number of high-confidence references so object sharing is caused by
// ObjLinker rather than by fixed corpus names.
func (ol *ObjectLinker) LinkProgramsV2(prog1, prog2 *prog.Prog) *prog.Prog {
	linked, _ := ol.LinkProgramsV2WithResult(prog1, prog2)
	return linked
}

func (ol *ObjectLinker) LinkProgramsV2WithResult(prog1, prog2 *prog.Prog) (*prog.Prog, objectLinkResult) {
	if prog1 == nil || prog2 == nil {
		return prog2, objectLinkResult{}
	}

	ol.mu.Lock()
	ol.linkAttempts++
	attempt := ol.linkAttempts
	ol.mu.Unlock()

	sourceRefs := extractSemanticObjectRefs(prog1)
	if len(sourceRefs) == 0 {
		return prog2.Clone(), objectLinkResult{}
	}

	linked := prog2.Clone()
	targetRefs := extractSemanticObjectRefs(linked)
	if len(targetRefs) == 0 {
		return linked, objectLinkResult{}
	}

	result := unifySemanticObjectRefs(sourceRefs, targetRefs)
	if result.unified > 0 {
		ol.mu.Lock()
		ol.linkSuccesses++
		ol.pathsUnified += result.unified
		ol.mu.Unlock()

		log.Logf(0, "[OBJLINK-V2] unified %d semantic fs objects (exact=%d cross_family=%d attempt=%d)",
			result.unified, result.exact, result.crossFamily, attempt)
	}

	return linked, result
}

type objectLinkResult struct {
	unified     int
	exact       int
	crossFamily int
}

type objectLinkTier string

const (
	objectLinkTierExact       objectLinkTier = "exact"
	objectLinkTierCrossFamily objectLinkTier = "cross_family"
)

func unifySemanticObjectRefs(sourceRefs, targetRefs []semanticObjectRef) objectLinkResult {
	const maxSemanticRewrites = 2
	result := objectLinkResult{}
	candidates := buildSemanticLinkCandidates(sourceRefs, targetRefs)
	usedTargets := make(map[int]bool)

	for _, candidate := range candidates {
		if result.unified >= maxSemanticRewrites {
			break
		}
		if usedTargets[candidate.targetIdx] {
			continue
		}
		if rewriteSemanticObjectRef(candidate.target, candidate.source) {
			usedTargets[candidate.targetIdx] = true
			result.unified++
			if candidate.tier == objectLinkTierExact {
				result.exact++
			} else {
				result.crossFamily++
			}
			logSemanticRewrite(candidate.tier, candidate.target, candidate.source)
		}
	}

	return result
}

type semanticLinkCandidate struct {
	source    semanticObjectRef
	target    semanticObjectRef
	targetIdx int
	sourceIdx int
	tier      objectLinkTier
	score     int
}

func buildSemanticLinkCandidates(sourceRefs, targetRefs []semanticObjectRef) []semanticLinkCandidate {
	var candidates []semanticLinkCandidate
	for targetIdx, target := range targetRefs {
		for sourceIdx, source := range sourceRefs {
			score := semanticLinkScore(source, target)
			if score <= 0 {
				continue
			}
			tier := objectLinkTierCrossFamily
			if source.SyscallName == target.SyscallName {
				tier = objectLinkTierExact
			}
			candidates = append(candidates, semanticLinkCandidate{
				source:    source,
				target:    target,
				targetIdx: targetIdx,
				sourceIdx: sourceIdx,
				tier:      tier,
				score:     score,
			})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.score != right.score {
			return left.score > right.score
		}
		if left.target.CallIndex != right.target.CallIndex {
			return left.target.CallIndex < right.target.CallIndex
		}
		if left.source.CallIndex != right.source.CallIndex {
			return left.source.CallIndex < right.source.CallIndex
		}
		return left.sourceIdx < right.sourceIdx
	})
	return candidates
}

func semanticLinkScore(source, target semanticObjectRef) int {
	if !source.Rewritable || !target.Rewritable {
		return 0
	}
	if source.Domain != target.Domain || source.Kind != target.Kind || source.Scope != target.Scope {
		return 0
	}
	if source.Relative != target.Relative {
		return 0
	}
	if source.DataArg == nil || target.DataArg == nil {
		return 0
	}
	if len(source.DataArg.Data()) != len(target.DataArg.Data()) {
		return 0
	}
	if source.Operation == objectOpOpen && target.Operation == objectOpOpen &&
		source.ContextScore == 0 && target.ContextScore == 0 {
		return 0
	}
	if source.Operation == target.Operation && target.Operation != objectOpOpen {
		return 0
	}
	if target.Operation == objectOpOpen &&
		(source.Operation != objectOpOpen || source.ContextScore == 0 || target.ContextScore == 0) {
		return 0
	}
	score := source.Confidence + target.Confidence
	score += semanticTargetOperationPriority(target.Operation)
	score += target.ContextScore
	if source.SyscallName == target.SyscallName {
		score += 20
	}
	score += semanticOperationPairBonus(source.Operation, target.Operation)
	if source.PoolIndex == target.PoolIndex {
		score += 80
	}
	if dataEqual(source.DataArg.Data(), target.DataArg.Data()) {
		score = 0
	}
	return score
}

func semanticTargetOperationPriority(operation objectOperation) int {
	switch operation {
	case objectOpDataMutate:
		return 120
	case objectOpMetadataWrite:
		return 110
	case objectOpMetadataRead:
		return 90
	case objectOpOpen:
		return 0
	default:
		return 0
	}
}

func semanticOperationPairBonus(source, target objectOperation) int {
	if source == target {
		if target == objectOpOpen {
			return 0
		}
		return 60
	}
	if target == objectOpOpen {
		return 0
	}
	return 100
}

func semanticPartnerSelectionScore(sourceRefs, targetRefs []semanticObjectRef) int {
	candidates := buildSemanticLinkCandidates(sourceRefs, targetRefs)
	best := 0
	for _, candidate := range candidates {
		score := candidate.score
		if candidate.tier == objectLinkTierCrossFamily {
			score += 250
		}
		if candidate.target.Operation != objectOpOpen {
			score += 500
		} else if candidate.target.ContextScore > 0 {
			score += 250
		} else {
			score -= 500
		}
		if candidate.source.Operation != candidate.target.Operation {
			score += 120
		}
		if score > best {
			best = score
		}
	}
	return best
}

func logSemanticRewrite(tier objectLinkTier, target, source semanticObjectRef) {
	log.Logf(0, "[OBJLINK-V2-AUDIT] tier=%s domain=%s kind=%s target=%s[%d] source=%s[%d] op=%s/%s ctx=%d/%d path=%q -> %q",
		tier, target.Domain, target.Kind, target.SyscallName, target.CallIndex,
		source.SyscallName, source.CallIndex, target.Operation, source.Operation,
		target.ContextScore, source.ContextScore, target.Debug, source.Debug)
}

// findDataArg recursively finds the DataArg within an argument.
func findDataArg(arg prog.Arg) *prog.DataArg {
	if arg == nil {
		return nil
	}

	switch a := arg.(type) {
	case *prog.DataArg:
		return a
	case *prog.PointerArg:
		if a.Res != nil {
			return findDataArg(a.Res)
		}
	case *prog.GroupArg:
		for _, inner := range a.Inner {
			if result := findDataArg(inner); result != nil {
				return result
			}
		}
	case *prog.UnionArg:
		if a.Option != nil {
			return findDataArg(a.Option)
		}
	}
	return nil
}

func findConstArg(arg prog.Arg) *prog.ConstArg {
	if arg == nil {
		return nil
	}
	switch a := arg.(type) {
	case *prog.ConstArg:
		return a
	case *prog.GroupArg:
		for _, inner := range a.Inner {
			if result := findConstArg(inner); result != nil {
				return result
			}
		}
	case *prog.UnionArg:
		if a.Option != nil {
			return findConstArg(a.Option)
		}
	}
	return nil
}

// dataEqual checks if two byte slices are equal.
func dataEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// trimNullBytes removes trailing null bytes from a byte slice for display.
func trimNullBytes(data []byte) string {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			return string(data[:i+1])
		}
	}
	return ""
}
