// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math/rand"
	"sort"
	"strings"

	"github.com/google/syzkaller/prog"
)

type stateScopeOperator string

const (
	stateScopeOperatorNone         stateScopeOperator = ""
	stateScopeOperatorSameInstance stateScopeOperator = "same-instance"
	stateScopeOperatorRelation     stateScopeOperator = "related-instance"
	stateScopeOperatorContainer    stateScopeOperator = "same-container"
	stateScopeOperatorGlobal       stateScopeOperator = "global-interaction"
)

const defaultStateScopePartnerSamples = 64
const stateScopeTopCandidateBudget = 8

type stateScopeDecision struct {
	Operator stateScopeOperator
	Score    int
}

type stateScopeFeatures struct {
	refs          []semanticObjectRef
	domains       map[objectDomain]struct{}
	syscalls      map[string]int
	firstSyscall  string
	syscallCount  int
	hasKccwf      bool
	localOps      int
	fdEffects     int
	strongEffects int
	relationOps   int
	containerOps  int
	globalOps     int
	mutatingOps   int
}

type stateScopeCandidate struct {
	prog     *prog.Prog
	features stateScopeFeatures
}

type stateScopeScoredCandidate struct {
	prog  *prog.Prog
	score int
}

func (fuzzer *Fuzzer) chooseStateScopePartnerProgram(source *prog.Prog, rnd *rand.Rand) (*prog.Prog, stateScopeDecision) {
	if fuzzer == nil || source == nil {
		return nil, stateScopeDecision{}
	}
	sourceFeatures := classifyStateScopeFeatures(source)
	if !sourceFeatures.hasStateScopeSignals() {
		return nil, stateScopeDecision{}
	}
	samples := fuzzer.sampleStateScopeCandidates(rnd, normalizeStateScopePartnerSamples(fuzzer.Config.StateScopePartnerSamples))
	if len(samples) == 0 {
		return nil, stateScopeDecision{}
	}
	operators := stateScopeOperatorOrder(rnd, normalizeStateScopeSameInstanceRatio(fuzzer.Config.StateScopeSameInstanceRatio))
	for _, operator := range operators {
		var scored []stateScopeScoredCandidate
		for _, candidate := range samples {
			if candidate.prog == nil {
				continue
			}
			score := stateScopeOperatorScore(operator, sourceFeatures, candidate.features)
			if score > 0 {
				scored = append(scored, stateScopeScoredCandidate{
					prog:  candidate.prog,
					score: score,
				})
			}
		}
		selected := chooseStateScopeScoredCandidate(scored, rnd)
		if selected.prog != nil {
			return selected.prog.Clone(), stateScopeDecision{Operator: operator, Score: selected.score}
		}
	}
	return nil, stateScopeDecision{}
}

func chooseStateScopeScoredCandidate(scored []stateScopeScoredCandidate, rnd *rand.Rand) stateScopeScoredCandidate {
	if len(scored) == 0 {
		return stateScopeScoredCandidate{}
	}
	sort.SliceStable(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})
	limit := minInt(len(scored), stateScopeTopCandidateBudget)
	if limit == 1 || rnd == nil {
		return scored[0]
	}
	totalWeight := 0
	for i := 0; i < limit; i++ {
		weight := 1 + scored[i].score/100
		totalWeight += weight
	}
	pick := rnd.Intn(totalWeight)
	for i := 0; i < limit; i++ {
		weight := 1 + scored[i].score/100
		if pick < weight {
			return scored[i]
		}
		pick -= weight
	}
	return scored[0]
}

func (fuzzer *Fuzzer) sampleStateScopeCandidates(rnd *rand.Rand, samples int) []stateScopeCandidate {
	programs := fuzzer.sampleStateScopePrograms(rnd, samples)
	candidates := make([]stateScopeCandidate, 0, len(programs))
	for _, p := range programs {
		if p == nil {
			continue
		}
		features := classifyStateScopeFeatures(p)
		if !features.hasStateScopeSignals() {
			continue
		}
		candidates = append(candidates, stateScopeCandidate{
			prog:     p,
			features: features,
		})
	}
	return candidates
}

func (fuzzer *Fuzzer) sampleStateScopePrograms(rnd *rand.Rand, samples int) []*prog.Prog {
	if samples <= 0 {
		return nil
	}
	if fuzzer.Config.StaticInputExploration {
		if fuzzer.staticInputPool == nil {
			return nil
		}
		fuzzer.staticInputPool.mu.Lock()
		defer fuzzer.staticInputPool.mu.Unlock()
		pool := fuzzer.staticInputPool.pool
		if len(pool) == 0 {
			return nil
		}
		if samples > len(pool) {
			samples = len(pool)
		}
		programs := make([]*prog.Prog, 0, samples)
		for i := 0; i < samples; i++ {
			programs = append(programs, pool[fuzzer.staticInputPool.rnd.Intn(len(pool))])
		}
		return programs
	}
	if fuzzer.Config.Corpus == nil {
		return nil
	}
	programs := make([]*prog.Prog, 0, samples)
	for i := 0; i < samples; i++ {
		if p := fuzzer.Config.Corpus.ChooseProgram(rnd); p != nil {
			programs = append(programs, p)
		}
	}
	return programs
}

func classifyStateScopeFeatures(p *prog.Prog) stateScopeFeatures {
	features := stateScopeFeatures{
		refs:     extractSemanticObjectRefs(p),
		domains:  make(map[objectDomain]struct{}),
		syscalls: make(map[string]int),
	}
	for _, ref := range features.refs {
		features.domains[ref.Domain] = struct{}{}
		features.localOps++
		switch ref.Operation {
		case objectOpDataMutate, objectOpMetadataWrite:
			features.mutatingOps++
		}
	}
	if p == nil {
		return features
	}
	for _, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		name := call.Meta.Name
		if features.firstSyscall == "" {
			features.firstSyscall = name
		}
		features.syscallCount++
		features.syscalls[name]++
		if strings.Contains(name, "$kccwf") {
			features.hasKccwf = true
			features.domains[objectDomainFS] = struct{}{}
		}
		fdScore := kccwfFdEffectScore(name)
		if fdScore > 0 {
			features.fdEffects++
			if fdScore >= 120 {
				features.strongEffects++
				features.mutatingOps++
			}
		}
		if isStateScopeRelationSyscall(name) {
			features.relationOps++
			features.mutatingOps++
		}
		if isStateScopeContainerSyscall(name) {
			features.containerOps++
		}
		if isStateScopeGlobalSyscall(name) {
			features.globalOps++
			if isStateScopeGlobalMutator(name) {
				features.mutatingOps++
			}
		}
	}
	return features
}

func stateScopeOperatorOrder(rnd *rand.Rand, sameInstanceRatio float64) []stateScopeOperator {
	if rnd != nil && sameInstanceRatio > 0 && rnd.Float64() < sameInstanceRatio {
		return []stateScopeOperator{
			stateScopeOperatorSameInstance,
			stateScopeOperatorRelation,
			stateScopeOperatorContainer,
			stateScopeOperatorGlobal,
		}
	}
	base := []stateScopeOperator{
		stateScopeOperatorRelation,
		stateScopeOperatorContainer,
		stateScopeOperatorGlobal,
	}
	if rnd == nil {
		return base
	}
	start := rnd.Intn(len(base))
	operators := make([]stateScopeOperator, 0, len(base))
	for i := 0; i < len(base); i++ {
		operators = append(operators, base[(start+i)%len(base)])
	}
	return operators
}

func stateScopeOperatorScore(operator stateScopeOperator, source, candidate stateScopeFeatures) int {
	switch operator {
	case stateScopeOperatorSameInstance:
		return stateScopeSameInstanceScore(source, candidate)
	case stateScopeOperatorRelation:
		return stateScopeRelationScore(source, candidate)
	case stateScopeOperatorContainer:
		return stateScopeContainerScore(source, candidate)
	case stateScopeOperatorGlobal:
		return stateScopeGlobalScore(source, candidate)
	default:
		return 0
	}
}

func stateScopeSameInstanceScore(source, candidate stateScopeFeatures) int {
	if len(source.refs) == 0 || len(candidate.refs) == 0 {
		return 0
	}
	score := semanticPartnerSelectionScore(source.refs, candidate.refs)
	if score <= 0 {
		return 0
	}
	if score > 1100 {
		score = 1100
	}
	score = score/2 + 220
	score += stateScopeCommonBonus(source, candidate)
	score += minInt(source.fdEffects+candidate.fdEffects, 4) * 35
	score += stateScopeDiversityBonus(source, candidate)
	return score
}

func stateScopeRelationScore(source, candidate stateScopeFeatures) int {
	if source.relationOps+candidate.relationOps == 0 {
		return 0
	}
	if !stateScopeDomainOverlap(source, candidate) {
		return 0
	}
	score := stateScopeRelationSideScore(source, candidate) + stateScopeRelationSideScore(candidate, source)
	if score == 0 {
		return 0
	}
	score += 360
	score += stateScopeCommonBonus(source, candidate)
	score += stateScopeDiversityBonus(source, candidate)
	return score
}

func stateScopeRelationSideScore(relation, peer stateScopeFeatures) int {
	if relation.relationOps == 0 {
		return 0
	}
	peerState := peer.localOps*80 + peer.fdEffects*70 + peer.containerOps*90 + peer.globalOps*55
	if peerState == 0 {
		return 0
	}
	return minInt(relation.relationOps, 3)*180 + minInt(peerState, 520)
}

func stateScopeContainerScore(source, candidate stateScopeFeatures) int {
	if !stateScopeDomainOverlap(source, candidate) {
		return 0
	}
	if source.containerOps+candidate.containerOps == 0 && !(source.hasKccwf && candidate.hasKccwf) {
		return 0
	}
	if !source.hasStateScopeSignals() || !candidate.hasStateScopeSignals() {
		return 0
	}
	score := 260
	if source.hasKccwf && candidate.hasKccwf {
		score += 160
	}
	score += minInt(source.containerOps+candidate.containerOps, 4) * 120
	score += minInt(source.localOps+candidate.localOps, 6) * 35
	score += minInt(source.relationOps+candidate.relationOps, 4) * 45
	score += minInt(source.globalOps+candidate.globalOps, 4) * 40
	score += stateScopeDiversityBonus(source, candidate)
	return score
}

func stateScopeGlobalScore(source, candidate stateScopeFeatures) int {
	if source.globalOps+candidate.globalOps == 0 {
		return 0
	}
	if !stateScopeDomainOverlap(source, candidate) {
		return 0
	}
	score := stateScopeGlobalSideScore(source, candidate) + stateScopeGlobalSideScore(candidate, source)
	if score == 0 {
		return 0
	}
	score += 420
	score += stateScopeCommonBonus(source, candidate)
	score += stateScopeDiversityBonus(source, candidate)
	return score
}

func stateScopeGlobalSideScore(global, peer stateScopeFeatures) int {
	if global.globalOps == 0 {
		return 0
	}
	peerState := peer.localOps*75 + peer.fdEffects*80 + peer.relationOps*95 + peer.containerOps*85
	if peerState == 0 {
		return 0
	}
	return minInt(global.globalOps, 3)*200 + minInt(peerState, 600)
}

func (features stateScopeFeatures) hasStateScopeSignals() bool {
	return features.localOps+features.fdEffects+features.relationOps+features.containerOps+features.globalOps > 0
}

func stateScopeCommonBonus(source, candidate stateScopeFeatures) int {
	score := 0
	if source.hasKccwf && candidate.hasKccwf {
		score += 100
	}
	if stateScopeDomainOverlap(source, candidate) {
		score += 80
	}
	return score
}

func stateScopeDiversityBonus(source, candidate stateScopeFeatures) int {
	score := 0
	if source.firstSyscall != "" && candidate.firstSyscall != "" && source.firstSyscall != candidate.firstSyscall {
		score += 80
	}
	if !stateScopeSameSyscallSet(source, candidate) {
		score += 60
	}
	if source.mutatingOps > 0 || candidate.mutatingOps > 0 {
		score += 60
	}
	if source.mutatingOps > 0 && candidate.mutatingOps > 0 {
		score += 40
	}
	return score
}

func stateScopeDomainOverlap(source, candidate stateScopeFeatures) bool {
	if source.hasKccwf && candidate.hasKccwf {
		return true
	}
	for domain := range source.domains {
		if _, ok := candidate.domains[domain]; ok {
			return true
		}
	}
	return false
}

func stateScopeSameSyscallSet(source, candidate stateScopeFeatures) bool {
	if len(source.syscalls) != len(candidate.syscalls) {
		return false
	}
	for name, count := range source.syscalls {
		if candidate.syscalls[name] != count {
			return false
		}
	}
	return true
}

func isStateScopeRelationSyscall(name string) bool {
	base := stateScopeSyscallBase(name)
	switch base {
	case "link", "linkat", "symlink", "symlinkat", "unlink", "unlinkat",
		"rename", "renameat", "renameat2", "mknod", "mknodat",
		"name_to_handle_at", "bind", "connect", "accept", "accept4",
		"socketpair":
		return true
	}
	return strings.Contains(base, "attach") || strings.Contains(base, "associate")
}

func isStateScopeContainerSyscall(name string) bool {
	base := stateScopeSyscallBase(name)
	switch base {
	case "mkdir", "mkdirat", "rmdir", "getdents", "getdents64", "getcwd",
		"fchdir", "chdir", "mount", "umount", "umount2", "pivot_root",
		"chroot", "statfs", "fstatfs":
		return true
	}
	return strings.Contains(name, "_dir") || strings.Contains(base, "namespace")
}

func isStateScopeGlobalSyscall(name string) bool {
	base := stateScopeSyscallBase(name)
	switch base {
	case "sync", "syncfs", "fsync", "fdatasync", "sync_file_range",
		"ioctl", "fcntl", "flock", "fallocate", "readahead", "fadvise64":
		return true
	}
	return strings.Contains(base, "flush") ||
		strings.Contains(base, "cache") ||
		strings.Contains(base, "journal") ||
		strings.Contains(base, "writeback")
}

func isStateScopeGlobalMutator(name string) bool {
	base := stateScopeSyscallBase(name)
	switch base {
	case "sync", "syncfs", "fsync", "fdatasync", "sync_file_range",
		"ioctl", "fcntl", "flock", "fallocate":
		return true
	}
	return strings.Contains(base, "flush") ||
		strings.Contains(base, "journal") ||
		strings.Contains(base, "writeback")
}

func stateScopeSyscallBase(name string) string {
	if idx := strings.IndexByte(name, '$'); idx >= 0 {
		return name[:idx]
	}
	return name
}

func normalizeStateScopeGuidanceRatio(ratio float64) float64 {
	if ratio <= 0 || ratio > 1 {
		return 1.0
	}
	return ratio
}

func normalizeStateScopeSameInstanceRatio(ratio float64) float64 {
	if ratio < 0 || ratio > 1 {
		return 0
	}
	return ratio
}

func normalizeStateScopePartnerSamples(samples int) int {
	if samples <= 0 {
		return defaultStateScopePartnerSamples
	}
	if samples > 256 {
		return 256
	}
	return samples
}

func (fuzzer *Fuzzer) recordStateScopeDecision(decision stateScopeDecision) {
	if decision.Operator == stateScopeOperatorNone {
		return
	}
	fuzzer.statStateScopeGuides.Add(1)
	switch decision.Operator {
	case stateScopeOperatorSameInstance:
		fuzzer.statStateScopeInstance.Add(1)
	case stateScopeOperatorRelation:
		fuzzer.statStateScopeRelation.Add(1)
	case stateScopeOperatorContainer:
		fuzzer.statStateScopeContainer.Add(1)
	case stateScopeOperatorGlobal:
		fuzzer.statStateScopeGlobal.Add(1)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
