// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package fuzzer provides Race-Guided Program-Group Fuzzing mechanisms.
// This file implements two core modules for improving Race Pair discovery:
//   - M1': Hybrid Partner Selection (StrongShare + RacePrior + Explore)
//   - M2: Race-Yield Weighted Selection with Thompson Sampling

package fuzzer

import (
	"math"
	"math/rand"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

// ============================================================================
// Race Group Manager - Central coordinator for all race-guided mechanisms
// ============================================================================

// RaceGroupConfig holds configuration for race-guided fuzzing mechanisms.
type RaceGroupConfig struct {
	// M1': Partner Selection (Score-based + RacePrior + Explore)
	EnablePartnerSelection bool // Enable guided partner selection

	// M1' Selection weights (should sum to 1.0)
	ScoreBasedWeight float64 // Weight for score-based selection (e.g., 0.6)
	RacePriorWeight  float64 // Weight for historical race-producing pairs (e.g., 0.3)
	ExploreWeight    float64 // Weight for random exploration (e.g., 0.1)

	// M1' Pair filtering constraints
	MaxLengthDiff int     // Max allowed length difference between two programs (e.g., 3)
	MinPairScore  float64 // Minimum score for a pair to be considered worth running

	// M2: Race-Yield Feedback (Thompson Sampling)
	EnableRaceYieldFeedback bool    // Enable race-yield weighted selection
	ExploitRate             float64 // Probability to exploit high-yield progs (0.0-1.0)
	HighYieldThreshold      int     // Minimum race count to be considered high-yield

	// Object-Level Linking
	EnableObjectLinking bool // Enable object-level program linking

	// Solo Execution Cache
	EnableSoloCache bool // Enable solo execution result caching
	SoloCacheSize   int  // Maximum cache size

	// Syscall Affinity Table
	EnableAffinityTable bool    // Enable syscall affinity learning
	AffinityWeight      float64 // Weight for affinity-based selection

	// VarName Pair Registry
	MaxStacksPerVarPair int // Max unique stack pairs per VarName pair (default: 100)

	// Pair Cooldown Configuration
	CooldownThreshold  int // Failure score threshold to enter cooldown (default: 20)
	NewStackPenalty    int // Failure score penalty for new stack only (default: 1)
	NoDiscoveryPenalty int // Failure score penalty for no discovery (default: 2)

	// A/B Testing: Random Baseline Mode
	// When enabled, disables all intelligent selection strategies:
	// - M2 Bandit corpus selection → random
	// - M1' Partner selection → random
	// - Pair cooldown → disabled
	// - Affinity learning → disabled
	RandomBaselineMode bool
}

// DefaultRaceGroupConfig returns the default configuration.
func DefaultRaceGroupConfig() RaceGroupConfig {
	return RaceGroupConfig{
		// M1' Partner Selection
		EnablePartnerSelection: true,
		ScoreBasedWeight:       0.6, // 60% score-based selection
		RacePriorWeight:        0.3, // 30% historical race-producing pairs
		ExploreWeight:          0.1, // 10% random exploration

		// M1' Pair filtering
		MaxLengthDiff: 3,   // Max 3 syscalls difference
		MinPairScore:  0.1, // Minimum score threshold

		// M2: Thompson Sampling
		EnableRaceYieldFeedback: true,
		ExploitRate:             0.8, // 80% exploit, 20% explore
		HighYieldThreshold:      3,   // At least 3 race pairs to be high-yield

		// Object-Level Linking
		EnableObjectLinking: true, // V2: Syscall variant unification (more effective)

		// Solo Execution Cache
		EnableSoloCache: true,
		SoloCacheSize:   10000,

		// Syscall Affinity Table
		EnableAffinityTable: true,
		AffinityWeight:      0.2, // 20% weight for affinity

		// VarName Pair Registry
		MaxStacksPerVarPair: DefaultMaxStacksPerVarPair, // 100 stacks per VarName pair
	}
}

// RaceGroupManager coordinates all race-guided fuzzing mechanisms.
type RaceGroupManager struct {
	mu     sync.RWMutex
	config RaceGroupConfig

	// M1: Namespace index
	namespaceIndex *NamespaceIndex

	// M1': Race prior index (tracks historically race-producing prog pairs)
	racePrior *RacePriorIndex

	// M2: Race-yield tracking
	raceYield *RaceYieldTracker

	// M2: Bandit-based corpus selector (Thompson Sampling)
	bandit *BanditCorpusSelector

	// VarName Pair Registry - limits stacks per VarName pair
	varPairRegistry *VarNamePairRegistry

	// Object-Level Program Linker
	objectLinker *ObjectLinker

	// Solo Execution Pair Cache
	soloPairCache *SoloPairCache

	// Syscall Affinity Table
	affinityTable *SyscallAffinityTable

	// Pair Cooldown - prevents exhausted pairs from being re-selected
	pairCooldown *PairCooldown

	// Statistics
	stats *RaceGroupStats
}

// RaceGroupStats tracks statistics for evaluation and ablation studies.
type RaceGroupStats struct {
	// M1' stats
	StatPartnerSelections   *stat.Val
	StatSharedNSSelections  *stat.Val
	StatRacePriorSelections *stat.Val // M1' Race prior selections
	StatRandomSelections    *stat.Val
	StatSharedNSHitRate     *stat.Val // Percentage of shared namespace hits

	// M2 stats
	StatHighYieldSelections *stat.Val
	StatExploreSelections   *stat.Val
	StatTotalRaceYield      *stat.Val
}

// NewRaceGroupManager creates a new race group manager.
func NewRaceGroupManager(config RaceGroupConfig) *RaceGroupManager {
	mgr := &RaceGroupManager{
		config:          config,
		namespaceIndex:  NewNamespaceIndex(),
		racePrior:       NewRacePriorIndex(),
		raceYield:       NewRaceYieldTracker(config.HighYieldThreshold),
		bandit:          NewBanditCorpusSelector(),
		varPairRegistry: NewVarNamePairRegistry(config.MaxStacksPerVarPair),
		stats:           newRaceGroupStats(),
	}

	// Initialize Object-Level Linker
	if config.EnableObjectLinking {
		mgr.objectLinker = NewObjectLinker()
	}

	// Initialize Solo Pair Cache
	if config.EnableSoloCache {
		mgr.soloPairCache = NewSoloPairCache(config.SoloCacheSize)
	}

	// Initialize Syscall Affinity Table
	if config.EnableAffinityTable {
		mgr.affinityTable = NewSyscallAffinityTable()
	}

	// Initialize Pair Cooldown with configuration
	cooldownConfig := PairCooldownConfig{
		CooldownThreshold:  config.CooldownThreshold,
		NewStackPenalty:    config.NewStackPenalty,
		NoDiscoveryPenalty: config.NoDiscoveryPenalty,
	}
	mgr.pairCooldown = NewPairCooldownWithConfig(cooldownConfig)

	return mgr
}

func newRaceGroupStats() *RaceGroupStats {
	return &RaceGroupStats{
		StatPartnerSelections: stat.New("race partner selections",
			"Total partner selection attempts", stat.Console, stat.Graph("race_group")),
		StatSharedNSSelections: stat.New("race shared ns selections",
			"Partner selections from shared namespace", stat.Console, stat.Graph("race_group")),
		StatRacePriorSelections: stat.New("race prior selections",
			"Partner selections from historical race pairs", stat.Console, stat.Graph("race_group")),
		StatRandomSelections: stat.New("race random selections",
			"Partner selections via random fallback", stat.Console, stat.Graph("race_group")),
		StatSharedNSHitRate: stat.New("race shared ns hit rate",
			"Percentage of shared namespace partner selections", stat.Graph("race_group")),

		StatHighYieldSelections: stat.New("race high yield selections",
			"Selections of high-yield programs", stat.Console, stat.Graph("race_group")),
		StatExploreSelections: stat.New("race explore selections",
			"Exploration selections (random)", stat.Console, stat.Graph("race_group")),
		StatTotalRaceYield: stat.New("race total yield",
			"Total race pairs discovered", stat.Console, stat.Graph("race_group")),
	}
}

// SelectProgramWithBandit uses Thompson Sampling to select a program.
// This is the M2 bandit-based corpus selection.
func (mgr *RaceGroupManager) SelectProgramWithBandit(corpus []*prog.Prog, rnd *rand.Rand) *prog.Prog {
	if !mgr.config.EnableRaceYieldFeedback || len(corpus) == 0 {
		return corpus[rnd.Intn(len(corpus))]
	}
	return mgr.bandit.SelectProgram(corpus, rnd)
}

// RecordBanditExecution records execution result for bandit learning.
// Returns:
//   - newVarNamePairCount: number of NEW unique (FreeAccessName, UseAccessName) pairs discovered
//   - newStackCount: number of new stacks discovered for existing VarName pairs
func (mgr *RaceGroupManager) RecordBanditExecution(p *prog.Prog, pairs []*ddrd.MayUAFPair) (newVarNamePairCount, newStackCount int) {
	// In random baseline mode, skip bandit feedback updates
	if mgr.config.RandomBaselineMode {
		return 0, 0
	}
	return mgr.bandit.RecordExecution(p, pairs)
}

// BoostBanditForNewCoverage gives an exploration bonus to programs that discovered new code coverage.
// New coverage suggests the program triggers unexplored code paths, worth exploring for race detection.
func (mgr *RaceGroupManager) BoostBanditForNewCoverage(p *prog.Prog) {
	// In random baseline mode, skip bandit boost
	if mgr.config.RandomBaselineMode {
		return
	}
	if p == nil || mgr.bandit == nil {
		return
	}

	sig := progSignature(p)
	mgr.bandit.mu.Lock()
	defer mgr.bandit.mu.Unlock()

	params := mgr.bandit.getOrCreateParams(sig)
	// Boost Alpha to give exploration priority
	// New coverage = new code paths = potential for new VarName pairs
	const explorationBonus = 2.0
	params.Alpha += explorationBonus

	log.Logf(0, "[BANDIT-BOOST] new coverage program boosted: alpha=%.1f beta=%.1f",
		params.Alpha, params.Beta)
}

// RecordPairExecution records a (main, partner) execution result for cooldown tracking.
// Uses three-tier penalty system based on discovery type.
func (mgr *RaceGroupManager) RecordPairExecution(main, partner *prog.Prog, newVarNamePairCount, newStackCount int) {
	// In random baseline mode, skip cooldown tracking
	if mgr.config.RandomBaselineMode {
		return
	}
	if mgr.pairCooldown != nil {
		mgr.pairCooldown.RecordExecution(main, partner, newVarNamePairCount, newStackCount)
	}
}

// GetPairCooldown returns the pair cooldown manager.
func (mgr *RaceGroupManager) GetPairCooldown() *PairCooldown {
	return mgr.pairCooldown
}

// GetKnownVarPairCount returns total unique VarName pairs discovered.
func (mgr *RaceGroupManager) GetKnownVarPairCount() int {
	return mgr.bandit.GetKnownVarPairCount()
}

// ============================================================================
// M1: Namespace-Guided Partner Selection
// ============================================================================

// NamespaceIndex maintains an index of programs by their syscall namespaces.
// Programs with the same namespace (e.g., $kccwf) are more likely to share
// kernel resources and thus more likely to produce race conditions.
type NamespaceIndex struct {
	mu sync.RWMutex
	// namespace -> list of programs using that namespace
	index map[string][]*prog.Prog
	// prog signature -> namespaces it uses
	progNamespaces map[string][]string
	// namespace -> share score (learned from cross-program races)
	shareScores map[string]float64
}

// NewNamespaceIndex creates a new namespace index.
func NewNamespaceIndex() *NamespaceIndex {
	return &NamespaceIndex{
		index:          make(map[string][]*prog.Prog),
		progNamespaces: make(map[string][]string),
		shareScores:    make(map[string]float64),
	}
}

// ExtractNamespaces extracts syscall namespaces from a program.
// Namespace is the suffix after '$' in syscall names, e.g., "open$kccwf" -> "kccwf".
func ExtractNamespaces(p *prog.Prog) []string {
	if p == nil {
		return nil
	}
	nsSet := make(map[string]bool)
	for _, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		name := call.Meta.Name
		if idx := strings.LastIndex(name, "$"); idx != -1 && idx < len(name)-1 {
			ns := name[idx+1:]
			// Filter out very short or common suffixes that don't indicate shared resources
			if len(ns) >= 2 {
				nsSet[ns] = true
			}
		}
	}
	namespaces := make([]string, 0, len(nsSet))
	for ns := range nsSet {
		namespaces = append(namespaces, ns)
	}
	return namespaces
}

// AddProgram adds a program to the namespace index.
func (ni *NamespaceIndex) AddProgram(p *prog.Prog) {
	if p == nil {
		return
	}
	namespaces := ExtractNamespaces(p)
	if len(namespaces) == 0 {
		return
	}

	sig := progSignature(p)
	ni.mu.Lock()
	defer ni.mu.Unlock()

	// Avoid duplicates
	if _, exists := ni.progNamespaces[sig]; exists {
		return
	}

	ni.progNamespaces[sig] = namespaces
	for _, ns := range namespaces {
		ni.index[ns] = append(ni.index[ns], p)
	}
}

// GetSharedNamespacePartners returns programs that share at least one namespace with p.
func (ni *NamespaceIndex) GetSharedNamespacePartners(p *prog.Prog) []*prog.Prog {
	if p == nil {
		return nil
	}
	namespaces := ExtractNamespaces(p)
	if len(namespaces) == 0 {
		return nil
	}

	ni.mu.RLock()
	defer ni.mu.RUnlock()

	// Collect all programs that share any namespace
	seen := make(map[string]bool)
	var partners []*prog.Prog
	pSig := progSignature(p)

	for _, ns := range namespaces {
		for _, partner := range ni.index[ns] {
			partnerSig := progSignature(partner)
			if partnerSig == pSig || seen[partnerSig] {
				continue
			}
			seen[partnerSig] = true
			partners = append(partners, partner)
		}
	}
	return partners
}

// HasSharedNamespace checks if two programs share at least one namespace.
func HasSharedNamespace(p1, p2 *prog.Prog) bool {
	ns1 := ExtractNamespaces(p1)
	ns2 := ExtractNamespaces(p2)
	if len(ns1) == 0 || len(ns2) == 0 {
		return false
	}
	ns2Set := make(map[string]bool, len(ns2))
	for _, ns := range ns2 {
		ns2Set[ns] = true
	}
	for _, ns := range ns1 {
		if ns2Set[ns] {
			return true
		}
	}
	return false
}

// IncrementShareScore increases the share score for a namespace.
// Higher scores indicate namespaces that produce more cross-program races.
func (ni *NamespaceIndex) IncrementShareScore(namespace string, delta float64) {
	if namespace == "" {
		return
	}
	ni.mu.Lock()
	defer ni.mu.Unlock()
	ni.shareScores[namespace] += delta
}

// GetShareScore returns the current share score for a namespace.
func (ni *NamespaceIndex) GetShareScore(namespace string) float64 {
	ni.mu.RLock()
	defer ni.mu.RUnlock()
	return ni.shareScores[namespace]
}

// GetTotalShareScore returns the sum of share scores for a program's namespaces.
func (ni *NamespaceIndex) GetTotalShareScore(p *prog.Prog) float64 {
	namespaces := ExtractNamespaces(p)
	if len(namespaces) == 0 {
		return 0
	}
	ni.mu.RLock()
	defer ni.mu.RUnlock()
	var total float64
	for _, ns := range namespaces {
		total += ni.shareScores[ns]
	}
	return total
}

// ============================================================================
// M1': Race Prior Index - Tracks historically race-producing prog pairs
// ============================================================================

// RacePriorIndex maintains an index of program pairs that historically produced races.
// This enables selecting partners based on past race-producing combinations.
type RacePriorIndex struct {
	mu sync.RWMutex
	// prog signature -> list of partner signatures that produced races together
	pairHistory map[string]map[string]int // inner map: partner sig -> race count
	// prog signature -> the actual prog (for retrieval)
	progCache map[string]*prog.Prog
	// Maximum number of programs to cache
	maxProgsCache int
}

// NewRacePriorIndex creates a new race prior index.
func NewRacePriorIndex() *RacePriorIndex {
	return &RacePriorIndex{
		pairHistory:   make(map[string]map[string]int),
		progCache:     make(map[string]*prog.Prog),
		maxProgsCache: 10000, // Limit memory usage
	}
}

// RecordRacePair records that two programs produced a race together.
func (rpi *RacePriorIndex) RecordRacePair(p1, p2 *prog.Prog, raceCount int) {
	if p1 == nil || p2 == nil || raceCount <= 0 {
		return
	}
	sig1 := progSignature(p1)
	sig2 := progSignature(p2)
	if sig1 == sig2 {
		return // Same program, skip
	}

	rpi.mu.Lock()
	defer rpi.mu.Unlock()

	// Record bidirectionally
	if rpi.pairHistory[sig1] == nil {
		rpi.pairHistory[sig1] = make(map[string]int)
	}
	rpi.pairHistory[sig1][sig2] += raceCount

	if rpi.pairHistory[sig2] == nil {
		rpi.pairHistory[sig2] = make(map[string]int)
	}
	rpi.pairHistory[sig2][sig1] += raceCount

	// Cache programs for retrieval
	if len(rpi.progCache) < rpi.maxProgsCache {
		if _, exists := rpi.progCache[sig1]; !exists {
			rpi.progCache[sig1] = p1.Clone()
		}
		if _, exists := rpi.progCache[sig2]; !exists {
			rpi.progCache[sig2] = p2.Clone()
		}
	}
}

// GetRacePriorPartners returns programs that historically produced races with p.
// Returns up to maxResults partners, weighted by race count.
func (rpi *RacePriorIndex) GetRacePriorPartners(p *prog.Prog, maxResults int) []*prog.Prog {
	if p == nil {
		return nil
	}
	sig := progSignature(p)

	rpi.mu.RLock()
	defer rpi.mu.RUnlock()

	partners, ok := rpi.pairHistory[sig]
	if !ok || len(partners) == 0 {
		return nil
	}

	// Collect partners with their race counts
	type partnerCount struct {
		sig   string
		count int
	}
	var pcs []partnerCount
	for partnerSig, count := range partners {
		pcs = append(pcs, partnerCount{partnerSig, count})
	}

	// Sort by count descending (higher count = better partner)
	for i := range pcs {
		for j := i + 1; j < len(pcs); j++ {
			if pcs[j].count > pcs[i].count {
				pcs[i], pcs[j] = pcs[j], pcs[i]
			}
		}
	}

	// Take top maxResults
	if maxResults > 0 && len(pcs) > maxResults {
		pcs = pcs[:maxResults]
	}

	// Retrieve actual programs from cache
	var result []*prog.Prog
	for _, pc := range pcs {
		if prog, exists := rpi.progCache[pc.sig]; exists {
			result = append(result, prog)
		}
	}
	return result
}

// HasRacePrior checks if there's historical race data for the given program.
// Size returns the number of programs with race prior history.
func (rpi *RacePriorIndex) Size() int {
	rpi.mu.RLock()
	defer rpi.mu.RUnlock()
	return len(rpi.pairHistory)
}

func (rpi *RacePriorIndex) HasRacePrior(p *prog.Prog) bool {
	if p == nil {
		return false
	}
	sig := progSignature(p)

	rpi.mu.RLock()
	defer rpi.mu.RUnlock()

	partners, ok := rpi.pairHistory[sig]
	return ok && len(partners) > 0
}

// SelectPartner selects a partner program for concurrent execution.
// M1' Selection Strategy:
//   - ScoreBased (60%): Select based on pair score (considers M2 bandit + length diff)
//   - RacePrior (30%): Programs that historically produced races together
//   - Explore (10%): Random exploration
//
// All selections enforce MaxLengthDiff constraint.
func (mgr *RaceGroupManager) SelectPartner(primary *prog.Prog, corpus []*prog.Prog, rnd *rand.Rand) *prog.Prog {
	if len(corpus) == 0 {
		return nil
	}

	mgr.stats.StatPartnerSelections.Add(1)

	// Debug log every 1000 selections with key metrics
	if mgr.stats.StatPartnerSelections.Val()%1000 == 0 {
		racePriorSize := mgr.racePrior.Size()
		highYieldCount := len(mgr.raceYield.GetHighYieldPrograms())
		knownVarPairs := mgr.bandit.GetKnownVarPairCount()

		// Pair cooldown stats
		pairCount, totalCooldowns, activeCooldowns := 0, 0, 0
		if mgr.pairCooldown != nil {
			pairCount, totalCooldowns, activeCooldowns = mgr.pairCooldown.GetStats()
		}

		log.Logf(0, "[RACE-GROUP] partner_total=%d race_prior=%d high_yield=%d known_varnames=%d pair_tracked=%d cooldowns=%d/%d",
			mgr.stats.StatPartnerSelections.Val(), racePriorSize, highYieldCount,
			knownVarPairs, pairCount, activeCooldowns, totalCooldowns)
	}
	if !mgr.config.EnablePartnerSelection {
		// Fallback to random selection with length filter
		return mgr.selectRandomWithLengthFilter(primary, corpus, rnd)
	}

	// Pre-filter corpus by length difference
	primaryLen := len(primary.Calls)
	candidates := mgr.filterByLengthDiff(primary, corpus)
	if len(candidates) == 0 {
		// No candidates within length limit, use random from full corpus
		mgr.stats.StatRandomSelections.Add(1)
		return corpus[rnd.Intn(len(corpus))]
	}

	// M1' Three-bucket sampling
	r := rnd.Float64()
	scoreBasedThreshold := mgr.config.ScoreBasedWeight
	racePriorThreshold := scoreBasedThreshold + mgr.config.RacePriorWeight

	if r < scoreBasedThreshold {
		// Bucket 1: Score-based selection using weighted random
		partner := mgr.selectByScore(primary, candidates, rnd)
		if partner != nil {
			mgr.stats.StatSharedNSSelections.Add(1) // Reuse stat for score-based
			return partner
		}
	}

	if r < racePriorThreshold {
		// Bucket 2: RacePrior - Try historically race-producing partners
		partners := mgr.racePrior.GetRacePriorPartners(primary, 10)
		// Filter by length diff
		var filteredPartners []*prog.Prog
		for _, p := range partners {
			if abs(len(p.Calls)-primaryLen) <= mgr.config.MaxLengthDiff {
				filteredPartners = append(filteredPartners, p)
			}
		}
		if len(filteredPartners) > 0 {
			mgr.stats.StatRacePriorSelections.Add(1)
			return filteredPartners[rnd.Intn(len(filteredPartners))]
		}
	}

	// Bucket 3: Explore - Random selection from filtered candidates
	mgr.stats.StatRandomSelections.Add(1)
	return candidates[rnd.Intn(len(candidates))]
}

// filterByLengthDiff returns programs within MaxLengthDiff of primary.
func (mgr *RaceGroupManager) filterByLengthDiff(primary *prog.Prog, corpus []*prog.Prog) []*prog.Prog {
	primaryLen := len(primary.Calls)
	maxDiff := mgr.config.MaxLengthDiff
	var result []*prog.Prog
	for _, p := range corpus {
		if abs(len(p.Calls)-primaryLen) <= maxDiff {
			result = append(result, p)
		}
	}
	return result
}

// selectRandomWithLengthFilter selects randomly but respects length filter.
func (mgr *RaceGroupManager) selectRandomWithLengthFilter(primary *prog.Prog, corpus []*prog.Prog, rnd *rand.Rand) *prog.Prog {
	candidates := mgr.filterByLengthDiff(primary, corpus)
	if len(candidates) == 0 {
		mgr.stats.StatRandomSelections.Add(1)
		return corpus[rnd.Intn(len(corpus))]
	}
	mgr.stats.StatRandomSelections.Add(1)
	return candidates[rnd.Intn(len(candidates))]
}

// selectByScore uses weighted random selection based on pair scores.
// Score = banditScore * lengthPenalty * affinityScore * pairPenalty
// - banditScore: from M2 Thompson Sampling (higher = more race-productive)
// - lengthPenalty: 1.0 for same length, decreases with length difference
// - affinityScore: from SyscallAffinityTable (higher = more likely to interact)
// - pairPenalty: from PairCooldown (0.01 if exhausted, 1.0 otherwise)
func (mgr *RaceGroupManager) selectByScore(primary *prog.Prog, candidates []*prog.Prog, rnd *rand.Rand) *prog.Prog {
	if len(candidates) == 0 {
		return nil
	}

	primaryLen := len(primary.Calls)

	// Decrement cooldown counters (once per selection round)
	if mgr.pairCooldown != nil {
		mgr.pairCooldown.DecrementCooldowns()
	}

	// Calculate scores for all candidates
	type scoredProg struct {
		prog  *prog.Prog
		score float64
	}
	scored := make([]scoredProg, 0, len(candidates))
	totalScore := 0.0

	for _, p := range candidates {
		// Length penalty: 1.0 for same length, decreasing with diff
		lenDiff := abs(len(p.Calls) - primaryLen)
		lengthPenalty := 1.0 / (1.0 + float64(lenDiff)*0.3)

		// Bandit score from M2 (if available)
		banditScore := 1.0
		if mgr.bandit != nil {
			sig := progSignature(p)
			mgr.bandit.mu.RLock()
			if params, exists := mgr.bandit.betaParams[sig]; exists {
				// Use mean of Beta distribution as score
				banditScore = params.Alpha / (params.Alpha + params.Beta)
			}
			mgr.bandit.mu.RUnlock()
		}

		// Affinity score from SyscallAffinityTable (if available)
		affinityScore := 1.0
		if mgr.affinityTable != nil && mgr.config.EnableAffinityTable {
			// Get affinity score: 0.5 (neutral) to 1.0 (high affinity)
			rawAffinity := mgr.affinityTable.GetProgramAffinityScore(primary, p)
			// Scale: 0.5 + rawAffinity * weight (so neutral programs get 0.5 + 0.5*0.2 = 0.6)
			affinityScore = 0.5 + rawAffinity*mgr.config.AffinityWeight
		}

		// Pair penalty from PairCooldown (0.01 if in cooldown, 1.0 otherwise)
		pairPenalty := 1.0
		if mgr.pairCooldown != nil {
			pairPenalty = mgr.pairCooldown.GetPenalty(primary, p)
		}

		// Combined score
		score := banditScore * lengthPenalty * affinityScore * pairPenalty
		if score < mgr.config.MinPairScore {
			continue // Skip low-scoring pairs
		}

		scored = append(scored, scoredProg{prog: p, score: score})
		totalScore += score
	}

	if len(scored) == 0 || totalScore <= 0 {
		return nil
	}

	// Weighted random selection (similar to ChoiceTable)
	target := rnd.Float64() * totalScore
	cumulative := 0.0
	for _, sp := range scored {
		cumulative += sp.score
		if cumulative >= target {
			return sp.prog
		}
	}

	// Fallback to last
	return scored[len(scored)-1].prog
}

// abs returns absolute value of an integer.
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// UpdateNamespaceIndex adds a program to the namespace index.
func (mgr *RaceGroupManager) UpdateNamespaceIndex(p *prog.Prog) {
	if mgr.config.EnablePartnerSelection {
		mgr.namespaceIndex.AddProgram(p)
	}
}

// IncrementShareScore increases the share score for a namespace.
// This is called when a cross-program race is detected, to learn which
// namespaces are more likely to produce races.
func (mgr *RaceGroupManager) IncrementShareScore(namespace string, delta float64) {
	if mgr.namespaceIndex != nil {
		mgr.namespaceIndex.IncrementShareScore(namespace, delta)
	}
}

// GetShareScore returns the share score for a namespace.
func (mgr *RaceGroupManager) GetShareScore(namespace string) float64 {
	if mgr.namespaceIndex == nil {
		return 0
	}
	return mgr.namespaceIndex.GetShareScore(namespace)
}

// ============================================================================
// M2: Race-Yield Weighted Selection with Thompson Sampling (Bandit)
// ============================================================================

// BetaParams holds Beta distribution parameters for Thompson Sampling.
type BetaParams struct {
	Alpha float64 // Success count (new VarName pairs discovered)
	Beta  float64 // Failure count (no new VarName pairs)
}

// BanditCorpusSelector implements Thompson Sampling for corpus selection.
// Each program maintains a Beta(α, β) distribution:
//   - α increases when the program discovers new unique VarName pairs
//   - β increases when execution produces no new pairs
//
// Selection uses Thompson Sampling: sample from each prog's Beta distribution,
// select the prog with highest sampled value.
type BanditCorpusSelector struct {
	mu sync.RWMutex
	// prog signature -> Beta parameters
	betaParams map[string]*BetaParams
	// prog signature -> the actual prog
	progCache map[string]*prog.Prog
	// Set of known VarName pairs (for uniqueness check) - used for Alpha boost
	knownVarPairs map[uint64]bool
	// Set of known (VarName pair + stack pair) for stack tracking
	knownStackPairs map[uint64]map[uint64]bool // varPairID -> set of stackPairID
	// Initial prior: Beta(1, 1) = uniform
	initialAlpha float64
	initialBeta  float64
}

// NewBanditCorpusSelector creates a new bandit corpus selector.
func NewBanditCorpusSelector() *BanditCorpusSelector {
	return &BanditCorpusSelector{
		betaParams:      make(map[string]*BetaParams),
		progCache:       make(map[string]*prog.Prog),
		knownVarPairs:   make(map[uint64]bool),
		knownStackPairs: make(map[uint64]map[uint64]bool),
		initialAlpha:    1.0, // Beta(1,1) = uniform prior
		initialBeta:     1.0,
	}
}

// getOrCreateParams returns Beta params for a program, creating if needed.
func (bcs *BanditCorpusSelector) getOrCreateParams(sig string) *BetaParams {
	if params, exists := bcs.betaParams[sig]; exists {
		return params
	}
	params := &BetaParams{
		Alpha: bcs.initialAlpha,
		Beta:  bcs.initialBeta,
	}
	bcs.betaParams[sig] = params
	return params
}

// varNamePairID creates a unique ID from two VarNames (order-independent).
func varNamePairID(varName1, varName2 uint64) uint64 {
	// Order-independent hash
	if varName1 > varName2 {
		varName1, varName2 = varName2, varName1
	}
	return (varName1 * 0x9E3779B97F4A7C15) ^ varName2
}

// RecordExecution records an execution result and updates Beta params.
// pairs: the race pairs discovered in this execution (may be empty).
// Returns:
//   - newVarNamePairCount: number of NEW unique (FreeAccessName, UseAccessName) pairs discovered
//   - newStackCount: number of new stacks discovered for existing VarName pairs
func (bcs *BanditCorpusSelector) RecordExecution(p *prog.Prog, pairs []*ddrd.MayUAFPair) (newVarNamePairCount, newStackCount int) {
	if p == nil {
		return 0, 0
	}
	sig := progSignature(p)

	bcs.mu.Lock()
	defer bcs.mu.Unlock()

	params := bcs.getOrCreateParams(sig)

	// Cache program if not already cached
	if _, exists := bcs.progCache[sig]; !exists {
		bcs.progCache[sig] = p.Clone()
	}

	// Track Alpha boost from new stacks with harmonic decay
	var stackAlphaBoost float64

	// Count NEW unique VarName pairs and new stacks
	for _, pair := range pairs {
		if pair == nil {
			continue
		}
		varPairID := varNamePairID(pair.FreeAccessName, pair.UseAccessName)
		stkPairID := stackPairID(pair.FreeCallStack, pair.UseCallStack)

		if !bcs.knownVarPairs[varPairID] {
			// New VarName pair (highest value)
			bcs.knownVarPairs[varPairID] = true
			// Also initialize stack tracking for this VarName pair
			bcs.knownStackPairs[varPairID] = map[uint64]bool{stkPairID: true}
			newVarNamePairCount++
		} else {
			// Existing VarName pair - check if stack is new
			stacks := bcs.knownStackPairs[varPairID]
			if stacks == nil {
				stacks = make(map[uint64]bool)
				bcs.knownStackPairs[varPairID] = stacks
			}
			if !stacks[stkPairID] {
				// Calculate harmonic decay boost based on existing stack count
				// Formula: 2.0 / (1 + existingStackCount)
				// Cumulative: sum of 100 stacks ≈ 2 * ln(100) ≈ 10 (same as new VarName pair)
				existingStackCount := len(stacks)
				stackAlphaBoost += 2.0 / float64(1+existingStackCount)
				stacks[stkPairID] = true
				newStackCount++
			}
		}
	}

	// Update Beta distribution based on discovery type
	if newVarNamePairCount > 0 {
		// Highest value: discovered new VarName pairs
		// Give significant Alpha boost (10 per new VarName pair)
		params.Alpha += float64(newVarNamePairCount) * 10.0
		// Also add any stack boost from the same execution
		params.Alpha += stackAlphaBoost
	} else if newStackCount > 0 {
		// Medium value: discovered new stacks for existing VarName pairs
		// Apply harmonic decay boost (already calculated above)
		params.Alpha += stackAlphaBoost
	} else {
		// No new discovery: failure
		params.Beta += 1.0
	}

	return newVarNamePairCount, newStackCount
}

// sampleBeta samples from Beta(alpha, beta) distribution.
// Uses the approximation: X = Gamma(alpha) / (Gamma(alpha) + Gamma(beta))
// Simplified implementation using standard library.
func sampleBeta(rnd *rand.Rand, alpha, beta float64) float64 {
	// Gamma sampling using standard technique
	gammaAlpha := sampleGamma(rnd, alpha)
	gammaBeta := sampleGamma(rnd, beta)
	if gammaAlpha+gammaBeta == 0 {
		return 0.5
	}
	return gammaAlpha / (gammaAlpha + gammaBeta)
}

// sampleGamma samples from Gamma(shape, 1) distribution using Marsaglia's method.
func sampleGamma(rnd *rand.Rand, shape float64) float64 {
	if shape < 1 {
		// For shape < 1, use boost: X = Gamma(1+shape) * U^(1/shape)
		u := rnd.Float64()
		return sampleGamma(rnd, 1+shape) * math.Pow(u, 1.0/shape)
	}
	// Marsaglia and Tsang's method for shape >= 1
	d := shape - 1.0/3.0
	c := 1.0 / math.Sqrt(9.0*d)
	for {
		var x, v float64
		for {
			x = rnd.NormFloat64()
			v = 1.0 + c*x
			if v > 0 {
				break
			}
		}
		v = v * v * v
		u := rnd.Float64()
		if u < 1.0-0.0331*(x*x)*(x*x) {
			return d * v
		}
		if math.Log(u) < 0.5*x*x+d*(1.0-v+math.Log(v)) {
			return d * v
		}
	}
}

// SelectProgram uses Thompson Sampling to select a program from the corpus.
// Returns the program with highest sampled value from Beta distribution.
func (bcs *BanditCorpusSelector) SelectProgram(corpus []*prog.Prog, rnd *rand.Rand) *prog.Prog {
	if len(corpus) == 0 {
		return nil
	}

	bcs.mu.RLock()
	defer bcs.mu.RUnlock()

	var bestProg *prog.Prog
	bestSample := -1.0

	for _, p := range corpus {
		sig := progSignature(p)
		var alpha, beta float64 = bcs.initialAlpha, bcs.initialBeta
		if params, exists := bcs.betaParams[sig]; exists {
			alpha = params.Alpha
			beta = params.Beta
		}

		// Thompson Sampling: sample from Beta distribution
		sample := sampleBeta(rnd, alpha, beta)
		if sample > bestSample {
			bestSample = sample
			bestProg = p
		}
	}

	return bestProg
}

// GetKnownVarPairCount returns the number of unique VarName pairs discovered.
func (bcs *BanditCorpusSelector) GetKnownVarPairCount() int {
	bcs.mu.RLock()
	defer bcs.mu.RUnlock()
	return len(bcs.knownVarPairs)
}

// ============================================================================
// VarName Pair Registry - Limits stacks per VarName pair (max 20)
// ============================================================================

// DefaultMaxStacksPerVarPair is the default maximum number of different stack pairs
// to record for each (VarName1, VarName2) combination.
// With 100 stacks, the cumulative affinity bonus approaches BaseWeight
// (using harmonic series: sum(1/n) for n=2..100 ≈ 4.6, scaled to match BaseWeight).
const DefaultMaxStacksPerVarPair = 100

// VarNamePairRegistry limits the number of stack pairs recorded per VarName pair.
// This prevents unbounded growth while keeping diverse stack information.
type VarNamePairRegistry struct {
	mu sync.RWMutex
	// varNamePairID -> set of stack pair IDs recorded for this VarName pair
	stacksPerPair map[uint64]map[uint64]bool
	// maxStacks is the maximum number of different stacks per VarName pair
	maxStacks int
}

// NewVarNamePairRegistry creates a new VarName pair registry.
// maxStacks specifies the maximum number of different stack pairs per VarName pair.
// If maxStacks <= 0, DefaultMaxStacksPerVarPair (100) is used.
func NewVarNamePairRegistry(maxStacks int) *VarNamePairRegistry {
	if maxStacks <= 0 {
		maxStacks = DefaultMaxStacksPerVarPair
	}
	return &VarNamePairRegistry{
		stacksPerPair: make(map[uint64]map[uint64]bool),
		maxStacks:     maxStacks,
	}
}

// stackPairID creates a unique ID from two call stacks.
func stackPairID(stack1, stack2 uint64) uint64 {
	// Order-independent hash
	if stack1 > stack2 {
		stack1, stack2 = stack2, stack1
	}
	return (stack1 * 0x517CC1B727220A95) ^ stack2
}

// ShouldRecord checks if a race pair should be recorded based on the limit.
// Returns true if the stack pair is new or we haven't hit the limit yet.
func (reg *VarNamePairRegistry) ShouldRecord(pair *ddrd.MayUAFPair) bool {
	if reg == nil || pair == nil {
		return true
	}

	varPairID := varNamePairID(pair.FreeAccessName, pair.UseAccessName)
	stkPairID := stackPairID(pair.FreeCallStack, pair.UseCallStack)

	reg.mu.RLock()
	stacks, exists := reg.stacksPerPair[varPairID]
	if !exists {
		reg.mu.RUnlock()
		return true // First stack for this VarName pair
	}
	if stacks[stkPairID] {
		reg.mu.RUnlock()
		return false // Already recorded this exact stack pair
	}
	count := len(stacks)
	reg.mu.RUnlock()

	return count < reg.maxStacks
}

// Record records a race pair. Returns true if it was recorded (new or under limit).
func (reg *VarNamePairRegistry) Record(pair *ddrd.MayUAFPair) bool {
	if reg == nil || pair == nil {
		return false
	}

	varPairID := varNamePairID(pair.FreeAccessName, pair.UseAccessName)
	stkPairID := stackPairID(pair.FreeCallStack, pair.UseCallStack)

	reg.mu.Lock()
	defer reg.mu.Unlock()

	stacks, exists := reg.stacksPerPair[varPairID]
	if !exists {
		stacks = make(map[uint64]bool)
		reg.stacksPerPair[varPairID] = stacks
		// log.Logf(0, "[VARNAME-REG] New VarName pair: var1=0x%x var2=0x%x (1st stack)", pair.FreeAccessName, pair.UseAccessName)
	}

	if stacks[stkPairID] {
		return false // Already recorded
	}

	if len(stacks) >= reg.maxStacks {
		// log.Logf(0, "[VARNAME-REG] Limit reached for VarName pair var1=0x%x var2=0x%x (max %d stacks)",
		// 	pair.FreeAccessName, pair.UseAccessName, reg.maxStacks)
		return false // At limit
	}

	stacks[stkPairID] = true
	// log.Logf(0, "[VARNAME-REG] New stack for VarName pair: var1=0x%x var2=0x%x, stack count=%d/%d",
	// 	pair.FreeAccessName, pair.UseAccessName, len(stacks), MaxStacksPerVarPair)
	return true
}

// GetStats returns statistics about the registry.
func (reg *VarNamePairRegistry) GetStats() (varPairCount, totalStackPairs int) {
	if reg == nil {
		return 0, 0
	}
	reg.mu.RLock()
	defer reg.mu.RUnlock()

	varPairCount = len(reg.stacksPerPair)
	for _, stacks := range reg.stacksPerPair {
		totalStackPairs += len(stacks)
	}
	return
}

// CheckNewness checks if a pair represents a new VarName pair or a new stack for an existing VarName pair.
// Returns (isNewVarNamePair, isNewStack, existingStackCount):
//   - isNewVarNamePair: true if this is the first time seeing this (FreeAccessName, UseAccessName) combination
//   - isNewStack: true if the VarName pair exists but this (FreeCallStack, UseCallStack) is new
//   - existingStackCount: number of existing stacks for this VarName pair (0 if new VarName pair)
//
// Both booleans return false if the exact pair (including stacks) has already been recorded.
func (reg *VarNamePairRegistry) CheckNewness(pair *ddrd.MayUAFPair) (isNewVarNamePair, isNewStack bool, existingStackCount int) {
	if reg == nil || pair == nil {
		return false, false, 0
	}

	varPairID := varNamePairID(pair.FreeAccessName, pair.UseAccessName)
	stkPairID := stackPairID(pair.FreeCallStack, pair.UseCallStack)

	reg.mu.RLock()
	defer reg.mu.RUnlock()

	stacks, exists := reg.stacksPerPair[varPairID]
	if !exists {
		return true, false, 0 // New VarName pair
	}
	existingStackCount = len(stacks)
	if !stacks[stkPairID] {
		return false, true, existingStackCount // Existing VarName pair, new stack
	}
	return false, false, existingStackCount // Already recorded
}

// RaceYieldTracker tracks race pair yield per program for feedback-driven selection.
type RaceYieldTracker struct {
	mu sync.RWMutex
	// prog signature -> race yield count
	yieldCount map[string]int
	// prog signature -> race pairs (for M3: prefix-preserving mutation)
	progPairs map[string][]*ddrd.MayUAFPair
	// High-yield programs (cached for fast access)
	highYieldProgs []*prog.Prog
	// Threshold to be considered high-yield
	threshold int
}

// NewRaceYieldTracker creates a new race yield tracker.
func NewRaceYieldTracker(threshold int) *RaceYieldTracker {
	return &RaceYieldTracker{
		yieldCount:     make(map[string]int),
		progPairs:      make(map[string][]*ddrd.MayUAFPair),
		highYieldProgs: make([]*prog.Prog, 0),
		threshold:      threshold,
	}
}

// RecordRaceYield records that a program produced race pairs.
func (ryt *RaceYieldTracker) RecordRaceYield(p *prog.Prog, pairs []*ddrd.MayUAFPair) {
	if p == nil || len(pairs) == 0 {
		return
	}
	sig := progSignature(p)

	ryt.mu.Lock()
	defer ryt.mu.Unlock()

	prevCount := ryt.yieldCount[sig]
	ryt.yieldCount[sig] = prevCount + len(pairs)

	// Store pairs for M3: prefix-preserving mutation
	ryt.progPairs[sig] = append(ryt.progPairs[sig], pairs...)

	// Update high-yield cache if crossing threshold
	if prevCount < ryt.threshold && ryt.yieldCount[sig] >= ryt.threshold {
		ryt.highYieldProgs = append(ryt.highYieldProgs, p.Clone())
	}
}

// GetRacePairs returns the race pairs associated with a program.
func (ryt *RaceYieldTracker) GetRacePairs(p *prog.Prog) []*ddrd.MayUAFPair {
	if p == nil {
		return nil
	}
	sig := progSignature(p)

	ryt.mu.RLock()
	defer ryt.mu.RUnlock()

	return ryt.progPairs[sig]
}

// GetYieldCount returns the race yield count for a program.
func (ryt *RaceYieldTracker) GetYieldCount(p *prog.Prog) int {
	if p == nil {
		return 0
	}
	sig := progSignature(p)

	ryt.mu.RLock()
	defer ryt.mu.RUnlock()

	return ryt.yieldCount[sig]
}

// GetHighYieldPrograms returns programs that have exceeded the yield threshold.
func (ryt *RaceYieldTracker) GetHighYieldPrograms() []*prog.Prog {
	ryt.mu.RLock()
	defer ryt.mu.RUnlock()

	result := make([]*prog.Prog, len(ryt.highYieldProgs))
	copy(result, ryt.highYieldProgs)
	return result
}

// ChooseProgramWithFeedback selects a program considering race yield feedback.
// It balances exploitation (high-yield programs) and exploration (random).
func (mgr *RaceGroupManager) ChooseProgramWithFeedback(corpus []*prog.Prog, rnd *rand.Rand) *prog.Prog {
	if len(corpus) == 0 {
		return nil
	}

	if !mgr.config.EnableRaceYieldFeedback {
		return corpus[rnd.Intn(len(corpus))]
	}

	// Exploit: choose from high-yield programs
	if rnd.Float64() < mgr.config.ExploitRate {
		highYield := mgr.raceYield.GetHighYieldPrograms()
		if len(highYield) > 0 {
			mgr.stats.StatHighYieldSelections.Add(1)
			return highYield[rnd.Intn(len(highYield))]
		}
	}

	// Explore: random selection
	mgr.stats.StatExploreSelections.Add(1)
	return corpus[rnd.Intn(len(corpus))]
}

// FilterRacePairs filters race pairs based on VarName pair stack limits.
// Returns only pairs that should be recorded (new or under limit).
func (mgr *RaceGroupManager) FilterRacePairs(pairs []*ddrd.MayUAFPair) []*ddrd.MayUAFPair {
	if len(pairs) == 0 {
		return nil
	}

	filtered := make([]*ddrd.MayUAFPair, 0, len(pairs))
	for _, pair := range pairs {
		if mgr.varPairRegistry.ShouldRecord(pair) {
			mgr.varPairRegistry.Record(pair)
			filtered = append(filtered, pair)
		}
	}
	return filtered
}

// RecordRacePairs records race pair discovery for yield tracking.
// Applies VarName pair stack limit (max 20 stacks per VarName pair).
func (mgr *RaceGroupManager) RecordRacePairs(p *prog.Prog, pairs []*ddrd.MayUAFPair) {
	if len(pairs) == 0 {
		return
	}

	// log.Logf(0, "[RACE-GROUP] RecordRacePairs: received %d pairs", len(pairs))

	// Filter pairs based on VarName pair stack limits
	filtered := mgr.FilterRacePairs(pairs)
	if len(filtered) == 0 {
		// log.Logf(0, "[RACE-GROUP] All %d pairs filtered (duplicate/limit)", len(pairs))
		return
	}

	// log.Logf(0, "[RACE-GROUP] After filtering: %d/%d pairs recorded", len(filtered), len(pairs))

	mgr.raceYield.RecordRaceYield(p, filtered)
	mgr.stats.StatTotalRaceYield.Add(len(filtered))

	// Also update namespace index for discovered programs
	mgr.UpdateNamespaceIndex(p)
}

// RecordRacePairWithPartner records race pair discovery with partner info for M1' RacePrior.
// This should be called when a (primary, partner) pair produces races.
// Applies VarName pair stack limit (max 20 stacks per VarName pair).
func (mgr *RaceGroupManager) RecordRacePairWithPartner(primary, partner *prog.Prog, pairs []*ddrd.MayUAFPair) {
	log.Logf(1, "[RACE-PRIOR-DBG] RecordRacePairWithPartner called: pairs=%d partner=%v", len(pairs), partner != nil)

	if len(pairs) == 0 {
		return
	}

	// Filter pairs based on VarName pair stack limits
	filtered := mgr.FilterRacePairs(pairs)
	log.Logf(1, "[RACE-PRIOR-DBG] after filter: %d -> %d pairs", len(pairs), len(filtered))
	if len(filtered) == 0 {
		return
	}

	// Record for single-prog yield tracking
	mgr.raceYield.RecordRaceYield(primary, filtered)
	mgr.stats.StatTotalRaceYield.Add(len(filtered))

	// Update namespace index
	mgr.UpdateNamespaceIndex(primary)
	if partner != nil {
		mgr.UpdateNamespaceIndex(partner)
	}

	// M1': Record race-producing pair for RacePrior
	if partner != nil {
		mgr.racePrior.RecordRacePair(primary, partner, len(filtered))
		log.Logf(0, "[RACE-PRIOR] recorded: primary=%d partner=%d races=%d prior_size=%d",
			len(primary.Calls), len(partner.Calls), len(filtered), mgr.racePrior.Size())
	}
}

// GetVarPairStats returns VarName pair registry statistics.
func (mgr *RaceGroupManager) GetVarPairStats() (varPairCount, totalStackPairs int) {
	return mgr.varPairRegistry.GetStats()
}

// CheckPairNewness checks if a pair is a new VarName pair or a new stack for existing VarName pair.
// Returns (isNewVarNamePair, isNewStack, existingStackCount).
func (mgr *RaceGroupManager) CheckPairNewness(pair *ddrd.MayUAFPair) (bool, bool, int) {
	if mgr == nil || mgr.varPairRegistry == nil {
		return false, false, 0
	}
	return mgr.varPairRegistry.CheckNewness(pair)
}

// GetRacePairsForProg returns stored race pairs for a program.
func (mgr *RaceGroupManager) GetRacePairsForProg(p *prog.Prog) []*ddrd.MayUAFPair {
	return mgr.raceYield.GetRacePairs(p)
}

// ============================================================================
// Utility Functions
// ============================================================================

// progSignature generates a signature for a program for deduplication.
func progSignature(p *prog.Prog) string {
	if p == nil {
		return ""
	}
	// Use serialized form as signature (could be optimized with hash)
	data := p.Serialize()
	if len(data) > 64 {
		data = data[:64]
	}
	return string(data)
}

// ============================================================================
// Integration helpers
// ============================================================================

// BuildBarrierProgramsWithRaceGuidance builds barrier programs using race-guided selection.
// This method integrates:
// 1. M1' Score-based partner selection
// 2. Object-Level Linking to ensure programs access the same kernel objects
func (mgr *RaceGroupManager) BuildBarrierProgramsWithRaceGuidance(
	primary *prog.Prog, count int, corpus []*prog.Prog, rnd *rand.Rand) []*prog.Prog {

	if count <= 0 {
		return nil
	}

	programs := make([]*prog.Prog, count)
	programs[0] = primary

	if count == 1 {
		return programs
	}

	for i := 1; i < count; i++ {
		// Use namespace-guided partner selection
		partner := mgr.SelectPartner(primary, corpus, rnd)
		if partner == nil {
			programs[i] = primary.Clone()
		} else {
			// Apply Object-Level Linking V2 to ensure shared kernel objects
			if mgr.objectLinker != nil && mgr.config.EnableObjectLinking {
				linkedPartner := mgr.objectLinker.LinkProgramsV2(primary, partner)
				programs[i] = linkedPartner
				// Note: ObjectLinker tracks its own stats internally
			} else {
				programs[i] = partner.Clone()
			}
		}
	}

	// Ensure no nil programs
	for i := range programs {
		if programs[i] == nil {
			programs[i] = primary.Clone()
		}
	}

	return programs
}

// GetSoloPairCache returns the solo pair cache (for soloFilterJob).
func (mgr *RaceGroupManager) GetSoloPairCache() *SoloPairCache {
	return mgr.soloPairCache
}

// GetAffinityTable returns the syscall affinity table.
func (mgr *RaceGroupManager) GetAffinityTable() *SyscallAffinityTable {
	return mgr.affinityTable
}

// GetObjectLinker returns the object linker.
func (mgr *RaceGroupManager) GetObjectLinker() *ObjectLinker {
	return mgr.objectLinker
}

// ============================================================================
// Solo Filter for Cross-Program Race Pair Filtering
// ============================================================================

// VarNamePair represents a unique (VarName1, VarName2) pair for race detection.
// We normalize the pair so VarName1 <= VarName2 for consistent comparison.
type VarNamePair struct {
	VarName1 uint64
	VarName2 uint64
}

// NewVarNamePair creates a normalized VarNamePair (ensures VarName1 <= VarName2).
func NewVarNamePair(v1, v2 uint64) VarNamePair {
	if v1 <= v2 {
		return VarNamePair{VarName1: v1, VarName2: v2}
	}
	return VarNamePair{VarName1: v2, VarName2: v1}
}

// VarNamePairSet is a set of VarNamePairs for efficient filtering.
type VarNamePairSet struct {
	pairs map[VarNamePair]struct{}
}

// NewVarNamePairSet creates an empty VarNamePairSet.
func NewVarNamePairSet() *VarNamePairSet {
	return &VarNamePairSet{
		pairs: make(map[VarNamePair]struct{}),
	}
}

// Add adds a VarNamePair to the set.
func (s *VarNamePairSet) Add(pair VarNamePair) {
	s.pairs[pair] = struct{}{}
}

// AddFromRacePair extracts and adds a VarNamePair from a MayRacePair.
func (s *VarNamePairSet) AddFromRacePair(rp *ddrd.MayRacePair) {
	if rp == nil {
		return
	}
	pair := NewVarNamePair(rp.VarName1, rp.VarName2)
	s.Add(pair)
}

// Contains checks if a VarNamePair exists in the set.
func (s *VarNamePairSet) Contains(pair VarNamePair) bool {
	_, exists := s.pairs[pair]
	return exists
}

// ContainsFromRacePair checks if a race pair's VarNames exist in the set.
func (s *VarNamePairSet) ContainsFromRacePair(rp *ddrd.MayRacePair) bool {
	if rp == nil {
		return false
	}
	pair := NewVarNamePair(rp.VarName1, rp.VarName2)
	return s.Contains(pair)
}

// Size returns the number of pairs in the set.
func (s *VarNamePairSet) Size() int {
	return len(s.pairs)
}

// Merge adds all pairs from another set.
func (s *VarNamePairSet) Merge(other *VarNamePairSet) {
	if other == nil {
		return
	}
	for pair := range other.pairs {
		s.pairs[pair] = struct{}{}
	}
}

// FilterCrossProgramPairs filters race pairs to keep only those that are
// truly cross-program (appear in combined execution but not in solo executions).
// This is the core of the solo filter approach:
//   - Solo1: Execute prog1 alone → collect pairs_prog1
//   - Solo2: Execute prog2 alone → collect pairs_prog2
//   - Combined: Already executed during barrier → pairs_combined
//   - Filter: cross_program = pairs_combined - pairs_prog1 - pairs_prog2
func FilterCrossProgramPairs(
	combinedPairs []*ddrd.MayRacePair,
	prog1SoloPairs *VarNamePairSet,
	prog2SoloPairs *VarNamePairSet,
) []*ddrd.MayRacePair {
	if len(combinedPairs) == 0 {
		return nil
	}

	// Merge solo pairs into one set for efficient lookup
	soloPairs := NewVarNamePairSet()
	soloPairs.Merge(prog1SoloPairs)
	soloPairs.Merge(prog2SoloPairs)

	// Filter: keep only pairs not in solo runs
	var crossProgram []*ddrd.MayRacePair
	for _, rp := range combinedPairs {
		pair := NewVarNamePair(rp.VarName1, rp.VarName2)
		if !soloPairs.Contains(pair) {
			crossProgram = append(crossProgram, rp)
		}
	}

	return crossProgram
}

// CollectVarNamePairsFromReport extracts VarNamePairs from a DDRD report.
// For UAF pairs, we use FreeAccessName and UseAccessName as the VarName pair.
func CollectVarNamePairsFromReport(report *ddrd.Report) *VarNamePairSet {
	pairSet := NewVarNamePairSet()
	if report == nil {
		return pairSet
	}
	for _, uafPair := range report.UAFPairs {
		if uafPair != nil {
			pair := NewVarNamePair(uafPair.FreeAccessName, uafPair.UseAccessName)
			pairSet.Add(pair)
		}
	}
	return pairSet
}

// CertaintyScore calculates certainty score based on matching candidates.
// - Unique match (1 candidate): high certainty = 3.0
// - Multiple candidates: low certainty = 1.0
// This is used to weight share score updates in M1'.
func CertaintyScore(candidateCount int) float64 {
	if candidateCount <= 1 {
		return 3.0 // High certainty: unique match
	}
	return 1.0 // Low certainty: multiple candidates
}
