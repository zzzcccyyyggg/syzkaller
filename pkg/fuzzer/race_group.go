// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package fuzzer provides Race-Guided Program-Group Fuzzing mechanisms.
// This file implements infrastructure for improving Race Pair discovery:
//   - VarNamePairRegistry: Limits stacks per VarName pair
//   - NamespaceIndex: Tracks syscall namespaces across programs
//   - ObjectLinker, SoloPairCache, AffinityTable: Accessors
//   - Solo Filter types: Cross-program pair filtering

package fuzzer

import (
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

// ============================================================================
// Race Group Manager - Central coordinator for all race-guided mechanisms
// ============================================================================

// RaceGroupConfig holds configuration for race-guided fuzzing mechanisms.
type RaceGroupConfig struct {
	// Object-Level Linking
	EnableObjectLinking bool // Enable object-level program linking

	// Solo Execution Cache
	EnableSoloCache bool // Enable solo execution result caching
	SoloCacheSize   int  // Maximum cache size

	// Syscall Affinity Table
	EnableAffinityTable bool    // Enable syscall affinity learning
	AffinityWeight      float64 // Weight for affinity-based selection

	// VarName Pair Registry
	MaxStacksPerVarPair int // Max unique stack pairs per VarName pair (default: 10)

	// A/B Testing: Random Baseline Mode
	// When enabled, disables affinity learning
	RandomBaselineMode bool
}

// DefaultRaceGroupConfig returns the default configuration.
func DefaultRaceGroupConfig() RaceGroupConfig {
	return RaceGroupConfig{
		// Object-Level Linking
		EnableObjectLinking: true, // V2: Syscall variant unification

		// Solo Execution Cache
		EnableSoloCache: true,
		SoloCacheSize:   10000,

		// Syscall Affinity Table
		EnableAffinityTable: true,
		AffinityWeight:      0.2, // 20% weight for affinity

		// VarName Pair Registry
		MaxStacksPerVarPair: DefaultMaxStacksPerVarPair,
	}
}

// RaceGroupManager coordinates all race-guided fuzzing mechanisms.
type RaceGroupManager struct {
	mu     sync.RWMutex
	config RaceGroupConfig

	// Namespace index (tracks syscall namespaces for programs)
	namespaceIndex *NamespaceIndex

	// VarName Pair Registry - limits stacks per VarName pair
	varPairRegistry *VarNamePairRegistry

	// Object-Level Program Linker
	objectLinker *ObjectLinker

	// Solo Execution Pair Cache
	soloPairCache *SoloPairCache

	// Syscall Affinity Table
	affinityTable *SyscallAffinityTable

	// Statistics
	stats *RaceGroupStats
}

// RaceGroupStats tracks statistics for evaluation.
type RaceGroupStats struct {
	StatRandomSelections *stat.Val
	StatTotalRaceYield   *stat.Val
}

// NewRaceGroupManager creates a new race group manager.
func NewRaceGroupManager(config RaceGroupConfig) *RaceGroupManager {
	mgr := &RaceGroupManager{
		config:          config,
		namespaceIndex:  NewNamespaceIndex(),
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

	return mgr
}

func newRaceGroupStats() *RaceGroupStats {
	return &RaceGroupStats{
		StatRandomSelections: stat.New("race random selections",
			"Partner selections via random fallback", stat.Console, stat.Graph("race_group")),
		StatTotalRaceYield: stat.New("race total yield",
			"Total race pairs discovered", stat.Console, stat.Graph("race_group")),
	}
}

// GetVarPairRegistry returns the VarName pair registry for timing exploration.
func (mgr *RaceGroupManager) GetVarPairRegistry() *VarNamePairRegistry {
	return mgr.varPairRegistry
}

// UpdateNamespaceIndex adds a program to the namespace index.
func (mgr *RaceGroupManager) UpdateNamespaceIndex(p *prog.Prog) {
	mgr.namespaceIndex.AddProgram(p)
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

// RecordRacePairs records race pair discovery with VarName pair stack limit filtering.
func (mgr *RaceGroupManager) RecordRacePairs(p *prog.Prog, pairs []*ddrd.MayUAFPair) {
	if len(pairs) == 0 {
		return
	}

	filtered := mgr.FilterRacePairs(pairs)
	if len(filtered) == 0 {
		return
	}

	mgr.stats.StatTotalRaceYield.Add(len(filtered))

	// Update namespace index for discovered programs
	mgr.UpdateNamespaceIndex(p)
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
// Namespace Index
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
}

// NewNamespaceIndex creates a new namespace index.
func NewNamespaceIndex() *NamespaceIndex {
	return &NamespaceIndex{
		index:          make(map[string][]*prog.Prog),
		progNamespaces: make(map[string][]string),
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

// ============================================================================
// VarName Pair Registry - Limits stacks per VarName pair (default: 10)
// ============================================================================

// DefaultMaxStacksPerVarPair is the default maximum number of different stack pairs
// to record for each (VarName1, VarName2) combination.
const DefaultMaxStacksPerVarPair = DefaultMaxStacksPerVarnamePair

// VarNamePairRegistry limits the number of stack pairs recorded per VarName pair.
// This prevents unbounded growth while keeping diverse stack information.
//
// Extended for timing exploration:
// - Tracks which (VarName+Stack) pairs have been attempted for timing optimization
// - Records the best trigger rate achieved for each pair
type VarNamePairRegistry struct {
	mu sync.RWMutex
	// varNamePairID -> set of stack pair IDs recorded for this VarName pair
	stacksPerPair map[uint64]map[uint64]bool
	// maxStacks is the maximum number of different stacks per VarName pair
	maxStacks int

	// ======== Timing Exploration Tracking ========
	// stackPairID -> number of timing exploration attempts
	timingAttempts map[uint64]int
	// stackPairID -> best trigger rate achieved
	timingBestRates map[uint64]float64
	// Maximum timing attempts per stack pair (0 = unlimited)
	maxTimingAttempts int
	// Statistics
	timingTotalAttempts   int
	timingSuccessfulPairs int
}

// NewVarNamePairRegistry creates a new VarName pair registry.
// maxStacks specifies the maximum number of different stack pairs per VarName pair.
// If maxStacks <= 0, DefaultMaxStacksPerVarPair is used.
func NewVarNamePairRegistry(maxStacks int) *VarNamePairRegistry {
	if maxStacks <= 0 {
		maxStacks = DefaultMaxStacksPerVarPair
	}
	return &VarNamePairRegistry{
		stacksPerPair:     make(map[uint64]map[uint64]bool),
		maxStacks:         maxStacks,
		timingAttempts:    make(map[uint64]int),
		timingBestRates:   make(map[uint64]float64),
		maxTimingAttempts: DefaultMaxTimingAttemptsPerPair,
	}
}

// DefaultMaxTimingAttemptsPerPair is the default max timing exploration attempts per stack pair.
const DefaultMaxTimingAttemptsPerPair = 20

// varNamePairID creates an unordered pair ID from two VarNames.
func varNamePairID(varName1, varName2 uint64) uint64 {
	return ddrd.UnorderedVarNamePairID(varName1, varName2)
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
	}

	if stacks[stkPairID] {
		return false // Already recorded
	}

	if len(stacks) >= reg.maxStacks {
		return false // At limit
	}

	stacks[stkPairID] = true
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
// Returns (isNewVarNamePair, isNewStack, existingStackCount).
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

// ============================================================================
// Timing Exploration Methods
// ============================================================================

// ShouldAttemptTiming checks if a pair should be attempted for timing exploration.
func (reg *VarNamePairRegistry) ShouldAttemptTiming(pair *ddrd.MayUAFPair) bool {
	if reg == nil || pair == nil {
		return false
	}

	stkPairID := stackPairID(pair.FreeCallStack, pair.UseCallStack)

	reg.mu.RLock()
	defer reg.mu.RUnlock()

	if reg.maxTimingAttempts <= 0 {
		return true
	}
	return reg.timingAttempts[stkPairID] < reg.maxTimingAttempts
}

// RecordTimingAttempt records a timing exploration attempt for a pair.
func (reg *VarNamePairRegistry) RecordTimingAttempt(pair *ddrd.MayUAFPair, triggerRate float64) bool {
	if reg == nil || pair == nil {
		return false
	}

	stkPairID := stackPairID(pair.FreeCallStack, pair.UseCallStack)

	reg.mu.Lock()
	defer reg.mu.Unlock()

	reg.timingAttempts[stkPairID]++
	reg.timingTotalAttempts++

	if triggerRate > reg.timingBestRates[stkPairID] {
		reg.timingBestRates[stkPairID] = triggerRate
		if triggerRate >= 0.1 && reg.timingBestRates[stkPairID] < 0.1 {
			reg.timingSuccessfulPairs++
		}
	}

	if reg.maxTimingAttempts <= 0 {
		return true
	}
	return reg.timingAttempts[stkPairID] < reg.maxTimingAttempts
}

// GetTimingAttemptCount returns the number of timing attempts for a pair.
func (reg *VarNamePairRegistry) GetTimingAttemptCount(pair *ddrd.MayUAFPair) int {
	if reg == nil || pair == nil {
		return 0
	}

	stkPairID := stackPairID(pair.FreeCallStack, pair.UseCallStack)

	reg.mu.RLock()
	defer reg.mu.RUnlock()

	return reg.timingAttempts[stkPairID]
}

// GetTimingBestRate returns the best trigger rate achieved for a pair.
func (reg *VarNamePairRegistry) GetTimingBestRate(pair *ddrd.MayUAFPair) float64 {
	if reg == nil || pair == nil {
		return 0
	}

	stkPairID := stackPairID(pair.FreeCallStack, pair.UseCallStack)

	reg.mu.RLock()
	defer reg.mu.RUnlock()

	return reg.timingBestRates[stkPairID]
}

// GetTimingStats returns timing exploration statistics.
func (reg *VarNamePairRegistry) GetTimingStats() (uniquePairs, totalAttempts, successfulPairs int) {
	if reg == nil {
		return 0, 0, 0
	}

	reg.mu.RLock()
	defer reg.mu.RUnlock()

	return len(reg.timingAttempts), reg.timingTotalAttempts, reg.timingSuccessfulPairs
}

// SetMaxTimingAttempts sets the maximum timing attempts per pair.
func (reg *VarNamePairRegistry) SetMaxTimingAttempts(max int) {
	if reg == nil {
		return
	}

	reg.mu.Lock()
	defer reg.mu.Unlock()

	reg.maxTimingAttempts = max
}

// ============================================================================
// Utility Functions
// ============================================================================

// progSignature generates a signature for a program for deduplication.
func progSignature(p *prog.Prog) string {
	if p == nil {
		return ""
	}
	data := p.Serialize()
	if len(data) > 64 {
		data = data[:64]
	}
	return string(data)
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
func FilterCrossProgramPairs(
	combinedPairs []*ddrd.MayRacePair,
	prog1SoloPairs *VarNamePairSet,
	prog2SoloPairs *VarNamePairSet,
) []*ddrd.MayRacePair {
	if len(combinedPairs) == 0 {
		return nil
	}

	soloPairs := NewVarNamePairSet()
	soloPairs.Merge(prog1SoloPairs)
	soloPairs.Merge(prog2SoloPairs)

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
