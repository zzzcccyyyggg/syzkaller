package fuzzer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"sort"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/flatrpc"
	queue "github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type barrierSeedKind int

const (
	seedKindUAF barrierSeedKind = iota
	seedKindCoverage
)

type uafMode struct {
	fuzzer        *Fuzzer
	queue         *queue.PlainQueue
	mu            sync.Mutex
	entries       map[string]*barrierSeed
	corpus        *uafCorpus
	pairs         map[uint64]struct{}
	historyBuffer *VMHistoryBuffers // Per-VM rolling buffers of recent barrier executions
}

// DefaultMaxStacksPerVarnamePair is the default limit for unique (callstack1, callstack2)
// combinations tracked for each (FreeAccessName, UseAccessName) pair.
// This matches the M1'/M2/M3 framework design in dedup_races.py.
// Can be overridden by config.MaxStacksPerVarNamePair.
const DefaultMaxStacksPerVarnamePair = 20

type uafCorpus struct {
	mu                  sync.RWMutex
	seeds               map[string]uafSeedMeta
	pairs               map[uint64]struct{}
	varnamePairs        map[uint64]struct{} // unique (FreeAccessName, UseAccessName) pairs
	varnameStackCounts  map[uint64]int      // count of stacks per varname pair
	maxStacksPerVarName int                 // configurable limit per varname pair
	coverage            cover.Cover
	// Source tracking for pairs and varnames
	pairsFromFuzz      map[uint64]struct{} // pairs first discovered by normal fuzzing
	pairsFromTiming    map[uint64]struct{} // pairs first discovered by timing exploration
	varnamesFromFuzz   map[uint64]struct{} // varnames from normal fuzzing
	varnamesFromTiming map[uint64]struct{} // varnames from timing exploration
	statSeeds          *stat.Val
	statSeedsWithHist  *stat.Val
	statCover          *stat.Val
	statPairs          *stat.Val
	statVarnames       *stat.Val
	statSkippedByLimit *stat.Val
}

type uafSeedMeta struct {
	HasReplayHistory bool
}

type barrierSeed struct {
	kind      barrierSeedKind
	entry     *UAFCorpusEntry
	entryBlob *serializedSeedEntry
	execOpts  flatrpc.ExecOpts
	syncable  bool
	synced    bool
}

type serializedSeedEntry struct {
	Program        []byte
	Programs       [][]byte
	CallIdx        int
	Pairs          []ddrd.MayUAFPair
	PairBasicInfo  ddrd.MayUAFPair
	Signals        []uint64
	Barrier        BarrierSnapshot
	ReplayPlan     UAFCorpusReplayPlan
	Profile        UAFPairProfile
	Timestamp      time.Time
	Kind           barrierSeedKind
	Source         PairSource
	ReplayHistory  []serializedBarrierExecutionRecord
	AsyncMode      bool
	AsyncRaceCalls [2]int
}

type serializedBarrierExecutionRecord struct {
	Programs  [][]byte
	Timestamp time.Time
	GroupID   int64
	VMIndex   int
}

// UAFCorpusEntry represents a single stored UAF seed within the fuzzer.
type UAFCorpusEntry struct {
	Prog          *prog.Prog
	Programs      []*prog.Prog
	CallIdx       int
	Pairs         []*ddrd.MayUAFPair
	PairBasicInfo ddrd.MayUAFPair
	Signals       ddrd.UAFSignal
	Barrier       BarrierSnapshot
	ReplayPlan    UAFCorpusReplayPlan
	Profile       UAFPairProfile
	Timestamp     time.Time
	Kind          barrierSeedKind
	Source        PairSource // SourceFuzz or SourceTiming
	// ReplayHistory contains the execution history leading up to this pair's discovery.
	// This is used during validation to replay the system state before testing.
	ReplayHistory []*BarrierExecutionRecord

	// AsyncMode indicates this entry uses intra-process async execution instead of
	// cross-process barrier mode. The single Prog contains calls marked with Props.Async
	// that will run concurrently in the same process (shared fd table).
	AsyncMode bool
	// AsyncRaceCalls identifies the two call indices in Prog that race against each other.
	// Only meaningful when AsyncMode is true.
	AsyncRaceCalls [2]int

	// ValidateQueueKey/Seq are runtime-only metadata populated when an entry is
	// loaded from the validate queue. They are not persisted in uaf-corpus.db.
	ValidateQueueKey  string
	ValidateQueueSeq  uint64
	ValidatePairKey   string
	ValidateQueueKeys []string
	ValidatePairKeys  []string
	CorpusRecordID    string
}

// BarrierSnapshot records the barrier configuration used when discovering a UAF pair.
type BarrierSnapshot struct {
	Participants uint64
	GroupID      int64
	GroupSize    int
	ProcList     []int
}

// UAFCorpusReplayPlan carries deterministic replay hints such as executor start delays.
type UAFCorpusReplayPlan struct {
	DelaysMicros []int64
}

// UAFPairProfile captures intersection fields that uniquely identify a UAF pair.
type UAFPairProfile struct {
	FreeAccessName uint64
	UseAccessName  uint64
	FreeCallStack  uint64
	UseCallStack   uint64
}

func (plan UAFCorpusReplayPlan) clone() UAFCorpusReplayPlan {
	if len(plan.DelaysMicros) == 0 {
		return UAFCorpusReplayPlan{}
	}
	return UAFCorpusReplayPlan{DelaysMicros: append([]int64(nil), plan.DelaysMicros...)}
}

func (plan UAFCorpusReplayPlan) IsZero() bool {
	return len(plan.DelaysMicros) == 0
}

func newUAFPairProfile(pair *ddrd.MayUAFPair) UAFPairProfile {
	if pair == nil {
		return UAFPairProfile{}
	}
	return UAFPairProfile{
		FreeAccessName: pair.FreeAccessName,
		UseAccessName:  pair.UseAccessName,
		FreeCallStack:  pair.FreeCallStack,
		UseCallStack:   pair.UseCallStack,
	}
}

func (p UAFPairProfile) IsZero() bool {
	return p.FreeAccessName == 0 && p.UseAccessName == 0 && p.FreeCallStack == 0 && p.UseCallStack == 0
}

func newUAFMode(f *Fuzzer) *uafMode {
	if f == nil || !f.Config.ModeUAF {
		return nil
	}
	// Use configured history buffer size or default
	bufferSize := f.Config.HistoryBufferSize
	if bufferSize <= 0 {
		bufferSize = DefaultHistoryBufferSize
	}
	// Use configured max stacks per varname pair or default
	maxStacksPerVarName := f.Config.MaxStacksPerVarNamePair
	if maxStacksPerVarName <= 0 {
		maxStacksPerVarName = DefaultMaxStacksPerVarnamePair
	}
	return &uafMode{
		fuzzer:        f,
		entries:       make(map[string]*barrierSeed),
		corpus:        newUAFCorpus(maxStacksPerVarName),
		pairs:         make(map[uint64]struct{}),
		historyBuffer: NewVMHistoryBuffers(bufferSize),
	}
}

func newUAFCorpus(maxStacksPerVarName int) *uafCorpus {
	if maxStacksPerVarName <= 0 {
		maxStacksPerVarName = DefaultMaxStacksPerVarnamePair
	}
	uc := &uafCorpus{
		seeds:               make(map[string]uafSeedMeta),
		pairs:               make(map[uint64]struct{}),
		varnamePairs:        make(map[uint64]struct{}),
		varnameStackCounts:  make(map[uint64]int),
		maxStacksPerVarName: maxStacksPerVarName,
		pairsFromFuzz:       make(map[uint64]struct{}),
		pairsFromTiming:     make(map[uint64]struct{}),
		varnamesFromFuzz:    make(map[uint64]struct{}),
		varnamesFromTiming:  make(map[uint64]struct{}),
	}
	uc.statSeeds = stat.New("uaf corpus", "Number of UAF seeds managed by the fuzzer (total)",
		stat.Console, stat.Graph("uaf"), func() int {
			uc.mu.RLock()
			defer uc.mu.RUnlock()
			return len(uc.seeds)
		})
	uc.statSeedsWithHist = stat.New("uaf corpus with history", "Number of UAF seeds with replay history",
		stat.Console, stat.Graph("uaf"), func() int {
			uc.mu.RLock()
			defer uc.mu.RUnlock()
			count := 0
			for _, seed := range uc.seeds {
				if seed.HasReplayHistory {
					count++
				}
			}
			return count
		})
	uc.statCover = stat.New("uaf coverage", "Source coverage attributed to UAF seeds",
		stat.Console, stat.Graph("uaf"), func() int {
			uc.mu.RLock()
			defer uc.mu.RUnlock()
			return len(uc.coverage)
		})
	uc.statPairs = stat.New("uaf pairs", "Unique May-UAF pairs discovered",
		stat.Console, stat.Graph("uaf"), func() int {
			uc.mu.RLock()
			defer uc.mu.RUnlock()
			return len(uc.pairs)
		})
	uc.statVarnames = stat.New("uaf varnames", "Unique VarName pairs (FreeAccessName, UseAccessName)",
		stat.Console, stat.Graph("uaf"), func() int {
			uc.mu.RLock()
			defer uc.mu.RUnlock()
			return len(uc.varnamePairs)
		})
	// Source tracking statistics
	stat.New("uaf pairs fuzz", "UAF pairs from normal fuzzing",
		stat.Console, stat.Graph("uaf"), func() int {
			uc.mu.RLock()
			defer uc.mu.RUnlock()
			return len(uc.pairsFromFuzz)
		})
	stat.New("uaf pairs timing", "UAF pairs from timing exploration",
		stat.Console, stat.Graph("uaf"), func() int {
			uc.mu.RLock()
			defer uc.mu.RUnlock()
			return len(uc.pairsFromTiming)
		})
	stat.New("uaf varnames fuzz", "UAF varnames from normal fuzzing",
		stat.Console, stat.Graph("uaf"), func() int {
			uc.mu.RLock()
			defer uc.mu.RUnlock()
			return len(uc.varnamesFromFuzz)
		})
	stat.New("uaf varnames timing", "UAF varnames from timing exploration",
		stat.Console, stat.Graph("uaf"), func() int {
			uc.mu.RLock()
			defer uc.mu.RUnlock()
			return len(uc.varnamesFromTiming)
		})
	uc.statSkippedByLimit = stat.New("uaf skipped", "UAF pairs skipped due to MaxStacksPerVarnamePair limit",
		stat.All, stat.Graph("uaf"))
	return uc
}

// PairSource indicates the source of a discovered pair.
type PairSource int

const (
	SourceFuzz   PairSource = iota // From normal fuzzing
	SourceTiming                   // From timing exploration
)

func (uc *uafCorpus) addSeed(key string, entry *UAFCorpusEntry, source PairSource) {
	if uc == nil || entry == nil {
		return
	}
	uc.mu.Lock()
	defer uc.mu.Unlock()
	uc.seeds[key] = uafSeedMeta{
		HasReplayHistory: len(entry.ReplayHistory) > 0,
	}
	for _, pair := range entry.Pairs {
		if pair == nil {
			continue
		}
		// Calculate varname pair ID first to check stack limit
		varnameID := varnamePairID(pair.FreeAccessName, pair.UseAccessName)

		// Check if this varname pair has reached the stack limit
		currentCount := uc.varnameStackCounts[varnameID]
		if currentCount >= uc.maxStacksPerVarName {
			// Skip this pair - already have enough stacks for this varname pair
			if uc.statSkippedByLimit != nil {
				uc.statSkippedByLimit.Add(1)
			}
			continue
		}

		id := pair.UAFPairID()
		if id == 0 {
			continue
		}

		// Only add if this is a new pair (avoid counting duplicates)
		if _, exists := uc.pairs[id]; !exists {
			uc.pairs[id] = struct{}{}
			// Track unique varname pairs and increment stack count
			uc.varnamePairs[varnameID] = struct{}{}
			uc.varnameStackCounts[varnameID] = currentCount + 1

			// Track source for this pair (only for new pairs)
			switch source {
			case SourceFuzz:
				uc.pairsFromFuzz[id] = struct{}{}
				// Track varname source (first source wins)
				if _, exists := uc.varnamesFromTiming[varnameID]; !exists {
					uc.varnamesFromFuzz[varnameID] = struct{}{}
				}
			case SourceTiming:
				uc.pairsFromTiming[id] = struct{}{}
				// Track varname source (first source wins)
				if _, exists := uc.varnamesFromFuzz[varnameID]; !exists {
					uc.varnamesFromTiming[varnameID] = struct{}{}
				}
			}
		}
	}
}

// varnamePairID delegates to the canonical ddrd.OrderedVarNamePairID.
// Uses ordered (direction-sensitive) ID because UAF corpus entries have a clear Free→Use direction.
func varnamePairID(name1, name2 uint64) uint64 {
	return ddrd.OrderedVarNamePairID(name1, name2)
}

// GetVarNamePairCount returns the number of corpus entries (stacks) for a VarName pair
func (uc *uafCorpus) GetVarNamePairCount(freeAccessName, useAccessName uint64) int {
	if uc == nil {
		return 0
	}
	varnameID := varnamePairID(freeAccessName, useAccessName)
	uc.mu.RLock()
	defer uc.mu.RUnlock()
	return uc.varnameStackCounts[varnameID]
}

func (uc *uafCorpus) recordCoverage(info *flatrpc.ProgInfo) {
	if uc == nil {
		return
	}
	raw := collectAllCoverage(info)
	if len(raw) == 0 {
		// log.Logf(0, "uaf: recording coverage of size %d from execution", len(raw))
		return
	}
	uc.mu.Lock()
	uc.coverage.Merge(raw)
	uc.mu.Unlock()
}

// recordCoverageWithDiff records coverage and returns newly discovered PCs.
// Returns a Cover containing only the new PCs (empty if no new coverage).
func (uc *uafCorpus) recordCoverageWithDiff(info *flatrpc.ProgInfo) cover.Cover {
	if uc == nil {
		return nil
	}
	raw := collectAllCoverage(info)
	if len(raw) == 0 {
		return nil
	}
	uc.mu.Lock()
	newPCs := uc.coverage.MergeDiff(raw)
	uc.mu.Unlock()

	if len(newPCs) == 0 {
		return nil
	}
	return cover.FromRaw(newPCs)
}

func (uc *uafCorpus) mergeCoverage(raw []uint64) {
	if uc == nil || len(raw) == 0 {
		return
	}
	uc.mu.Lock()
	uc.coverage.Merge(raw)
	uc.mu.Unlock()
}

func (u *uafMode) setQueue(q *queue.PlainQueue) {
	if u == nil {
		return
	}
	u.queue = q
}

func (u *uafMode) addPairLocked(pair *ddrd.MayUAFPair) *ddrd.MayUAFPair {
	if u == nil || pair == nil {
		return nil
	}
	id := pair.UAFPairID()
	if id == 0 {
		return nil
	}
	if _, ok := u.pairs[id]; ok {
		return nil // Already exists, return nil to skip
	}
	u.pairs[id] = struct{}{}
	clone := new(ddrd.MayUAFPair)
	*clone = *pair
	return clone
}

func (u *uafMode) tryPersistSeed(seed *barrierSeed) {
	if u == nil || seed == nil || seed.synced || !seed.syncable || seed.entry == nil {
		return
	}
	if u.fuzzer == nil || u.fuzzer.Config.PersistUAFCorpusEntry == nil {
		return
	}
	if err := u.fuzzer.Config.PersistUAFCorpusEntry(seed.entry); err != nil {
		u.fuzzer.Logf(0, "uaf: immediate persist failed for seed %016x: %v", seed.entry.PairID(), err)
		return
	}
	seed.synced = true
}

// handleFilteredPairs handles cross-program pairs after solo filtering.
// This is called from soloFilterJob after filtering out intra-program pairs.
func (u *uafMode) handleFilteredPairs(req *queue.Request, res *queue.Result, prog1, prog2 *prog.Prog, pairs []*ddrd.MayUAFPair, source PairSource) {
	if u == nil || len(pairs) == 0 || prog1 == nil || prog2 == nil {
		return
	}
	now := time.Now()

	u.mu.Lock()
	var batch []*ddrd.MayUAFPair
	for _, pair := range pairs {
		cloned := u.addPairLocked(pair)
		if cloned == nil {
			continue
		}
		batch = append(batch, cloned)
	}
	u.mu.Unlock()
	if len(batch) == 0 {
		return
	}

	timingCandidates := u.timingExplorationCandidates(batch)

	// Determine history count before recording pairs
	var historyCount int
	if u.historyBuffer != nil && u.fuzzer.raceGroup != nil {
		historyCount = u.determineHistoryCount(batch)
	}

	isThreadBarrier := isThreadBarrierRequest(req)

	// DUAL-QUEUE: Enqueue NEW VarName pairs to Timing Exploration
	// Skip for thread-barrier entries — they already share address space and don't need timing exploration.
	if !isThreadBarrier && u.fuzzer.timingScheduler != nil && u.fuzzer.timingScheduler.Config().EnableTimingExploration {
		objectLink := queue.ObjectLinkProvenance{}
		if req != nil {
			objectLink = req.ObjectLink
		}
		for _, pair := range timingCandidates {
			u.fuzzer.timingScheduler.OnNewVarNamePairDiscoveredWithProvenance(prog1, prog2, pair, objectLink)
		}
	}

	// NOTE: M2 race yield recording is handled by processCrossProgramPairs in job.go
	// to avoid double-recording which causes pairs to be filtered out.

	// Create UAF corpus entry with both programs
	programs := []*prog.Prog{prog1.Clone(), prog2.Clone()}
	barrier := buildBarrierSnapshot(req, res)
	plan := snapshotReplayPlan(req)

	// Use newUAFCorpusEntry to properly set PairBasicInfo and other fields
	entry := newUAFCorpusEntry(prog1, batch, barrier, now)
	entry.Kind = seedKindUAF
	entry.Programs = programs
	entry.ReplayPlan = plan.clone()
	entry.Source = source
	if len(entry.Programs) != 0 {
		entry.Prog = nil
	}

	// For thread-barrier entries, set AsyncMode so validate uses runAsyncBatch (single-process threaded).
	// The merged program (req.Prog) carries the Async-marked calls for concurrent execution.
	if isThreadBarrier && req.Prog != nil {
		entry.AsyncMode = true
		entry.Prog = req.Prog.Clone()
		// Extract async call indices from the merged program
		idx := 0
		for i, call := range req.Prog.Calls {
			if call.Props.Async && idx < 2 {
				entry.AsyncRaceCalls[idx] = i
				idx++
			}
		}
	}

	// Get replay history if new pairs found
	if historyCount > 0 && res != nil {
		vmIndex := res.Executor.VM
		entry.ReplayHistory = u.historyBuffer.GetLatest(vmIndex, historyCount)
	}

	id := entry.PairID()
	if id == 0 {
		return
	}
	key := uafSeedKey(id)
	u.mu.Lock()
	if _, exists := u.entries[key]; exists {
		u.mu.Unlock()
		return
	}
	seed := &barrierSeed{
		kind:     seedKindUAF,
		entry:    entry,
		execOpts: req.ExecOpts,
		syncable: true,
		synced:   false,
	}
	u.entries[key] = seed
	u.corpus.addSeed(key, entry, source)
	u.tryPersistSeed(seed)
	u.mu.Unlock()

	u.enqueueSeed(seed)
}

func isThreadBarrierRequest(req *queue.Request) bool {
	// We can't rely on ExecFlagThreaded because default executor options may
	// enable threaded execution for ordinary multi-process barrier requests too.
	return req != nil && req.ThreadBarrier
}

func (u *uafMode) timingExplorationCandidates(pairs []*ddrd.MayUAFPair) []*ddrd.MayUAFPair {
	if u == nil || u.corpus == nil || len(pairs) == 0 {
		return nil
	}

	var candidates []*ddrd.MayUAFPair
	seenVarNames := make(map[uint64]struct{})
	for _, pair := range pairs {
		if pair == nil {
			continue
		}
		varnameID := varnamePairID(pair.FreeAccessName, pair.UseAccessName)
		if _, exists := seenVarNames[varnameID]; exists {
			continue
		}
		if u.corpus.GetVarNamePairCount(pair.FreeAccessName, pair.UseAccessName) != 0 {
			continue
		}
		seenVarNames[varnameID] = struct{}{}
		candidates = append(candidates, pair)
	}
	return candidates
}

// determineHistoryCount determines how many history records to save based on pair newness.
// If any pair is a new VarName pair, save NewVarNamePairHistory records (from config or default).
// If any pair is a new stack for existing VarName pair, save NewStackHistory records (from config or default).
// For known pairs (neither new VarName nor new stack), save a minimal history (1 record) to enable replay.
// Returns the maximum count needed.
func (u *uafMode) determineHistoryCount(pairs []*ddrd.MayUAFPair) int {
	if u.fuzzer.raceGroup == nil || len(pairs) == 0 {
		return 0
	}
	// Get configured values or use defaults
	newVarNamePairHistory := u.fuzzer.Config.NewVarNamePairHistory
	if newVarNamePairHistory <= 0 {
		newVarNamePairHistory = DefaultNewVarNamePairHistory
	}
	newStackHistory := u.fuzzer.Config.NewStackHistory
	if newStackHistory <= 0 {
		newStackHistory = DefaultNewStackHistory
	}

	// Default: at least 1 history record for any UAF corpus entry with pairs
	// This ensures replay is possible even for known pairs
	maxCount := 1
	if len(u.timingExplorationCandidates(pairs)) > 0 {
		return newVarNamePairHistory
	}
	for _, pair := range pairs {
		if pair == nil {
			continue
		}
		isNewVarNamePair, isNewStack, _ := u.fuzzer.raceGroup.CheckPairNewness(pair)
		if isNewVarNamePair {
			// New VarName pair: save full history
			return newVarNamePairHistory
		}
		if isNewStack && maxCount < newStackHistory {
			maxCount = newStackHistory
		}
	}
	return maxCount
}

func (u *uafMode) handleCoverage(req *queue.Request, res *queue.Result, triage map[int]*triageCall) {
	if u == nil || len(triage) == 0 || req == nil || req.Prog == nil {
		return
	}
	raw := aggregateCoverageSignals(triage)
	if len(raw) == 0 {
		return
	}
	barrier := buildBarrierSnapshot(req, res)
	group := snapshotProgramGroup(req)
	plan := snapshotReplayPlan(req)
	key := coverageSeedKey(raw, barrier, req.Prog, group, plan)
	if u.corpus != nil {
		u.corpus.mergeCoverage(raw)
	}

	entry := newUAFCorpusEntry(req.Prog, nil, barrier, time.Now())
	entry.Kind = seedKindCoverage
	entry.Source = SourceFuzz
	entry.Programs = clonePrograms(group)
	entry.ReplayPlan = plan.clone()
	if len(entry.Programs) != 0 {
		entry.Prog = nil
	}
	seed := &barrierSeed{
		kind:     seedKindCoverage,
		entry:    entry,
		execOpts: req.ExecOpts,
		syncable: false,
		synced:   true,
	}
	u.mu.Lock()
	if _, exists := u.entries[key]; exists {
		u.mu.Unlock()
		return
	}
	u.entries[key] = seed
	u.corpus.addSeed(key, entry, SourceFuzz)
	u.mu.Unlock()

	u.enqueueSeed(seed)
	// u.fuzzer.Logf(0, "uaf: queued coverage seed %s (total=%d)", key, u.count())
}

func (u *uafMode) recordExecution(req *queue.Request, res *queue.Result) cover.Cover {
	if u == nil || res == nil || res.Info == nil || req == nil {
		return nil
	}
	var newCover cover.Cover
	if u.corpus != nil {
		newCover = u.corpus.recordCoverageWithDiff(res.Info)
	}
	// Record barrier execution history for replay (per-VM)
	if u.historyBuffer != nil && len(req.BarrierPrograms) > 0 {
		vmIndex := res.Executor.VM
		u.historyBuffer.AddPrograms(vmIndex, req.BarrierPrograms, res.BarrierGroupID)
		// Debug logging disabled for production (log every 500th record)
		// if size := u.historyBuffer.Size(vmIndex); size%500 == 0 {
		//	u.fuzzer.Logf(0, "[history] VM %d: history buffer has %d records",
		//		vmIndex, size)
		// }
	}
	// u.updateMainCorpusCoverage(req, res.Info)
	return newCover
}

// clearVMHistory clears the execution history for a specific VM.
// This should be called when a VM is restarted.
func (u *uafMode) clearVMHistory(vmIndex int) {
	if u == nil || u.historyBuffer == nil {
		return
	}
	_ = u.historyBuffer.Size(vmIndex) // unused, just for potential future use
	u.historyBuffer.ClearVM(vmIndex)
	// Debug logging disabled for production
	// u.fuzzer.Logf(0, "[history] VM %d: cleared history buffer (was %d records)", vmIndex, oldSize)
}

func (u *uafMode) updateMainCorpusCoverage(req *queue.Request, info *flatrpc.ProgInfo) {
	if u == nil || info == nil {
		return
	}
	corp := u.fuzzer.Config.Corpus
	if corp == nil || req == nil || req.Prog == nil {
		return
	}
	var empty signal.Signal
	save := func(callIdx int, covData []uint64) {
		if len(covData) == 0 {
			return
		}
		raw := append([]uint64(nil), covData...)
		var cov cover.Cover
		cov.Merge(raw)
		input := corpus.NewInput{
			Prog:     req.Prog.Clone(),
			Call:     callIdx,
			Signal:   empty,
			Cover:    cov.Serialize(),
			RawCover: raw,
		}
		corp.Save(input)
	}
	for idx, call := range info.Calls {
		if call == nil {
			continue
		}
		save(idx, call.Cover)
	}
	if info.Extra != nil {
		save(-1, info.Extra.Cover)
	}
}

func (u *uafMode) enqueueSeed(seed *barrierSeed) {
	if u == nil || u.queue == nil || seed == nil {
		return
	}
	entry, err := seed.materializeEntry(u.fuzzer.target)
	if err != nil {
		if u.fuzzer != nil {
			u.fuzzer.Logf(0, "uaf: failed to materialize seed entry: %v", err)
		}
		return
	}
	if entry == nil {
		return
	}
	var baseProg *prog.Prog
	switch {
	case entry.Prog != nil:
		baseProg = entry.Prog.Clone()
	case len(entry.Programs) != 0 && entry.Programs[0] != nil:
		baseProg = entry.Programs[0].Clone()
	default:
		return
	}
	req := &queue.Request{
		Prog:     baseProg,
		ExecOpts: seed.execOpts,
	}
	if entry.Source != SourceTiming {
		u.fuzzer.applyNormalTimingThreshold(req)
	}
	if barrier := entry.Barrier; barrier.Participants != 0 {
		req.SetBarrier(barrier.Participants)
		if len(barrier.ProcList) != 0 {
			req.BarrierProcList = append([]int(nil), barrier.ProcList...)
		}
		var programs []*prog.Prog
		switch {
		case len(entry.Programs) != 0:
			programs = entry.Programs
		}
		if len(programs) != 0 {
			req.BarrierPrograms = clonePrograms(programs)
		}
		plan := entry.ReplayPlan
		if !plan.IsZero() {
			if err := req.SetBarrierStartDelays(plan.DelaysMicros); err != nil {
				u.fuzzer.Logf(0, "uaf: failed to set barrier delays for seed: %v", err)
			}
		}
	}
	u.queue.Submit(req)
	if seed.synced || !seed.syncable {
		seed.releaseEntry()
	} else {
		seed.entry = entry
		seed.compactEntry()
	}
}

func (u *uafMode) pendingEntries() []*UAFCorpusEntry {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	var pending []*UAFCorpusEntry
	var target *prog.Target
	if u.fuzzer != nil {
		target = u.fuzzer.target
	}
	for _, seed := range u.entries {
		if seed == nil || seed.synced || !seed.syncable {
			continue
		}
		entry, err := seed.materializeEntry(target)
		if err != nil || entry == nil {
			if err != nil && u.fuzzer != nil {
				u.fuzzer.Logf(0, "uaf: failed to materialize pending seed: %v", err)
			}
			continue
		}
		seed.synced = true
		pending = append(pending, entry.clone())
		seed.releaseEntry()
	}
	return pending
}

func (u *uafMode) restore(entries []*UAFCorpusEntry) int {
	if u == nil || len(entries) == 0 {
		return 0
	}
	u.mu.Lock()
	var seeds []*barrierSeed
	var allPairs []*ddrd.MayUAFPair // Collect all pairs to register with varPairRegistry
	for _, entry := range entries {
		if entry == nil || (entry.Prog == nil && len(entry.Programs) == 0) {
			continue
		}
		id := entry.PairID()
		if id == 0 {
			continue
		}
		key := uafSeedKey(id)
		if _, exists := u.entries[key]; exists {
			continue
		}
		// u.fuzzer.Logf(0, "uaf: restoring pair id=%016x free_access=0x%016x use_access=0x%016x free_sn=%d use_sn=%d lock_type=%d access_type=%d",
		// 	id,
		// 	entry.PairBasicInfo.FreeAccessName,
		// 	entry.PairBasicInfo.UseAccessName,
		// 	entry.PairBasicInfo.FreeSN,
		// 	entry.PairBasicInfo.UseSN,
		// 	entry.PairBasicInfo.LockType,
		// 	entry.PairBasicInfo.UseAccessType)
		clone := entry.clone()
		for _, pair := range clone.Pairs {
			if added := u.addPairLocked(pair); added != nil {
				allPairs = append(allPairs, added)
			}
		}
		seed := &barrierSeed{
			kind:     clone.Kind,
			entry:    clone,
			execOpts: setFlags(flatrpc.ExecFlagCollectSignal),
			syncable: clone.Kind == seedKindUAF,
			synced:   true,
		}
		u.entries[key] = seed
		u.corpus.addSeed(key, clone, clone.Source)
		seeds = append(seeds, seed)
	}
	u.mu.Unlock()

	// Register restored pairs with varPairRegistry to keep it in sync
	// This ensures CheckPairNewness returns correct results for restored pairs
	if len(allPairs) > 0 && u.fuzzer.raceGroup != nil {
		u.fuzzer.raceGroup.RecordRacePairs(nil, allPairs)
	}

	for _, seed := range seeds {
		u.enqueueSeed(seed)
	}
	return len(seeds)
}

func (u *uafMode) count() int {
	if u == nil {
		return 0
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.entries)
}

// GetVarNamePairCount returns the number of corpus entries for a VarName pair
func (u *uafMode) GetVarNamePairCount(freeAccessName, useAccessName uint64) int {
	if u == nil || u.corpus == nil {
		return 0
	}
	return u.corpus.GetVarNamePairCount(freeAccessName, useAccessName)
}

func clonePrograms(programs []*prog.Prog) []*prog.Prog {
	if len(programs) == 0 {
		return nil
	}
	clones := make([]*prog.Prog, len(programs))
	for i, p := range programs {
		if p == nil {
			continue
		}
		clones[i] = p.Clone()
	}
	return clones
}

func seedSerializeProgramGroup(programs []*prog.Prog) [][]byte {
	if len(programs) == 0 {
		return nil
	}
	serialized := make([][]byte, len(programs))
	for i, p := range programs {
		if p != nil {
			serialized[i] = append([]byte(nil), p.Serialize()...)
		}
	}
	return serialized
}

func seedDeserializeProgramGroup(target *prog.Target, blobs [][]byte) ([]*prog.Prog, error) {
	if target == nil || len(blobs) == 0 {
		return nil, nil
	}
	programs := make([]*prog.Prog, len(blobs))
	for i, blob := range blobs {
		if len(blob) == 0 {
			continue
		}
		p, err := target.Deserialize(blob, prog.NonStrict)
		if err != nil {
			return nil, err
		}
		programs[i] = p
	}
	return programs, nil
}

func seedSerializeReplayHistory(history []*BarrierExecutionRecord) []serializedBarrierExecutionRecord {
	if len(history) == 0 {
		return nil
	}
	serialized := make([]serializedBarrierExecutionRecord, 0, len(history))
	for _, rec := range history {
		if rec == nil {
			continue
		}
		serialized = append(serialized, serializedBarrierExecutionRecord{
			Programs:  seedSerializeProgramGroup(rec.Programs),
			Timestamp: rec.Timestamp,
			GroupID:   rec.GroupID,
			VMIndex:   rec.VMIndex,
		})
	}
	return serialized
}

func seedDeserializeReplayHistory(target *prog.Target, records []serializedBarrierExecutionRecord) ([]*BarrierExecutionRecord, error) {
	if target == nil || len(records) == 0 {
		return nil, nil
	}
	history := make([]*BarrierExecutionRecord, 0, len(records))
	for _, rec := range records {
		programs, err := seedDeserializeProgramGroup(target, rec.Programs)
		if err != nil {
			return nil, err
		}
		history = append(history, &BarrierExecutionRecord{
			Programs:  programs,
			Timestamp: rec.Timestamp,
			GroupID:   rec.GroupID,
			VMIndex:   rec.VMIndex,
		})
	}
	return history, nil
}

func newSerializedSeedEntry(entry *UAFCorpusEntry) *serializedSeedEntry {
	if entry == nil {
		return nil
	}
	blob := &serializedSeedEntry{
		CallIdx:        entry.CallIdx,
		PairBasicInfo:  entry.PairBasicInfo,
		Signals:        entry.SignalsSlice(),
		Barrier:        entry.Barrier.clone(),
		ReplayPlan:     entry.ReplayPlan.clone(),
		Profile:        entry.Profile,
		Timestamp:      entry.Timestamp,
		Kind:           entry.Kind,
		Source:         entry.Source,
		ReplayHistory:  seedSerializeReplayHistory(entry.ReplayHistory),
		AsyncMode:      entry.AsyncMode,
		AsyncRaceCalls: entry.AsyncRaceCalls,
	}
	if entry.Prog != nil && (len(entry.Programs) == 0 || entry.AsyncMode) {
		blob.Program = append([]byte(nil), entry.Prog.Serialize()...)
	}
	if len(entry.Programs) != 0 {
		blob.Programs = seedSerializeProgramGroup(entry.Programs)
	}
	if len(entry.Pairs) != 0 {
		blob.Pairs = make([]ddrd.MayUAFPair, 0, len(entry.Pairs))
		for _, pair := range entry.Pairs {
			if pair != nil {
				blob.Pairs = append(blob.Pairs, *pair)
			}
		}
	}
	return blob
}

func (blob *serializedSeedEntry) materialize(target *prog.Target) (*UAFCorpusEntry, error) {
	if blob == nil {
		return nil, nil
	}
	entry := &UAFCorpusEntry{
		CallIdx:        blob.CallIdx,
		PairBasicInfo:  blob.PairBasicInfo,
		Signals:        sliceToSignal(blob.Signals),
		Barrier:        blob.Barrier.clone(),
		ReplayPlan:     blob.ReplayPlan.clone(),
		Profile:        blob.Profile,
		Timestamp:      blob.Timestamp,
		Kind:           blob.Kind,
		Source:         blob.Source,
		AsyncMode:      blob.AsyncMode,
		AsyncRaceCalls: blob.AsyncRaceCalls,
	}
	if target != nil && len(blob.Program) != 0 {
		p, err := target.Deserialize(blob.Program, prog.NonStrict)
		if err != nil {
			return nil, err
		}
		entry.Prog = p
	}
	if target != nil && len(blob.Programs) != 0 {
		programs, err := seedDeserializeProgramGroup(target, blob.Programs)
		if err != nil {
			return nil, err
		}
		entry.Programs = programs
		if !entry.AsyncMode {
			entry.Prog = nil
		}
	}
	if len(blob.Pairs) != 0 {
		entry.Pairs = make([]*ddrd.MayUAFPair, 0, len(blob.Pairs))
		for i := range blob.Pairs {
			pair := blob.Pairs[i]
			copyPair := pair
			entry.Pairs = append(entry.Pairs, &copyPair)
		}
	}
	if target != nil && len(blob.ReplayHistory) != 0 {
		history, err := seedDeserializeReplayHistory(target, blob.ReplayHistory)
		if err != nil {
			return nil, err
		}
		entry.ReplayHistory = history
	}
	return entry, nil
}

func (seed *barrierSeed) materializeEntry(target *prog.Target) (*UAFCorpusEntry, error) {
	if seed == nil {
		return nil, nil
	}
	if seed.entry != nil {
		return seed.entry, nil
	}
	return seed.entryBlob.materialize(target)
}

func (seed *barrierSeed) compactEntry() {
	if seed == nil || seed.entry == nil || seed.entryBlob != nil {
		return
	}
	seed.entryBlob = newSerializedSeedEntry(seed.entry)
	seed.entry = nil
}

func (seed *barrierSeed) releaseEntry() {
	if seed == nil {
		return
	}
	seed.entry = nil
	seed.entryBlob = nil
}

func snapshotProgramGroup(req *queue.Request) []*prog.Prog {
	if req == nil {
		return nil
	}
	if len(req.BarrierPrograms) != 0 {
		group := make([]*prog.Prog, len(req.BarrierPrograms))
		for i, p := range req.BarrierPrograms {
			if p != nil {
				group[i] = p.Clone()
				continue
			}
			if i == 0 && req.Prog != nil {
				group[i] = req.Prog.Clone()
			}
		}
		return group
	}
	if req.Prog != nil {
		return []*prog.Prog{req.Prog.Clone()}
	}
	return nil
}

func snapshotReplayPlan(req *queue.Request) UAFCorpusReplayPlan {
	if req == nil || len(req.BarrierStartDelayUs) == 0 {
		return UAFCorpusReplayPlan{}
	}
	return UAFCorpusReplayPlan{DelaysMicros: append([]int64(nil), req.BarrierStartDelayUs...)}
}

func buildBarrierSnapshot(req *queue.Request, res *queue.Result) BarrierSnapshot {
	snapshot := BarrierSnapshot{
		Participants: req.BarrierParticipants,
	}
	if res != nil {
		snapshot.GroupID = res.BarrierGroupID
		snapshot.GroupSize = res.BarrierGroupSize
	}
	if snapshot.GroupSize == 0 && snapshot.Participants != 0 {
		snapshot.GroupSize = bits.OnesCount64(snapshot.Participants)
	}
	if len(req.BarrierProcList) != 0 {
		snapshot.ProcList = append([]int(nil), req.BarrierProcList...)
	}
	return snapshot
}

func newUAFCorpusEntry(program *prog.Prog, pairs []*ddrd.MayUAFPair, barrier BarrierSnapshot, ts time.Time) *UAFCorpusEntry {
	entry := &UAFCorpusEntry{
		CallIdx:   -1,
		Barrier:   barrier.clone(),
		Timestamp: ts,
	}
	if program != nil {
		entry.Prog = program.Clone()
	}
	if len(pairs) != 0 {
		entry.Pairs = clonePairs(pairs)
		if len(entry.Pairs) != 0 {
			entry.PairBasicInfo = *entry.Pairs[0]
			entry.Signals = cloneSignal(ddrd.FromUAFPairs(entry.Pairs, ddrd.UAFSignalPrioHigh))
			entry.Profile = newUAFPairProfile(entry.Pairs[0])
		}
	}
	return entry
}

func clonePairs(pairs []*ddrd.MayUAFPair) []*ddrd.MayUAFPair {
	if len(pairs) == 0 {
		return nil
	}
	cloned := make([]*ddrd.MayUAFPair, 0, len(pairs))
	for _, pair := range pairs {
		if pair == nil {
			continue
		}
		copyPair := new(ddrd.MayUAFPair)
		*copyPair = *pair
		cloned = append(cloned, copyPair)
	}
	if len(cloned) == 0 {
		return nil
	}
	return cloned
}

func cloneSignal(signal ddrd.UAFSignal) ddrd.UAFSignal {
	if signal == nil {
		return nil
	}
	cloned := make(ddrd.UAFSignal, len(signal))
	for value := range signal {
		cloned[value] = struct{}{}
	}
	return cloned
}

func sliceToSignal(values []uint64) ddrd.UAFSignal {
	if len(values) == 0 {
		return nil
	}
	signal := make(ddrd.UAFSignal, len(values))
	for _, value := range values {
		signal[value] = struct{}{}
	}
	return signal
}

func (entry *UAFCorpusEntry) clone() *UAFCorpusEntry {
	if entry == nil {
		return nil
	}
	clone := *entry
	if entry.Prog != nil {
		clone.Prog = entry.Prog.Clone()
	}
	if len(entry.Programs) != 0 {
		clone.Programs = clonePrograms(entry.Programs)
	}
	if len(entry.Pairs) != 0 {
		clone.Pairs = clonePairs(entry.Pairs)
	}
	clone.Signals = cloneSignal(entry.Signals)
	clone.Barrier = entry.Barrier.clone()
	clone.ReplayPlan = entry.ReplayPlan.clone()
	if len(entry.ValidateQueueKeys) != 0 {
		clone.ValidateQueueKeys = append([]string(nil), entry.ValidateQueueKeys...)
	}
	if len(entry.ValidatePairKeys) != 0 {
		clone.ValidatePairKeys = append([]string(nil), entry.ValidatePairKeys...)
	}
	// Clone replay history
	if len(entry.ReplayHistory) != 0 {
		clone.ReplayHistory = make([]*BarrierExecutionRecord, len(entry.ReplayHistory))
		for i, rec := range entry.ReplayHistory {
			if rec != nil {
				clone.ReplayHistory[i] = rec.Clone()
			}
		}
	}
	return &clone
}

// Clone returns a deep copy of the corpus entry for external consumers.
func (entry *UAFCorpusEntry) Clone() *UAFCorpusEntry {
	return entry.clone()
}

func (entry *UAFCorpusEntry) PairID() uint64 {
	if entry == nil {
		return 0
	}
	return entry.PairBasicInfo.UAFPairID()
}

func (entry *UAFCorpusEntry) SignalsSlice() []uint64 {
	if entry == nil || entry.Signals == nil {
		return nil
	}
	result := make([]uint64, 0, len(entry.Signals))
	for value := range entry.Signals {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func (b BarrierSnapshot) clone() BarrierSnapshot {
	copy := b
	if len(b.ProcList) != 0 {
		copy.ProcList = append([]int(nil), b.ProcList...)
	}
	return copy
}

func collectAllCoverage(info *flatrpc.ProgInfo) []uint64 {
	if info == nil {
		return nil
	}
	var merged []uint64
	for _, call := range info.Calls {
		if call == nil || len(call.Cover) == 0 {
			continue
		}
		merged = append(merged, call.Cover...)
	}
	if info.Extra != nil && len(info.Extra.Cover) != 0 {
		merged = append(merged, info.Extra.Cover...)
	}
	if len(merged) == 0 {
		return nil
	}
	var cov cover.Cover
	cov.Merge(merged)
	return cov.Serialize()
}

func aggregateCoverageSignals(triage map[int]*triageCall) []uint64 {
	if len(triage) == 0 {
		return nil
	}
	seen := make(map[uint64]struct{})
	var merged []uint64
	for _, call := range triage {
		if call == nil || call.newSignal == nil {
			continue
		}
		for _, val := range call.newSignal.ToRaw() {
			if _, ok := seen[val]; ok {
				continue
			}
			seen[val] = struct{}{}
			merged = append(merged, val)
		}
	}
	if len(merged) == 0 {
		return nil
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i] < merged[j] })
	return merged
}

func coverageSeedKey(raw []uint64, barrier BarrierSnapshot, program *prog.Prog, group []*prog.Prog, plan UAFCorpusReplayPlan) string {
	var procList []int64
	if len(barrier.ProcList) != 0 {
		procList = make([]int64, len(barrier.ProcList))
		for i, v := range barrier.ProcList {
			procList[i] = int64(v)
		}
	}
	var serialized []byte
	if program != nil {
		serialized = program.Serialize()
	}
	groupData := serializeProgramGroup(group)
	var delays []int64
	if len(plan.DelaysMicros) != 0 {
		delays = append([]int64(nil), plan.DelaysMicros...)
	}
	// Note: Do NOT include barrier.GroupID in the key - it's a runtime-assigned
	// incrementing value that would prevent proper deduplication.
	return "cov-" + hash.String("cov", raw, barrier.Participants,
		int64(barrier.GroupSize), procList, serialized, groupData, delays)
}

func serializeProgramGroup(programs []*prog.Prog) []byte {
	if len(programs) == 0 {
		return nil
	}
	buf := new(bytes.Buffer)
	for _, p := range programs {
		if p == nil {
			var zero [4]byte
			buf.Write(zero[:])
			continue
		}
		data := p.Serialize()
		var lenBuf [4]byte
		binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(data)))
		buf.Write(lenBuf[:])
		buf.Write(data)
	}
	return buf.Bytes()
}

func uafSeedKey(id uint64) string {
	return fmt.Sprintf("uaf-%016x", id)
}
