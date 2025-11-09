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
	"github.com/google/syzkaller/pkg/log"
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
	fuzzer  *Fuzzer
	queue   *queue.PlainQueue
	mu      sync.Mutex
	entries map[string]*barrierSeed
	corpus  *uafCorpus
}

type uafCorpus struct {
	mu        sync.RWMutex
	seeds     map[string]*UAFCorpusEntry
	pairIDs   map[uint64]struct{}
	coverage  cover.Cover
	statSeeds *stat.Val
	statCover *stat.Val
	statPairs *stat.Val
}

type barrierSeed struct {
	kind            barrierSeedKind
	entry           *UAFCorpusEntry
	execOpts        flatrpc.ExecOpts
	barrierPrograms []*prog.Prog
	syncable        bool
	synced          bool
}

// UAFCorpusEntry represents a single stored UAF seed within the fuzzer.
type UAFCorpusEntry struct {
	Prog          *prog.Prog
	Programs      []*prog.Prog
	CallIdx       int
	PairBasicInfo ddrd.MayUAFPair
	Signals       ddrd.UAFSignal
	Barrier       BarrierSnapshot
	Timestamp     time.Time
	Kind          barrierSeedKind
}

// BarrierSnapshot records the barrier configuration used when discovering a UAF pair.
type BarrierSnapshot struct {
	Participants uint64
	GroupID      int64
	GroupSize    int
	ProcList     []int
}

func newUAFMode(f *Fuzzer) *uafMode {
	if f == nil || !f.Config.ModeUAF {
		return nil
	}
	return &uafMode{
		fuzzer:  f,
		entries: make(map[string]*barrierSeed),
		corpus:  newUAFCorpus(),
	}
}

func newUAFCorpus() *uafCorpus {
	uc := &uafCorpus{
		seeds:   make(map[string]*UAFCorpusEntry),
		pairIDs: make(map[uint64]struct{}),
	}
	uc.statSeeds = stat.New("uaf corpus", "Number of UAF seeds managed by the fuzzer",
		stat.Console, stat.Graph("uaf"), func() int {
			uc.mu.RLock()
			defer uc.mu.RUnlock()
			return len(uc.seeds)
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
			return len(uc.pairIDs)
		})
	return uc
}

func (uc *uafCorpus) addSeed(key string, entry *UAFCorpusEntry) {
	if uc == nil || entry == nil {
		return
	}
	clone := entry.clone()
	uc.mu.Lock()
	defer uc.mu.Unlock()
	uc.seeds[key] = clone
	if id := clone.PairID(); id != 0 {
		uc.pairIDs[id] = struct{}{}
	}
}

func (uc *uafCorpus) recordCoverage(info *flatrpc.ProgInfo) {
	if uc == nil {
		return
	}
	raw := collectAllCoverage(info)
	if len(raw) == 0 {
		log.Logf(0, "uaf: recording coverage of size %d from execution", len(raw))
		return
	}
	uc.mu.Lock()
	uc.coverage.Merge(raw)
	uc.mu.Unlock()
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

func (u *uafMode) handleNewPairs(req *queue.Request, res *queue.Result, pairs []*ddrd.MayUAFPair) {
	if u == nil || len(pairs) == 0 || req == nil || req.Prog == nil {
		return
	}
	now := time.Now()
	barrier := buildBarrierSnapshot(req, res)
	groupTemplate := snapshotProgramGroup(req)

	u.mu.Lock()
	var seeds []*barrierSeed
	for _, pair := range pairs {
		if pair == nil {
			continue
		}
		id := pair.UAFPairID()
		if id == 0 {
			continue
		}
		key := uafSeedKey(id)
		if _, exists := u.entries[key]; exists {
			continue
		}
		entry := newUAFCorpusEntry(req.Prog, pair, barrier, now)
		entry.Kind = seedKindUAF
		if len(groupTemplate) != 0 {
			entry.Programs = clonePrograms(groupTemplate)
		}
		seed := &barrierSeed{
			kind:     seedKindUAF,
			entry:    entry,
			execOpts: req.ExecOpts,
			syncable: true,
			synced:   false,
		}
		if len(req.BarrierPrograms) != 0 {
			seed.barrierPrograms = clonePrograms(req.BarrierPrograms)
		} else if len(entry.Programs) != 0 {
			seed.barrierPrograms = clonePrograms(entry.Programs)
		}
		u.entries[key] = seed
		u.corpus.addSeed(key, entry)
		seeds = append(seeds, seed)
		u.fuzzer.Logf(0, "uaf: queued uaf pair seed %s (total=%d)", key, u.count())
	}
	u.mu.Unlock()

	for _, seed := range seeds {
		u.enqueueSeed(seed)
	}
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
	key := coverageSeedKey(raw, barrier, req.Prog, group)
	if u.corpus != nil {
		u.corpus.mergeCoverage(raw)
	}

	entry := newUAFCorpusEntry(req.Prog, nil, barrier, time.Now())
	entry.Kind = seedKindCoverage
	entry.Programs = clonePrograms(group)
	seed := &barrierSeed{
		kind:     seedKindCoverage,
		entry:    entry,
		execOpts: req.ExecOpts,
		syncable: false,
		synced:   true,
	}
	if len(req.BarrierPrograms) != 0 {
		seed.barrierPrograms = clonePrograms(req.BarrierPrograms)
	} else if len(entry.Programs) != 0 {
		seed.barrierPrograms = clonePrograms(entry.Programs)
	}

	u.mu.Lock()
	if _, exists := u.entries[key]; exists {
		u.mu.Unlock()
		return
	}
	u.entries[key] = seed
	u.corpus.addSeed(key, entry)
	u.mu.Unlock()

	u.enqueueSeed(seed)
	// u.fuzzer.Logf(0, "uaf: queued coverage seed %s (total=%d)", key, u.count())
}

func (u *uafMode) recordExecution(req *queue.Request, res *queue.Result) {
	if u == nil || res == nil || res.Info == nil || req == nil {
		return
	}
	if u.corpus != nil {
		u.corpus.recordCoverage(res.Info)
	}
	u.updateMainCorpusCoverage(req, res.Info)
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
	if u == nil || u.queue == nil || seed == nil || seed.entry == nil || seed.entry.Prog == nil {
		return
	}
	req := &queue.Request{
		Prog:     seed.entry.Prog.Clone(),
		ExecOpts: seed.execOpts,
	}
	if barrier := seed.entry.Barrier; barrier.Participants != 0 {
		req.SetBarrier(barrier.Participants)
		if len(barrier.ProcList) != 0 {
			req.BarrierProcList = append([]int(nil), barrier.ProcList...)
		}
		var programs []*prog.Prog
		switch {
		case len(seed.barrierPrograms) != 0:
			programs = seed.barrierPrograms
		case len(seed.entry.Programs) != 0:
			programs = seed.entry.Programs
		}
		if len(programs) != 0 {
			req.BarrierPrograms = clonePrograms(programs)
		}
	}
	u.queue.Submit(req)
}

func (u *uafMode) pendingEntries() []*UAFCorpusEntry {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	var pending []*UAFCorpusEntry
	for _, seed := range u.entries {
		if seed == nil || seed.entry == nil || seed.synced || !seed.syncable {
			continue
		}
		seed.synced = true
		pending = append(pending, seed.entry.clone())
	}
	return pending
}

func (u *uafMode) restore(entries []*UAFCorpusEntry) int {
	if u == nil || len(entries) == 0 {
		return 0
	}
	u.mu.Lock()
	var seeds []*barrierSeed
	for _, entry := range entries {
		if entry == nil || entry.Prog == nil {
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
		u.fuzzer.Logf(0, "uaf: restoring pair id=%016x free_access=0x%016x use_access=0x%016x free_sn=%d use_sn=%d lock_type=%d access_type=%d",
			id,
			entry.PairBasicInfo.FreeAccessName,
			entry.PairBasicInfo.UseAccessName,
			entry.PairBasicInfo.FreeSN,
			entry.PairBasicInfo.UseSN,
			entry.PairBasicInfo.LockType,
			entry.PairBasicInfo.UseAccessType)
		clone := entry.clone()
		seed := &barrierSeed{
			kind:     clone.Kind,
			entry:    clone,
			execOpts: setFlags(flatrpc.ExecFlagCollectSignal),
			syncable: clone.Kind == seedKindUAF,
			synced:   clone.Kind != seedKindUAF,
		}
		if len(clone.Programs) != 0 {
			seed.barrierPrograms = clonePrograms(clone.Programs)
		}
		u.entries[key] = seed
		u.corpus.addSeed(key, clone)
		seeds = append(seeds, seed)
	}
	u.mu.Unlock()
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

func newUAFCorpusEntry(program *prog.Prog, pair *ddrd.MayUAFPair, barrier BarrierSnapshot, ts time.Time) *UAFCorpusEntry {
	entry := &UAFCorpusEntry{
		CallIdx:   -1,
		Barrier:   barrier.clone(),
		Timestamp: ts,
	}
	if program != nil {
		entry.Prog = program.Clone()
	}
	if pair != nil {
		entry.PairBasicInfo = *pair
		entry.Signals = cloneSignal(ddrd.FromUAFPairs([]*ddrd.MayUAFPair{pair}, ddrd.UAFSignalPrioHigh))
	}
	return entry
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
	clone.Signals = cloneSignal(entry.Signals)
	clone.Barrier = entry.Barrier.clone()
	return &clone
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

func coverageSeedKey(raw []uint64, barrier BarrierSnapshot, program *prog.Prog, group []*prog.Prog) string {
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
	return "cov-" + hash.String("cov", raw, barrier.Participants, barrier.GroupID,
		int64(barrier.GroupSize), procList, serialized, groupData)
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
