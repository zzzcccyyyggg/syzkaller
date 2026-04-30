// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"bufio"
	"compress/flate"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// StreamingUAFCorpusReader provides memory-efficient streaming access to large UAF corpus files.
// Instead of loading the entire database into memory, it reads entries one at a time.
type StreamingUAFCorpusReader struct {
	path   string
	target *prog.Target
}

// NewStreamingUAFCorpusReader creates a new streaming reader for UAF corpus.
func NewStreamingUAFCorpusReader(path string, target *prog.Target) *StreamingUAFCorpusReader {
	return &StreamingUAFCorpusReader{
		path:   path,
		target: target,
	}
}

// StreamingEntry represents a single entry during streaming iteration.
type StreamingEntry struct {
	Key   string
	Seq   uint64
	Entry *fuzzer.UAFCorpusEntry
	Err   error
}

// dbMagic and other constants match pkg/db/db.go
const (
	streamDBMagic    = uint32(0xbaddb)
	streamRecMagic   = uint32(0xfee1bad)
	streamSeqDeleted = ^uint64(0)
)

// CountEntries counts the number of valid entries without fully deserializing them.
// This is useful for progress reporting and memory estimation.
func (r *StreamingUAFCorpusReader) CountEntries() (int, error) {
	f, err := os.Open(r.path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	reader := bufio.NewReaderSize(f, 64*1024) // 64KB buffer

	// Skip header
	if err := r.skipHeader(reader); err != nil {
		return 0, err
	}

	count := 0
	deleted := make(map[string]bool)
	keys := make(map[string]bool)

	for {
		key, _, seq, err := r.readRecordMeta(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}

		if seq == streamSeqDeleted {
			deleted[key] = true
			delete(keys, key)
		} else {
			keys[key] = true
			delete(deleted, key)
		}
	}

	return len(keys), nil
}

// IterateEntries streams entries one at a time, calling the callback for each.
// This avoids loading all entries into memory at once.
// If sinceSeq > 0, only entries with seq > sinceSeq are returned.
// If batchSize > 0, entries are yielded in batches for efficiency.
func (r *StreamingUAFCorpusReader) IterateEntries(sinceSeq uint64, callback func(entry *fuzzer.UAFCorpusEntry, seq uint64) bool) (maxSeq uint64, err error) {
	f, err := os.Open(r.path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	// Get file size for progress reporting
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	fileSize := fi.Size()
	fileSizeMB := fileSize / (1024 * 1024)
	log.Logf(0, "streaming: starting to read %d MB file...", fileSizeMB)

	// Use a larger buffer for better I/O performance
	reader := bufio.NewReaderSize(f, 256*1024) // 256KB buffer

	// Skip header
	if err := r.skipHeader(reader); err != nil {
		return 0, err
	}

	// First pass: collect all valid keys and their latest data
	// We need this because the DB format can have multiple records for the same key
	type recordInfo struct {
		seq  uint64
		data []byte
	}
	records := make(map[string]*recordInfo)

	recordCount := 0
	lastProgress := time.Now()
	progressInterval := 5 * time.Second

	for {
		key, data, seq, err := r.readRecord(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return maxSeq, fmt.Errorf("read record: %w", err)
		}

		recordCount++

		// Progress reporting every 5 seconds
		if time.Since(lastProgress) > progressInterval {
			// Estimate progress based on buffer position (rough)
			log.Logf(0, "streaming: read %d records, %d unique keys so far...", recordCount, len(records))
			lastProgress = time.Now()
		}

		if seq == streamSeqDeleted {
			delete(records, key)
			continue
		}

		// Only keep if newer than what we have
		if existing, ok := records[key]; !ok || seq > existing.seq {
			records[key] = &recordInfo{seq: seq, data: data}
		}
	}

	log.Logf(0, "streaming: finished reading %d records, %d unique keys", recordCount, len(records))

	// Sort by seq for deterministic ordering
	type keySeq struct {
		key string
		seq uint64
	}
	var sorted []keySeq
	for key, info := range records {
		if info.seq > sinceSeq {
			sorted = append(sorted, keySeq{key, info.seq})
		}
		if info.seq > maxSeq {
			maxSeq = info.seq
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].seq < sorted[j].seq
	})

	// Now deserialize and yield entries one at a time
	for _, ks := range sorted {
		info := records[ks.key]
		entry, err := r.deserializeEntry(info.data)
		if err != nil {
			log.Logf(0, "streaming: failed to deserialize entry %s: %v", ks.key, err)
			continue
		}
		entry.CorpusRecordID = ks.key
		if !callback(entry, info.seq) {
			break
		}
	}

	return maxSeq, nil
}

// LoadEntryByKey materializes a single heavy corpus record and injects the
// target pair into the returned entry. It scans the append-only DB file without
// caching all corpus values in memory.
func (r *StreamingUAFCorpusReader) LoadEntryByKey(key string, pair *ddrd.MayUAFPair) (*fuzzer.UAFCorpusEntry, uint64, error) {
	if r == nil || key == "" {
		return nil, 0, nil
	}
	f, err := os.Open(r.path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	reader := bufio.NewReaderSize(f, 256*1024)
	if err := r.skipHeader(reader); err != nil {
		return nil, 0, err
	}

	var latest []byte
	var latestSeq uint64
	for {
		recKey, data, seq, err := r.readRecord(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, latestSeq, fmt.Errorf("read record: %w", err)
		}
		if recKey != key {
			continue
		}
		if seq == streamSeqDeleted {
			latest = nil
			latestSeq = seq
			continue
		}
		latest = data
		latestSeq = seq
	}
	if len(latest) == 0 || latestSeq == streamSeqDeleted {
		return nil, latestSeq, nil
	}
	entry, err := r.deserializeEntry(latest)
	if err != nil {
		return nil, latestSeq, err
	}
	entry.CorpusRecordID = key
	attachPairToEntry(entry, pair)
	return entry, latestSeq, nil
}

// IterateEntriesBatched streams entries in batches for better efficiency.
// Each batch is processed together, then memory is released before the next batch.
func (r *StreamingUAFCorpusReader) IterateEntriesBatched(sinceSeq uint64, batchSize int, callback func(entries []*fuzzer.UAFCorpusEntry, seqs []uint64) bool) (maxSeq uint64, err error) {
	if batchSize <= 0 {
		batchSize = 100
	}

	var batch []*fuzzer.UAFCorpusEntry
	var seqs []uint64

	maxSeq, err = r.IterateEntries(sinceSeq, func(entry *fuzzer.UAFCorpusEntry, seq uint64) bool {
		batch = append(batch, entry)
		seqs = append(seqs, seq)

		if len(batch) >= batchSize {
			cont := callback(batch, seqs)
			// Clear batch to release memory
			batch = nil
			seqs = nil
			return cont
		}
		return true
	})

	// Process remaining entries
	if len(batch) > 0 {
		callback(batch, seqs)
	}

	return maxSeq, err
}

func (r *StreamingUAFCorpusReader) skipHeader(reader *bufio.Reader) error {
	var magic, ver uint32
	if err := binary.Read(reader, binary.LittleEndian, &magic); err != nil {
		if err == io.EOF {
			return nil // Empty file
		}
		return err
	}
	if magic != streamDBMagic {
		return fmt.Errorf("bad db header: 0x%x", magic)
	}
	if err := binary.Read(reader, binary.LittleEndian, &ver); err != nil {
		return err
	}
	if ver >= 2 {
		var userVer uint64
		if err := binary.Read(reader, binary.LittleEndian, &userVer); err != nil {
			return err
		}
	}
	return nil
}

func (r *StreamingUAFCorpusReader) readRecordMeta(reader *bufio.Reader) (key string, valLen uint32, seq uint64, err error) {
	var magic uint32
	if err = binary.Read(reader, binary.LittleEndian, &magic); err != nil {
		return
	}
	if magic != streamRecMagic {
		err = fmt.Errorf("bad record header: 0x%x", magic)
		return
	}

	var keyLen uint32
	if err = binary.Read(reader, binary.LittleEndian, &keyLen); err != nil {
		return
	}
	keyBuf := make([]byte, keyLen)
	if _, err = io.ReadFull(reader, keyBuf); err != nil {
		return
	}
	key = string(keyBuf)

	if err = binary.Read(reader, binary.LittleEndian, &seq); err != nil {
		return
	}

	if seq == streamSeqDeleted {
		return
	}

	if err = binary.Read(reader, binary.LittleEndian, &valLen); err != nil {
		return
	}

	// Skip the value data
	if valLen > 0 {
		if _, err = io.CopyN(io.Discard, reader, int64(valLen)); err != nil {
			return
		}
	}

	return
}

func (r *StreamingUAFCorpusReader) readRecord(reader *bufio.Reader) (key string, val []byte, seq uint64, err error) {
	var magic uint32
	if err = binary.Read(reader, binary.LittleEndian, &magic); err != nil {
		return
	}
	if magic != streamRecMagic {
		err = fmt.Errorf("bad record header: 0x%x", magic)
		return
	}

	var keyLen uint32
	if err = binary.Read(reader, binary.LittleEndian, &keyLen); err != nil {
		return
	}
	keyBuf := make([]byte, keyLen)
	if _, err = io.ReadFull(reader, keyBuf); err != nil {
		return
	}
	key = string(keyBuf)

	if err = binary.Read(reader, binary.LittleEndian, &seq); err != nil {
		return
	}

	if seq == streamSeqDeleted {
		return
	}

	var valLen uint32
	if err = binary.Read(reader, binary.LittleEndian, &valLen); err != nil {
		return
	}

	if valLen > 0 {
		fr := flate.NewReader(&io.LimitedReader{R: reader, N: int64(valLen)})
		val, err = io.ReadAll(fr)
		fr.Close()
		if err != nil {
			return
		}
	}

	return
}

func (r *StreamingUAFCorpusReader) deserializeEntry(data []byte) (*fuzzer.UAFCorpusEntry, error) {
	var stored storedUAFCorpusEntry
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}

	entry := &fuzzer.UAFCorpusEntry{
		CallIdx:        stored.CallIdx,
		PairBasicInfo:  stored.Pair,
		Signals:        sliceToSignal(stored.Signals),
		Barrier:        stored.Barrier,
		Timestamp:      stored.Timestamp,
		Source:         fuzzer.PairSource(stored.Source),
		AsyncMode:      stored.AsyncMode,
		AsyncRaceCalls: stored.AsyncRaceCalls,
	}

	if len(stored.Pairs) != 0 {
		entry.Pairs = make([]*ddrd.MayUAFPair, 0, len(stored.Pairs))
		for i := range stored.Pairs {
			pairCopy := stored.Pairs[i]
			entry.Pairs = append(entry.Pairs, &pairCopy)
		}
	} else if !isZeroMayUAFPair(stored.Pair) {
		pairCopy := stored.Pair
		entry.Pairs = []*ddrd.MayUAFPair{&pairCopy}
	}
	if len(entry.Pairs) != 0 {
		entry.PairBasicInfo = *entry.Pairs[0]
	}

	if r.target != nil && len(stored.Program) != 0 {
		progObj, err := r.target.Deserialize(stored.Program, prog.NonStrict)
		if err != nil {
			return nil, err
		}
		entry.Prog = progObj
	}

	if r.target != nil && len(stored.Programs) != 0 {
		group := make([]*prog.Prog, len(stored.Programs))
		for i, blob := range stored.Programs {
			if len(blob) == 0 {
				continue
			}
			progObj, err := r.target.Deserialize(blob, prog.NonStrict)
			if err != nil {
				return nil, fmt.Errorf("deserialize program %d: %w", i, err)
			}
			group[i] = progObj
		}
		entry.Programs = group
		if !entry.AsyncMode {
			entry.Prog = nil
		}
	}

	if stored.ReplayPlan != nil {
		entry.ReplayPlan = fuzzer.UAFCorpusReplayPlan{
			DelaysMicros: stored.ReplayPlan.DelaysMicros,
		}
	}

	if stored.Profile != nil {
		entry.Profile = fuzzer.UAFPairProfile{
			FreeAccessName: stored.Profile.FreeAccessName,
			UseAccessName:  stored.Profile.UseAccessName,
			FreeCallStack:  stored.Profile.FreeCallStack,
			UseCallStack:   stored.Profile.UseCallStack,
		}
	} else {
		entry.Profile = fuzzer.UAFPairProfile{
			FreeAccessName: stored.Pair.FreeAccessName,
			UseAccessName:  stored.Pair.UseAccessName,
			FreeCallStack:  stored.Pair.FreeCallStack,
			UseCallStack:   stored.Pair.UseCallStack,
		}
	}

	// Deserialize replay history. This is only used when a worker materializes
	// a concrete validation task; queue/index paths keep history out of memory.
	if len(stored.ReplayHistory) != 0 && r.target != nil {
		history := make([]*fuzzer.BarrierExecutionRecord, 0, len(stored.ReplayHistory))
		for _, rec := range stored.ReplayHistory {
			record := &fuzzer.BarrierExecutionRecord{
				Timestamp: rec.Timestamp,
				GroupID:   rec.GroupID,
			}
			if len(rec.Programs) != 0 {
				programs := make([]*prog.Prog, len(rec.Programs))
				for i, blob := range rec.Programs {
					if len(blob) == 0 {
						continue
					}
					progObj, err := r.target.Deserialize(blob, prog.NonStrict)
					if err != nil {
						continue // Skip invalid programs in history
					}
					programs[i] = progObj
				}
				record.Programs = programs
			}
			history = append(history, record)
		}
		entry.ReplayHistory = history
	}

	return entry, nil
}

// EstimateMemoryUsage estimates the memory usage for loading the corpus.
func (r *StreamingUAFCorpusReader) EstimateMemoryUsage() (int64, error) {
	info, err := os.Stat(r.path)
	if err != nil {
		return 0, err
	}
	// Rough estimate: decompressed data is about 3-5x larger than compressed
	// Plus JSON parsing overhead and Go object overhead
	return info.Size() * 5, nil
}

// LoadEntriesWithLimit loads entries up to a maximum count.
// This is useful when you want to process a subset of a large corpus.
func (r *StreamingUAFCorpusReader) LoadEntriesWithLimit(limit int, sinceSeq uint64) ([]*fuzzer.UAFCorpusEntry, uint64, error) {
	var entries []*fuzzer.UAFCorpusEntry
	maxSeq, err := r.IterateEntries(sinceSeq, func(entry *fuzzer.UAFCorpusEntry, seq uint64) bool {
		entries = append(entries, entry)
		return len(entries) < limit
	})
	return entries, maxSeq, err
}

// LoadEntriesWithProgress loads all entries with progress reporting.
func (r *StreamingUAFCorpusReader) LoadEntriesWithProgress(sinceSeq uint64, progressFn func(loaded, total int)) ([]*fuzzer.UAFCorpusEntry, uint64, error) {
	total, err := r.CountEntries()
	if err != nil {
		log.Logf(0, "streaming: failed to count entries: %v", err)
		total = 0
	}

	var entries []*fuzzer.UAFCorpusEntry
	loaded := 0
	lastReport := time.Now()

	maxSeq, err := r.IterateEntries(sinceSeq, func(entry *fuzzer.UAFCorpusEntry, seq uint64) bool {
		entries = append(entries, entry)
		loaded++

		// Report progress every second
		if progressFn != nil && time.Since(lastReport) > time.Second {
			progressFn(loaded, total)
			lastReport = time.Now()
		}
		return true
	})

	if progressFn != nil {
		progressFn(loaded, total)
	}

	return entries, maxSeq, err
}
