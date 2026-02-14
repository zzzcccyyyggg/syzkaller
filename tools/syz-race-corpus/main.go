// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-uaf-corpus is a tool to inspect and dump the contents of uaf-corpus.db files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
)

var (
	flagWorkdir        = flag.String("workdir", "", "path to workdir containing uaf-corpus.db")
	flagConfig         = flag.String("config", "", "syzkaller config file to get workdir and target")
	flagDBPath         = flag.String("db", "", "direct path to uaf-corpus.db file")
	flagKey            = flag.String("key", "", "show only entry with this key")
	flagSummary        = flag.Bool("summary", false, "show summary statistics only")
	flagPrograms       = flag.Bool("programs", true, "show program source code")
	flagPairs          = flag.Bool("pairs", true, "show UAF pair details")
	flagJSON           = flag.Bool("json", false, "output in JSON format")
	flagLimit          = flag.Int("limit", 0, "limit number of entries to show (0 = all)")
	flagSortTime       = flag.Bool("sort-time", false, "sort entries by timestamp (newest first)")
	flagVarNames       = flag.Bool("varnames", false, "show distinct VarName pairs with counts")
	flagVarNamesStacks = flag.Bool("varnames-stacks", false, "show distinct VarName pairs with unique callstack counts (sorted by stack count)")
	flagSource         = flag.String("source", "", "filter by source: 'fuzz', 'timing', or '' for all")
)

type storedUAFCorpusEntry struct {
	Program    []byte                 `json:"program"`
	Programs   [][]byte               `json:"programs,omitempty"`
	CallIdx    int                    `json:"call_idx"`
	Pair       ddrd.MayUAFPair        `json:"pair"`
	Pairs      []ddrd.MayUAFPair      `json:"pairs,omitempty"`
	Signals    []uint64               `json:"signals,omitempty"`
	Barrier    fuzzer.BarrierSnapshot `json:"barrier"`
	ReplayPlan *storedReplayPlan      `json:"replay_plan,omitempty"`
	Profile    *storedPairProfile     `json:"profile,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
	Source     int                    `json:"source,omitempty"` // 0=fuzz, 1=timing
}

type storedReplayPlan struct {
	DelaysMicros []int64 `json:"delays_micros,omitempty"`
}

type storedPairProfile struct {
	FreeAccessName uint64 `json:"free_access_name,omitempty"`
	UseAccessName  uint64 `json:"use_access_name,omitempty"`
	FreeCallStack  uint64 `json:"free_call_stack,omitempty"`
	UseCallStack   uint64 `json:"use_call_stack,omitempty"`
}

type entryInfo struct {
	Key       string
	Seq       uint64
	Entry     *storedUAFCorpusEntry
	Timestamp time.Time
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "syz-uaf-corpus - UAF corpus database inspector\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  syz-uaf-corpus -workdir=/path/to/workdir\n")
		fmt.Fprintf(os.Stderr, "  syz-uaf-corpus -config=config.cfg\n")
		fmt.Fprintf(os.Stderr, "  syz-uaf-corpus -db=/path/to/uaf-corpus.db\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  # Show all entries\n")
		fmt.Fprintf(os.Stderr, "  syz-uaf-corpus -config=wifi.cfg\n\n")
		fmt.Fprintf(os.Stderr, "  # Show summary only\n")
		fmt.Fprintf(os.Stderr, "  syz-uaf-corpus -config=wifi.cfg -summary\n\n")
		fmt.Fprintf(os.Stderr, "  # Show distinct VarName pairs\n")
		fmt.Fprintf(os.Stderr, "  syz-uaf-corpus -config=wifi.cfg -varnames\n\n")
		fmt.Fprintf(os.Stderr, "  # Show distinct VarName pairs with unique callstack counts\n")
		fmt.Fprintf(os.Stderr, "  syz-uaf-corpus -config=wifi.cfg -varnames-stacks\n\n")
		fmt.Fprintf(os.Stderr, "  # Show specific entry by key\n")
		fmt.Fprintf(os.Stderr, "  syz-uaf-corpus -config=wifi.cfg -key=abc123\n\n")
		fmt.Fprintf(os.Stderr, "  # Export to JSON\n")
		fmt.Fprintf(os.Stderr, "  syz-uaf-corpus -config=wifi.cfg -json > corpus.json\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	dbPath := *flagDBPath
	var target *prog.Target

	if *flagConfig != "" {
		cfg, err := mgrconfig.LoadFile(*flagConfig)
		if err != nil {
			tool.Failf("failed to load config: %v", err)
		}
		if dbPath == "" {
			dbPath = filepath.Join(cfg.Workdir, "uaf-corpus.db")
		}
		target = cfg.Target
	} else if *flagWorkdir != "" {
		if dbPath == "" {
			dbPath = filepath.Join(*flagWorkdir, "uaf-corpus.db")
		}
	}

	if dbPath == "" {
		tool.Failf("must specify -workdir, -config, or -db")
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		tool.Failf("database file not found: %s", dbPath)
	}

	corpusDB, err := db.Open(dbPath, false)
	if err != nil {
		tool.Failf("failed to open database: %v", err)
	}

	var entries []entryInfo
	totalRecords := len(corpusDB.Records)
	processed := 0
	lastProgress := 0
	fmt.Fprintf(os.Stderr, "Loading %d entries from database...\n", totalRecords)
	for key, rec := range corpusDB.Records {
		processed++
		// Show progress every 10%
		progress := processed * 100 / totalRecords
		if progress >= lastProgress+10 {
			fmt.Fprintf(os.Stderr, "  Loading: %d%% (%d/%d)\n", progress, processed, totalRecords)
			lastProgress = progress
		}

		if *flagKey != "" && key != *flagKey && !strings.Contains(key, *flagKey) {
			continue
		}

		var stored storedUAFCorpusEntry
		if err := json.Unmarshal(rec.Val, &stored); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to parse entry %s: %v\n", key, err)
			continue
		}

		entries = append(entries, entryInfo{
			Key:       key,
			Seq:       rec.Seq,
			Entry:     &stored,
			Timestamp: stored.Timestamp,
		})
	}
	fmt.Fprintf(os.Stderr, "Loaded %d entries.\n", len(entries))

	// Filter by source if requested
	if *flagSource != "" {
		var sourceFilter int
		switch strings.ToLower(*flagSource) {
		case "fuzz", "0":
			sourceFilter = 0
		case "timing", "1":
			sourceFilter = 1
		default:
			tool.Failf("invalid -source value %q, use 'fuzz' or 'timing'", *flagSource)
		}
		var filtered []entryInfo
		for _, e := range entries {
			if e.Entry.Source == sourceFilter {
				filtered = append(filtered, e)
			}
		}
		fmt.Fprintf(os.Stderr, "Filtered to %d entries (source=%s).\n", len(filtered), *flagSource)
		entries = filtered
	}

	if *flagSortTime {
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Timestamp.After(entries[j].Timestamp)
		})
	} else {
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Seq < entries[j].Seq
		})
	}

	if *flagLimit > 0 && len(entries) > *flagLimit {
		entries = entries[:*flagLimit]
	}

	if *flagJSON {
		outputJSON(entries, target)
		return
	}

	if *flagVarNamesStacks {
		printVarNamesWithStacks(entries, dbPath)
		return
	}

	if *flagVarNames {
		printVarNames(entries, dbPath)
		return
	}

	if *flagSummary {
		printSummary(entries, dbPath)
		return
	}

	printEntries(entries, target)
}

func printVarNames(entries []entryInfo, dbPath string) {
	// VarNamePair represents a unique FreeAccessName-UseAccessName combination
	type VarNamePair struct {
		FreeAccessName uint64
		UseAccessName  uint64
	}

	// Count occurrences of each VarName pair
	pairCounts := make(map[VarNamePair]int)
	for _, e := range entries {
		stored := e.Entry

		// Count the main pair
		if stored.Pair.FreeAccessName != 0 || stored.Pair.UseAccessName != 0 {
			key := VarNamePair{
				FreeAccessName: stored.Pair.FreeAccessName,
				UseAccessName:  stored.Pair.UseAccessName,
			}
			pairCounts[key]++
		}

		// Count pairs from the Pairs slice
		for _, p := range stored.Pairs {
			if p.FreeAccessName != 0 || p.UseAccessName != 0 {
				key := VarNamePair{
					FreeAccessName: p.FreeAccessName,
					UseAccessName:  p.UseAccessName,
				}
				pairCounts[key]++
			}
		}
	}

	// Convert to slice for sorting
	type pairWithCount struct {
		Pair  VarNamePair
		Count int
	}
	var sortedPairs []pairWithCount
	for pair, count := range pairCounts {
		sortedPairs = append(sortedPairs, pairWithCount{Pair: pair, Count: count})
	}

	// Sort by count (descending)
	sort.Slice(sortedPairs, func(i, j int) bool {
		return sortedPairs[i].Count > sortedPairs[j].Count
	})

	fmt.Printf("UAF Corpus Database: %s\n", dbPath)
	fmt.Printf("================================================================================\n\n")
	fmt.Printf("Distinct VarName Pairs: %d\n\n", len(pairCounts))

	fmt.Printf("%-18s  %-18s  %s\n", "FreeAccessName", "UseAccessName", "Count")
	fmt.Printf("%-18s  %-18s  %s\n", strings.Repeat("-", 18), strings.Repeat("-", 18), "-----")

	for _, pc := range sortedPairs {
		fmt.Printf("%016x  %016x  %d\n",
			pc.Pair.FreeAccessName,
			pc.Pair.UseAccessName,
			pc.Count)
	}

	fmt.Printf("\nTotal entries: %d\n", len(entries))
}

func printVarNamesWithStacks(entries []entryInfo, dbPath string) {
	// VarNamePair represents a unique FreeAccessName-UseAccessName combination
	type VarNamePair struct {
		FreeAccessName uint64
		UseAccessName  uint64
	}

	// Map: VarNamePair -> set of unique FreeCallStacks
	varNameFreeStacks := make(map[VarNamePair]map[uint64]struct{})
	// Map: VarNamePair -> set of unique UseCallStacks
	varNameUseStacks := make(map[VarNamePair]map[uint64]struct{})
	// Also count total entries for each VarNamePair
	varNameEntries := make(map[VarNamePair]int)

	addPair := func(p ddrd.MayUAFPair) {
		if p.FreeAccessName == 0 && p.UseAccessName == 0 {
			return
		}
		vnKey := VarNamePair{
			FreeAccessName: p.FreeAccessName,
			UseAccessName:  p.UseAccessName,
		}

		if varNameFreeStacks[vnKey] == nil {
			varNameFreeStacks[vnKey] = make(map[uint64]struct{})
		}
		if varNameUseStacks[vnKey] == nil {
			varNameUseStacks[vnKey] = make(map[uint64]struct{})
		}
		varNameFreeStacks[vnKey][p.FreeCallStack] = struct{}{}
		varNameUseStacks[vnKey][p.UseCallStack] = struct{}{}
		varNameEntries[vnKey]++
	}

	totalEntries := len(entries)
	lastProgress := 0
	fmt.Fprintf(os.Stderr, "Processing %d entries for stack analysis...\n", totalEntries)
	for i, e := range entries {
		// Show progress every 10%
		progress := (i + 1) * 100 / totalEntries
		if progress >= lastProgress+10 {
			fmt.Fprintf(os.Stderr, "  Processing: %d%% (%d/%d)\n", progress, i+1, totalEntries)
			lastProgress = progress
		}

		stored := e.Entry

		// Process the main pair
		addPair(stored.Pair)

		// Process pairs from the Pairs slice
		for _, p := range stored.Pairs {
			addPair(p)
		}
	}
	fmt.Fprintf(os.Stderr, "Processing complete. Sorting results...\n")

	// Convert to slice for sorting
	type pairWithStats struct {
		Pair           VarNamePair
		FreeStackCount int // Number of unique FreeCallStack
		UseStackCount  int // Number of unique UseCallStack
		EntryCount     int // Total number of entries
	}
	var sortedPairs []pairWithStats
	for pair := range varNameFreeStacks {
		sortedPairs = append(sortedPairs, pairWithStats{
			Pair:           pair,
			FreeStackCount: len(varNameFreeStacks[pair]),
			UseStackCount:  len(varNameUseStacks[pair]),
			EntryCount:     varNameEntries[pair],
		})
	}

	// Sort by total stack count (FreeStackCount + UseStackCount) descending
	sort.Slice(sortedPairs, func(i, j int) bool {
		totalI := sortedPairs[i].FreeStackCount + sortedPairs[i].UseStackCount
		totalJ := sortedPairs[j].FreeStackCount + sortedPairs[j].UseStackCount
		if totalI != totalJ {
			return totalI > totalJ
		}
		// Secondary sort by entry count
		return sortedPairs[i].EntryCount > sortedPairs[j].EntryCount
	})

	fmt.Printf("UAF Corpus Database: %s\n", dbPath)
	fmt.Printf("================================================================================\n\n")
	fmt.Printf("Distinct VarName Pairs: %d\n\n", len(varNameFreeStacks))

	fmt.Printf("%-18s  %-18s  %-12s  %-12s  %s\n", "FreeAccessName", "UseAccessName", "FreeStacks", "UseStacks", "Entries")
	fmt.Printf("%-18s  %-18s  %-12s  %-12s  %s\n", strings.Repeat("-", 18), strings.Repeat("-", 18), strings.Repeat("-", 12), strings.Repeat("-", 12), "-------")

	totalFreeStacks := 0
	totalUseStacks := 0
	for _, pc := range sortedPairs {
		fmt.Printf("%016x  %016x  %-12d  %-12d  %d\n",
			pc.Pair.FreeAccessName,
			pc.Pair.UseAccessName,
			pc.FreeStackCount,
			pc.UseStackCount,
			pc.EntryCount)
		totalFreeStacks += pc.FreeStackCount
		totalUseStacks += pc.UseStackCount
	}

	fmt.Printf("\nTotal entries: %d\n", len(entries))
	fmt.Printf("Total unique FreeCallStacks: %d\n", totalFreeStacks)
	fmt.Printf("Total unique UseCallStacks: %d\n", totalUseStacks)
}

func printSummary(entries []entryInfo, dbPath string) {
	fmt.Printf("UAF Corpus Database: %s\n", dbPath)
	fmt.Printf("================================================================================\n\n")
	fmt.Printf("Total entries: %d\n\n", len(entries))

	if len(entries) == 0 {
		return
	}

	var (
		totalPairs     int
		totalPrograms  int
		withBarrier    int
		withReplayPlan int
		barrierSizes   = make(map[int]int)
		accessTypes    = make(map[uint32]int)
		sourceCounts   = make(map[int]int) // 0=fuzz, 1=timing
	)

	var earliest, latest time.Time
	for _, e := range entries {
		stored := e.Entry
		totalPairs += len(stored.Pairs)
		if stored.Pair.FreeAccessName != 0 || stored.Pair.UseAccessName != 0 {
			totalPairs++
		}
		totalPrograms += len(stored.Programs)
		if stored.Program != nil {
			totalPrograms++
		}
		if stored.Barrier.Participants != 0 || stored.Barrier.GroupSize > 0 {
			withBarrier++
			barrierSizes[stored.Barrier.GroupSize]++
		}
		if stored.ReplayPlan != nil && len(stored.ReplayPlan.DelaysMicros) > 0 {
			withReplayPlan++
		}
		accessTypes[stored.Pair.UseAccessType]++
		sourceCounts[stored.Source]++

		if earliest.IsZero() || stored.Timestamp.Before(earliest) {
			earliest = stored.Timestamp
		}
		if latest.IsZero() || stored.Timestamp.After(latest) {
			latest = stored.Timestamp
		}
	}

	fmt.Printf("Time range:\n")
	fmt.Printf("  Earliest: %s\n", earliest.Format(time.RFC3339))
	fmt.Printf("  Latest:   %s\n", latest.Format(time.RFC3339))
	fmt.Printf("  Duration: %s\n\n", latest.Sub(earliest).Round(time.Second))

	fmt.Printf("Statistics:\n")
	fmt.Printf("  Total UAF pairs: %d\n", totalPairs)
	fmt.Printf("  Total programs:  %d\n", totalPrograms)
	fmt.Printf("  With barrier:    %d (%.1f%%)\n", withBarrier, float64(withBarrier)*100/float64(len(entries)))
	fmt.Printf("  With replay:     %d (%.1f%%)\n", withReplayPlan, float64(withReplayPlan)*100/float64(len(entries)))

	fmt.Printf("\nSource breakdown:\n")
	fmt.Printf("  Fuzz:   %d (%.1f%%)\n", sourceCounts[0], float64(sourceCounts[0])*100/float64(len(entries)))
	fmt.Printf("  Timing: %d (%.1f%%)\n", sourceCounts[1], float64(sourceCounts[1])*100/float64(len(entries)))

	fmt.Printf("\nBarrier group sizes:\n")
	for size, count := range barrierSizes {
		fmt.Printf("  Size %d: %d entries\n", size, count)
	}

	fmt.Printf("\nUse access types:\n")
	for typ, count := range accessTypes {
		typeName := "unknown"
		switch typ {
		case 0:
			typeName = "read"
		case 1:
			typeName = "write"
		}
		fmt.Printf("  %s: %d\n", typeName, count)
	}
}

func sourceName(source int) string {
	switch source {
	case 0:
		return "fuzz"
	case 1:
		return "timing"
	default:
		return fmt.Sprintf("unknown(%d)", source)
	}
}

func printEntries(entries []entryInfo, target *prog.Target) {
	fmt.Printf("UAF Corpus Entries (%d total)\n", len(entries))
	fmt.Printf("================================================================================\n\n")

	for i, e := range entries {
		stored := e.Entry
		fmt.Printf("Entry %d/%d\n", i+1, len(entries))
		fmt.Printf("--------------------------------------------------------------------------------\n")
		fmt.Printf("Key:       %s\n", e.Key)
		fmt.Printf("Seq:       %d\n", e.Seq)
		fmt.Printf("Timestamp: %s\n", stored.Timestamp.Format(time.RFC3339))
		fmt.Printf("Source:    %s\n", sourceName(stored.Source))
		fmt.Printf("CallIdx:   %d\n", stored.CallIdx)

		if stored.Barrier.Participants != 0 || stored.Barrier.GroupSize > 0 {
			fmt.Printf("\nBarrier:\n")
			fmt.Printf("  Participants: 0x%x\n", stored.Barrier.Participants)
			fmt.Printf("  GroupID:      %d\n", stored.Barrier.GroupID)
			fmt.Printf("  GroupSize:    %d\n", stored.Barrier.GroupSize)
			if len(stored.Barrier.ProcList) > 0 {
				fmt.Printf("  ProcList:     %v\n", stored.Barrier.ProcList)
			}
		}

		if stored.ReplayPlan != nil && len(stored.ReplayPlan.DelaysMicros) > 0 {
			fmt.Printf("\nReplay Plan:\n")
			fmt.Printf("  Delays (us): %v\n", stored.ReplayPlan.DelaysMicros)
		}

		if stored.Profile != nil && (stored.Profile.FreeAccessName != 0 || stored.Profile.UseAccessName != 0) {
			fmt.Printf("\nProfile:\n")
			fmt.Printf("  FreeAccessName: 0x%016x\n", stored.Profile.FreeAccessName)
			fmt.Printf("  UseAccessName:  0x%016x\n", stored.Profile.UseAccessName)
			fmt.Printf("  FreeCallStack:  0x%016x\n", stored.Profile.FreeCallStack)
			fmt.Printf("  UseCallStack:   0x%016x\n", stored.Profile.UseCallStack)
		}

		if *flagPairs && (stored.Pair.FreeAccessName != 0 || stored.Pair.UseAccessName != 0) {
			fmt.Printf("\nMain UAF Pair:\n")
			printPair(&stored.Pair, "  ")
		}

		if *flagPairs && len(stored.Pairs) > 0 {
			fmt.Printf("\nAdditional UAF Pairs (%d):\n", len(stored.Pairs))
			for j, pair := range stored.Pairs {
				fmt.Printf("  [%d]:\n", j)
				printPair(&pair, "    ")
			}
		}

		if len(stored.Signals) > 0 {
			fmt.Printf("\nSignals (%d):\n", len(stored.Signals))
			for j, sig := range stored.Signals {
				if j >= 5 {
					fmt.Printf("  ... and %d more\n", len(stored.Signals)-5)
					break
				}
				fmt.Printf("  0x%016x\n", sig)
			}
		}

		if *flagPrograms {
			if stored.Program != nil {
				fmt.Printf("\nMain Program:\n")
				printProgram(stored.Program, target, "  ")
			}
			if len(stored.Programs) > 0 {
				fmt.Printf("\nPrograms (%d):\n", len(stored.Programs))
				for j, p := range stored.Programs {
					fmt.Printf("  [%d]:\n", j)
					printProgram(p, target, "    ")
				}
			}
		}

		fmt.Printf("\n")
	}
}

func printPair(pair *ddrd.MayUAFPair, indent string) {
	accessType := "read"
	if pair.UseAccessType == 1 {
		accessType = "write"
	}
	lockType := "none"
	switch pair.LockType {
	case 1:
		lockType = "mutex"
	case 2:
		lockType = "rwlock"
	case 3:
		lockType = "spinlock"
	}

	fmt.Printf("%sFreeAccessName: 0x%016x\n", indent, pair.FreeAccessName)
	fmt.Printf("%sUseAccessName:  0x%016x\n", indent, pair.UseAccessName)
	fmt.Printf("%sFreeCallStack:  0x%016x\n", indent, pair.FreeCallStack)
	fmt.Printf("%sUseCallStack:   0x%016x\n", indent, pair.UseCallStack)
	fmt.Printf("%sSignal:         0x%016x\n", indent, pair.Signal)
	fmt.Printf("%sTimeDiff:       %d ns (%.3f ms)\n", indent, pair.TimeDiff, float64(pair.TimeDiff)/1e6)
	fmt.Printf("%sFreeSN:         %d\n", indent, pair.FreeSN)
	fmt.Printf("%sUseSN:          %d\n", indent, pair.UseSN)
	fmt.Printf("%sUseAccessType:  %s (%d)\n", indent, accessType, pair.UseAccessType)
	fmt.Printf("%sLockType:       %s (%d)\n", indent, lockType, pair.LockType)
}

func printProgram(data []byte, target *prog.Target, indent string) {
	if target != nil {
		p, err := target.Deserialize(data, prog.NonStrict)
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(p.Serialize())), "\n")
			for _, line := range lines {
				fmt.Printf("%s%s\n", indent, line)
			}
			return
		}
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		fmt.Printf("%s%s\n", indent, line)
	}
}

func outputJSON(entries []entryInfo, target *prog.Target) {
	type jsonEntry struct {
		Key        string                 `json:"key"`
		Seq        uint64                 `json:"seq"`
		Timestamp  string                 `json:"timestamp"`
		Source     string                 `json:"source"`
		CallIdx    int                    `json:"call_idx"`
		Pair       *ddrd.MayUAFPair       `json:"pair,omitempty"`
		Pairs      []ddrd.MayUAFPair      `json:"pairs,omitempty"`
		Barrier    fuzzer.BarrierSnapshot `json:"barrier,omitempty"`
		ReplayPlan *storedReplayPlan      `json:"replay_plan,omitempty"`
		Profile    *storedPairProfile     `json:"profile,omitempty"`
		Signals    []string               `json:"signals,omitempty"`
		Programs   []string               `json:"programs,omitempty"`
	}

	var output []jsonEntry
	for _, e := range entries {
		stored := e.Entry
		je := jsonEntry{
			Key:        e.Key,
			Seq:        e.Seq,
			Timestamp:  stored.Timestamp.Format(time.RFC3339),
			Source:     sourceName(stored.Source),
			CallIdx:    stored.CallIdx,
			Barrier:    stored.Barrier,
			ReplayPlan: stored.ReplayPlan,
			Profile:    stored.Profile,
		}

		if stored.Pair.FreeAccessName != 0 || stored.Pair.UseAccessName != 0 {
			je.Pair = &stored.Pair
		}
		if len(stored.Pairs) > 0 {
			je.Pairs = stored.Pairs
		}

		for _, sig := range stored.Signals {
			je.Signals = append(je.Signals, fmt.Sprintf("0x%016x", sig))
		}

		if stored.Program != nil {
			if target != nil {
				if p, err := target.Deserialize(stored.Program, prog.NonStrict); err == nil {
					je.Programs = append(je.Programs, string(p.Serialize()))
				} else {
					je.Programs = append(je.Programs, string(stored.Program))
				}
			} else {
				je.Programs = append(je.Programs, string(stored.Program))
			}
		}
		for _, progData := range stored.Programs {
			if target != nil {
				if p, err := target.Deserialize(progData, prog.NonStrict); err == nil {
					je.Programs = append(je.Programs, string(p.Serialize()))
				} else {
					je.Programs = append(je.Programs, string(progData))
				}
			} else {
				je.Programs = append(je.Programs, string(progData))
			}
		}

		output = append(output, je)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		tool.Failf("failed to encode JSON: %v", err)
	}
}
