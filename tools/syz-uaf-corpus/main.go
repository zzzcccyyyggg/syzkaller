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
	flagWorkdir  = flag.String("workdir", "", "path to workdir containing uaf-corpus.db")
	flagConfig   = flag.String("config", "", "syzkaller config file to get workdir and target")
	flagDBPath   = flag.String("db", "", "direct path to uaf-corpus.db file")
	flagKey      = flag.String("key", "", "show only entry with this key")
	flagSummary  = flag.Bool("summary", false, "show summary statistics only")
	flagPrograms = flag.Bool("programs", true, "show program source code")
	flagPairs    = flag.Bool("pairs", true, "show UAF pair details")
	flagJSON     = flag.Bool("json", false, "output in JSON format")
	flagLimit    = flag.Int("limit", 0, "limit number of entries to show (0 = all)")
	flagSortTime = flag.Bool("sort-time", false, "sort entries by timestamp (newest first)")
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
	for key, rec := range corpusDB.Records {
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

	if *flagSummary {
		printSummary(entries, dbPath)
		return
	}

	printEntries(entries, target)
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
