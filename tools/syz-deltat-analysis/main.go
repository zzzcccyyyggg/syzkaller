// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-deltat-analysis performs post-hoc Δt-bucketed analysis of validation outcomes.
// It reads uaf-corpus.db, validated_uaf.db, invalid_uaf.db and varname_backoff_stats.db,
// cross-references each unique pair's initial Δt with its validation outcome, and computes
// per-bucket statistics (hit rate, median attempts, CPU time per confirmation).
//
// Usage:
//
//	syz-deltat-analysis -workdir /path/to/workdir [-csv output.csv] [-json output.json]
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
)

var (
	flagWorkdir = flag.String("workdir", "", "path to validation workdir containing DBs")
	flagCorpus  = flag.String("corpus", "", "explicit path to uaf-corpus.db (overrides workdir)")
	flagValid   = flag.String("valid", "", "explicit path to validated_uaf.db (overrides workdir)")
	flagInvalid = flag.String("invalid", "", "explicit path to invalid_uaf.db (overrides workdir)")
	flagBackoff = flag.String("backoff", "", "explicit path to varname_backoff_stats.db (overrides workdir)")
	flagCSV     = flag.String("csv", "", "write per-bucket CSV to this path")
	flagJSON    = flag.String("json", "", "write full JSON report to this path")
	flagPairCSV = flag.String("pair-csv", "", "write per-pair CSV (for scatter plots)")
	flagQuiet   = flag.Bool("q", false, "quiet mode: only output structured data")
)

// Log-scale Δt buckets (nanoseconds)
type bucket struct {
	Label string
	MinNs uint64 // inclusive
	MaxNs uint64 // exclusive (0 means no upper bound)
}

var buckets = []bucket{
	{"[0, 10μs)", 0, 10_000},
	{"[10μs, 100μs)", 10_000, 100_000},
	{"[100μs, 1ms)", 100_000, 1_000_000},
	{"[1ms, 10ms)", 1_000_000, 10_000_000},
	{"[10ms, 100ms)", 10_000_000, 100_000_000},
	{"[100ms, 500ms]", 100_000_000, 500_000_001},
}

// storedUAFCorpusEntry mirrors the JSON structure in uaf-corpus.db
// We only need the pair metadata, not the programs.
type storedUAFCorpusEntry struct {
	Pair  ddrd.MayUAFPair   `json:"pair"`
	Pairs []ddrd.MayUAFPair `json:"pairs,omitempty"`
}

// varNameBackoffStats mirrors the JSON in varname_backoff_stats.db
type varNameBackoffStats struct {
	FreeAccessName uint64    `json:"free_access_name"`
	UseAccessName  uint64    `json:"use_access_name"`
	Failures       int       `json:"failures"`
	Successes      int       `json:"successes"`
	TotalAttempts  int       `json:"total_attempts"`
	LastAttempt    time.Time `json:"last_attempt"`
	LastSuccess    time.Time `json:"last_success,omitempty"`
	Created        time.Time `json:"created"`
	Verified       bool      `json:"verified"`
	VerifiedKey    string    `json:"verified_key,omitempty"`
}

type pairOutcome struct {
	PairKey        string
	VarNameKey     string
	TimeDiffNs     uint64
	Validated      bool
	Invalid        bool
	TotalAttempts  int
	Successes      int
	Failures       int
	FreeAccessName uint64
	UseAccessName  uint64
	FreeCallStack  uint64
	UseCallStack   uint64
}

type bucketStats struct {
	Label              string  `json:"label"`
	Total              int     `json:"total"`
	Validated          int     `json:"validated"`
	Invalid            int     `json:"invalid"`
	Pending            int     `json:"pending"`
	HitRate            float64 `json:"hit_rate"`
	HitRateOfResolved  float64 `json:"hit_rate_resolved"`
	MedianAttempts     float64 `json:"median_attempts_confirmed"`
	MeanAttempts       float64 `json:"mean_attempts_confirmed"`
	TotalAttemptsAll   int     `json:"total_attempts_all"`
	AvgAttemptsAll     float64 `json:"avg_attempts_all"`
	MedianTimeDiffUs   float64 `json:"median_timediff_us"`
	MeanTimeDiffUs     float64 `json:"mean_timediff_us"`
}

type analysisReport struct {
	Timestamp   string         `json:"timestamp"`
	WorkDir     string         `json:"workdir"`
	CorpusPath  string         `json:"corpus_path"`
	TotalPairs  int            `json:"total_pairs"`
	UniquePairs int            `json:"unique_pairs"`
	Validated   int            `json:"validated"`
	Invalid     int            `json:"invalid"`
	Pending     int            `json:"pending"`
	Buckets     []*bucketStats `json:"buckets"`
}

func main() {
	flag.Parse()

	corpusPath := resolvePath(*flagCorpus, *flagWorkdir, "uaf-corpus.db")
	validPath := resolvePath(*flagValid, *flagWorkdir, "validated_uaf.db")
	invalidPath := resolvePath(*flagInvalid, *flagWorkdir, "invalid_uaf.db")
	backoffPath := resolvePath(*flagBackoff, *flagWorkdir, "varname_backoff_stats.db")

	if corpusPath == "" {
		log.Fatal("must provide -workdir or -corpus")
	}

	// 1. Load corpus and extract all unique pairs with TimeDiff
	pairs := loadCorpusPairs(corpusPath)

	// 2. Load validation outcomes
	validSet := loadKeySet(validPath)
	invalidSet := loadKeySet(invalidPath)

	// 3. Load backoff stats (for attempt counts)
	backoffMap := loadBackoffStats(backoffPath)

	// 4. Build per-pair outcomes
	outcomes := buildOutcomes(pairs, validSet, invalidSet, backoffMap)

	// 5. Bucket and analyze
	report := analyze(outcomes, *flagWorkdir, corpusPath)

	// 6. Output
	printReport(report)
	if *flagCSV != "" {
		writeCSV(report, *flagCSV)
	}
	if *flagJSON != "" {
		writeJSON(report, *flagJSON)
	}
	if *flagPairCSV != "" {
		writePairCSV(outcomes, *flagPairCSV)
	}
}

func resolvePath(explicit, workdir, filename string) string {
	if explicit != "" {
		return explicit
	}
	if workdir != "" {
		return filepath.Join(workdir, filename)
	}
	return ""
}

// pairKey computes the validation-layer key for cross-referencing with validated/invalid DBs.
// Must match pkg/racevalidate/manager.go pairKey().
func pairKey(pair *ddrd.MayUAFPair) string {
	return fmt.Sprintf("%016x-%016x-%016x-%016x",
		pair.FreeAccessName,
		pair.UseAccessName,
		pair.FreeCallStack,
		pair.UseCallStack,
	)
}

// varNamePairKey matches pkg/racevalidate/varname_backoff.go VarNamePairKey().
func varNamePairKey(pair *ddrd.MayUAFPair) string {
	return fmt.Sprintf("%016x-%016x", pair.FreeAccessName, pair.UseAccessName)
}

func loadCorpusPairs(path string) map[string]*ddrd.MayUAFPair {
	database, err := db.Open(path, true)
	if err != nil {
		log.Fatalf("failed to open corpus db %q: %v", path, err)
	}

	result := make(map[string]*ddrd.MayUAFPair)
	totalPairs := 0
	for _, rec := range database.Records {
		var stored storedUAFCorpusEntry
		if err := json.Unmarshal(rec.Val, &stored); err != nil {
			continue
		}
		pairs := stored.Pairs
		if len(pairs) == 0 && !isZeroPair(&stored.Pair) {
			pairs = []ddrd.MayUAFPair{stored.Pair}
		}
		for i := range pairs {
			totalPairs++
			p := &pairs[i]
			key := pairKey(p)
			if _, exists := result[key]; !exists {
				pCopy := *p
				result[key] = &pCopy
			}
		}
	}
	if !*flagQuiet {
		fmt.Printf("Corpus: %d entries, %d total pairs, %d unique pairs\n",
			len(database.Records), totalPairs, len(result))
	}
	return result
}

func isZeroPair(p *ddrd.MayUAFPair) bool {
	return p.FreeAccessName == 0 && p.UseAccessName == 0 &&
		p.FreeCallStack == 0 && p.UseCallStack == 0
}

func loadKeySet(path string) map[string]bool {
	if path == "" {
		return nil
	}
	database, err := db.Open(path, true)
	if err != nil {
		if !*flagQuiet {
			fmt.Printf("Warning: cannot open %s: %v\n", path, err)
		}
		return nil
	}
	result := make(map[string]bool, len(database.Records))
	for key := range database.Records {
		result[key] = true
	}
	if !*flagQuiet {
		fmt.Printf("Loaded %d records from %s\n", len(result), filepath.Base(path))
	}
	return result
}

func loadBackoffStats(path string) map[string]*varNameBackoffStats {
	if path == "" {
		return nil
	}
	database, err := db.Open(path, true)
	if err != nil {
		if !*flagQuiet {
			fmt.Printf("Warning: cannot open %s: %v\n", path, err)
		}
		return nil
	}
	result := make(map[string]*varNameBackoffStats, len(database.Records))
	for key, rec := range database.Records {
		var stats varNameBackoffStats
		if err := json.Unmarshal(rec.Val, &stats); err != nil {
			continue
		}
		result[key] = &stats
	}
	if !*flagQuiet {
		fmt.Printf("Loaded %d VarName backoff stats from %s\n", len(result), filepath.Base(path))
	}
	return result
}

func buildOutcomes(pairs map[string]*ddrd.MayUAFPair, validSet, invalidSet map[string]bool, backoffMap map[string]*varNameBackoffStats) []*pairOutcome {
	outcomes := make([]*pairOutcome, 0, len(pairs))
	for key, pair := range pairs {
		vnKey := varNamePairKey(pair)
		o := &pairOutcome{
			PairKey:        key,
			VarNameKey:     vnKey,
			TimeDiffNs:     pair.TimeDiff,
			Validated:      validSet[key],
			Invalid:        invalidSet[key],
			FreeAccessName: pair.FreeAccessName,
			UseAccessName:  pair.UseAccessName,
			FreeCallStack:  pair.FreeCallStack,
			UseCallStack:   pair.UseCallStack,
		}
		if stats, ok := backoffMap[vnKey]; ok {
			o.TotalAttempts = stats.TotalAttempts
			o.Successes = stats.Successes
			o.Failures = stats.Failures
		}
		outcomes = append(outcomes, o)
	}
	sort.Slice(outcomes, func(i, j int) bool {
		return outcomes[i].TimeDiffNs < outcomes[j].TimeDiffNs
	})
	return outcomes
}

func assignBucket(timeDiffNs uint64) int {
	for i, b := range buckets {
		if timeDiffNs >= b.MinNs && timeDiffNs < b.MaxNs {
			return i
		}
	}
	return -1 // out of range
}

func analyze(outcomes []*pairOutcome, workdir, corpusPath string) *analysisReport {
	bstats := make([]*bucketStats, len(buckets))
	bOutcomes := make([][]*pairOutcome, len(buckets))
	for i := range buckets {
		bstats[i] = &bucketStats{Label: buckets[i].Label}
		bOutcomes[i] = nil
	}

	totalValidated, totalInvalid, totalPending := 0, 0, 0
	outOfRange := 0

	for _, o := range outcomes {
		idx := assignBucket(o.TimeDiffNs)
		if idx < 0 {
			outOfRange++
			continue
		}
		bstats[idx].Total++
		bOutcomes[idx] = append(bOutcomes[idx], o)
		if o.Validated {
			bstats[idx].Validated++
			totalValidated++
		} else if o.Invalid {
			bstats[idx].Invalid++
			totalInvalid++
		} else {
			bstats[idx].Pending++
			totalPending++
		}
		bstats[idx].TotalAttemptsAll += o.TotalAttempts
	}

	for i, bs := range bstats {
		if bs.Total > 0 {
			bs.HitRate = float64(bs.Validated) / float64(bs.Total)
		}
		resolved := bs.Validated + bs.Invalid
		if resolved > 0 {
			bs.HitRateOfResolved = float64(bs.Validated) / float64(resolved)
		}
		if bs.Total > 0 {
			bs.AvgAttemptsAll = float64(bs.TotalAttemptsAll) / float64(bs.Total)
		}

		// Compute median attempts for confirmed pairs (using VarName-level TotalAttempts)
		var confirmedAttempts []float64
		var timeDiffsUs []float64
		for _, o := range bOutcomes[i] {
			timeDiffsUs = append(timeDiffsUs, float64(o.TimeDiffNs)/1000.0)
			if o.Validated && o.TotalAttempts > 0 {
				confirmedAttempts = append(confirmedAttempts, float64(o.TotalAttempts))
			}
		}
		if len(confirmedAttempts) > 0 {
			sort.Float64s(confirmedAttempts)
			bs.MedianAttempts = median(confirmedAttempts)
			bs.MeanAttempts = mean(confirmedAttempts)
		}
		if len(timeDiffsUs) > 0 {
			sort.Float64s(timeDiffsUs)
			bs.MedianTimeDiffUs = median(timeDiffsUs)
			bs.MeanTimeDiffUs = mean(timeDiffsUs)
		}
	}

	if !*flagQuiet && outOfRange > 0 {
		fmt.Printf("Note: %d pairs with Δt outside bucket range (>500ms)\n", outOfRange)
	}

	return &analysisReport{
		Timestamp:   time.Now().Format(time.RFC3339),
		WorkDir:     workdir,
		CorpusPath:  corpusPath,
		TotalPairs:  len(outcomes) + outOfRange,
		UniquePairs: len(outcomes),
		Validated:   totalValidated,
		Invalid:     totalInvalid,
		Pending:     totalPending,
		Buckets:     bstats,
	}
}

func median(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[n/2]
}

func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func printReport(report *analysisReport) {
	if *flagQuiet {
		return
	}
	fmt.Println()
	fmt.Println("========== Δt-Bucketed Validation Analysis ==========")
	fmt.Printf("Total unique pairs: %d  (validated=%d  invalid=%d  pending=%d)\n",
		report.UniquePairs, report.Validated, report.Invalid, report.Pending)
	fmt.Println()

	// Header
	fmt.Printf("%-20s %6s %6s %6s %6s %8s %8s %10s %10s\n",
		"Bucket", "Total", "Valid", "Inval", "Pend", "HitRate", "HitR(R)", "MedAttempt", "MedΔt(μs)")
	fmt.Println(strings.Repeat("-", 96))

	for _, bs := range report.Buckets {
		hitRateStr := "-"
		hitRateRStr := "-"
		medAttemptStr := "-"
		if bs.Total > 0 {
			hitRateStr = fmt.Sprintf("%.1f%%", bs.HitRate*100)
		}
		if bs.Validated+bs.Invalid > 0 {
			hitRateRStr = fmt.Sprintf("%.1f%%", bs.HitRateOfResolved*100)
		}
		if bs.MedianAttempts > 0 {
			medAttemptStr = fmt.Sprintf("%.1f", bs.MedianAttempts)
		}
		medDtStr := "-"
		if bs.Total > 0 {
			medDtStr = formatTimeDiffUs(bs.MedianTimeDiffUs)
		}
		fmt.Printf("%-20s %6d %6d %6d %6d %8s %8s %10s %10s\n",
			bs.Label, bs.Total, bs.Validated, bs.Invalid, bs.Pending,
			hitRateStr, hitRateRStr, medAttemptStr, medDtStr)
	}
	fmt.Println(strings.Repeat("=", 96))
}

func formatTimeDiffUs(us float64) string {
	if us < 1 {
		return fmt.Sprintf("%.0fns", us*1000)
	}
	if us < 1000 {
		return fmt.Sprintf("%.1fμs", us)
	}
	if us < 1_000_000 {
		return fmt.Sprintf("%.2fms", us/1000)
	}
	return fmt.Sprintf("%.2fs", us/1_000_000)
}

func writeCSV(report *analysisReport, path string) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("failed to create CSV %q: %v", path, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	w.Write([]string{
		"bucket", "total", "validated", "invalid", "pending",
		"hit_rate", "hit_rate_resolved",
		"median_attempts_confirmed", "mean_attempts_confirmed",
		"total_attempts_all", "avg_attempts_all",
		"median_timediff_us", "mean_timediff_us",
	})

	for _, bs := range report.Buckets {
		w.Write([]string{
			bs.Label,
			fmt.Sprintf("%d", bs.Total),
			fmt.Sprintf("%d", bs.Validated),
			fmt.Sprintf("%d", bs.Invalid),
			fmt.Sprintf("%d", bs.Pending),
			fmt.Sprintf("%.6f", bs.HitRate),
			fmt.Sprintf("%.6f", bs.HitRateOfResolved),
			fmt.Sprintf("%.2f", bs.MedianAttempts),
			fmt.Sprintf("%.2f", bs.MeanAttempts),
			fmt.Sprintf("%d", bs.TotalAttemptsAll),
			fmt.Sprintf("%.2f", bs.AvgAttemptsAll),
			fmt.Sprintf("%.2f", bs.MedianTimeDiffUs),
			fmt.Sprintf("%.2f", bs.MeanTimeDiffUs),
		})
	}

	if !*flagQuiet {
		fmt.Printf("\nCSV written to %s\n", path)
	}
}

func writePairCSV(outcomes []*pairOutcome, path string) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("failed to create pair CSV %q: %v", path, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{
		"pair_key", "varname_key",
		"timediff_ns", "timediff_us", "log10_timediff_us",
		"bucket", "validated", "invalid",
		"total_attempts", "successes", "failures",
		"free_access", "use_access", "free_callstack", "use_callstack",
	})

	for _, o := range outcomes {
		idx := assignBucket(o.TimeDiffNs)
		bucketLabel := "out_of_range"
		if idx >= 0 {
			bucketLabel = buckets[idx].Label
		}
		tdUs := float64(o.TimeDiffNs) / 1000.0
		logTdUs := 0.0
		if tdUs > 0 {
			logTdUs = math.Log10(tdUs)
		}
		w.Write([]string{
			o.PairKey,
			o.VarNameKey,
			fmt.Sprintf("%d", o.TimeDiffNs),
			fmt.Sprintf("%.3f", tdUs),
			fmt.Sprintf("%.4f", logTdUs),
			bucketLabel,
			boolStr(o.Validated),
			boolStr(o.Invalid),
			fmt.Sprintf("%d", o.TotalAttempts),
			fmt.Sprintf("%d", o.Successes),
			fmt.Sprintf("%d", o.Failures),
			fmt.Sprintf("%016x", o.FreeAccessName),
			fmt.Sprintf("%016x", o.UseAccessName),
			fmt.Sprintf("%016x", o.FreeCallStack),
			fmt.Sprintf("%016x", o.UseCallStack),
		})
	}

	if !*flagQuiet {
		fmt.Printf("Per-pair CSV written to %s\n", path)
	}
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func writeJSON(report *analysisReport, path string) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal JSON: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Fatalf("failed to write JSON %q: %v", path, err)
	}
	if !*flagQuiet {
		fmt.Printf("JSON report written to %s\n", path)
	}
}

// Suppress unused import warning for math package.
var _ = math.Log10
