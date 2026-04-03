package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
)

var (
	dbPath       = flag.String("db", "validated_uaf.db", "path to validated_uaf.db")
	summary      = flag.Bool("summary", false, "only print record metadata, skip report bodies")
	format       = flag.Bool("format", false, "prettify report output for easier reading")
	manager      = flag.String("manager_cfg", "", "optional syz-manager config for symbolization")
	groupByVar   = flag.Bool("group_by_var", false, "group reports by VarName pairs")
	showHistory  = flag.Bool("show_history", false, "show replay history details")
	historyStats = flag.Bool("history_stats", false, "show only history statistics without full content")
)

type VarNamePair struct {
	VarName1 uint64
	VarName2 uint64
}

func (p VarNamePair) String() string {
	return fmt.Sprintf("%d-%d", p.VarName1, p.VarName2)
}

type RecordInfo struct {
	Key    string
	Record *db.Record
	Index  int
}

func main() {
	flag.Parse()
	if *dbPath == "" {
		log.Fatal("db path must be provided")
	}

	reporter, err := initReporter(*manager)
	if err != nil {
		log.Fatalf("failed to initialize reporter: %v", err)
	}

	database, err := db.Open(*dbPath, true)
	if err != nil {
		log.Fatalf("failed to open db %q: %v", *dbPath, err)
	}

	records := make([]*RecordInfo, 0, len(database.Records))
	idx := 0
	for key, rec := range database.Records {
		idx++
		recCopy := rec
		records = append(records, &RecordInfo{
			Key:    key,
			Record: &recCopy,
			Index:  idx,
		})
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Key < records[j].Key
	})

	fmt.Printf("validated records: %d\n", len(records))

	// Print overall history statistics
	if *historyStats || *showHistory {
		printHistoryStatistics(records)
	}

	if *groupByVar {
		printGroupedByVarName(records, reporter)
	} else {
		printSequential(records, reporter)
	}
}

func printHistoryStatistics(records []*RecordInfo) {
	totalWithHistory := 0
	totalMinimized := 0
	totalHistoryRecords := 0
	totalOriginalRecords := 0
	maxHistory := 0
	maxReduction := 0.0

	for _, info := range records {
		histInfo := extractHistoryInfo(info.Record.Val)
		if histInfo.HistoryCount > 0 {
			totalWithHistory++
			totalHistoryRecords += histInfo.HistoryCount
			if histInfo.HistoryCount > maxHistory {
				maxHistory = histInfo.HistoryCount
			}
		}
		if histInfo.Minimized {
			totalMinimized++
			totalOriginalRecords += histInfo.OriginalCount
			if histInfo.OriginalCount > 0 {
				reduction := 1.0 - float64(histInfo.HistoryCount)/float64(histInfo.OriginalCount)
				if reduction > maxReduction {
					maxReduction = reduction
				}
			}
		}
	}

	fmt.Printf("\n=== REPLAY HISTORY STATISTICS ===\n")
	fmt.Printf("Records with history: %d / %d (%.1f%%)\n",
		totalWithHistory, len(records), float64(totalWithHistory)*100/float64(len(records)))
	if totalWithHistory > 0 {
		fmt.Printf("Total history records: %d (avg %.1f per entry)\n",
			totalHistoryRecords, float64(totalHistoryRecords)/float64(totalWithHistory))
		fmt.Printf("Max history in single entry: %d\n", maxHistory)
	}
	if totalMinimized > 0 {
		fmt.Printf("Minimized entries: %d\n", totalMinimized)
		fmt.Printf("Original total before minimization: %d\n", totalOriginalRecords)
		fmt.Printf("Max reduction ratio: %.1f%%\n", maxReduction*100)
	}
	fmt.Printf("=================================\n\n")
}

func initReporter(path string) (*report.Reporter, error) {
	if path == "" {
		return nil, nil
	}
	cfg, err := mgrconfig.LoadPartialFile(path)
	if err != nil {
		return nil, fmt.Errorf("load manager config: %w", err)
	}
	cfg.CompleteKernelDirs()
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		return nil, fmt.Errorf("create reporter: %w", err)
	}
	return reporter, nil
}

func symbolizeBody(reporter *report.Reporter, body []byte) ([]byte, error) {
	if reporter == nil || len(body) == 0 {
		return body, nil
	}
	reps := report.ParseAll(reporter, body)
	if len(reps) == 0 {
		rep := &report.Report{Report: append([]byte{}, body...), Output: append([]byte{}, body...)}
		if err := reporter.Symbolize(rep); err != nil {
			return nil, err
		}
		return append([]byte{}, rep.Report...), nil
	}
	var buf bytes.Buffer
	for i, rep := range reps {
		if err := reporter.Symbolize(rep); err != nil {
			return nil, err
		}
		if i != 0 {
			buf.WriteString("\n\n")
		}
		buf.Write(rep.Report)
	}
	return buf.Bytes(), nil
}

func formatReport(raw []byte) []byte {
	return raw
}

func extractVarNames(body []byte) *VarNamePair {
	re := regexp.MustCompile(`VarName\s+(\d+)`)
	matches := re.FindAllSubmatch(body, -1)
	if len(matches) < 2 {
		return nil
	}
	var1, err1 := strconv.ParseUint(string(matches[0][1]), 10, 64)
	var2, err2 := strconv.ParseUint(string(matches[1][1]), 10, 64)
	if err1 != nil || err2 != nil {
		return nil
	}
	// 规范化顺序，小的在前
	if var1 > var2 {
		var1, var2 = var2, var1
	}
	return &VarNamePair{VarName1: var1, VarName2: var2}
}

// HistoryInfo contains parsed replay history information
type HistoryInfo struct {
	HistoryCount  int
	OriginalCount int
	Minimized     bool
}

// extractHistoryInfo parses the REPLAY HISTORY section from the record
func extractHistoryInfo(body []byte) *HistoryInfo {
	info := &HistoryInfo{}

	// Find HistoryCount
	reCount := regexp.MustCompile(`HistoryCount:\s*(\d+)`)
	if match := reCount.FindSubmatch(body); match != nil {
		if count, err := strconv.Atoi(string(match[1])); err == nil {
			info.HistoryCount = count
		}
	}

	// Find OriginalCount (only present if minimized)
	reOriginal := regexp.MustCompile(`OriginalCount:\s*(\d+)`)
	if match := reOriginal.FindSubmatch(body); match != nil {
		if count, err := strconv.Atoi(string(match[1])); err == nil {
			info.OriginalCount = count
		}
	}

	// Check if minimized
	reMinimized := regexp.MustCompile(`Minimized:\s*true`)
	info.Minimized = reMinimized.Match(body)

	return info
}

func printSequential(records []*RecordInfo, reporter *report.Reporter) {
	for _, info := range records {
		printRecord(info, reporter)
	}
}

func printGroupedByVarName(records []*RecordInfo, reporter *report.Reporter) {
	grouped := make(map[string][]*RecordInfo)
	noVarName := []*RecordInfo{}

	for _, info := range records {
		pair := extractVarNames(info.Record.Val)
		if pair == nil {
			noVarName = append(noVarName, info)
			continue
		}
		key := pair.String()
		grouped[key] = append(grouped[key], info)
	}

	// 按 VarNamePair 排序
	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	fmt.Printf("\n========================================\n")
	fmt.Printf("Found %d unique VarName pairs\n", len(keys))
	fmt.Printf("========================================\n\n")

	for _, key := range keys {
		group := grouped[key]
		fmt.Printf("\n========== VarName Pair: %s ==========\n", key)
		fmt.Printf("Total reports: %d\n", len(group))
		fmt.Println("========================================")
		for _, info := range group {
			printRecord(info, reporter)
		}
	}

	if len(noVarName) > 0 {
		fmt.Printf("\n========== Records without VarName pair ==========\n")
		fmt.Printf("Total reports: %d\n", len(noVarName))
		fmt.Println("==================================================")
		for _, info := range noVarName {
			printRecord(info, reporter)
		}
	}
}

func printRecord(info *RecordInfo, reporter *report.Reporter) {
	body := info.Record.Val

	// Extract history info for display
	histInfo := extractHistoryInfo(body)
	historyDesc := ""
	if histInfo.HistoryCount > 0 {
		if histInfo.Minimized {
			historyDesc = fmt.Sprintf(" history=%d (minimized from %d)", histInfo.HistoryCount, histInfo.OriginalCount)
		} else {
			historyDesc = fmt.Sprintf(" history=%d", histInfo.HistoryCount)
		}
	}

	fmt.Printf("[%d] key=%s seq=%d size=%d bytes%s\n",
		info.Index, info.Key, info.Record.Seq, len(body), historyDesc)

	if *historyStats {
		// Only show history stats, not full content
		return
	}

	if *summary || len(body) == 0 {
		return
	}
	fmt.Println("-----BEGIN REPORT-----")
	if reporter != nil {
		if symBody, err := symbolizeBody(reporter, body); err != nil {
			log.Printf("warn: failed to symbolize key=%s: %v", info.Key, err)
		} else if len(symBody) != 0 {
			body = symBody
		}
	}

	// If not showing history, truncate output before REPLAY HISTORY section
	if !*showHistory {
		if idx := bytes.Index(body, []byte("\n=== REPLAY HISTORY ===")); idx > 0 {
			body = append(body[:idx], []byte("\n=== REPLAY HISTORY ===\n[use -show_history to see details]\n")...)
		}
	}

	if *format {
		body = formatReport(body)
	}
	if _, err := os.Stdout.Write(body); err != nil {
		log.Fatalf("failed to write report for key %s: %v", info.Key, err)
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		fmt.Println()
	}
	fmt.Println("-----END REPORT-----")
}
