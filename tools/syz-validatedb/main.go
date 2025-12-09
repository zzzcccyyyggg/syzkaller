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
	dbPath     = flag.String("db", "validated_uaf.db", "path to validated_uaf.db")
	summary    = flag.Bool("summary", false, "only print record metadata, skip report bodies")
	format     = flag.Bool("format", false, "prettify report output for easier reading")
	manager    = flag.String("manager_cfg", "", "optional syz-manager config for symbolization")
	groupByVar = flag.Bool("group_by_var", false, "group reports by VarName pairs")
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

	if *groupByVar {
		printGroupedByVarName(records, reporter)
	} else {
		printSequential(records, reporter)
	}
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
	fmt.Printf("[%d] key=%s seq=%d size=%d bytes\n", 
		info.Index, info.Key, info.Record.Seq, len(info.Record.Val))
	if *summary || len(info.Record.Val) == 0 {
		return
	}
	fmt.Println("-----BEGIN REPORT-----")
	body := info.Record.Val
	if reporter != nil {
		if symBody, err := symbolizeBody(reporter, body); err != nil {
			log.Printf("warn: failed to symbolize key=%s: %v", info.Key, err)
		} else if len(symBody) != 0 {
			body = symBody
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
