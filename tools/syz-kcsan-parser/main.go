// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-kcsan-parser parses KCSAN data race reports and extracts race pairs
// in a format compatible with DDRD-syzkaller for comparison.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	flagCrashDir = flag.String("crash-dir", "", "directory containing KCSAN crash reports")
	flagOutput   = flag.String("output", "race_pairs.json", "output JSON file")
	flagVerbose  = flag.Bool("v", false, "verbose output")
)

// AccessRecord represents a single memory access in a race
type AccessRecord struct {
	Type      string   `json:"type"`       // "read" or "write"
	Address   string   `json:"address"`    // memory address
	Size      int      `json:"size"`       // access size in bytes
	TaskID    int      `json:"task_id"`    // task/thread ID
	CPU       int      `json:"cpu"`        // CPU number
	Function  string   `json:"function"`   // function name
	Offset    string   `json:"offset"`     // function offset
	SourceLoc string   `json:"source_loc"` // source file:line
	CallStack []string `json:"call_stack"` // full call stack
}

// RacePair represents a detected data race between two accesses
type RacePair struct {
	ID        int          `json:"id"`
	Access1   AccessRecord `json:"access1"`
	Access2   AccessRecord `json:"access2"`
	RawReport string       `json:"raw_report,omitempty"`
}

// KCSANReport represents a parsed KCSAN report
type KCSANReport struct {
	Function1 string `json:"function1"`
	Function2 string `json:"function2"`
	RacePair  RacePair
}

func main() {
	flag.Parse()

	if *flagCrashDir == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -crash-dir <dir> [-output <file>] [-v]\n", os.Args[0])
		os.Exit(1)
	}

	reports, err := parseKCSANDirectory(*flagCrashDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing crash directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d KCSAN race reports\n", len(reports))

	// Extract race pairs
	var racePairs []RacePair
	for i, report := range reports {
		report.RacePair.ID = i + 1
		racePairs = append(racePairs, report.RacePair)
	}

	// Output results
	output, err := json.MarshalIndent(racePairs, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*flagOutput, output, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Race pairs written to %s\n", *flagOutput)

	// Print summary
	printSummary(racePairs)
}

func parseKCSANDirectory(dir string) ([]KCSANReport, error) {
	var reports []KCSANReport

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Each crash is in a subdirectory
		crashDir := filepath.Join(dir, entry.Name())

		// Check if it's a KCSAN report
		descFile := filepath.Join(crashDir, "description")
		desc, err := os.ReadFile(descFile)
		if err != nil {
			continue
		}

		if !strings.Contains(string(desc), "KCSAN") {
			continue
		}

		// Find and parse the log file
		logFiles, _ := filepath.Glob(filepath.Join(crashDir, "log*"))
		for _, logFile := range logFiles {
			content, err := os.ReadFile(logFile)
			if err != nil {
				continue
			}

			report, err := parseKCSANReport(string(content))
			if err != nil {
				if *flagVerbose {
					fmt.Printf("Warning: failed to parse %s: %v\n", logFile, err)
				}
				continue
			}

			reports = append(reports, report)
			break
		}
	}

	return reports, nil
}

func parseKCSANReport(content string) (KCSANReport, error) {
	var report KCSANReport

	// Find the KCSAN report section
	startIdx := strings.Index(content, "BUG: KCSAN:")
	if startIdx == -1 {
		return report, fmt.Errorf("no KCSAN report found")
	}

	endIdx := strings.Index(content[startIdx:], "==================================================================")
	if endIdx == -1 {
		endIdx = len(content) - startIdx
	}

	reportText := content[startIdx : startIdx+endIdx]

	// Parse the header: "BUG: KCSAN: data-race in func1 / func2"
	headerRe := regexp.MustCompile(`BUG: KCSAN: data-race in (\S+) / (\S+)`)
	headerMatch := headerRe.FindStringSubmatch(reportText)
	if headerMatch != nil {
		report.Function1 = headerMatch[1]
		report.Function2 = headerMatch[2]
	}

	// Parse access records
	access1, err := parseAccessRecord(reportText, true)
	if err == nil {
		report.RacePair.Access1 = access1
	}

	access2, err := parseAccessRecord(reportText, false)
	if err == nil {
		report.RacePair.Access2 = access2
	}

	report.RacePair.RawReport = reportText

	return report, nil
}

func parseAccessRecord(report string, first bool) (AccessRecord, error) {
	var access AccessRecord

	// Pattern for access line: "write to 0x... of N bytes by task X on cpu Y:"
	// or "read to 0x... of N bytes by task X on cpu Y:"
	accessRe := regexp.MustCompile(`(read|write) to (0x[0-9a-fA-F]+) of (\d+) bytes by task (\d+) on cpu (\d+):`)

	matches := accessRe.FindAllStringSubmatch(report, -1)
	if len(matches) == 0 {
		return access, fmt.Errorf("no access record found")
	}

	var match []string
	if first && len(matches) >= 1 {
		match = matches[0]
	} else if !first && len(matches) >= 2 {
		match = matches[1]
	} else {
		return access, fmt.Errorf("access record not found")
	}

	access.Type = match[1]
	access.Address = match[2]
	access.Size, _ = strconv.Atoi(match[3])
	access.TaskID, _ = strconv.Atoi(match[4])
	access.CPU, _ = strconv.Atoi(match[5])

	// Parse call stack
	access.CallStack = parseCallStack(report, match[0])

	// Extract function name and offset from first stack frame
	if len(access.CallStack) > 0 {
		funcRe := regexp.MustCompile(`(\S+)\+0x([0-9a-fA-F]+)/0x[0-9a-fA-F]+`)
		funcMatch := funcRe.FindStringSubmatch(access.CallStack[0])
		if funcMatch != nil {
			access.Function = funcMatch[1]
			access.Offset = funcMatch[2]
		}

		// Extract source location
		locRe := regexp.MustCompile(`(\S+:\d+)`)
		locMatch := locRe.FindStringSubmatch(access.CallStack[0])
		if locMatch != nil {
			access.SourceLoc = locMatch[1]
		}
	}

	return access, nil
}

func parseCallStack(report, accessLine string) []string {
	var stack []string

	// Find the position after the access line
	idx := strings.Index(report, accessLine)
	if idx == -1 {
		return stack
	}

	// Stack frames start with a space and contain function+offset
	lines := strings.Split(report[idx+len(accessLine):], "\n")
	frameRe := regexp.MustCompile(`^\s+(\S+\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+.*)`)

	for _, line := range lines {
		// Stop at empty line or next section
		if strings.TrimSpace(line) == "" {
			break
		}
		if strings.HasPrefix(line, "read ") || strings.HasPrefix(line, "write ") {
			break
		}
		if strings.HasPrefix(line, "Reported by") {
			break
		}

		match := frameRe.FindStringSubmatch(line)
		if match != nil {
			stack = append(stack, strings.TrimSpace(match[1]))
		}
	}

	return stack
}

func printSummary(pairs []RacePair) {
	fmt.Println("\n=== Race Pair Summary ===")

	// Count by access type combination
	typeCount := make(map[string]int)
	funcPairs := make(map[string]int)

	for _, pair := range pairs {
		key := fmt.Sprintf("%s-%s", pair.Access1.Type, pair.Access2.Type)
		typeCount[key]++

		funcKey := fmt.Sprintf("%s <-> %s", pair.Access1.Function, pair.Access2.Function)
		funcPairs[funcKey]++
	}

	fmt.Println("\nAccess Type Distribution:")
	for t, count := range typeCount {
		fmt.Printf("  %s: %d\n", t, count)
	}

	fmt.Println("\nTop Function Pairs:")
	// Sort and print top 10
	type kv struct {
		Key   string
		Value int
	}
	var sorted []kv
	for k, v := range funcPairs {
		sorted = append(sorted, kv{k, v})
	}

	// Simple bubble sort for top 10
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Value > sorted[i].Value {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	for i := 0; i < len(sorted) && i < 10; i++ {
		fmt.Printf("  %s: %d\n", sorted[i].Key, sorted[i].Value)
	}
}
