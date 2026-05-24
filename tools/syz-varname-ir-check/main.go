// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/tool"
)

type caseFlags []string

func (f *caseFlags) String() string {
	return strings.Join(*f, ",")
}

func (f *caseFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type storedUAFCorpusEntry struct {
	Pair  mayUAFPair   `json:"pair"`
	Pairs []mayUAFPair `json:"pairs,omitempty"`
}

type mayUAFPair struct {
	FreeAccessName uint64
	UseAccessName  uint64
}

type corpusStats struct {
	Entries      int
	PairTotal    int
	UniquePairs  map[pairKey]int
	UniqueNames  map[uint64]int
	InvalidJSON  int
	ZeroOnlyPair int
}

type pairKey struct {
	Free uint64
	Use  uint64
}

type checkCase struct {
	Name       string
	CorpusPath string
	IRPath     string
}

var (
	flagCases         caseFlags
	flagMissingLimit  = flag.Int("missing-limit", 12, "number of missing examples to print per case")
	flagRequireAll    = flag.Bool("require-all", false, "exit non-zero if any case has missing names or pairs")
	recMemAccessConst = regexp.MustCompile(`@kccwf_rec_mem_access\([^)]*\bi64\s+(-?[0-9]+)`)
)

func main() {
	flag.Var(&flagCases, "case", "case in name:corpus.db:ir-dir form; may be repeated")
	flag.Parse()
	if len(flagCases) == 0 {
		tool.Failf("must provide at least one -case name:corpus.db:ir-dir")
	}

	var failed bool
	fmt.Printf("%-10s %8s %10s %10s %10s %10s %9s %9s\n",
		"module", "entries", "pairs", "pair_hit", "pair_miss", "names", "name_hit", "name_miss")
	for _, raw := range flagCases {
		c, err := parseCase(raw)
		if err != nil {
			tool.Failf("%v", err)
		}
		stats, err := loadCorpusStats(c.CorpusPath)
		if err != nil {
			tool.Failf("[%s] load corpus: %v", c.Name, err)
		}
		irNames, err := loadIRNames(c.IRPath)
		if err != nil {
			tool.Failf("[%s] load IR: %v", c.Name, err)
		}

		pairHit, missingPairs := countPairHits(stats.UniquePairs, irNames)
		nameHit, missingNames := countNameHits(stats.UniqueNames, irNames)
		fmt.Printf("%-10s %8d %10d %10d %10d %10d %9d %9d\n",
			c.Name, stats.Entries, len(stats.UniquePairs), pairHit, len(missingPairs),
			len(stats.UniqueNames), nameHit, len(missingNames))

		if stats.InvalidJSON != 0 || stats.ZeroOnlyPair != 0 {
			fmt.Printf("  notes: invalid_json=%d zero_only_pairs=%d\n", stats.InvalidJSON, stats.ZeroOnlyPair)
		}
		if len(missingNames) != 0 {
			fmt.Printf("  missing names: %s\n", formatNames(missingNames, *flagMissingLimit))
		}
		if len(missingPairs) != 0 {
			fmt.Printf("  missing pairs: %s\n", formatPairs(missingPairs, *flagMissingLimit))
		}
		if len(missingNames) != 0 || len(missingPairs) != 0 {
			failed = true
		}
	}
	if failed && *flagRequireAll {
		os.Exit(1)
	}
}

func parseCase(raw string) (checkCase, error) {
	parts := strings.SplitN(raw, ":", 3)
	if len(parts) != 3 {
		return checkCase{}, fmt.Errorf("invalid -case %q, want name:corpus.db:ir-dir", raw)
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return checkCase{}, fmt.Errorf("invalid -case %q, empty component", raw)
	}
	return checkCase{Name: parts[0], CorpusPath: parts[1], IRPath: parts[2]}, nil
}

func loadCorpusStats(path string) (*corpusStats, error) {
	corpusDB, err := db.OpenNoCompact(path, false)
	if err != nil {
		return nil, err
	}
	stats := &corpusStats{
		UniquePairs: make(map[pairKey]int),
		UniqueNames: make(map[uint64]int),
	}
	for _, rec := range corpusDB.Records {
		stats.Entries++
		var stored storedUAFCorpusEntry
		if err := json.Unmarshal(rec.Val, &stored); err != nil {
			stats.InvalidJSON++
			continue
		}
		addPair(stats, stored.Pair)
		for _, pair := range stored.Pairs {
			addPair(stats, pair)
		}
	}
	return stats, nil
}

func addPair(stats *corpusStats, pair mayUAFPair) {
	if pair.FreeAccessName == 0 && pair.UseAccessName == 0 {
		stats.ZeroOnlyPair++
		return
	}
	stats.PairTotal++
	key := pairKey{Free: pair.FreeAccessName, Use: pair.UseAccessName}
	stats.UniquePairs[key]++
	if pair.FreeAccessName != 0 {
		stats.UniqueNames[pair.FreeAccessName]++
	}
	if pair.UseAccessName != 0 {
		stats.UniqueNames[pair.UseAccessName]++
	}
}

func loadIRNames(root string) (map[uint64]struct{}, error) {
	names := make(map[uint64]struct{})
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".ll") {
			return nil
		}
		return scanIRFile(path, names)
	})
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no kccwf_rec_mem_access varnames found under %s", root)
	}
	return names, nil
}

func scanIRFile(path string, names map[uint64]struct{}) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	const maxScanTokenSize = 4 * 1024 * 1024
	scanner.Buffer(make([]byte, 1024), maxScanTokenSize)
	for scanner.Scan() {
		line := scanner.Text()
		matches := recMemAccessConst.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			value, err := parseIRInt64AsUint64(match[1])
			if err != nil {
				return fmt.Errorf("%s: parse %q: %w", path, match[1], err)
			}
			names[value] = struct{}{}
		}
	}
	return scanner.Err()
}

func parseIRInt64AsUint64(text string) (uint64, error) {
	if strings.HasPrefix(text, "-") {
		value, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return 0, err
		}
		return uint64(value), nil
	}
	return strconv.ParseUint(text, 10, 64)
}

func countPairHits(pairs map[pairKey]int, irNames map[uint64]struct{}) (int, []pairKey) {
	var missing []pairKey
	for pair := range pairs {
		_, freeOK := irNames[pair.Free]
		_, useOK := irNames[pair.Use]
		if freeOK && useOK {
			continue
		}
		missing = append(missing, pair)
	}
	sortPairs(missing)
	return len(pairs) - len(missing), missing
}

func countNameHits(names map[uint64]int, irNames map[uint64]struct{}) (int, []uint64) {
	var missing []uint64
	for name := range names {
		if _, ok := irNames[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Slice(missing, func(i, j int) bool {
		if names[missing[i]] == names[missing[j]] {
			return missing[i] < missing[j]
		}
		return names[missing[i]] > names[missing[j]]
	})
	return len(names) - len(missing), missing
}

func sortPairs(pairs []pairKey) {
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Free == pairs[j].Free {
			return pairs[i].Use < pairs[j].Use
		}
		return pairs[i].Free < pairs[j].Free
	})
}

func formatNames(names []uint64, limit int) string {
	if limit <= 0 || limit > len(names) {
		limit = len(names)
	}
	parts := make([]string, 0, limit)
	for _, name := range names[:limit] {
		parts = append(parts, fmt.Sprintf("%016x", name))
	}
	if limit < len(names) {
		parts = append(parts, fmt.Sprintf("...(+%d)", len(names)-limit))
	}
	return strings.Join(parts, ", ")
}

func formatPairs(pairs []pairKey, limit int) string {
	if limit <= 0 || limit > len(pairs) {
		limit = len(pairs)
	}
	parts := make([]string, 0, limit)
	for _, pair := range pairs[:limit] {
		parts = append(parts, fmt.Sprintf("%016x-%016x", pair.Free, pair.Use))
	}
	if limit < len(pairs) {
		parts = append(parts, fmt.Sprintf("...(+%d)", len(pairs)-limit))
	}
	return strings.Join(parts, ", ")
}
