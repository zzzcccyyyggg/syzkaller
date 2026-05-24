package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type storedUAFCorpusEntry struct {
	Program        []byte                 `json:"program"`
	Programs       [][]byte               `json:"programs,omitempty"`
	CallIdx        int                    `json:"call_idx"`
	Pair           ddrd.MayUAFPair        `json:"pair"`
	Pairs          []ddrd.MayUAFPair      `json:"pairs,omitempty"`
	Signals        []uint64               `json:"signals,omitempty"`
	Barrier        fuzzer.BarrierSnapshot `json:"barrier"`
	ReplayPlan     *storedReplayPlan      `json:"replay_plan,omitempty"`
	Profile        *storedPairProfile     `json:"profile,omitempty"`
	ReplayHistory  []storedBarrierRecord  `json:"replay_history,omitempty"`
	Timestamp      string                 `json:"timestamp"`
	Source         int                    `json:"source,omitempty"`
	AsyncMode      bool                   `json:"async_mode,omitempty"`
	AsyncRaceCalls [2]int                 `json:"async_race_calls,omitempty"`
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

type storedBarrierRecord struct {
	Programs  [][]byte `json:"programs"`
	Timestamp string   `json:"timestamp"`
	GroupID   int64    `json:"group_id"`
}

type keyedRecord struct {
	Key string
	Val []byte
	Seq uint64
}

var (
	flagIn            = flag.String("in", "", "input uaf-corpus.db")
	flagOut           = flag.String("out", "", "output canonicalized uaf-corpus.db")
	flagOS            = flag.String("os", runtime.GOOS, "target OS")
	flagArch          = flag.String("arch", runtime.GOARCH, "target arch")
	flagValidate      = flag.Bool("validate", true, "deserialize rewritten programs to check syntax")
	flagLimit         = flag.Int("limit", 0, "limit records after sorting by seq/timestamp order (0 = all)")
	flagMaxHist       = flag.Int("max-history", 0, "keep only the most recent N replay_history records per entry (0 = keep all)")
	flagAllToTestfile = flag.Bool("all-to-testfile", false, "rewrite every recognized kccwf path to testfile instead of preserving path family")
	flagPreserveKeys  = flag.Bool("preserve-keys", false, "preserve original uaf-corpus.db record keys instead of rehashing rewritten values")

	absPathRE = regexp.MustCompile(`/mnt/kccwf/[A-Za-z0-9_%#]+`)
	relFileRE = regexp.MustCompile(`(^|[^/A-Za-z0-9_])(testfile(?:#|[0-9]+)?|file[A-Za-z0-9]+xxx)(\\x00)`)
	relDirRE  = regexp.MustCompile(`(^|[^/A-Za-z0-9_])(testdir|testdi[0-9]+|dir[A-Za-z0-9]+xx)(\\x00)`)
	relHardRE = regexp.MustCompile(`(^|[^/A-Za-z0-9_])(hardlink(?:#|[0-9]+)?|hard[A-Za-z0-9]+xxx)(\\x00)`)
	relSymRE  = regexp.MustCompile(`(^|[^/A-Za-z0-9_])(symlink(?:#|[0-9]+)?|sym[A-Za-z0-9]+xxx)(\\x00)`)
	relTgtRE  = regexp.MustCompile(`(^|[^/A-Za-z0-9_])(target(?:_%d|[0-9]+%d)|tgt[A-Za-z0-9]+xx%d)(\\x00)`)
)

func main() {
	flag.Parse()
	if *flagIn == "" || *flagOut == "" {
		flag.Usage()
		os.Exit(2)
	}
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		tool.Failf("failed to get target: %v", err)
	}
	inDB, err := db.Open(*flagIn, false)
	if err != nil {
		tool.Failf("failed to open input db: %v", err)
	}

	keys := make([]string, 0, len(inDB.Records))
	for key := range inDB.Records {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		ri := inDB.Records[keys[i]]
		rj := inDB.Records[keys[j]]
		if ri.Seq != rj.Seq {
			return ri.Seq < rj.Seq
		}
		return keys[i] < keys[j]
	})
	if *flagLimit > 0 && *flagLimit < len(keys) {
		keys = keys[:*flagLimit]
	}

	var records []db.Record
	var keyedRecords []keyedRecord
	var entries, changedEntries, programs, changedPrograms, failedPrograms int
	var historyBefore, historyAfter int
	for _, key := range keys {
		rec := inDB.Records[key]
		var stored storedUAFCorpusEntry
		if err := json.Unmarshal(rec.Val, &stored); err != nil {
			tool.Failf("failed to parse record %s: %v", key, err)
		}
		entries++
		historyBefore += len(stored.ReplayHistory)
		if *flagMaxHist > 0 && len(stored.ReplayHistory) > *flagMaxHist {
			stored.ReplayHistory = stored.ReplayHistory[len(stored.ReplayHistory)-*flagMaxHist:]
		}
		historyAfter += len(stored.ReplayHistory)
		changed := false
		changed = rewriteProgram(&stored.Program, target) || changed
		if len(stored.Program) != 0 {
			programs++
			if *flagValidate && !validProgram(target, stored.Program) {
				failedPrograms++
			}
		}
		for i := range stored.Programs {
			programs++
			before := string(stored.Programs[i])
			rewriteProgram(&stored.Programs[i], target)
			if string(stored.Programs[i]) != before {
				changed = true
				changedPrograms++
			}
			if *flagValidate && !validProgram(target, stored.Programs[i]) {
				failedPrograms++
			}
		}
		for i := range stored.ReplayHistory {
			for j := range stored.ReplayHistory[i].Programs {
				programs++
				before := string(stored.ReplayHistory[i].Programs[j])
				rewriteProgram(&stored.ReplayHistory[i].Programs[j], target)
				if string(stored.ReplayHistory[i].Programs[j]) != before {
					changed = true
					changedPrograms++
				}
				if *flagValidate && !validProgram(target, stored.ReplayHistory[i].Programs[j]) {
					failedPrograms++
				}
			}
		}
		if changed {
			changedEntries++
		}
		data, err := json.Marshal(stored)
		if err != nil {
			tool.Failf("failed to marshal record %s: %v", key, err)
		}
		if *flagPreserveKeys {
			keyedRecords = append(keyedRecords, keyedRecord{Key: key, Val: data, Seq: rec.Seq})
		} else {
			records = append(records, db.Record{Val: data, Seq: rec.Seq})
		}
	}
	if *flagPreserveKeys {
		if err := createWithKeys(*flagOut, inDB.Version, keyedRecords); err != nil {
			tool.Failf("failed to create output db: %v", err)
		}
	} else {
		if err := db.Create(*flagOut, inDB.Version, records); err != nil {
			tool.Failf("failed to create output db: %v", err)
		}
	}
	fmt.Printf("uaf kccwf canonicalize: input=%s output=%s entries=%d changed_entries=%d programs=%d changed_programs=%d failed_programs=%d\n",
		*flagIn, *flagOut, entries, changedEntries, programs, changedPrograms, failedPrograms)
	fmt.Printf("uaf kccwf canonicalize: limit=%d max_history=%d history_before=%d history_after=%d\n",
		*flagLimit, *flagMaxHist, historyBefore, historyAfter)
	fmt.Printf("uaf kccwf canonicalize: preserve_keys=%v all_to_testfile=%v\n", *flagPreserveKeys, *flagAllToTestfile)
}

func createWithKeys(path string, version uint64, records []keyedRecord) error {
	_ = os.Remove(path)
	outDB, err := db.Open(path, true)
	if err != nil {
		return fmt.Errorf("failed to open output db: %w", err)
	}
	if err := outDB.BumpVersion(version); err != nil {
		return fmt.Errorf("failed to bump output db version: %w", err)
	}
	for _, rec := range records {
		outDB.Save(rec.Key, rec.Val, rec.Seq)
	}
	return outDB.Flush()
}

func rewriteProgram(data *[]byte, target *prog.Target) bool {
	if data == nil || len(*data) == 0 {
		return false
	}
	before := string(*data)
	after := canonicalizeText(before)
	*data = []byte(after)
	return after != before
}

func validProgram(target *prog.Target, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	_, err := target.Deserialize(data, prog.NonStrict)
	return err == nil
}

func canonicalizeText(s string) string {
	if *flagAllToTestfile {
		return canonicalizeTextAllToTestfile(s)
	}
	s = absPathRE.ReplaceAllStringFunc(s, canonicalAbsPath)
	s = relFileRE.ReplaceAllString(s, `${1}testfile#${3}`)
	s = relDirRE.ReplaceAllString(s, `${1}testdir${3}`)
	s = relHardRE.ReplaceAllString(s, `${1}hardlink#${3}`)
	s = relSymRE.ReplaceAllString(s, `${1}symlink#${3}`)
	s = relTgtRE.ReplaceAllString(s, `${1}target_%d${3}`)
	return s
}

func canonicalizeTextAllToTestfile(s string) string {
	s = absPathRE.ReplaceAllString(s, "/mnt/kccwf/testfile")
	s = relFileRE.ReplaceAllString(s, `${1}testfile${3}`)
	s = relDirRE.ReplaceAllString(s, `${1}testfile${3}`)
	s = relHardRE.ReplaceAllString(s, `${1}testfile${3}`)
	s = relSymRE.ReplaceAllString(s, `${1}testfile${3}`)
	s = relTgtRE.ReplaceAllString(s, `${1}testfile${3}`)
	return s
}

func canonicalAbsPath(path string) string {
	base := path[len("/mnt/kccwf/"):]
	switch {
	case base == "testfile#" || regexp.MustCompile(`^testfile[0-9]+$`).MatchString(base) || regexp.MustCompile(`^file[A-Za-z0-9]+xxx$`).MatchString(base):
		return "/mnt/kccwf/testfile#"
	case base == "testdir" || regexp.MustCompile(`^testdi[0-9]+$`).MatchString(base) || regexp.MustCompile(`^dir[A-Za-z0-9]+xx$`).MatchString(base):
		return "/mnt/kccwf/testdir"
	case base == "hardlink#" || regexp.MustCompile(`^hardlink[0-9]+$`).MatchString(base) || regexp.MustCompile(`^hard[A-Za-z0-9]+xxx$`).MatchString(base):
		return "/mnt/kccwf/hardlink#"
	case base == "symlink#" || regexp.MustCompile(`^symlink[0-9]+$`).MatchString(base) || regexp.MustCompile(`^sym[A-Za-z0-9]+xxx$`).MatchString(base):
		return "/mnt/kccwf/symlink#"
	case base == "target_%d" || regexp.MustCompile(`^target[0-9]+%d$`).MatchString(base) || regexp.MustCompile(`^tgt[A-Za-z0-9]+xx%d$`).MatchString(base):
		return "/mnt/kccwf/target_%d"
	default:
		return path
	}
}
