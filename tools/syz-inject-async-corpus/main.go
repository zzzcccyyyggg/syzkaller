// syz-inject-async-corpus creates a manual async UAFCorpusEntry and injects it
// into a uaf-corpus.db for testing the async validation pipeline.
//
// Usage:
//
//	go run ./tools/syz-inject-async-corpus -config=exp/bt-stack/exp-validate.cfg
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys/targets" // pull in all targets
)

var (
	flagConfig  = flag.String("config", "", "syzkaller config file (to get workdir and target)")
	flagWorkdir = flag.String("workdir", "", "workdir containing uaf-corpus.db (overrides config)")
	flagDryRun  = flag.Bool("dry-run", false, "print entry without writing to DB")
	flagProgram = flag.String("prog", "", "path to program text file (overrides built-in SCO program)")
	flagRace0   = flag.Int("race0", -1, "first racing call index (overrides auto-detection)")
	flagRace1   = flag.Int("race1", -1, "second racing call index (overrides auto-detection)")
)

func main() {
	flag.Parse()

	if *flagConfig == "" && *flagWorkdir == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -config=<cfg> or -workdir=<dir>\n", os.Args[0])
		os.Exit(1)
	}

	// Determine target and workdir
	var target *prog.Target
	var workdir string

	if *flagConfig != "" {
		cfg, err := mgrconfig.LoadFile(*flagConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
			os.Exit(1)
		}
		target = cfg.Target
		workdir = cfg.Workdir
	} else {
		var err error
		target, err = prog.GetTarget("linux", "amd64")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get target: %v\n", err)
			os.Exit(1)
		}
		workdir = *flagWorkdir
	}

	if *flagWorkdir != "" {
		workdir = *flagWorkdir
	}

	// Parse program
	var p *prog.Prog
	if *flagProgram != "" {
		data, err := os.ReadFile(*flagProgram)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read program file: %v\n", err)
			os.Exit(1)
		}
		p, err = target.Deserialize(data, prog.NonStrict)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse program: %v\n", err)
			os.Exit(1)
		}
	} else {
		p = buildSCORaceProgram(target)
	}

	// Determine racing call indices
	race0, race1 := findAsyncCalls(p)
	if *flagRace0 >= 0 {
		race0 = *flagRace0
	}
	if *flagRace1 >= 0 {
		race1 = *flagRace1
	}

	if race0 < 0 || race1 < 0 || race0 >= len(p.Calls) || race1 >= len(p.Calls) {
		fmt.Fprintf(os.Stderr, "invalid racing call indices: %d, %d (program has %d calls)\n",
			race0, race1, len(p.Calls))
		os.Exit(1)
	}

	// Mark the racing calls as async
	p.Calls[race0].Props.Async = true
	p.Calls[race1].Props.Async = true

	fmt.Printf("Program (%d calls):\n%s\n", len(p.Calls), string(p.Serialize()))
	fmt.Printf("Racing calls: [%d] %s  vs  [%d] %s\n",
		race0, p.Calls[race0].Meta.Name,
		race1, p.Calls[race1].Meta.Name)

	// Create the entry
	// Use synthetic VarName/Stack values for the pair
	// In real usage these would be kernel PC addresses from KCSAN
	pair := ddrd.MayUAFPair{
		FreeAccessName: 0xdead0001, // synthetic: represents sco_sock_connect state read
		UseAccessName:  0xdead0002, // synthetic: represents sco_connect state write
		FreeCallStack:  0xbeef0001,
		UseCallStack:   0xbeef0002,
	}

	entry := &fuzzer.UAFCorpusEntry{
		Prog:          p,
		CallIdx:       race0,
		PairBasicInfo: pair,
		Pairs:         []*ddrd.MayUAFPair{&pair},
		Barrier: fuzzer.BarrierSnapshot{
			Participants: 0, // no barrier for async mode
		},
		Timestamp:      time.Now(),
		AsyncMode:      true,
		AsyncRaceCalls: [2]int{race0, race1},
	}

	entryID := entry.PairID()
	key := fmt.Sprintf("%016x", entryID)
	fmt.Printf("Entry key: %s (ID: %d)\n", key, entryID)
	fmt.Printf("AsyncMode: true, AsyncRaceCalls: [%d, %d]\n", race0, race1)

	if *flagDryRun {
		data, err := serializeEntry(entry)
		if err != nil {
			fmt.Fprintf(os.Stderr, "serialize error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nSerialized JSON (%d bytes):\n%s\n", len(data), string(data))
		return
	}

	// Write to DB
	dbPath := filepath.Join(workdir, "uaf-corpus.db")
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create workdir: %v\n", err)
		os.Exit(1)
	}

	corpusDB, err := db.Open(dbPath, true)
	if err != nil && corpusDB == nil {
		fmt.Fprintf(os.Stderr, "failed to open DB %s: %v\n", dbPath, err)
		os.Exit(1)
	}

	data, err := serializeEntry(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serialize error: %v\n", err)
		os.Exit(1)
	}

	seq := uint64(entry.Timestamp.UnixNano())
	corpusDB.Save(key, data, seq)
	if err := corpusDB.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to flush DB: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nInjected entry into %s (key=%s, seq=%d)\n", dbPath, key, seq)
	fmt.Printf("Total entries in DB: %d\n", len(corpusDB.Records))
}

// buildSCORaceProgram constructs a syzkaller program that triggers the SCO
// sk->sk_state data race. The program:
//  1. Creates a BT SCO socket (in init net namespace via syz_init_net_socket)
//  2. Binds it to BDADDR_ANY
//  3. Calls connect$bt_sco twice (both marked async) to race on sk->sk_state
func buildSCORaceProgram(target *prog.Target) *prog.Prog {
	// Use the text format and parse it. This is the simplest way to
	// construct a valid program with the right types.
	progText := `r0 = syz_init_net_socket$bt_sco(0x1f, 0x5, 0x2)
bind$bt_sco(r0, &(0x7f0000000000)={0x1f, @any}, 0x8)
connect$bt_sco(r0, &(0x7f0000000040)={0x1f, @fixed={0x10}}, 0x8) (async)
connect$bt_sco(r0, &(0x7f0000000080)={0x1f, @fixed={0x10}}, 0x8) (async)
`
	p, err := target.Deserialize([]byte(progText), prog.NonStrict)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse built-in SCO program: %v\n", err)
		os.Exit(1)
	}
	return p
}

// findAsyncCalls returns the indices of calls marked async in the program.
// If none found, returns the last two call indices.
func findAsyncCalls(p *prog.Prog) (int, int) {
	var asyncIdx []int
	for i, c := range p.Calls {
		if c.Props.Async {
			asyncIdx = append(asyncIdx, i)
		}
	}
	if len(asyncIdx) >= 2 {
		return asyncIdx[0], asyncIdx[1]
	}
	// Default: last two calls
	n := len(p.Calls)
	if n >= 2 {
		return n - 2, n - 1
	}
	return 0, 0
}

// Serialization types matching pkg/manager/race_store.go
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
	Timestamp      time.Time              `json:"timestamp"`
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
	Programs  [][]byte  `json:"programs"`
	Timestamp time.Time `json:"timestamp"`
	GroupID   int64     `json:"group_id"`
}

func serializeEntry(entry *fuzzer.UAFCorpusEntry) ([]byte, error) {
	stored := storedUAFCorpusEntry{
		CallIdx:        entry.CallIdx,
		Pair:           entry.PairBasicInfo,
		Barrier:        entry.Barrier,
		Timestamp:      entry.Timestamp,
		Source:         int(entry.Source),
		AsyncMode:      entry.AsyncMode,
		AsyncRaceCalls: entry.AsyncRaceCalls,
	}
	if len(entry.Pairs) != 0 {
		stored.Pairs = make([]ddrd.MayUAFPair, 0, len(entry.Pairs))
		for _, pair := range entry.Pairs {
			if pair != nil {
				stored.Pairs = append(stored.Pairs, *pair)
			}
		}
	}
	if entry.Prog != nil {
		stored.Program = entry.Prog.Serialize()
	}
	if len(entry.Programs) != 0 {
		for _, p := range entry.Programs {
			if p != nil {
				stored.Programs = append(stored.Programs, p.Serialize())
			}
		}
	}
	if entry.Profile.FreeAccessName != 0 || entry.Profile.UseAccessName != 0 {
		stored.Profile = &storedPairProfile{
			FreeAccessName: entry.Profile.FreeAccessName,
			UseAccessName:  entry.Profile.UseAccessName,
			FreeCallStack:  entry.Profile.FreeCallStack,
			UseCallStack:   entry.Profile.UseCallStack,
		}
	}
	return json.Marshal(stored)
}
