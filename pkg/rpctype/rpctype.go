// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package rpctype contains types of message passed via net/rpc connections
// between various parts of the system.
package rpctype

import (
	"math"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/signal"
)

// ===============DDRD====================

// RaceData contains all race-related information in a unified structure
type RaceData struct {
	Signals   []uint64           // race detection signals (64-bit to match executor output)
	RacePairs []ddrd.MayRacePair // detailed race pair information with metadata
}

// ===============DDRD====================

type Input struct {
	Call     string
	Prog     []byte
	Signal   signal.Serial
	Cover    []uint32
	CallID   int // seq number of call in the prog to which the item is related (-1 for extra)
	RawCover []uint32
	// ===============DDRD====================
	RaceData RaceData // unified race data structure containing both signals and mapping data
	// ===============DDRD====================
}

type Candidate struct {
	Prog      []byte
	Minimized bool
	Smashed   bool
}

type ExecTask struct {
	Prog []byte
	ID   int64
}

type ConnectArgs struct {
	Name        string
	MachineInfo []byte
	Modules     []host.KernelModule
}

type ConnectRes struct {
	EnabledCalls      []int
	NoMutateCalls     map[int]bool
	GitRevision       string
	TargetRevision    string
	AllSandboxes      bool
	CheckResult       *CheckArgs
	MemoryLeakFrames  []string
	DataRaceFrames    []string
	CoverFilterBitmap []byte
}

type CheckArgs struct {
	Name          string
	Error         string
	EnabledCalls  map[string][]int
	DisabledCalls map[string][]SyscallReason
	Features      *host.Features
	GlobFiles     map[string][]string
}

type SyscallReason struct {
	ID     int
	Reason string
}

type NewInputArgs struct {
	Name string
	Input
}

type PollArgs struct {
	Name           string
	NeedCandidates bool
	MaxSignal      signal.Serial
	Stats          map[string]uint64
}

type PollRes struct {
	Candidates []Candidate
	NewInputs  []Input
	MaxSignal  signal.Serial
}

type RunnerConnectArgs struct {
	Pool, VM int
}

type RunnerConnectRes struct {
	// CheckUnsupportedCalls is set to true if the Runner needs to query the kernel
	// for unsupported system calls and report them back to the server.
	CheckUnsupportedCalls bool
}

// UpdateUnsupportedArgs contains the data passed from client to server in an
// UpdateSupported call, namely the system calls not supported by the client's
// kernel.
type UpdateUnsupportedArgs struct {
	// Pool is used to identify the checked kernel.
	Pool int
	// UnsupportedCalls contains the ID's of system calls not supported by the
	// client and the reason for this.
	UnsupportedCalls []SyscallReason
}

// NextExchangeArgs contains the data passed from client to server namely
// identification information of the VM and program execution results.
type NextExchangeArgs struct {
	// Pool/VM are used to identify the instance on which the client is running.
	Pool, VM int
	// ExecTaskID is used to uniquely identify the program for which the client is
	// sending results.
	ExecTaskID int64
	// Hanged is set to true if the program for which we are sending results
	// was killed due to hanging.
	Hanged bool
	// Info contains information about the execution of each system call in the
	// program.
	Info ipc.ProgInfo
}

// NextExchaneRes contains the data passed from server to client namely
// programs  to execute on the VM.
type NextExchangeRes struct {
	ExecTask
}

type CheckModeArgs struct {
	Name string
}

type CheckModeRes struct {
	IsTestPairMode bool
}

const (
	NoTask int64 = math.MaxInt64
)

type HubConnectArgs struct {
	// Client/Key are used for authentication.
	Client string
	// The key may be a secret password or the oauth token prefixed by "Bearer ".
	Key string
	// Manager name, must start with Client.
	Manager string
	// See pkg/mgrconfig.Config.HubDomain.
	Domain string
	// Manager has started with an empty corpus and requests whole hub corpus.
	Fresh bool
	// Set of system call names supported by this manager.
	// Used to filter out programs with unsupported calls.
	Calls []string
	// Current manager corpus.
	Corpus [][]byte
}

type HubSyncArgs struct {
	// see HubConnectArgs.
	Client     string
	Key        string
	Manager    string
	NeedRepros bool
	// Programs added to corpus since last sync or connect.
	Add [][]byte
	// Hashes of programs removed from corpus since last sync or connect.
	Del []string
	// Repros found since last sync.
	Repros [][]byte
}

type HubSyncRes struct {
	// Set of inputs from other managers.
	Inputs []HubInput
	// Same as Inputs but for legacy managers that don't understand new format (remove later).
	Progs [][]byte
	// Set of repros from other managers.
	Repros [][]byte
	// Number of remaining pending programs,
	// if >0 manager should do sync again.
	More int
}

type HubInput struct {
	// Domain of the source manager.
	Domain string
	Prog   []byte
}

type RunTestPollReq struct {
	Name string
}

type RunTestPollRes struct {
	ID     int
	Bin    []byte
	Prog   []byte
	Cfg    *ipc.Config
	Opts   *ipc.ExecOpts
	Repeat int
}

type RunTestDoneArgs struct {
	Name   string
	ID     int
	Output []byte
	Info   []*ipc.ProgInfo
	Error  string
}

type LogMessageReq struct {
	Level   int
	Name    string
	Message string
}

// ===============DDRD====================

// TestPairTask represents a test pair execution task
type TestPairTask struct {
	ID       string        // unique test pair ID
	Prog1    []byte        // first program serialized data
	Prog2    []byte        // second program serialized data
	Hash1    string        // first program hash
	Hash2    string        // second program hash
	Opts     *ipc.ExecOpts // execution options
	Priority int           // execution priority
}

// TestPairResult represents the result of test pair execution
type TestPairResult struct {
	ID       string             // test pair ID
	Success  bool               // execution success
	Error    string             // error message if failed
	ExecTime int64              // execution time in nanoseconds
	Races    []ddrd.MayRacePair // detected race conditions
}

// PollTestPairsArgs for fuzzer requesting test pairs from manager
type PollTestPairsArgs struct {
	FuzzerName string // fuzzer name
	MaxTasks   int    // maximum number of tasks to request
}

// PollTestPairsRes for manager sending test pairs to fuzzer
type PollTestPairsRes struct {
	Tasks []TestPairTask // test pair tasks to execute
}

// SubmitTestPairResultsArgs for fuzzer submitting results to manager
type SubmitTestPairResultsArgs struct {
	FuzzerName string           // fuzzer name
	Results    []TestPairResult // completed test pair results
}

// ===============DDRD====================
// RPC structures for race pair management

// NewRacePairArgs for reporting newly discovered race pairs
type NewRacePairArgs struct {
	Name      string         // fuzzer name
	PairID    string         // unique pair identifier
	Prog1Data []byte         // first program data
	Prog2Data []byte         // second program data
	Races     []RacePairData // detected race pairs
	Output    []byte         // execution output
}

// NewRacePairRes response for new race pair reporting
type NewRacePairRes struct {
	// Currently empty, may add feedback later
}

// RacePairData represents a race pair for RPC communication
type RacePairData struct {
	Syscall1    string // First syscall in the race pair
	Syscall2    string // Second syscall in the race pair
	VarName1    string // First variable name identifier
	VarName2    string // Second variable name identifier
	CallStack1  uint64 // Callstack hash for first access
	CallStack2  uint64 // Callstack hash for second access
	Signal      uint64 // Race signal generated by executor
	LockType    string // Lock type (e.g., mutex, rwlock)
	AccessType1 byte   // First access type (read/write/free)
	AccessType2 byte   // Second access type (read/write/free)
	TimeDiff    uint64 // Time difference between accesses (nanoseconds)
}

// ===============DDRD====================
