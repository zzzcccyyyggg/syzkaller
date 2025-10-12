// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// Configuration flags for Config.Flags.
type EnvFlags uint64

// Note: New / changed flags should be added to parse_env_flags in executor.cc.
const (
	FlagDebug               EnvFlags = 1 << iota // debug output from executor
	FlagSignal                                   // collect feedback signals (coverage)
	FlagSandboxSetuid                            // impersonate nobody user
	FlagSandboxNamespace                         // use namespaces for sandboxing
	FlagSandboxAndroid                           // use Android sandboxing for the untrusted_app domain
	FlagExtraCover                               // collect extra coverage
	FlagEnableTun                                // setup and use /dev/tun for packet injection
	FlagEnableNetDev                             // setup more network devices for testing
	FlagEnableNetReset                           // reset network namespace between programs
	FlagEnableCgroups                            // setup cgroups for testing
	FlagEnableCloseFds                           // close fds after each program
	FlagEnableDevlinkPCI                         // setup devlink PCI device
	FlagEnableVhciInjection                      // setup and use /dev/vhci for hci packet injection
	FlagEnableWifi                               // setup and use mac80211_hwsim for wifi emulation
	FlagDelayKcovMmap                            // manage kcov memory in an optimized way
	FlagEnableNicVF                              // setup NIC VF device
)

// Per-exec flags for ExecOpts.Flags.
type ExecFlags uint64

const (
	FlagCollectSignal        ExecFlags = 1 << iota // collect feedback signals
	FlagCollectCover                               // collect coverage
	FlagDedupCover                                 // deduplicate coverage in executor
	FlagCollectComps                               // collect KCOV comparisons
	FlagThreaded                                   // use multiple threads to mitigate blocked syscalls
	FlagEnableCoverageFilter                       // setup and use bitmap to do coverage filter
	FlagCollectRace                                // collect race pair signals
	FlagTestPairSync                               // synchronize execution with another program (test pair mode)
	FlagCollectUAF                                 // collect UAF (Use-After-Free) detection signals
)

type ExecOpts struct {
	Flags ExecFlags
}

// Config is the configuration for Env.
type Config struct {
	// Path to executor binary.
	Executor string

	UseShmem      bool // use shared memory instead of pipes for communication
	UseForkServer bool // use extended protocol with handshake

	// Flags are configuation flags, defined above.
	Flags      EnvFlags
	SandboxArg int

	Timeouts targets.Timeouts
}

type CallFlags uint32

const (
	CallExecuted      CallFlags = 1 << iota // was started at all
	CallFinished                            // finished executing (rather than blocked forever)
	CallBlocked                             // finished but blocked during execution
	CallFaultInjected                       // fault was injected into this call
)

type CallInfo struct {
	Flags  CallFlags
	Signal []uint32 // feedback signal (coverage), filled if FlagSignal is set
	Cover  []uint32 // per-call coverage, filled if FlagSignal is set and cover == true,
	// if dedup == false, then cov effectively contains a trace, otherwise duplicates are removed
	Comps prog.CompMap // per-call comparison operands
	Errno int          // call errno (0 if the call was successful)

	// ===============DDRD====================
	StartTime uint64 // syscall start time (in nanoseconds)
	EndTime   uint64 // syscall end time (in nanoseconds)
}

type ProgInfo struct {
	Calls []CallInfo
	Extra CallInfo // stores Signal and Cover collected from background threads
}

type PairProgInfo struct {
	PairCount    uint32             // number of pairs
	MayRacePairs []ddrd.MayRacePair // store the detail information of each pair
	MayUAFPairs  []ddrd.MayUAFPair  // store UAF pair information
	UAFCount     uint32             // number of UAF pairs
	// Extended information for path-distance-aware scheduling
	ExtendedRacePairs []ddrd.ExtendedRacePair
	ExtendedUAFPairs  []ddrd.ExtendedUAFPair
	HasExtendedInfo   bool
}

// Race validation related structures
type RaceValidationOpts struct {
	Opts1      *ExecOpts // Options for first program
	Opts2      *ExecOpts // Options for second program
	RaceSignal uint64
	VarName1   uint64
	VarName2   uint64
	CallStack1 uint64
	CallStack2 uint64
	Sn1        uint64
	Sn2        uint64
	LockStatus uint32
	Attempts   int
}

type RaceValidationResult struct {
	RaceDetected bool
	Attempts     int
	Details      string
}

type Env struct {
	in  []byte
	out []byte

	cmd       *command
	inFile    *os.File
	outFile   *os.File
	bin       []string
	linkedBin string
	pid       int
	config    *Config

	StatExecs    uint64
	StatRestarts uint64
}

const (
	// outputSize = 16 << 20
	outputSize = 80 << 25
	statusFail = 67

	// Comparison types masks taken from KCOV headers.
	compSizeMask  = 6
	compSize8     = 6
	compConstMask = 1

	extraReplyIndex = 0xffffffff // uint32(-1)
)

func SandboxToFlags(sandbox string) (EnvFlags, error) {
	switch sandbox {
	case "none":
		return 0, nil
	case "setuid":
		return FlagSandboxSetuid, nil
	case "namespace":
		return FlagSandboxNamespace, nil
	case "android":
		return FlagSandboxAndroid, nil
	default:
		return 0, fmt.Errorf("sandbox must contain one of none/setuid/namespace/android")
	}
}

func FlagsToSandbox(flags EnvFlags) string {
	if flags&FlagSandboxSetuid != 0 {
		return "setuid"
	} else if flags&FlagSandboxNamespace != 0 {
		return "namespace"
	} else if flags&FlagSandboxAndroid != 0 {
		return "android"
	}
	return "none"
}

func MakeEnv(config *Config, pid int) (*Env, error) {
	if config.Timeouts.Slowdown == 0 || config.Timeouts.Scale == 0 ||
		config.Timeouts.Syscall == 0 || config.Timeouts.Program == 0 {
		return nil, fmt.Errorf("ipc.MakeEnv: uninitialized timeouts (%+v)", config.Timeouts)
	}
	var inf, outf *os.File
	var inmem, outmem []byte
	if config.UseShmem {
		var err error
		inf, inmem, err = osutil.CreateMemMappedFile(prog.ExecBufferSize)
		if err != nil {
			return nil, err
		}
		defer func() {
			if inf != nil {
				osutil.CloseMemMappedFile(inf, inmem)
			}
		}()
		outf, outmem, err = osutil.CreateMemMappedFile(outputSize)
		if err != nil {
			return nil, err
		}
		defer func() {
			if outf != nil {
				osutil.CloseMemMappedFile(outf, outmem)
			}
		}()
	} else {
		inmem = make([]byte, prog.ExecBufferSize)
		outmem = make([]byte, outputSize)
	}
	env := &Env{
		in:      inmem,
		out:     outmem,
		inFile:  inf,
		outFile: outf,
		bin:     append(strings.Split(config.Executor, " "), "exec"),
		pid:     pid,
		config:  config,
	}
	if len(env.bin) == 0 {
		return nil, fmt.Errorf("binary is empty string")
	}
	env.bin[0] = osutil.Abs(env.bin[0]) // we are going to chdir
	// Append pid to binary name.
	// E.g. if binary is 'syz-executor' and pid=15,
	// we create a link from 'syz-executor.15' to 'syz-executor' and use 'syz-executor.15' as binary.
	// This allows to easily identify program that lead to a crash in the log.
	// Log contains pid in "executing program 15" and crashes usually contain "Comm: syz-executor.15".
	// Note: pkg/report knowns about this and converts "syz-executor.15" back to "syz-executor".
	base := filepath.Base(env.bin[0])
	pidStr := fmt.Sprintf(".%v", pid)
	const maxLen = 16 // TASK_COMM_LEN is currently set to 16
	if len(base)+len(pidStr) >= maxLen {
		// Remove beginning of file name, in tests temp files have unique numbers at the end.
		base = base[len(base)+len(pidStr)-maxLen+1:]
	}
	binCopy := filepath.Join(filepath.Dir(env.bin[0]), base+pidStr)
	if err := os.Link(env.bin[0], binCopy); err == nil {
		env.bin[0] = binCopy
		env.linkedBin = binCopy
	}
	inf = nil
	outf = nil
	return env, nil
}

func (env *Env) Close() error {
	if env.cmd != nil {
		env.cmd.close()
	}
	if env.linkedBin != "" {
		os.Remove(env.linkedBin)
	}
	var err1, err2 error
	if env.inFile != nil {
		err1 = osutil.CloseMemMappedFile(env.inFile, env.in)
	}
	if env.outFile != nil {
		err2 = osutil.CloseMemMappedFile(env.outFile, env.out)
	}
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	default:
		return nil
	}
}

var rateLimit = time.NewTicker(1 * time.Second)

// Exec starts executor binary to execute program p and returns information about the execution:
// output: process output
// info: per-call info
// hanged: program hanged and was killed
// err0: failed to start the process or bug in executor itself.
func (env *Env) Exec(opts *ExecOpts, p *prog.Prog) (output []byte, info *ProgInfo, hanged bool, err0 error) {
	// Copy-in serialized program.
	progSize, err := p.SerializeForExec(env.in)
	if err != nil {
		err0 = err
		return
	}
	var progData []byte
	if !env.config.UseShmem {
		progData = env.in[:progSize]
	}
	// Zero out the first two words (ncmd and nsig), so that we don't have garbage there
	// if executor crashes before writing non-garbage there.
	for i := 0; i < 4; i++ {
		env.out[i] = 0
	}

	atomic.AddUint64(&env.StatExecs, 1)
	err0 = env.RestartIfNeeded(p.Target)
	if err0 != nil {
		return
	}

	output, hanged, err0 = env.cmd.exec(opts, progData)
	if err0 != nil {
		env.cmd.close()
		env.cmd = nil
		return
	}

	info, err0 = env.parseOutput(p, opts)
	if info != nil && env.config.Flags&FlagSignal == 0 {
		addFallbackSignal(p, info)
	}
	if !env.config.UseForkServer {
		env.cmd.close()
		env.cmd = nil
	}
	return
}

// execPair executes two programs concurrently in a single executor for race detection
// Returns unified race coverage results after both programs complete
func (c *command) execPair(opts1, opts2 *ExecOpts, prog1Data, prog2Data []byte, prog1Size, prog2Size int) (output []byte, hanged bool, err0 error) {
	// Debug: Log the values being sent to executor
	// log.Printf("DEBUG execPair: about to send to executor - prog1Size=%d (0x%x), prog2Size=%d (0x%x)",
	// 	prog1Size, prog1Size, prog2Size, prog2Size)

	req := &executePairReq{
		magic:            inPairMagic,
		envFlags:         uint64(c.config.Flags),
		execFlags1:       uint64(opts1.Flags),
		execFlags2:       uint64(opts2.Flags),
		pid:              uint64(c.pid),
		syscallTimeoutMS: uint64(c.config.Timeouts.Syscall / time.Millisecond),
		programTimeoutMS: uint64(c.config.Timeouts.Program / time.Millisecond),
		slowdownScale:    uint64(c.config.Timeouts.Scale),
		prog1Size:        uint64(prog1Size), // Use actual program sizes
		prog2Size:        uint64(prog2Size),
	}

	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	if _, err := c.outwp.Write(reqData); err != nil {
		output = <-c.readDone
		err0 = fmt.Errorf("executor %v: failed to write pair control pipe: %w", c.pid, err)
		return
	}

	// Send first program data
	if prog1Data != nil {
		if _, err := c.outwp.Write(prog1Data); err != nil {
			output = <-c.readDone
			err0 = fmt.Errorf("executor %v: failed to write prog1 data: %w", c.pid, err)
			return
		}
	}

	// Send second program data
	if prog2Data != nil {
		if _, err := c.outwp.Write(prog2Data); err != nil {
			output = <-c.readDone
			err0 = fmt.Errorf("executor %v: failed to write prog2 data: %w", c.pid, err)
			return
		}
	}

	// Wait for pair execution completion
	done := make(chan bool)
	hang := make(chan bool)
	go func() {
		t := time.NewTimer(c.timeout)
		select {
		case <-t.C:
			c.cmd.Process.Kill()
			hang <- true
		case <-done:
			t.Stop()
			hang <- false
		}
	}()

	exitStatus := -1

	// For pair execution, we expect a single completion message
	// indicating both programs have finished and race analysis is complete
	reply := &executeReply{}
	replyData := (*[unsafe.Sizeof(*reply)]byte)(unsafe.Pointer(reply))[:]
	if _, err := io.ReadFull(c.inrp, replyData); err != nil {
		close(done)
		if <-hang {
			hanged = true
		}
		output = <-c.readDone
		err0 = fmt.Errorf("executor %v: failed to read pair completion: %w", c.pid, err)
		return
	}

	if reply.magic != outPairMagic {
		fmt.Fprintf(os.Stderr, "executor %v: got bad pair reply magic 0x%x\n", c.pid, reply.magic)
		os.Exit(1)
	}

	exitStatus = int(reply.status)
	close(done)

	if exitStatus == 0 {
		// Pair execution was OK.
		<-hang
		return
	}

	c.cmd.Process.Kill()
	output = <-c.readDone
	err := c.wait()
	if err != nil {
		output = append(output, err.Error()...)
		output = append(output, '\n')
	}
	if <-hang {
		hanged = true
		return
	}

	if exitStatus == -1 {
		if c.cmd.ProcessState == nil {
			exitStatus = statusFail
		} else {
			exitStatus = osutil.ProcessExitStatus(c.cmd.ProcessState)
		}
	}

	if exitStatus == statusFail {
		err0 = fmt.Errorf("executor %v: pair exit status %d err %w\n%s", c.pid, exitStatus, err, output)
	}
	return
}

// ================DDRD==========================
// ExecPair executes a pair of programs with strict synchronization
// Both programs will start execution at the same time after synchronization
// Returns unified race coverage results after both programs complete
func (env *Env) ExecPair(opts1, opts2 *ExecOpts, p1, p2 *prog.Prog) (
	output []byte,
	info *PairProgInfo,
	hanged bool,
	err0 error) {

	// Validate inputs
	if p1 == nil || p2 == nil {
		err0 = fmt.Errorf("both programs must be non-nil")
		return
	}

	// Enable test pair synchronization and race collection
	if opts1 == nil || opts2 == nil {
		err0 = fmt.Errorf("both opts must be non-nil")
		return
	}

	// Serialize both programs
	prog1Size, err := p1.SerializeForExec(env.in)
	if err != nil {
		err0 = fmt.Errorf("failed to serialize program 1: %w", err)
		return
	}

	// Use a separate buffer for the second program to avoid overwriting env.in
	prog2Buffer := make([]byte, prog.ExecBufferSize)
	prog2Size, err := p2.SerializeForExec(prog2Buffer)
	if err != nil {
		err0 = fmt.Errorf("failed to serialize program 2: %w", err)
		return
	}

	var prog1Data, prog2Data []byte
	if !env.config.UseShmem {
		// Pipe mode: send program data through pipes
		prog1Data = env.in[:prog1Size]
		prog2Data = prog2Buffer[:prog2Size]
	} else {
		// Shared memory mode: programs are already in shared memory
		// For shmem mode with two programs, we need to handle this carefully

		// Ensure program 2 starts at 8-byte aligned boundary
		alignedProg1Size := (prog1Size + 7) &^ 7 // Round up to next 8-byte boundary

		if alignedProg1Size+prog2Size > len(env.in) {
			err0 = fmt.Errorf("programs too large for shared memory buffer (aligned size: %d)", alignedProg1Size+prog2Size)
			return
		}

		// Clear any padding between prog1 and prog2
		for i := prog1Size; i < alignedProg1Size; i++ {
			env.in[i] = 0
		}

		// Copy second program data starting at aligned position
		copy(env.in[alignedProg1Size:], prog2Buffer[:prog2Size])

		// In shmem mode, progData should be nil since data is already in shared memory
		prog1Data = nil
		prog2Data = nil
	}

	// Clear output buffer for race data
	for i := 0; i < 8; i++ {
		env.out[i] = 0
	}

	atomic.AddUint64(&env.StatExecs, 1)
	err0 = env.RestartIfNeeded(p1.Target)
	if err0 != nil {
		return
	}

	// Execute pair using the new execPair method
	output, hanged, err0 = env.cmd.execPair(opts1, opts2, prog1Data, prog2Data, int(prog1Size), int(prog2Size))
	if err0 != nil {
		log.Logf(1, "execPair failed: prog1_size=%d, prog2_size=%d, hanged=%v, error=%v",
			prog1Size, prog2Size, hanged, err0)
		if len(output) > 0 {
			log.Logf(2, "execPair output before error: %q", output)
		}
		env.cmd.close()
		env.cmd = nil
		return
	}

	// Parse race-focused output (simplified parsing)
	info, err0 = env.parsePairOutput(p1, p2)
	if err0 != nil {
		// Truncate program strings to avoid overly long logs
		prog1Str := p1.String()
		if len(prog1Str) > 100 {
			prog1Str = prog1Str[:100]
		}
		prog2Str := p2.String()
		if len(prog2Str) > 100 {
			prog2Str = prog2Str[:100]
		}
		log.Logf(1, "parsePairOutput failed: prog1=%s, prog2=%s, output_len=%d, error=%v",
			prog1Str, prog2Str, len(output), err0)
	}
	if !env.config.UseForkServer {
		env.cmd.close()
		env.cmd = nil
	}

	return
}

// parseMayRacePair manually parses a MayRacePair from byte array
// This avoids unsafe pointer conversion and memory alignment issues
func parseMayRacePair(data []byte) (*ddrd.MayRacePair, error) {
	if len(data) < 84 { // Should match C struct size
		return nil, fmt.Errorf("insufficient data for MayRacePair: need 84 bytes, got %d", len(data))
	}

	pair := &ddrd.MayRacePair{}
	offset := 0

	// Parse fields according to new Go struct order (matching C send order)
	pair.VarName1 = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	pair.VarName2 = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	pair.CallStack1 = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	pair.CallStack2 = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	pair.Signal = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	pair.TimeDiff = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	pair.Sn1 = int32(prog.HostEndian.Uint32(data[offset:]))
	offset += 4
	pair.Sn2 = int32(prog.HostEndian.Uint32(data[offset:]))
	offset += 4
	pair.Syscall1Idx = int32(prog.HostEndian.Uint32(data[offset:]))
	offset += 4
	pair.Syscall2Idx = int32(prog.HostEndian.Uint32(data[offset:]))
	offset += 4
	pair.Syscall1Num = int32(prog.HostEndian.Uint32(data[offset:]))
	offset += 4
	pair.Syscall2Num = int32(prog.HostEndian.Uint32(data[offset:]))
	offset += 4
	pair.LockType = prog.HostEndian.Uint32(data[offset:])
	offset += 4
	pair.AccessType1 = prog.HostEndian.Uint32(data[offset:])
	offset += 4
	pair.AccessType2 = prog.HostEndian.Uint32(data[offset:])
	offset += 4
	// Total: 84 bytes

	return pair, nil
}

// parseMayUAFPair parses UAF pair data from executor
func parseMayUAFPair(data []byte) (*ddrd.MayUAFPair, error) {
	if len(data) < 80 { // Match new Go struct size (80 bytes)
		return nil, fmt.Errorf("insufficient data for MayUAFPair: need 80 bytes, got %d", len(data))
	}

	pair := &ddrd.MayUAFPair{}
	offset := 0

	// Parse fields according to new Go struct order (matching C send order)
	pair.FreeAccessName = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	pair.UseAccessName = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	pair.FreeCallStack = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	pair.UseCallStack = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	pair.Signal = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	pair.TimeDiff = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	pair.FreeSyscallIdx = int32(prog.HostEndian.Uint32(data[offset:]))
	offset += 4
	pair.UseSyscallIdx = int32(prog.HostEndian.Uint32(data[offset:]))
	offset += 4
	pair.FreeSyscallNum = int32(prog.HostEndian.Uint32(data[offset:]))
	offset += 4
	pair.UseSyscallNum = int32(prog.HostEndian.Uint32(data[offset:]))
	offset += 4
	pair.FreeSN = int32(prog.HostEndian.Uint32(data[offset:]))
	offset += 4
	pair.UseSN = int32(prog.HostEndian.Uint32(data[offset:]))
	offset += 4
	pair.LockType = prog.HostEndian.Uint32(data[offset:])
	offset += 4
	pair.UseAccessType = prog.HostEndian.Uint32(data[offset:])
	offset += 4
	// Total should be 80 bytes

	return pair, nil
}

// parseExtendedRacePair parses extended race pair data with history
func parseExtendedRacePair(data []byte) (*ddrd.ExtendedRacePair, error) {
	// 计算最小所需大小：基本信息(84) + 计数信息(8) + 目标时间(16) + 路径距离(16) = 124字节 + 历史记录数据
	if len(data) < 124 {
		return nil, fmt.Errorf("insufficient data for ExtendedRacePair header: need at least 124 bytes, got %d", len(data))
	}

	extPair := &ddrd.ExtendedRacePair{}
	offset := 0

	// Parse basic race info (84 bytes)
	basicData := data[offset : offset+84]
	basicPair, err := parseMayRacePair(basicData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse basic race info: %w", err)
	}
	extPair.BasicInfo = *basicPair
	offset += 84

	// Parse extended fields
	extPair.Thread1HistoryCount = prog.HostEndian.Uint32(data[offset:])
	offset += 4
	extPair.Thread2HistoryCount = prog.HostEndian.Uint32(data[offset:])
	offset += 4
	extPair.Thread1TargetTime = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	extPair.Thread2TargetTime = prog.HostEndian.Uint64(data[offset:])
	offset += 8

	// Parse access history records directly
	totalRecords := extPair.Thread1HistoryCount + extPair.Thread2HistoryCount
	recordSize := 8 + 8 + 8 + 4 + 4 // serialized_access_record_t size = 32 bytes
	expectedHistorySize := uint32(recordSize) * totalRecords

	if uint32(len(data)) < 104+expectedHistorySize { // No path distances in simplified structure
		return nil, fmt.Errorf("insufficient data for access history: need %d bytes, got %d",
			104+expectedHistorySize, len(data))
	}

	extPair.AccessHistory = make([]ddrd.SerializedAccessRecord, totalRecords)
	for i := uint32(0); i < totalRecords; i++ {
		record := &extPair.AccessHistory[i]
		record.VarName = prog.HostEndian.Uint64(data[offset:])
		offset += 8
		record.CallStackHash = prog.HostEndian.Uint64(data[offset:])
		offset += 8
		record.AccessTime = prog.HostEndian.Uint64(data[offset:])
		offset += 8
		record.SN = prog.HostEndian.Uint32(data[offset:])
		offset += 4
		record.AccessType = prog.HostEndian.Uint32(data[offset:])
		offset += 4
	}

	return extPair, nil
}

// parseExtendedUAFPair parses extended UAF pair data with history
func parseExtendedUAFPair(data []byte) (*ddrd.ExtendedUAFPair, error) {
	// 扩展UAF数据结构：
	// - 扩展头部：4 + 4 + 8 + 8 = 24字节 (计数 + 目标时间)
	// - 历史记录：变长 (count × 32字节)
	// - 路径距离：8 + 8 = 16字节
	// 最小大小：24 + 16 = 40字节
	if len(data) < 40 {
		return nil, fmt.Errorf("insufficient data for ExtendedUAFPair header: need at least 40 bytes, got %d", len(data))
	}

	extUAF := &ddrd.ExtendedUAFPair{}
	offset := 0

	// Parse extended header fields (executor doesn't send basic UAF info again)
	extUAF.UseThreadHistoryCount = prog.HostEndian.Uint32(data[offset:])
	offset += 4
	extUAF.FreeThreadHistoryCount = prog.HostEndian.Uint32(data[offset:])
	offset += 4
	extUAF.UseTargetTime = prog.HostEndian.Uint64(data[offset:])
	offset += 8
	extUAF.FreeTargetTime = prog.HostEndian.Uint64(data[offset:])
	offset += 8

	// Parse access history records
	totalRecords := extUAF.UseThreadHistoryCount + extUAF.FreeThreadHistoryCount
	recordSize := 32 // serialized_access_record_t size = 3×8 + 2×4 = 32 bytes
	expectedHistorySize := int(recordSize) * int(totalRecords)

	if len(data) < 24+expectedHistorySize+16 {
		return nil, fmt.Errorf("insufficient data for access history: need %d bytes, got %d",
			24+expectedHistorySize+16, len(data))
	}

	extUAF.AccessHistory = make([]ddrd.SerializedAccessRecord, totalRecords)
	for i := uint32(0); i < totalRecords; i++ {
		record := &extUAF.AccessHistory[i]
		record.VarName = prog.HostEndian.Uint64(data[offset:])
		offset += 8
		record.CallStackHash = prog.HostEndian.Uint64(data[offset:])
		offset += 8
		record.AccessTime = prog.HostEndian.Uint64(data[offset:])
		offset += 8
		record.SN = prog.HostEndian.Uint32(data[offset:])
		offset += 4
		record.AccessType = prog.HostEndian.Uint32(data[offset:])
		offset += 4
	}

	// Skip path distances (sent as uint64 but not stored in Go struct)
	// TODO: Add path distance fields to ExtendedUAFPair struct if needed
	offset += 8 // pathDistUse
	offset += 8 // pathDistFree

	return extUAF, nil
}

// parsePairOutput parses the race detection output from pair execution
func (env *Env) parsePairOutput(_, _ *prog.Prog) (*PairProgInfo, error) {

	out := env.out

	// Debug: Show initial buffer state
	debugLen := 32
	if len(out) < debugLen {
		debugLen = len(out)
	}
	// fmt.Printf("DEBUG parsePairOutput: initial buffer length=%d, first %d bytes: %v\n",
	// 	len(out), debugLen, out[:debugLen])

	info := &PairProgInfo{}

	// Parse multiple sections with different magics
	if len(out) >= 8 { // At least magic + count
		magic, ok := readUint32(&out)
		if !ok {
			return nil, fmt.Errorf("failed to read magic")
		}

		switch magic {
		case outPairMagic:
			// Parse basic race pairs
			err := env.parseBasicRacePairs(&out, info)
			if err != nil {
				return nil, fmt.Errorf("failed to parse basic race pairs: %w", err)
			}

		case outUAFMagic:
			// Parse basic UAF pairs
			// fmt.Printf("DEBUG parsePairOutput: parsing basic UAF pairs\n")
			err := env.parseBasicUAFPairs(&out, info)
			if err != nil {
				return nil, fmt.Errorf("failed to parse basic UAF pairs: %w", err)
			}

		case outExtendedPairMagic:
			// Parse extended race pairs
			err := env.parseExtendedRacePairs(&out, info)
			if err != nil {
				return nil, fmt.Errorf("failed to parse extended race pairs: %w", err)
			}
			info.HasExtendedInfo = true

		case outExtendedUAFMagic:
			// Parse extended UAF pairs
			err := env.parseExtendedUAFPairs(&out, info)
			if err != nil {
				return nil, fmt.Errorf("failed to parse extended UAF pairs: %w", err)
			}
			info.HasExtendedInfo = true

		default:
			return nil, fmt.Errorf("unknown magic 0x%x", magic)
		}
	}

	// fmt.Printf("DEBUG parsePairOutput: successfully parsed race_pairs=%d, uaf_pairs=%d, extended_info=%v\n",
	// 	len(info.MayRacePairs), len(info.MayUAFPairs), info.HasExtendedInfo)
	return info, nil
}

// parseBasicRacePairs parses basic race pair data
func (env *Env) parseBasicRacePairs(out *[]byte, info *PairProgInfo) error {
	pairCount, ok := readUint32(out)
	if !ok {
		return fmt.Errorf("failed to read race pair count")
	}

	info.MayRacePairs = make([]ddrd.MayRacePair, pairCount)
	info.PairCount = pairCount

	const pairDataSize = 84
	for i := uint32(0); i < pairCount; i++ {
		if len(*out) < pairDataSize {
			return fmt.Errorf("race pair %v: truncated output, need %d bytes but only %d available", i, pairDataSize, len(*out))
		}

		mayRacePair, err := parseMayRacePair((*out)[:pairDataSize])
		if err != nil {
			return fmt.Errorf("failed to parse race pair %d: %w", i, err)
		}

		info.MayRacePairs[i] = *mayRacePair
		*out = (*out)[pairDataSize:]
	}
	return nil
}

// parseBasicUAFPairs parses basic UAF pair data
func (env *Env) parseBasicUAFPairs(out *[]byte, info *PairProgInfo) error {
	uafCount, ok := readUint32(out)
	// fmt.Printf("DEBUG parseBasicUAFPairs: UAF pair count = %d\n", uafCount)
	if !ok {
		return fmt.Errorf("failed to read UAF pair count")
	}

	info.MayUAFPairs = make([]ddrd.MayUAFPair, uafCount)
	info.UAFCount = uafCount

	const uafDataSize = 80 // Match executor UAF output size (6×8 + 8×4 = 80 bytes)
	for i := uint32(0); i < uafCount; i++ {
		if len(*out) < uafDataSize {
			return fmt.Errorf("UAF pair %v: truncated output, need %d bytes but only %d available", i, uafDataSize, len(*out))
		}

		mayUAFPair, err := parseMayUAFPair((*out)[:uafDataSize])
		if err != nil {
			return fmt.Errorf("failed to parse UAF pair %d: %w", i, err)
		}

		// 详细输出UAF pair结构体信息
		fmt.Printf("DEBUG UAF Pair %d:\n", i)
		fmt.Printf("  FreeAccessName: 0x%016x\n", mayUAFPair.FreeAccessName)
		fmt.Printf("  UseAccessName:  0x%016x\n", mayUAFPair.UseAccessName)
		fmt.Printf("  FreeCallStack:  0x%016x\n", mayUAFPair.FreeCallStack)
		fmt.Printf("  UseCallStack:   0x%016x\n", mayUAFPair.UseCallStack)
		fmt.Printf("  Signal:         0x%016x\n", mayUAFPair.Signal)
		fmt.Printf("  TimeDiff:       %d ns\n", mayUAFPair.TimeDiff)
		fmt.Printf("  FreeSyscallIdx: %d\n", mayUAFPair.FreeSyscallIdx)
		fmt.Printf("  UseSyscallIdx:  %d\n", mayUAFPair.UseSyscallIdx)
		fmt.Printf("  FreeSyscallNum: %d\n", mayUAFPair.FreeSyscallNum)
		fmt.Printf("  UseSyscallNum:  %d\n", mayUAFPair.UseSyscallNum)
		fmt.Printf("  FreeSN:         %d\n", mayUAFPair.FreeSN)
		fmt.Printf("  UseSN:          %d\n", mayUAFPair.UseSN)
		fmt.Printf("  LockType:       %d\n", mayUAFPair.LockType)
		fmt.Printf("  UseAccessType:  %d\n", mayUAFPair.UseAccessType)
		fmt.Printf("  StructSize:     %d bytes (expected: %d)\n", uafDataSize, uafDataSize)
		fmt.Println()

		info.MayUAFPairs[i] = *mayUAFPair
		*out = (*out)[uafDataSize:]
	}

	return nil
}

// parseExtendedRacePairs parses extended race pair data with history
func (env *Env) parseExtendedRacePairs(out *[]byte, info *PairProgInfo) error {
	extRaceCount, ok := readUint32(out)
	if !ok {
		return fmt.Errorf("failed to read extended race pair count")
	}

	info.ExtendedRacePairs = make([]ddrd.ExtendedRacePair, extRaceCount)

	// Extended race pair size: basic(84) + history_counts(8) + target_times(16) + variable history size
	// We need to calculate the actual size based on history counts
	const extRaceMinSize = 108 // Minimum size without history data
	for i := uint32(0); i < extRaceCount; i++ {
		if len(*out) < extRaceMinSize {
			return fmt.Errorf("extended race pair %v: truncated output, need at least %d bytes but only %d available", i, extRaceMinSize, len(*out))
		}

		// Calculate actual size by reading the history counts first
		thread1Count := prog.HostEndian.Uint32((*out)[84:88])
		thread2Count := prog.HostEndian.Uint32((*out)[88:92])
		recordSize := uint32(32) // New simplified record size
		totalHistorySize := recordSize * (thread1Count + thread2Count)
		actualSize := extRaceMinSize + totalHistorySize

		if len(*out) < int(actualSize) {
			return fmt.Errorf("extended race pair %v: insufficient data for history, need %d bytes but only %d available", i, actualSize, len(*out))
		}

		extRacePair, err := parseExtendedRacePair((*out)[:actualSize])
		if err != nil {
			return fmt.Errorf("failed to parse extended race pair %d: %w", i, err)
		}

		info.ExtendedRacePairs[i] = *extRacePair
		*out = (*out)[actualSize:]
	}
	return nil
}

// parseExtendedUAFPairs parses extended UAF pair data with history
func (env *Env) parseExtendedUAFPairs(out *[]byte, info *PairProgInfo) error {
	extUAFCount, ok := readUint32(out)
	if !ok {
		return fmt.Errorf("failed to read extended UAF pair count")
	}

	info.ExtendedUAFPairs = make([]ddrd.ExtendedUAFPair, extUAFCount)

	for i := uint32(0); i < extUAFCount; i++ {
		// 读取计数信息来计算大小
		if len(*out) < 8 {
			return fmt.Errorf("extended UAF pair %v: insufficient data for history counts", i)
		}

		useCount := prog.HostEndian.Uint32((*out)[0:4])  // 正确偏移
		freeCount := prog.HostEndian.Uint32((*out)[4:8]) // 正确偏移

		// 计算实际大小
		recordSize := uint32(32) // serialized_access_record_t = 3×8 + 2×4 = 32字节
		totalHistorySize := recordSize * (useCount + freeCount)
		actualSize := 24 + totalHistorySize + 16 // 扩展头部 + 历史 + 路径距离

		if len(*out) < int(actualSize) {
			return fmt.Errorf("extended UAF pair %v: insufficient data, need %d bytes but only %d available", i, actualSize, len(*out))
		}

		extUAFPair, err := parseExtendedUAFPair((*out)[:actualSize])
		if err != nil {
			return fmt.Errorf("failed to parse extended UAF pair %d: %w", i, err)
		}

		info.ExtendedUAFPairs[i] = *extUAFPair
		*out = (*out)[actualSize:]
	}
	return nil
}

// ExecPairOpts holds options for ExecPair execution
type ExecPairOpts struct {
	Opts1 *ExecOpts // Options for first program
	Opts2 *ExecOpts // Options for second program

	// Additional pair-specific options
	SyncTimeout          time.Duration // Maximum time to wait for sync (default: 10s)
	EnableRaceCollection bool          // Enable race detection for both programs
}

// ExecPairWithOpts executes a pair of programs with advanced options
func (env *Env) ExecPairWithOpts(pairOpts *ExecPairOpts, p1, p2 *prog.Prog) (
	output []byte,
	info *PairProgInfo,
	hanged bool,
	err0 error) {

	if pairOpts == nil {
		pairOpts = &ExecPairOpts{}
	}

	// Set default sync timeout
	if pairOpts.SyncTimeout == 0 {
		pairOpts.SyncTimeout = 10 * time.Second
	}

	opts1 := pairOpts.Opts1
	opts2 := pairOpts.Opts2
	if opts1 == nil {
		opts1 = &ExecOpts{}
	}
	if opts2 == nil {
		opts2 = &ExecOpts{}
	}

	// Enable test pair sync and race collection if requested
	opts1.Flags |= FlagTestPairSync
	opts2.Flags |= FlagTestPairSync

	if pairOpts.EnableRaceCollection {
		opts1.Flags |= FlagCollectRace | FlagCollectUAF
		opts2.Flags |= FlagCollectRace | FlagCollectUAF
	}

	// Use the unified ExecPair implementation
	return env.ExecPair(opts1, opts2, p1, p2)
}

// RaceValidation executes race validation using executor's standalone race validation mode
func (env *Env) RaceValidation(opts *RaceValidationOpts, p1, p2 *prog.Prog) (output []byte, hanged bool, err0 error) {
	if p1 == nil || p2 == nil {
		err0 = fmt.Errorf("both programs must be non-nil")
		return nil, false, err0
	}

	if opts.Opts1 == nil {
		opts.Opts1 = &ExecOpts{}
	}
	if opts.Opts2 == nil {
		opts.Opts2 = &ExecOpts{}
	}

	if opts.Attempts <= 0 {
		opts.Attempts = 1
	}

	// Serialize both programs
	prog1Size, err := p1.SerializeForExec(env.in)
	if err != nil {
		err0 = fmt.Errorf("failed to serialize program 1: %w", err)
		return
	}

	// Use a separate buffer for the second program to avoid overwriting env.in
	prog2Buffer := make([]byte, prog.ExecBufferSize)
	prog2Size, err := p2.SerializeForExec(prog2Buffer)
	if err != nil {
		err0 = fmt.Errorf("failed to serialize program 2: %w", err)
		return
	}
	var prog1Data, prog2Data []byte
	if !env.config.UseShmem {
		// Pipe mode: send program data through pipes
		prog1Data = env.in[:prog1Size]
		prog2Data = prog2Buffer[:prog2Size]
	} else {
		// Shared memory mode: programs are already in shared memory
		// For shmem mode with two programs, we need to handle this carefully

		// Ensure program 2 starts at 8-byte aligned boundary
		alignedProg1Size := (prog1Size + 7) &^ 7 // Round up to next 8-byte boundary

		if alignedProg1Size+prog2Size > len(env.in) {
			err0 = fmt.Errorf("programs too large for shared memory buffer (aligned size: %d)", alignedProg1Size+prog2Size)
			return
		}

		// Clear any padding between prog1 and prog2
		for i := prog1Size; i < alignedProg1Size; i++ {
			env.in[i] = 0
		}

		// Copy second program data starting at aligned position
		copy(env.in[alignedProg1Size:], prog2Buffer[:prog2Size])

		// In shmem mode, progData should be nil since data is already in shared memory
		prog1Data = nil
		prog2Data = nil
	}

	// Clear output buffer for race data
	for i := 0; i < 8; i++ {
		env.out[i] = 0
	}

	err0 = env.RestartIfNeeded(p1.Target)
	if err0 != nil {
		return
	}

	output, hanged, err0 = env.cmd.execRaceValidation(opts, prog1Data, prog2Data, int(prog1Size), int(prog2Size))
	if err0 != nil {
		env.cmd.close()
		env.cmd = nil
		return
	}

	return
}

func (env *Env) ForceRestart() {
	if env.cmd != nil {
		env.cmd.close()
		env.cmd = nil
	}
}

// This smethod brings up an executor process if it was stopped.
func (env *Env) RestartIfNeeded(target *prog.Target) error {
	if env.cmd == nil {
		if target.OS != targets.TestOS && targets.Get(target.OS, target.Arch).HostFuzzer {
			// The executor is actually ssh,
			// starting them too frequently leads to timeouts.
			<-rateLimit.C
		}
		tmpDirPath := "./"
		atomic.AddUint64(&env.StatRestarts, 1)
		var err error
		env.cmd, err = makeCommand(env.pid, env.bin, env.config, env.inFile, env.outFile, env.out, tmpDirPath)
		return err
	}
	return nil
}

// addFallbackSignal computes simple fallback signal in cases we don't have real coverage signal.
// We use syscall number or-ed with returned errno value as signal.
// At least this gives us all combinations of syscall+errno.
func addFallbackSignal(p *prog.Prog, info *ProgInfo) {
	callInfos := make([]prog.CallInfo, len(info.Calls))
	for i, inf := range info.Calls {
		if inf.Flags&CallExecuted != 0 {
			callInfos[i].Flags |= prog.CallExecuted
		}
		if inf.Flags&CallFinished != 0 {
			callInfos[i].Flags |= prog.CallFinished
		}
		if inf.Flags&CallBlocked != 0 {
			callInfos[i].Flags |= prog.CallBlocked
		}
		callInfos[i].Errno = inf.Errno
	}
	p.FallbackSignal(callInfos)
	for i, inf := range callInfos {
		info.Calls[i].Signal = inf.Signal
	}
}

func (env *Env) parseOutput(p *prog.Prog, opts *ExecOpts) (*ProgInfo, error) {
	out := env.out
	ncmd, ok := readUint32(&out)
	if !ok {
		return nil, fmt.Errorf("failed to read number of calls")
	}
	info := &ProgInfo{Calls: make([]CallInfo, len(p.Calls))}
	extraParts := make([]CallInfo, 0)
	for i := uint32(0); i < ncmd; i++ {
		if len(out) < int(unsafe.Sizeof(callReply{})) {
			return nil, fmt.Errorf("failed to read call %v reply", i)
		}

		// Try to find correct reply position by searching for correct magic
		reply := *(*callReply)(unsafe.Pointer(&out[0]))
		searchOffset := 0

		if reply.magic != outMagic {
			fmt.Fprintf(os.Stderr, "DEBUG: Bad reply magic detected at call %d!\n", i)
			fmt.Fprintf(os.Stderr, "  Expected magic: 0x%x\n", outMagic)
			fmt.Fprintf(os.Stderr, "  Actual magic: 0x%x\n", reply.magic)

			// Search forward 4 bytes at a time for the correct magic
			maxSearchBytes := 64 // Limit search to 64 bytes to avoid infinite loop
			for searchOffset = 4; searchOffset < maxSearchBytes && searchOffset < len(out)-int(unsafe.Sizeof(callReply{})); searchOffset += 4 {
				testReply := *(*callReply)(unsafe.Pointer(&out[searchOffset]))
				if testReply.magic == outMagic {
					fmt.Fprintf(os.Stderr, "  Found correct magic at offset %d bytes\n", searchOffset)
					reply = testReply
					break
				}
			}
		}

		// Adjust the output buffer position based on search offset
		out = out[searchOffset:]
		out = out[unsafe.Sizeof(callReply{}):]
		var inf *CallInfo
		// 判断是正常syscall写入的相关数据 还是 extra
		if reply.index != extraReplyIndex {
			if int(reply.index) >= len(info.Calls) {
				return nil, fmt.Errorf("bad call %v index %v/%v", i, reply.index, len(info.Calls))
			}
			if num := p.Calls[reply.index].Meta.ID; int(reply.num) != num {
				return nil, fmt.Errorf("wrong call %v num %v/%v", i, reply.num, num)
			}
			inf = &info.Calls[reply.index]
			if inf.Flags != 0 || inf.Signal != nil {
				return nil, fmt.Errorf("duplicate reply for call %v/%v/%v", i, reply.index, reply.num)
			}
			inf.Errno = int(reply.errno)
			inf.Flags = CallFlags(reply.flags)

			// ===============DDRD====================
			// Parse timing information
			inf.StartTime = uint64(reply.startTimeLow) | (uint64(reply.startTimeHigh) << 32)
			inf.EndTime = uint64(reply.endTimeLow) | (uint64(reply.endTimeHigh) << 32)
			// ===============DDRD====================
		} else {
			extraParts = append(extraParts, CallInfo{})
			inf = &extraParts[len(extraParts)-1]
		}
		// Read coverage signals
		if inf.Signal, ok = readUint32Array(&out, reply.signalSize); !ok {
			return nil, fmt.Errorf("call %v/%v/%v: signal overflow: %v/%v",
				i, reply.index, reply.num, reply.signalSize, len(out))
		}

		if inf.Cover, ok = readUint32Array(&out, reply.coverSize); !ok {
			return nil, fmt.Errorf("call %v/%v/%v: cover overflow: %v/%v",
				i, reply.index, reply.num, reply.coverSize, len(out))
		}
		comps, err := readComps(&out, reply.compsSize)
		if err != nil {
			return nil, err
		}
		inf.Comps = comps
	}
	if len(extraParts) == 0 {
		return info, nil
	}
	info.Extra = convertExtra(extraParts, opts.Flags&FlagDedupCover > 0)
	return info, nil
}

func convertExtra(extraParts []CallInfo, dedupCover bool) CallInfo {
	var extra CallInfo
	if dedupCover {
		// Use a simple map for deduplication instead of cover.Cover
		extraCover := make(map[uint32]struct{})
		for _, part := range extraParts {
			for _, pc := range part.Cover {
				extraCover[pc] = struct{}{}
			}
		}
		// Convert back to slice
		extra.Cover = make([]uint32, 0, len(extraCover))
		for pc := range extraCover {
			extra.Cover = append(extra.Cover, pc)
		}
	} else {
		for _, part := range extraParts {
			extra.Cover = append(extra.Cover, part.Cover...)
		}
	}

	// Process coverage signals
	extraSignal := make(signal.Signal)
	for _, part := range extraParts {
		extraSignal.Merge(signal.FromRaw(part.Signal, 0))
	}
	extra.Signal = make([]uint32, len(extraSignal))
	i := 0
	for s := range extraSignal {
		extra.Signal[i] = uint32(s)
		i++
	}

	return extra
}

func readComps(outp *[]byte, compsSize uint32) (prog.CompMap, error) {
	if compsSize == 0 {
		return nil, nil
	}
	compMap := make(prog.CompMap)
	for i := uint32(0); i < compsSize; i++ {
		typ, ok := readUint32(outp)
		if !ok {
			return nil, fmt.Errorf("failed to read comp %v", i)
		}
		if typ > compConstMask|compSizeMask {
			return nil, fmt.Errorf("bad comp %v type %v", i, typ)
		}
		var op1, op2 uint64
		var ok1, ok2 bool
		if typ&compSizeMask == compSize8 {
			op1, ok1 = readUint64(outp)
			op2, ok2 = readUint64(outp)
		} else {
			var tmp1, tmp2 uint32
			tmp1, ok1 = readUint32(outp)
			tmp2, ok2 = readUint32(outp)
			op1, op2 = uint64(tmp1), uint64(tmp2)
		}
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("failed to read comp %v op", i)
		}
		if op1 == op2 {
			continue // it's useless to store such comparisons
		}
		compMap.AddComp(op2, op1)
		if (typ & compConstMask) != 0 {
			// If one of the operands was const, then this operand is always
			// placed first in the instrumented callbacks. Such an operand
			// could not be an argument of our syscalls (because otherwise
			// it wouldn't be const), thus we simply ignore it.
			continue
		}
		compMap.AddComp(op1, op2)
	}
	return compMap, nil
}

func readUint32(outp *[]byte) (uint32, bool) {
	out := *outp
	if len(out) < 4 {
		return 0, false
	}
	v := prog.HostEndian.Uint32(out)
	*outp = out[4:]
	return v, true
}

func readUint64(outp *[]byte) (uint64, bool) {
	out := *outp
	if len(out) < 8 {
		return 0, false
	}
	v := prog.HostEndian.Uint64(out)
	*outp = out[8:]
	return v, true
}

func readUint32Array(outp *[]byte, size uint32) ([]uint32, bool) {
	if size == 0 {
		return nil, true
	}
	out := *outp
	if int(size)*4 > len(out) {
		return nil, false
	}
	var res []uint32
	hdr := (*reflect.SliceHeader)((unsafe.Pointer(&res)))
	hdr.Data = uintptr(unsafe.Pointer(&out[0]))
	hdr.Len = int(size)
	hdr.Cap = int(size)
	*outp = out[size*4:]
	return res, true
}

// ===============DDRD====================
func readUint64Array(outp *[]byte, size uint32) ([]uint64, bool) {
	if size == 0 {
		return nil, true
	}
	out := *outp
	if int(size)*8 > len(out) {
		return nil, false
	}
	var res []uint64
	hdr := (*reflect.SliceHeader)((unsafe.Pointer(&res)))
	hdr.Data = uintptr(unsafe.Pointer(&out[0]))
	hdr.Len = int(size)
	hdr.Cap = int(size)
	*outp = out[size*8:]
	return res, true
}

// ===============DDRD====================

func readByteArray(outp *[]byte, size uint32) ([]byte, bool) {
	if size == 0 {
		return nil, true
	}
	out := *outp
	if int(size) > len(out) {
		return nil, false
	}
	res := make([]byte, size)
	copy(res, out[:size])
	*outp = out[size:]
	return res, true
}

type command struct {
	pid      int
	config   *Config
	timeout  time.Duration
	cmd      *exec.Cmd
	dir      string
	readDone chan []byte
	exited   chan error
	inrp     *os.File
	outwp    *os.File
	outmem   []byte
}

const (
	inMagic                = uint64(0xbadc0ffeebadface)
	inPairMagic            = uint64(0xbadc0ffeebadfa0e) // Magic for pair execution requests
	inRaceValidationMagic  = uint64(0xbadc0ffeebadfade) // Magic for race validation requests
	outMagic               = uint32(0xbadf00d)
	outPairMagic           = uint32(0xbadfeed)
	outUAFMagic            = uint32(0xbadfaad) // Basic UAF info
	outExtendedPairMagic   = uint32(0xbadface) // Extended race info magic
	outExtendedUAFMagic    = uint32(0xbadfeee) // Extended UAF info magic
	outRaceValidationMagic = uint32(0xbadfa1d)
)

type handshakeReq struct {
	magic      uint64
	flags      uint64 // env flags
	pid        uint64
	sandboxArg uint64
}

type handshakeReply struct {
	magic uint32
}

type executeReq struct {
	magic            uint64
	envFlags         uint64 // env flags
	execFlags        uint64 // exec flags
	pid              uint64
	syscallTimeoutMS uint64
	programTimeoutMS uint64
	slowdownScale    uint64
	progSize         uint64
	// This structure is followed by a serialized test program in encodingexec format.
	// Both when sent over a pipe or in shared memory.
}

// executePairReq is for concurrent execution of two programs in a single executor
type executePairReq struct {
	magic            uint64
	envFlags         uint64 // env flags
	execFlags1       uint64 // exec flags for first program
	execFlags2       uint64 // exec flags for second program
	pid              uint64
	syscallTimeoutMS uint64
	programTimeoutMS uint64
	slowdownScale    uint64
	prog1Size        uint64 // size of first program
	prog2Size        uint64 // size of second program
	// This structure is followed by two serialized test programs in encodingexec format.
}

// raceValidationReq is for race validation execution
type raceValidationReq struct {
	magic        uint64
	prog1Size    uint64
	prog2Size    uint64
	raceSignal   uint64
	varName1     uint64
	varName2     uint64
	callStack1   uint64
	callStack2   uint64
	sn1          uint64
	sn2          uint64
	lockStatus   uint32
	attemptCount uint32
	// This structure is followed by two serialized test programs
}

type executeReply struct {
	magic uint32
	// If done is 0, then this is call completion message followed by callReply.
	// If done is 1, then program execution is finished and status is set.
	done   uint32
	status uint32
}

type callReply struct {
	magic uint32
	index uint32 // call index in the program
	num   uint32 // syscall number (for cross-checking)
	errno uint32
	flags uint32 // see CallFlags

	// ===============DDRD====================
	startTimeLow  uint32 // syscall start time (low 32 bits, nanoseconds)
	startTimeHigh uint32 // syscall start time (high 32 bits, nanoseconds)
	endTimeLow    uint32 // syscall end time (low 32 bits, nanoseconds)
	endTimeHigh   uint32 // syscall end time (high 32 bits, nanoseconds)
	// ===============DDRD====================

	signalSize uint32 // coverage signals
	coverSize  uint32
	compsSize  uint32
	// signal/race-signal/cover/comps/race-mapping follow
}

func makeCommand(pid int, bin []string, config *Config, inFile, outFile *os.File, outmem []byte,
	tmpDirPath string) (*command, error) {
	dir, err := os.MkdirTemp(tmpDirPath, "syzkaller-testdir")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	dir = osutil.Abs(dir)

	timeout := config.Timeouts.Program
	if config.UseForkServer {
		// Executor has an internal timeout and protects against most hangs when fork server is enabled,
		// so we use quite large timeout. Executor can be slow due to global locks in namespaces
		// and other things, so let's better wait than report false misleading crashes.
		timeout *= 5
	}

	c := &command{
		pid:     pid,
		config:  config,
		timeout: timeout,
		dir:     dir,
		outmem:  outmem,
	}
	defer func() {
		if c != nil {
			c.close()
		}
	}()

	if err := os.Chmod(dir, 0777); err != nil {
		return nil, fmt.Errorf("failed to chmod temp dir: %w", err)
	}

	// Output capture pipe.
	rp, wp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %w", err)
	}
	defer wp.Close()

	// executor->ipc command pipe.
	inrp, inwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %w", err)
	}
	defer inwp.Close()
	c.inrp = inrp

	// ipc->executor command pipe.
	outrp, outwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %w", err)
	}
	defer outrp.Close()
	c.outwp = outwp

	c.readDone = make(chan []byte, 1)

	cmd := osutil.Command(bin[0], bin[1:]...)
	if inFile != nil && outFile != nil {
		cmd.ExtraFiles = []*os.File{inFile, outFile}
	}
	cmd.Dir = dir
	// Tell ASAN to not mess with our NONFAILING.
	cmd.Env = append(append([]string{}, os.Environ()...), "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1")
	cmd.Stdin = outrp
	cmd.Stdout = inwp
	if config.Flags&FlagDebug != 0 {
		close(c.readDone)
		cmd.Stderr = os.Stdout
	} else {
		cmd.Stderr = wp
		go func(c *command) {
			// Read out output in case executor constantly prints something.
			const bufSize = 128 << 10
			output := make([]byte, bufSize)
			var size uint64
			for {
				n, err := rp.Read(output[size:])
				if n > 0 {
					size += uint64(n)
					if size >= bufSize*3/4 {
						copy(output, output[size-bufSize/2:size])
						size = bufSize / 2
					}
				}
				if err != nil {
					rp.Close()
					c.readDone <- output[:size]
					close(c.readDone)
					return
				}
			}
		}(c)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start executor binary: %w", err)
	}
	c.exited = make(chan error, 1)
	c.cmd = cmd
	go func(c *command) {
		err := c.cmd.Wait()
		c.exited <- err
		close(c.exited)
		// Avoid a livelock if cmd.Stderr has been leaked to another alive process.
		rp.SetDeadline(time.Now().Add(5 * time.Second))
	}(c)
	wp.Close()
	// Note: we explicitly close inwp before calling handshake even though we defer it above.
	// If we don't do it and executor exits before writing handshake reply,
	// reading from inrp will hang since we hold another end of the pipe open.
	inwp.Close()

	if c.config.UseForkServer {
		if err := c.handshake(); err != nil {
			return nil, err
		}
	}
	tmp := c
	c = nil // disable defer above
	return tmp, nil
}

func (c *command) close() {
	if c.cmd != nil {
		c.cmd.Process.Kill()
		c.wait()
	}
	osutil.RemoveAll(c.dir)
	if c.inrp != nil {
		c.inrp.Close()
	}
	if c.outwp != nil {
		c.outwp.Close()
	}
}

// handshake sends handshakeReq and waits for handshakeReply.
func (c *command) handshake() error {
	req := &handshakeReq{
		magic:      inMagic,
		flags:      uint64(c.config.Flags),
		pid:        uint64(c.pid),
		sandboxArg: uint64(c.config.SandboxArg),
	}
	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	if _, err := c.outwp.Write(reqData); err != nil {
		return c.handshakeError(fmt.Errorf("failed to write control pipe: %w", err))
	}

	read := make(chan error, 1)
	go func() {
		reply := &handshakeReply{}
		replyData := (*[unsafe.Sizeof(*reply)]byte)(unsafe.Pointer(reply))[:]
		if _, err := io.ReadFull(c.inrp, replyData); err != nil {
			read <- err
			return
		}
		if reply.magic != outMagic {
			read <- fmt.Errorf("bad handshake reply magic 0x%x", reply.magic)
			return
		}
		read <- nil
	}()
	// Sandbox setup can take significant time.
	timeout := time.NewTimer(time.Minute * c.config.Timeouts.Scale)
	select {
	case err := <-read:
		timeout.Stop()
		if err != nil {
			return c.handshakeError(err)
		}
		return nil
	case <-timeout.C:
		return c.handshakeError(fmt.Errorf("not serving"))
	}
}

func (c *command) handshakeError(err error) error {
	c.cmd.Process.Kill()
	output := <-c.readDone
	err = fmt.Errorf("executor %v: %w\n%s", c.pid, err, output)
	c.wait()
	return err
}

func (c *command) wait() error {
	return <-c.exited
}

func (c *command) exec(opts *ExecOpts, progData []byte) (output []byte, hanged bool, err0 error) {
	req := &executeReq{
		magic:            inMagic,
		envFlags:         uint64(c.config.Flags),
		execFlags:        uint64(opts.Flags),
		pid:              uint64(c.pid),
		syscallTimeoutMS: uint64(c.config.Timeouts.Syscall / time.Millisecond),
		programTimeoutMS: uint64(c.config.Timeouts.Program / time.Millisecond),
		slowdownScale:    uint64(c.config.Timeouts.Scale),
		progSize:         uint64(len(progData)),
	}
	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	if _, err := c.outwp.Write(reqData); err != nil {
		output = <-c.readDone
		err0 = fmt.Errorf("executor %v: failed to write control pipe: %w", c.pid, err)
		return
	}
	if progData != nil {
		if _, err := c.outwp.Write(progData); err != nil {
			output = <-c.readDone
			err0 = fmt.Errorf("executor %v: failed to write control pipe: %w", c.pid, err)
			return
		}
	}
	// At this point program is executing.

	done := make(chan bool)
	hang := make(chan bool)
	go func() {
		t := time.NewTimer(c.timeout)
		select {
		case <-t.C:
			c.cmd.Process.Kill()
			hang <- true
		case <-done:
			t.Stop()
			hang <- false
		}
	}()
	exitStatus := -1
	completedCalls := (*uint32)(unsafe.Pointer(&c.outmem[0]))
	outmem := c.outmem[4:]
	for {
		reply := &executeReply{}
		replyData := (*[unsafe.Sizeof(*reply)]byte)(unsafe.Pointer(reply))[:]
		if _, err := io.ReadFull(c.inrp, replyData); err != nil {
			break
		}
		if reply.magic != outMagic {
			// fmt.Fprintf(os.Stderr, "executor %v: got bad reply magic 0x%x\n", c.pid, reply.magic)
			break
			// os.Exit(1)
		}
		if reply.done != 0 {
			exitStatus = int(reply.status)
			break
		}
		callReply := &callReply{}
		callReplyData := (*[unsafe.Sizeof(*callReply)]byte)(unsafe.Pointer(callReply))[:]
		if _, err := io.ReadFull(c.inrp, callReplyData); err != nil {
			break
		}
		if callReply.signalSize != 0 || callReply.coverSize != 0 || callReply.compsSize != 0 {
			// This is unsupported yet.
			fmt.Fprintf(os.Stderr, "executor %v: got call reply with coverage\n", c.pid)
			os.Exit(1)
		}
		copy(outmem, callReplyData)
		outmem = outmem[len(callReplyData):]
		*completedCalls++
	}
	close(done)
	if exitStatus == 0 {
		// Program was OK.
		<-hang
		return
	}
	c.cmd.Process.Kill()
	output = <-c.readDone
	err := c.wait()
	if err != nil {
		output = append(output, err.Error()...)
		output = append(output, '\n')
	}
	if <-hang {
		hanged = true
		return
	}
	if exitStatus == -1 {
		if c.cmd.ProcessState == nil {
			exitStatus = statusFail
		} else {
			exitStatus = osutil.ProcessExitStatus(c.cmd.ProcessState)
		}
	}
	// Ignore all other errors.
	// Without fork server executor can legitimately exit (program contains exit_group),
	// with fork server the top process can exit with statusFail if it wants special handling.
	if exitStatus == statusFail {
		err0 = fmt.Errorf("executor %v: exit status %d err %w\n%s", c.pid, exitStatus, err, output)
	}
	return
}

func (c *command) execRaceValidation(opts *RaceValidationOpts, prog1Data, prog2Data []byte, prog1Size, prog2Size int) (output []byte, hanged bool, err0 error) {
	req := &raceValidationReq{
		magic:        inRaceValidationMagic,
		prog1Size:    uint64(prog1Size),
		prog2Size:    uint64(prog2Size),
		raceSignal:   opts.RaceSignal,
		varName1:     opts.VarName1,
		varName2:     opts.VarName2,
		callStack1:   opts.CallStack1,
		callStack2:   opts.CallStack2,
		sn1:          opts.Sn1,
		sn2:          opts.Sn2,
		lockStatus:   opts.LockStatus,
		attemptCount: uint32(opts.Attempts),
	}

	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	if _, err := c.outwp.Write(reqData); err != nil {
		output = <-c.readDone
		err0 = fmt.Errorf("executor %v: failed to write race validation control pipe: %w", c.pid, err)
		return
	}

	// Write program 1 data
	if _, err := c.outwp.Write(prog1Data); err != nil {
		output = <-c.readDone
		err0 = fmt.Errorf("executor %v: failed to write prog1 data: %w", c.pid, err)
		return
	}

	// Write program 2 data
	if _, err := c.outwp.Write(prog2Data); err != nil {
		output = <-c.readDone
		err0 = fmt.Errorf("executor %v: failed to write prog2 data: %w", c.pid, err)
		return
	}

	// Wait for execution with timeout
	done := make(chan bool)
	hang := make(chan bool)
	go func() {
		t := time.NewTimer(c.timeout)
		select {
		case <-t.C:
			c.cmd.Process.Kill()
			hang <- true
		case <-done:
			t.Stop()
			hang <- false
		}
	}()

	exitStatus := -1

	reply := &executeReply{}
	replyData := (*[unsafe.Sizeof(*reply)]byte)(unsafe.Pointer(reply))[:]
	if _, err := io.ReadFull(c.inrp, replyData); err != nil {
		close(done)
		if <-hang {
			hanged = true
		}
		output = <-c.readDone
		err0 = fmt.Errorf("executor %v: failed to read pair completion: %w", c.pid, err)
		return
	}

	if reply.magic != outMagic {
		fmt.Fprintf(os.Stderr, "executor %v: got bad pair reply magic 0x%x\n", c.pid, reply.magic)
		os.Exit(1)
	}

	if exitStatus == 0 {
		// Pair execution was OK - now parse race/UAF data
		close(done)
		<-hang

		// Get the executor output data
		output = <-c.readDone

		// Parse race/UAF data from executor output
		if len(output) > 0 {
			races, uafs, extRaces, extUAFs, parseErr := parseRaceUAFData(output)
			if parseErr != nil {
				// Log parsing errors but don't fail the validation
				log.Logf(1, "executor %v: failed to parse race/UAF data: %v", c.pid, parseErr)
			} else {
				// Log parsed data for debugging
				if len(races) > 0 {
					log.Logf(1, "executor %v: parsed %d basic race pairs", c.pid, len(races))
				}
				if len(uafs) > 0 {
					log.Logf(1, "executor %v: parsed %d UAF pairs", c.pid, len(uafs))
				}
				if len(extRaces) > 0 {
					log.Logf(1, "executor %v: parsed %d extended race pairs", c.pid, len(extRaces))
				}
				if len(extUAFs) > 0 {
					log.Logf(1, "executor %v: parsed %d extended UAF pairs", c.pid, len(extUAFs))
				}
			}
		}
		return
	}

	c.cmd.Process.Kill()
	output = <-c.readDone
	err := c.wait()
	if err != nil {
		output = append(output, err.Error()...)
		output = append(output, '\n')
	}
	if <-hang {
		hanged = true
		return
	}

	if exitStatus == -1 {
		if c.cmd.ProcessState == nil {
			exitStatus = statusFail
		} else {
			exitStatus = osutil.ProcessExitStatus(c.cmd.ProcessState)
		}
	}

	if exitStatus == statusFail {
		err0 = fmt.Errorf("executor %v: validate exit status %d err %w\n%s", c.pid, exitStatus, err, output)
	}
	return
}

// parseBasicRacePairs parses multiple basic race pairs from data
func parseBasicRacePairs(data []byte) ([]ddrd.MayRacePair, int, error) {
	var pairs []ddrd.MayRacePair
	offset := 0

	// First 4 bytes should be count
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("insufficient data for race pair count")
	}

	count := prog.HostEndian.Uint32(data[offset:])
	offset += 4

	for i := uint32(0); i < count; i++ {
		if offset+84 > len(data) {
			return nil, offset, fmt.Errorf("insufficient data for race pair %d", i)
		}

		pair, err := parseMayRacePair(data[offset:])
		if err != nil {
			return nil, offset, fmt.Errorf("failed to parse race pair %d: %w", i, err)
		}

		pairs = append(pairs, *pair)
		offset += 84
	}

	return pairs, offset, nil
}

// parseExtendedRacePairs parses multiple extended race pairs from data
func parseExtendedRacePairs(data []byte) ([]ddrd.ExtendedRacePair, int, error) {
	var pairs []ddrd.ExtendedRacePair
	offset := 0

	// First 4 bytes should be count
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("insufficient data for extended race pair count")
	}

	count := prog.HostEndian.Uint32(data[offset:])
	offset += 4

	for i := uint32(0); i < count; i++ {
		if offset+380 > len(data) {
			return nil, offset, fmt.Errorf("insufficient data for extended race pair %d", i)
		}

		pair, err := parseExtendedRacePair(data[offset:])
		if err != nil {
			return nil, offset, fmt.Errorf("failed to parse extended race pair %d: %w", i, err)
		}

		pairs = append(pairs, *pair)
		offset += 380
	}

	return pairs, offset, nil
}

// parseExtendedUAFPairs parses multiple extended UAF pairs from data
func parseExtendedUAFPairs(data []byte) ([]ddrd.ExtendedUAFPair, int, error) {
	var pairs []ddrd.ExtendedUAFPair
	offset := 0

	// First 4 bytes should be count
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("insufficient data for extended UAF pair count")
	}

	count := prog.HostEndian.Uint32(data[offset:])
	offset += 4

	for i := uint32(0); i < count; i++ {
		if offset+380 > len(data) {
			return nil, offset, fmt.Errorf("insufficient data for extended UAF pair %d", i)
		}

		pair, err := parseExtendedUAFPair(data[offset:])
		if err != nil {
			return nil, offset, fmt.Errorf("failed to parse extended UAF pair %d: %w", i, err)
		}

		pairs = append(pairs, *pair)
		offset += 380
	}

	return pairs, offset, nil
}

// parseRaceUAFData parses race and UAF data from executor output
func parseRaceUAFData(output []byte) (races []ddrd.MayRacePair, uafs []ddrd.MayUAFPair,
	extRaces []ddrd.ExtendedRacePair, extUAFs []ddrd.ExtendedUAFPair, err error) {

	offset := 0
	for offset < len(output) {
		if offset+4 > len(output) {
			break
		}

		// Read magic number
		magic := prog.HostEndian.Uint32(output[offset:])
		offset += 4

		switch magic {
		case outPairMagic:
			// Basic race pair data
			basicRaces, consumed, parseErr := parseBasicRacePairs(output[offset:])
			if parseErr != nil {
				return races, uafs, extRaces, extUAFs, fmt.Errorf("failed to parse basic race pairs: %w", parseErr)
			}
			races = append(races, basicRaces...)
			offset += consumed

		case outExtendedPairMagic:
			// Extended race pair data
			extendedRaces, consumed, parseErr := parseExtendedRacePairs(output[offset:])
			if parseErr != nil {
				return races, uafs, extRaces, extUAFs, fmt.Errorf("failed to parse extended race pairs: %w", parseErr)
			}
			extRaces = append(extRaces, extendedRaces...)
			offset += consumed

		case outExtendedUAFMagic:
			// Extended UAF pair data
			extendedUAFs, consumed, parseErr := parseExtendedUAFPairs(output[offset:])
			if parseErr != nil {
				return races, uafs, extRaces, extUAFs, fmt.Errorf("failed to parse extended UAF pairs: %w", parseErr)
			}
			extUAFs = append(extUAFs, extendedUAFs...)
			offset += consumed

		default:
			// Unknown magic number, try to skip or break
			log.Logf(1, "executor: unknown magic number 0x%x at offset %d", magic, offset-4)
			// Try to find next valid magic number
			foundNext := false
			for searchOffset := offset; searchOffset < len(output)-4; searchOffset++ {
				searchMagic := prog.HostEndian.Uint32(output[searchOffset:])
				if searchMagic == outPairMagic || searchMagic == outExtendedPairMagic || searchMagic == outExtendedUAFMagic {
					offset = searchOffset
					foundNext = true
					break
				}
			}
			if !foundNext {
				// No more valid magic numbers found
				break
			}
		}
	}

	return races, uafs, extRaces, extUAFs, nil
}

// ParseExecutorOutput parses executor output and returns basic and extended race/UAF data
func ParseExecutorOutput(output []byte) ([]ddrd.MayRacePair, []ddrd.MayUAFPair, []ddrd.ExtendedRacePair, []ddrd.ExtendedUAFPair) {
	races, uafs, extRaces, extUAFs, err := parseRaceUAFData(output)
	if err != nil {
		// Log error but don't fail - return what we can parse
		return races, uafs, extRaces, extUAFs
	}
	return races, uafs, extRaces, extUAFs
}
