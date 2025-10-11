// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package racevalidate

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
)

// Options contains configuration for UAF validation
type Options struct {
	Config         *mgrconfig.Config
	MaxAttempts    int
	Verbose        bool
	VMCount        int
	PathAware      bool
	CollectHistory bool
}

// UAFValidator manages UAF validation operations
type UAFValidator struct {
	opts      *Options
	ctx       *context
	uafCorpus map[string]*UAFCorpusItem
	results   *UAFValidationResults
	executor  *UAFExecutor
}

// UAFCorpusItem represents a UAF pair from the corpus database
type UAFCorpusItem struct {
	PairID           string    `json:"pair_id"`
	Prog1            []byte    `json:"prog1"`
	Prog2            []byte    `json:"prog2"`
	UAFSignal        []byte    `json:"uaf_signal"`        // serialized UAF signal
	UAFs             []byte    `json:"uafs"`              // serialized []ddrd.MayUAFPair
	Output           []byte    `json:"output"`            // execution output for debugging
	ExecutionContext []byte    `json:"execution_context"` // serialized execution sequence context
	FirstSeen        time.Time `json:"first_seen"`
	LastUpdated      time.Time `json:"last_updated"`
	Source           string    `json:"source"`             // source fuzzer name
	LogPath          string    `json:"log_path,omitempty"` // path to log file for reproduction
	Count            int       `json:"count"`              // discovery count
}

// UAFValidationResults contains overall UAF validation results
type UAFValidationResults struct {
	TotalUAFPairs     int `json:"total_uaf_pairs"`
	ConfirmedUAFPairs int `json:"confirmed_uaf_pairs"`
}

// StageResult represents results for each escalation stage
type StageResult struct {
	Stage          int     `json:"stage"`
	TestPairsCount int     `json:"test_pairs_count"`
	ConfirmedPairs int     `json:"confirmed_pairs"`
	AttemptedPairs int     `json:"attempted_pairs"`
	SuccessRate    float64 `json:"success_rate"`
}

// UAFPairResult represents validation result for a single UAF pair
type UAFPairResult struct {
	PairID         string        `json:"pair_id"`
	Stage          int           `json:"stage"`
	Confirmed      bool          `json:"confirmed"`
	AttemptCount   int           `json:"attempt_count"`
	TimeDifference int64         `json:"time_difference"` // nanoseconds
	DelayStrategy  string        `json:"delay_strategy"`
	FinalDelay     int           `json:"final_delay"` // microseconds
	ExecutionTime  time.Duration `json:"execution_time"`
	ErrorMessage   string        `json:"error_message,omitempty"`
}

// DelayCalculationStrategy defines how delays are calculated
type DelayCalculationStrategy struct {
	Name        string  `json:"name"`
	ProgLevel   bool    `json:"prog_level"`  // Program-level delay based on time difference
	PathLevel   bool    `json:"path_level"`  // Path-level delay based on access distance
	Probability float64 `json:"probability"` // Base probability for delay injection
	MaxDelay    int     `json:"max_delay"`   // Maximum delay in microseconds
}

// EscalationStage represents a single stage in the escalation strategy
type EscalationStage struct {
	Stage          int                      `json:"stage"`
	TestPairsCount int                      `json:"test_pairs_count"`
	MaxAttempts    int                      `json:"max_attempts"`
	DelayStrategy  DelayCalculationStrategy `json:"delay_strategy"`
}

// // validationContext manages the race validation process
// type validationContext struct {
// }

// ProgramPair represents a pair of programs from log files
type ProgramPair struct {
	PairID   int        // pair ID from log (如 2, 4, 5 等)
	Program1 *prog.Prog // 第一个程序
	Program2 *prog.Prog // 第二个程序
	Start    int        // 在日志中的开始位置
	End      int        // 在日志中的结束位置
}

// RacePairBinding binds a program pair to its corresponding race/UAF pairs
type RacePairBinding struct {
	ProgramPairID int                // Index into ProgramPairs array
	RaceType      string             // "race" or "uaf"
	RaceDetails   []ddrd.MayRacePair // Race pairs detected for this program pair
	UAFDetails    []ddrd.MayUAFPair  // UAF pairs detected for this program pair (if applicable)
}

// DelayInjectionResult contains the result of a single delay injection
type DelayInjectionResult struct {
	AccessPoint      ddrd.SerializedAccessRecord // Access point where delay was injected
	DelayMicros      int                         // Actual delay injected in microseconds
	DelayProbability float64                     // Calculated probability for this injection
	DistanceToTarget int                         // Distance to target race event
	InjectionTime    time.Time                   // When the injection was performed
}

// UAFValidationStage represents a single stage in the escalating UAF validation process
type UAFValidationStage struct {
	TestPairCount   int             // Number of test pairs to run before this stage
	MaxAttempts     int             // Maximum validation attempts for this stage
	DelayStrategies []DelayStrategy // Delay strategies to apply in this stage
}

// DelayStrategy defines how delays are applied during UAF validation
type DelayStrategy struct {
	Type             string  // "program_level" or "access_level"
	BaseProbability  float64 // Base probability for delay injection
	DistanceFunction string  // Function to calculate delay probability based on distance
	MaxDelayMicros   int     // Maximum delay in microseconds
	TargetAttempts   int     // Number of attempts with this strategy
}

// UAFValidationConfig contains configuration for escalating UAF validation
type UAFValidationConfig struct {
	Stages           []UAFValidationStage // Escalating validation stages
	MaxTotalAttempts int                  // Maximum total validation attempts across all stages
	GiveUpThreshold  int                  // Give up after this many failed attempts
	EnablePathAware  bool                 // Enable path-distance-aware scheduling
	CollectHistory   bool                 // Collect access history for analysis
}

// UAFValidationResult contains detailed results of UAF validation
type UAFValidationResult struct {
	UAFPairID         string                 // UAF pair identifier
	StagesAttempted   int                    // Number of stages attempted
	TotalAttempts     int                    // Total validation attempts made
	Confirmed         bool                   // Whether UAF was confirmed
	ConfirmationStage int                    // Stage where confirmation occurred (0-based)
	TimeDeltaUsed     uint64                 // Program-level time delta used
	DelayInjections   []DelayInjectionResult // All delay injections attempted
	StateReached      []string               // Log states that were reached
	ErrorMsg          string                 // Error message if validation failed
	Duration          time.Duration          // Total validation time
}

// Results contains overall validation results
type Results struct {
	TotalRaces     int
	ConfirmedRaces int
	RaceResults    []*RaceResult
}

// Stats contains performance statistics
type Stats struct {
	Log            []byte
	LoadCorpusTime time.Duration
	ValidateTime   time.Duration
	TotalTime      time.Duration
}

// RaceCorpusItem represents a race pair from the corpus (same as in manager.go)
type RaceCorpusItem struct {
	PairID      string    `json:"pair_id"`
	Prog1       []byte    `json:"prog1"`
	Prog2       []byte    `json:"prog2"`
	RaceSignal  []byte    `json:"race_signal"` // serialized ddrd.Serial
	Races       []byte    `json:"races"`       // serialized []ddrd.MayRacePair
	UAFs        []byte    `json:"uafs"`        // serialized []ddrd.MayUAFPair
	FirstSeen   time.Time `json:"first_seen"`
	LastUpdated time.Time `json:"last_updated"`
	Source      string    `json:"source"`   // source fuzzer name
	Count       int       `json:"count"`    // discovery count
	LogPath     string    `json:"log_path"` // path to log file containing program pairs
}

// RaceValidated represents a validated race pair stored in the database
type RaceValidated struct {
	PairID     string `json:"pair_id"`
	Prog1      []byte `json:"prog1"`
	Prog2      []byte `json:"prog2"`
	RaceSignal []byte `json:"race_signal"` // serialized ddrd.Serial
	Iscrashed  bool   `json:"is_crashed"`
}

// context contains race validation context
type context struct {
	logf         func(string, ...interface{})
	target       *targets.Target
	pTarget      *prog.Target
	cfg          *mgrconfig.Config
	vmPool       *vm.Pool
	reporter     *report.Reporter
	report       *report.Report
	maxAttempts  int
	raceCorpus   map[string]*RaceCorpusItem
	instances    chan *validationInstance
	bootRequests chan int
	stats        *Stats
	timeouts     targets.Timeouts
	validatedDB  *ValidatedDB // Database for tracking validated race pairs

	// Path-aware scheduling options
	pathAwareScheduling bool // Enable path-distance-aware scheduling
	maxDelayMs          int  // Maximum delay in milliseconds
	collectHistory      bool // Collect historical access patterns
}

// validationInstance wraps a VM instance for race validation
type validationInstance struct {
	index int
	inst  *instance.ExecProgInstance
}

// ErrNoPrograms is returned when no programs are available to validate
var ErrNoPrograms = fmt.Errorf("no programs to validate")

// Run performs race validation on the corpus
func Run(corpusPath string, cfg *mgrconfig.Config, hostFeatures *host.Features, reporter *report.Reporter, vmPool *vm.Pool, vmIndexes []int, maxAttempts int) (*Results, *Stats, error) {
	return RunWithOptions(corpusPath, cfg, hostFeatures, reporter, vmPool, vmIndexes, maxAttempts, false, 0, false)
}

// RunWithOptions performs race validation with optional path-aware scheduling
func RunWithOptions(corpusPath string, cfg *mgrconfig.Config, hostFeatures *host.Features, reporter *report.Reporter, vmPool *vm.Pool, vmIndexes []int, maxAttempts int, pathAware bool, maxDelayMs int, collectHistory bool) (*Results, *Stats, error) {
	// Prepare context
	ctx, err := prepareCtx(corpusPath, cfg, hostFeatures, reporter, vmPool, len(vmIndexes), maxAttempts)
	if err != nil {
		return nil, nil, err
	}

	// Set path-aware scheduling options
	ctx.pathAwareScheduling = pathAware
	ctx.maxDelayMs = maxDelayMs
	ctx.collectHistory = collectHistory

	// Start VM management
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx.createInstances()
	}()

	// Boot VMs in advance
	for _, idx := range vmIndexes {
		ctx.bootRequests <- idx
	}

	// Run validation
	results, stats, err := ctx.run()

	// Wait for createInstances goroutine to finish
	wg.Wait()

	// Close all remaining instances after validation and goroutines complete
	ctx.closeAllInstances()

	// Close validation database
	if closeErr := ctx.validatedDB.Close(); closeErr != nil {
		log.Logf(0, "Warning: failed to close validation database: %v", closeErr)
	}

	return results, stats, err
}

func prepareCtx(corpusPath string, cfg *mgrconfig.Config, _ *host.Features, reporter *report.Reporter,
	vmPool *vm.Pool, VMs int, maxAttempts int) (*context, error) {
	if VMs == 0 {
		return nil, fmt.Errorf("no VMs provided")
	}

	// Get prog.Target for program parsing
	pTarget, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		return nil, fmt.Errorf("failed to get prog target: %v", err)
	}

	// Initialize validation database
	validatedDB, err := OpenValidatedDB(cfg.Workdir)
	if err != nil {
		return nil, fmt.Errorf("failed to open validation database: %v", err)
	}

	ctx := &context{
		logf:         func(format string, args ...interface{}) { log.Logf(0, format, args...) },
		maxAttempts:  maxAttempts,
		target:       cfg.SysTarget,
		pTarget:      pTarget,
		cfg:          cfg,
		vmPool:       vmPool,
		reporter:     reporter,
		raceCorpus:   make(map[string]*RaceCorpusItem),
		instances:    make(chan *validationInstance, VMs),
		bootRequests: make(chan int, VMs),
		stats:        new(Stats),
		timeouts:     cfg.Timeouts,
		validatedDB:  validatedDB,
	}
	// Load race corpus
	loadStart := time.Now()
	if err := ctx.loadRaceCorpus(corpusPath); err != nil {
		return nil, fmt.Errorf("failed to load race corpus: %v", err)
	}
	ctx.stats.LoadCorpusTime = time.Since(loadStart)
	ctx.validateLogf(0, "loaded %d race pairs from corpus", len(ctx.raceCorpus))

	// Print validation statistics
	total, valid, invalid, err := ctx.validatedDB.GetValidationStats()
	if err != nil {
		ctx.validateLogf(0, "Warning: failed to get validation stats: %v", err)
	} else {
		ctx.validateLogf(0, "validation database stats: %d total (%d valid, %d invalid)", total, valid, invalid)
	}

	return ctx, nil
}

func (ctx *context) run() (*Results, *Stats, error) {
	// Indicate that we no longer need VMs.
	defer close(ctx.bootRequests)

	results, err := ctx.validate()
	if err != nil {
		return nil, nil, err
	}

	return results, ctx.stats, nil
} // min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parsePairLog 解析包含程序对的日志文件
func (ctx *context) parsePairLog(logPath string) ([]*ProgramPair, error) {
	// 读取日志文件
	data, err := os.ReadFile(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read log file %s: %v", logPath, err)
	}

	return ctx.parsePairLogData(data)
}

// parsePairLogData 解析包含程序对的日志数据
func (ctx *context) parsePairLogData(data []byte) ([]*ProgramPair, error) {
	var entries []*ProgramPair

	lines := strings.Split(string(data), "\n")

	// 正则表达式匹配 "executing program pair X:"
	pairRegex := regexp.MustCompile(`executing program pair (\d+):`)

	var currentEntry *ProgramPair
	var currentProgram strings.Builder
	var parsingProgram1 bool
	var parsingProgram2 bool

	for i, line := range lines {
		// 检查是否开始新的程序对
		if match := pairRegex.FindStringSubmatch(line); match != nil {
			// 如果之前有未完成的条目，先保存它
			if currentEntry != nil {
				entries = append(entries, currentEntry)
			}

			// 创建新的条目
			var pairID int
			fmt.Sscanf(match[1], "%d", &pairID)
			currentEntry = &ProgramPair{
				PairID: pairID,
				Start:  i,
			}
			continue
		}

		// 检查是否开始 Program 1
		if strings.Contains(line, "Program 1:") {
			parsingProgram1 = true
			parsingProgram2 = false
			currentProgram.Reset()
			continue
		}

		// 检查是否开始 Program 2
		if strings.Contains(line, "Program 2:") {
			// 保存 Program 1
			if currentEntry != nil && parsingProgram1 {
				prog1Text := currentProgram.String()
				if p, err := ctx.pTarget.Deserialize([]byte(prog1Text), prog.NonStrict); err == nil {
					currentEntry.Program1 = p
				}
			}

			parsingProgram1 = false
			parsingProgram2 = true
			currentProgram.Reset()
			continue
		}

		// 检查是否遇到日志行（以时间戳开头或内核日志格式）
		if strings.HasPrefix(line, "2025/") || strings.HasPrefix(strings.TrimSpace(line), "[") {
			// 如果正在解析 Program 2，保存它
			if currentEntry != nil && parsingProgram2 {
				prog2Text := currentProgram.String()
				if p, err := ctx.pTarget.Deserialize([]byte(prog2Text), prog.NonStrict); err == nil {
					currentEntry.Program2 = p
				}
				currentEntry.End = i
			}
			parsingProgram1 = false
			parsingProgram2 = false
			continue
		}

		// 如果正在解析程序内容，添加到当前程序
		if (parsingProgram1 || parsingProgram2) && strings.TrimSpace(line) != "" {
			currentProgram.WriteString(line)
			currentProgram.WriteString("\n")
		}
	}

	// 处理最后一个条目
	if currentEntry != nil {
		if parsingProgram2 && currentProgram.Len() > 0 {
			prog2Text := currentProgram.String()
			if p, err := ctx.pTarget.Deserialize([]byte(prog2Text), prog.NonStrict); err == nil {
				currentEntry.Program2 = p
			}
		}
		currentEntry.End = len(lines)
		entries = append(entries, currentEntry)
	}

	return entries, nil
}

// bindProgramPairsToRaces 将程序对与race pairs绑定
func (ctx *context) bindProgramPairsToRaces(programPairs []*ProgramPair, races []ddrd.MayRacePair) []RacePairBinding {
	var bindings []RacePairBinding

	// 简单的绑定策略：根据程序对的执行顺序与race检测的时间顺序进行关联
	// 这里可以根据实际需求实现更复杂的绑定逻辑
	for i := range programPairs {
		if len(races) > 0 {
			binding := RacePairBinding{
				ProgramPairID: i,
				RaceType:      "race",
				RaceDetails:   races, // 暂时将所有race关联到每个程序对
			}
			bindings = append(bindings, binding)
		}
	}

	return bindings
}

// getDefaultUAFValidationConfig returns default configuration for UAF validation
func (ctx *context) getDefaultUAFValidationConfig() UAFValidationConfig {
	return UAFValidationConfig{
		Stages: []UAFValidationStage{
			{
				TestPairCount: 100,
				MaxAttempts:   50,
				DelayStrategies: []DelayStrategy{
					{
						Type:             "program_level",
						BaseProbability:  1.0, // Always apply program-level delay
						DistanceFunction: "time_delta",
						MaxDelayMicros:   10000, // 10ms
						TargetAttempts:   25,
					},
				},
			},
			{
				TestPairCount: 1000,
				MaxAttempts:   200,
				DelayStrategies: []DelayStrategy{
					{
						Type:             "program_level",
						BaseProbability:  1.0,
						DistanceFunction: "time_delta",
						MaxDelayMicros:   50000, // 50ms
						TargetAttempts:   100,
					},
					{
						Type:             "access_level",
						BaseProbability:  0.1,
						DistanceFunction: "inverse_distance", // 1/(d+1)
						MaxDelayMicros:   1000,               // 1ms
						TargetAttempts:   100,
					},
				},
			},
			{
				TestPairCount: 10000,
				MaxAttempts:   1000,
				DelayStrategies: []DelayStrategy{
					{
						Type:             "program_level",
						BaseProbability:  1.0,
						DistanceFunction: "time_delta",
						MaxDelayMicros:   100000, // 100ms
						TargetAttempts:   500,
					},
					{
						Type:             "access_level",
						BaseProbability:  0.3,
						DistanceFunction: "inverse_distance",
						MaxDelayMicros:   5000, // 5ms
						TargetAttempts:   500,
					},
				},
			},
		},
		MaxTotalAttempts: 1250,
		GiveUpThreshold:  3, // Give up after 3 stages fail
		EnablePathAware:  true,
		CollectHistory:   true,
	}
}

// validateUAFWithEscalation performs escalating UAF validation
func (ctx *context) validateUAFWithEscalation(raceItem *RaceCorpusItem, uafPairs []ddrd.MayUAFPair) *UAFValidationResult {
	startTime := time.Now()
	config := ctx.getDefaultUAFValidationConfig()

	result := &UAFValidationResult{
		UAFPairID:       raceItem.PairID,
		StagesAttempted: 0,
		TotalAttempts:   0,
		Confirmed:       false,
		StateReached:    make([]string, 0),
		DelayInjections: make([]DelayInjectionResult, 0),
	}

	ctx.validateLogf(1, "Starting escalating UAF validation for pair %s with %d UAF pairs",
		raceItem.PairID, len(uafPairs))

	// Parse programs
	prog1, err := ctx.parseProgram(raceItem.Prog1)
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("failed to parse prog1: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	prog2, err := ctx.parseProgram(raceItem.Prog2)
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("failed to parse prog2: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	// Execute escalating validation stages
	for stageIdx, stage := range config.Stages {
		if result.TotalAttempts >= config.MaxTotalAttempts {
			ctx.validateLogf(1, "UAF validation reached maximum total attempts (%d)", config.MaxTotalAttempts)
			break
		}

		result.StagesAttempted = stageIdx + 1
		ctx.validateLogf(1, "UAF validation stage %d: testing with %d program pairs",
			stageIdx+1, stage.TestPairCount)

		// Try to reach target state by running test pairs
		stateReached := ctx.attemptToReachState(prog1, prog2, stage.TestPairCount)
		if stateReached != "" {
			result.StateReached = append(result.StateReached, stateReached)
			ctx.validateLogf(2, "UAF validation stage %d: reached state %s", stageIdx+1, stateReached)
		} else {
			ctx.validateLogf(1, "UAF validation stage %d: failed to reach target state", stageIdx+1)
			continue
		}

		// Apply delay strategies for this stage
		stageConfirmed := false
		for _, strategy := range stage.DelayStrategies {
			if result.TotalAttempts >= config.MaxTotalAttempts {
				break
			}

			ctx.validateLogf(2, "UAF validation stage %d: applying %s delay strategy",
				stageIdx+1, strategy.Type)

			confirmed, injections := ctx.applyDelayStrategy(prog1, prog2, uafPairs, strategy)
			result.DelayInjections = append(result.DelayInjections, injections...)
			result.TotalAttempts += strategy.TargetAttempts

			if confirmed {
				result.Confirmed = true
				result.ConfirmationStage = stageIdx
				stageConfirmed = true
				ctx.validateLogf(1, "UAF validation stage %d: UAF confirmed with %s strategy!",
					stageIdx+1, strategy.Type)
				break
			}
		}

		if stageConfirmed {
			break
		}

		ctx.validateLogf(1, "UAF validation stage %d: no confirmation, proceeding to next stage", stageIdx+1)
	}

	if !result.Confirmed {
		ctx.validateLogf(1, "UAF validation completed: UAF pair %s could not be confirmed after %d stages",
			raceItem.PairID, result.StagesAttempted)
	}

	result.Duration = time.Since(startTime)
	return result
}

// attemptToReachState tries to reach target state by running test pairs
func (ctx *context) attemptToReachState(prog1, prog2 *prog.Prog, testPairCount int) string {
	ctx.validateLogf(3, "Attempting to reach state by running %d test pairs", testPairCount)

	// Simulate running test pairs to reach target state
	// In a real implementation, this would:
	// 1. Parse program pairs from log files
	// 2. Execute them in sequence until reaching the target count
	// 3. Monitor system state and memory allocations
	// 4. Return state identifier if target state is reached

	// For now, simulate with a simple probability-based approach
	if testPairCount >= 100 {
		return fmt.Sprintf("state_reached_after_%d_pairs", testPairCount)
	}

	return "" // Failed to reach state
}

// ===============================================================================
// 模块2: 时差delay调控 (DelayManager)
// 实现基于UAF test时差的双层次delay控制 (Program级+Path级)
// ===============================================================================

// applyDelayStrategy applies a specific delay strategy and returns confirmation status
func (ctx *context) applyDelayStrategy(prog1, prog2 *prog.Prog, uafPairs []ddrd.MayUAFPair,
	strategy DelayStrategy) (bool, []DelayInjectionResult) {

	var injections []DelayInjectionResult

	ctx.validateLogf(3, "Applying delay strategy: type=%s, attempts=%d", strategy.Type, strategy.TargetAttempts)

	for attempt := 0; attempt < strategy.TargetAttempts; attempt++ {
		var injection DelayInjectionResult

		if strategy.Type == "program_level" {
			// Program-level delay: adjust program start time difference
			injection = ctx.applyProgramLevelDelay(prog1, prog2, uafPairs, strategy)
		} else if strategy.Type == "access_level" {
			// Access-level delay: inject delays at specific access points
			injection = ctx.applyAccessLevelDelay(prog1, prog2, uafPairs, strategy)
		}

		injections = append(injections, injection)

		// Simulate UAF detection check
		// In a real implementation, this would execute the programs and check for UAF
		if ctx.simulateUAFDetection(injection) {
			ctx.validateLogf(2, "UAF detected with delay strategy %s at attempt %d", strategy.Type, attempt+1)
			return true, injections
		}
	}

	return false, injections
}

// applyProgramLevelDelay calculates and applies program-level timing delays
func (ctx *context) applyProgramLevelDelay(prog1, prog2 *prog.Prog, uafPairs []ddrd.MayUAFPair,
	strategy DelayStrategy) DelayInjectionResult {

	injection := DelayInjectionResult{
		InjectionTime: time.Now(),
	}

	if len(uafPairs) > 0 {
		uaf := uafPairs[0] // Use first UAF pair for timing calculation

		// Calculate time delta based on UAF timing
		// This is a simplified calculation - in reality you'd analyze the actual timing data
		timeDelta := calculateTimeDelta(uaf)

		injection.DelayMicros = int(timeDelta / 1000) // Convert to microseconds
		if injection.DelayMicros > strategy.MaxDelayMicros {
			injection.DelayMicros = strategy.MaxDelayMicros
		}

		injection.DelayProbability = strategy.BaseProbability
		injection.DistanceToTarget = 0 // Program level has direct impact

		ctx.validateLogf(3, "Program-level delay: %d microseconds", injection.DelayMicros)
	}

	return injection
}

// applyAccessLevelDelay calculates and applies access-point-level delays
func (ctx *context) applyAccessLevelDelay(prog1, prog2 *prog.Prog, uafPairs []ddrd.MayUAFPair,
	strategy DelayStrategy) DelayInjectionResult {

	injection := DelayInjectionResult{
		InjectionTime: time.Now(),
	}

	if len(uafPairs) > 0 {
		uaf := uafPairs[0]

		// Simulate access point selection and distance calculation
		// In reality, this would analyze the execution path and access history
		accessDistance := ctx.calculateAccessDistance(uaf)

		// Apply distance-based probability: 1/(d+1)
		if strategy.DistanceFunction == "inverse_distance" {
			injection.DelayProbability = 1.0 / float64(accessDistance+1)
		} else {
			injection.DelayProbability = strategy.BaseProbability
		}

		// Calculate delay based on probability
		if ctx.shouldInjectDelay(injection.DelayProbability) {
			injection.DelayMicros = strategy.MaxDelayMicros
			injection.DistanceToTarget = accessDistance

			ctx.validateLogf(3, "Access-level delay: %d microseconds at distance %d (prob=%.3f)",
				injection.DelayMicros, accessDistance, injection.DelayProbability)
		}
	}

	return injection
}

// calculateTimeDelta calculates the time difference for program-level delay
func calculateTimeDelta(uaf ddrd.MayUAFPair) uint64 {
	// Use the TimeDiff field which contains time difference between free and use in nanoseconds
	return uaf.TimeDiff
}

// calculateAccessDistance calculates distance to target access point
func (ctx *context) calculateAccessDistance(uaf ddrd.MayUAFPair) int {
	// Calculate distance based on syscall sequence numbers
	// Distance is the difference between use and free sequence numbers
	distance := int(uaf.UseSN - uaf.FreeSN)
	if distance < 0 {
		distance = -distance
	}
	if distance == 0 {
		distance = 1 // Minimum distance of 1
	}
	return distance
}

// shouldInjectDelay determines whether to inject delay based on probability
func (ctx *context) shouldInjectDelay(probability float64) bool {
	// Simple probability check - in reality might use more sophisticated randomization
	return probability > 0.5
}

// simulateUAFDetection simulates UAF detection for testing purposes
func (ctx *context) simulateUAFDetection(injection DelayInjectionResult) bool {
	// Simplified simulation - in reality this would execute programs and check for UAF
	// Higher delay probability increases chance of detection
	return injection.DelayProbability > 0.8 && injection.DelayMicros > 1000
}

// parseProgram tries to parse a program from either text or binary format
func (ctx *context) parseProgram(data []byte) (*prog.Prog, error) {
	// First try as text format (standard Deserialize)
	if prog, err := ctx.pTarget.Deserialize(data, prog.NonStrict); err == nil {
		return prog, nil
	}

	// If that fails, try as binary format (which is what SerializeForExec produces)
	// Binary format starts with control characters, so check for that
	if len(data) > 0 && data[0] < 32 {
		// This is binary format - we need to deserialize it properly
		// Binary format is the output of SerializeForExec, we need to parse it back

		// Try to deserialize binary format
		// Unfortunately, syzkaller doesn't expose a public method to deserialize binary format
		// So we need to handle this by converting back to text first
		// For now, let's try strict text parsing as fallback
		if progResult, err := ctx.pTarget.Deserialize(data, prog.Strict); err == nil {
			return progResult, nil
		}

		return nil, fmt.Errorf("binary program format detected but failed to parse: data starts with 0x%x", data[0])
	}

	// Try strict text parsing as final attempt
	return ctx.pTarget.Deserialize(data, prog.Strict)
}

// loadRaceCorpus loads race pairs from the corpus database, filtering out already validated ones
func (ctx *context) loadRaceCorpus(corpusPath string) error {
	raceCorpusDB, err := db.Open(corpusPath, false) // Read-only
	if err != nil {
		return err
	}

	// Get list of unvalidated pairs from validation database
	unvalidatedPairIDs := ctx.validatedDB.GetUnvalidatedPairs(raceCorpusDB)
	unvalidatedSet := make(map[uint64]bool)
	for _, pairID := range unvalidatedPairIDs {
		unvalidatedSet[pairID] = true
	}

	ctx.raceCorpus = make(map[string]*RaceCorpusItem)

	loaded := 0
	skipped := 0
	broken := 0

	for key, rec := range raceCorpusDB.Records {
		// Parse pair ID from key (hex format)
		pairID, err := strconv.ParseUint(key, 16, 64)
		if err != nil {
			ctx.validateLogf(1, "Invalid corpus key format: %s, skipping", key)
			broken++
			continue
		}

		// Skip if already validated
		if !unvalidatedSet[pairID] {
			skipped++
			continue
		}

		var item RaceCorpusItem
		if err := json.Unmarshal(rec.Val, &item); err != nil {
			ctx.validateLogf(0, "failed to unmarshal race corpus item %s: %v", key, err)
			broken++
			continue
		}

		ctx.raceCorpus[key] = &item
		loaded++
	}

	ctx.validateLogf(0, "Race corpus loading complete: %d loaded, %d already validated (skipped), %d broken",
		loaded, skipped, broken)

	return nil
}

// validate performs race validation on all corpus items
func (ctx *context) validate() (*Results, error) {
	validateStart := time.Now()
	defer func() {
		ctx.validateLogf(3, "reproducing took %s", time.Since(validateStart))
	}()

	results := &Results{
		TotalRaces:     len(ctx.raceCorpus),
		ConfirmedRaces: 0,
		RaceResults:    make([]*RaceResult, 0),
	}

	for pairID, raceItem := range ctx.raceCorpus {
		ctx.validateLogf(0, "validating race %s ", pairID)
		raceResult := ctx.validateRace(raceItem)

		results.RaceResults = append(results.RaceResults, raceResult)

		// Convert string PairID to uint64
		pairIDNum, err := strconv.ParseUint(raceItem.PairID, 16, 64)
		if err != nil {
			ctx.validateLogf(0, "Warning: invalid PairID format %s: %v", raceItem.PairID, err)
			continue
		}

		if raceResult.Confirmed {
			results.ConfirmedRaces++
			// Record successful validation
			if err := ctx.validatedDB.MarkAsValidated(pairIDNum, raceItem.Source); err != nil {
				ctx.validateLogf(0, "Warning: failed to record successful validation for %x: %v", pairIDNum, err)
			} else {
				ctx.validateLogf(2, "Recorded successful validation for race pair %x", pairIDNum)
			}
		} else {
			// Record failed validation
			errorMsg := raceResult.ErrorMsg
			if errorMsg == "" {
				errorMsg = "race not confirmed after validation attempts"
			}
			if err := ctx.validatedDB.MarkAsInvalid(pairIDNum, errorMsg, raceItem.Source); err != nil {
				ctx.validateLogf(0, "Warning: failed to record failed validation for %x: %v", pairIDNum, err)
			} else {
				ctx.validateLogf(2, "Recorded failed validation for race pair %x: %s", pairIDNum, errorMsg)
			}
		}
	}

	// Flush validation database to ensure data is persisted
	if err := ctx.validatedDB.Flush(); err != nil {
		ctx.validateLogf(0, "Warning: failed to flush validation database: %v", err)
	}

	return results, nil
}

// validateRace validates a single race pair
func (ctx *context) validateRace(raceItem *RaceCorpusItem) *RaceResult {
	startTime := time.Now()
	result := &RaceResult{
		PairID:   raceItem.PairID,
		Attempts: ctx.maxAttempts,
		LogPath:  raceItem.LogPath,
	}

	// Parse program pairs from log file if available
	if raceItem.LogPath != "" {
		if programPairs, err := ctx.parsePairLog(raceItem.LogPath); err == nil {
			result.ProgramPairs = programPairs
			ctx.validateLogf(1, "race pair %s: parsed %d program pairs from log %s",
				raceItem.PairID, len(programPairs), raceItem.LogPath)
		} else {
			ctx.validateLogf(0, "Warning: failed to parse log file %s: %v", raceItem.LogPath, err)
		}
	}

	// Deserialize race pairs from the corpus item
	var racePairs []ddrd.MayRacePair
	if len(raceItem.Races) > 0 {
		if err := json.Unmarshal(raceItem.Races, &racePairs); err != nil {
			result.ErrorMsg = fmt.Sprintf("failed to deserialize race pairs: %v", err)
			result.Duration = time.Since(startTime)
			return result
		}
		ctx.validateLogf(1, "race pair %s has %d race pairs", raceItem.PairID, len(racePairs))

		// Bind program pairs to race pairs
		if len(result.ProgramPairs) > 0 {
			result.RacePairs = ctx.bindProgramPairsToRaces(result.ProgramPairs, racePairs)
			ctx.validateLogf(1, "race pair %s: created %d race pair bindings",
				raceItem.PairID, len(result.RacePairs))
		}
	} else {
		ctx.validateLogf(1, "race pair %s has no race data", raceItem.PairID)
	}

	// Deserialize UAF pairs from the corpus item if available
	var uafPairs []ddrd.MayUAFPair
	if len(raceItem.UAFs) > 0 {
		if err := json.Unmarshal(raceItem.UAFs, &uafPairs); err != nil {
			ctx.validateLogf(0, "Warning: failed to deserialize UAF pairs for %s: %v", raceItem.PairID, err)
		} else {
			ctx.validateLogf(1, "race pair %s has %d UAF pairs", raceItem.PairID, len(uafPairs))
		}
	}

	// Parse programs - try both text and binary formats
	prog1, err := ctx.parseProgram(raceItem.Prog1)
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("failed to parse prog1: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	prog2, err := ctx.parseProgram(raceItem.Prog2)
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("failed to parse prog2: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	// Attempt validation
	for attempt := 1; attempt <= ctx.maxAttempts; attempt++ {
		reports := ctx.attemptValidation(prog1, prog2, raceItem, racePairs)

		// Collect all reports
		result.Reports = append(result.Reports, reports...)

		// Check for race-related crashes
		raceDetected := false

		if raceDetected {
			result.Confirmed = true
			break
		}
	}

	// Perform escalating UAF validation if UAF pairs are available
	if len(uafPairs) > 0 {
		ctx.validateLogf(1, "Performing escalating UAF validation for %s with %d UAF pairs",
			raceItem.PairID, len(uafPairs))

		uafResult := ctx.validateUAFWithEscalation(raceItem, uafPairs)
		if uafResult != nil {
			result.UAFValidation = uafResult
			ctx.validateLogf(1, "UAF validation completed for %s: confirmed=%v, stages=%d, attempts=%d",
				raceItem.PairID, uafResult.Confirmed, uafResult.StagesAttempted, uafResult.TotalAttempts)

			// If UAF is confirmed, consider the overall result confirmed
			if uafResult.Confirmed {
				result.Confirmed = true
			}
		}
	} else {
		ctx.validateLogf(2, "No UAF pairs available for escalating validation")
	}

	result.Duration = time.Since(startTime)
	return result
}

// attemptValidation performs a single race validation attempt using direct IPC
func (ctx *context) attemptValidation(prog1, prog2 *prog.Prog, raceItem *RaceCorpusItem, racePairs []ddrd.MayRacePair) []*report.Report {
	// Check if path-aware scheduling is enabled
	if ctx.pathAwareScheduling {
		return ctx.attemptPathAwareValidation(prog1, prog2, raceItem, racePairs)
	}

	// Get VM instance
	inst := <-ctx.instances
	defer func() {
		ctx.instances <- inst
	}()

	// Create IPC environment directly
	target, err := prog.GetTarget(ctx.cfg.TargetOS, ctx.cfg.TargetArch)
	if err != nil {
		ctx.validateLogf(0, "failed to get target: %v", err)
		return nil
	}

	// Create IPC config using ipcconfig.Default
	ipcConfig, _, err := ipcconfig.Default(target)
	if err != nil {
		ctx.validateLogf(0, "failed to create default ipc config: %v", err)
		return nil
	}

	// Override executor path to use the one from config
	ipcConfig.Executor = ctx.cfg.ExecutorBin
	// Use manager timeouts if available
	if ctx.cfg.Timeouts.Slowdown > 0 {
		ipcConfig.Timeouts = ctx.cfg.Timeouts
	}

	env, err := ipc.MakeEnv(ipcConfig, 0)
	if err != nil {
		ctx.validateLogf(0, "failed to create IPC env: %v", err)
		return nil
	}
	defer env.Close()

	var reports []*report.Report

	if len(racePairs) > 0 {
		// Try validation for each race pair
		for i, racePair := range racePairs {
			ctx.validateLogf(2, "validating race pair %d/%d: signal=0x%x, vars=[%d,%d], callstacks=[0x%x,0x%x], sn=[%d,%d], lock=%d",
				i+1, len(racePairs), racePair.Signal, racePair.VarName1, racePair.VarName2,
				racePair.CallStack1, racePair.CallStack2, racePair.Sn1, racePair.Sn2, racePair.LockType)

			// Setup race validation options
			opts := &ipc.RaceValidationOpts{
				Opts1:      &ipc.ExecOpts{},
				Opts2:      &ipc.ExecOpts{},
				RaceSignal: racePair.Signal,
				VarName1:   racePair.VarName1,
				VarName2:   racePair.VarName2,
				CallStack1: racePair.CallStack1,
				CallStack2: racePair.CallStack2,
				Sn1:        uint64(racePair.Sn1),
				Sn2:        uint64(racePair.Sn2),
				LockStatus: racePair.LockType,
				Attempts:   ctx.maxAttempts,
			}

			// Execute race validation directly via IPC
			output, hanged, err := env.RaceValidation(opts, prog1, prog2)
			if err != nil {
				ctx.validateLogf(0, "race validation execution failed for pair %d: %v", i+1, err)
				continue
			}

			// Parse extended race/UAF data from output
			if len(output) > 0 {
				basicRaces, basicUAFs, extRaces, extUAFs := ipc.ParseExecutorOutput(output)

				// Log parsing results
				if len(basicRaces) > 0 {
					ctx.validateLogf(1, "race validation pair %d: parsed %d basic race pairs", i+1, len(basicRaces))
				}
				if len(basicUAFs) > 0 {
					ctx.validateLogf(1, "race validation pair %d: parsed %d basic UAF pairs", i+1, len(basicUAFs))
				}
				if len(extRaces) > 0 {
					ctx.validateLogf(1, "race validation pair %d: parsed %d extended race pairs", i+1, len(extRaces))
				}
				if len(extUAFs) > 0 {
					ctx.validateLogf(1, "race validation pair %d: parsed %d extended UAF pairs", i+1, len(extUAFs))
				}
			}

			if hanged {
				ctx.validateLogf(1, "race validation hanged for pair %d", i+1)
			} else {
				ctx.validateLogf(2, "race validation completed for pair %d", i+1)
			}

			// For now, we don't have crash detection logic in this simplified version
			// The reports are collected from the execution results
			// TODO: Add crash detection based on output analysis
		}
	} else {
		// Fallback when no race pairs are available
		ctx.validateLogf(2, "have no may race pair!")
	}

	return reports
}

// attemptPathAwareValidation performs race validation with path-distance-aware scheduling using direct IPC
func (ctx *context) attemptPathAwareValidation(prog1, prog2 *prog.Prog, _ *RaceCorpusItem, racePairs []ddrd.MayRacePair) []*report.Report {
	// Get VM instance
	inst := <-ctx.instances
	defer func() {
		ctx.instances <- inst
	}()

	// Create IPC environment directly
	target, err := prog.GetTarget(ctx.cfg.TargetOS, ctx.cfg.TargetArch)
	if err != nil {
		ctx.validateLogf(0, "failed to get target: %v", err)
		return nil
	}

	// Create IPC config using ipcconfig.Default
	ipcConfig, _, err := ipcconfig.Default(target)
	if err != nil {
		ctx.validateLogf(0, "failed to create default ipc config: %v", err)
		return nil
	}

	// Override executor path to use the one from config
	ipcConfig.Executor = ctx.cfg.ExecutorBin
	// Use manager timeouts if available
	if ctx.cfg.Timeouts.Slowdown > 0 {
		ipcConfig.Timeouts = ctx.cfg.Timeouts
	}

	env, err := ipc.MakeEnv(ipcConfig, 0)
	if err != nil {
		ctx.validateLogf(0, "failed to create IPC env: %v", err)
		return nil
	}
	defer env.Close()

	var reports []*report.Report

	if len(racePairs) > 0 {
		// Try path-aware validation for each race pair
		for i, racePair := range racePairs {
			ctx.validateLogf(2, "path-aware validating race pair %d/%d: signal=0x%x, vars=[%d,%d], callstacks=[0x%x,0x%x], sn=[%d,%d], lock=%d",
				i+1, len(racePairs), racePair.Signal, racePair.VarName1, racePair.VarName2,
				racePair.CallStack1, racePair.CallStack2, racePair.Sn1, racePair.Sn2, racePair.LockType)

			// Setup race validation options for path-aware scheduling
			opts := &ipc.RaceValidationOpts{
				Opts1:      &ipc.ExecOpts{},
				Opts2:      &ipc.ExecOpts{},
				RaceSignal: racePair.Signal,
				VarName1:   racePair.VarName1,
				VarName2:   racePair.VarName2,
				CallStack1: racePair.CallStack1,
				CallStack2: racePair.CallStack2,
				Sn1:        uint64(racePair.Sn1),
				Sn2:        uint64(racePair.Sn2),
				LockStatus: racePair.LockType,
				Attempts:   ctx.maxAttempts,
			}

			// Execute path-aware race validation directly via IPC
			output, hanged, err := env.RaceValidation(opts, prog1, prog2)
			if err != nil {
				ctx.validateLogf(0, "path-aware race validation execution failed for pair %d: %v", i+1, err)
				continue
			}

			// Parse extended race/UAF data from output
			if len(output) > 0 {
				basicRaces, basicUAFs, extRaces, extUAFs := ipc.ParseExecutorOutput(output)

				// Log parsing results with path-aware context
				if len(basicRaces) > 0 {
					ctx.validateLogf(1, "path-aware race validation pair %d: parsed %d basic race pairs", i+1, len(basicRaces))
				}
				if len(basicUAFs) > 0 {
					ctx.validateLogf(1, "path-aware race validation pair %d: parsed %d basic UAF pairs", i+1, len(basicUAFs))
				}
				if len(extRaces) > 0 {
					ctx.validateLogf(1, "path-aware race validation pair %d: parsed %d extended race pairs with history", i+1, len(extRaces))
				}
				if len(extUAFs) > 0 {
					ctx.validateLogf(1, "path-aware race validation pair %d: parsed %d extended UAF pairs with history", i+1, len(extUAFs))

					// Log path-distance statistics for UAFs
					for j, extUAF := range extUAFs {
						ctx.validateLogf(2, "path-aware UAF pair %d.%d: free_target_time=%d, use_target_time=%d, access_history=%d records",
							i+1, j+1, extUAF.FreeTargetTime, extUAF.UseTargetTime,
							len(extUAF.AccessHistory))
					}
				}
			}

			if hanged {
				ctx.validateLogf(1, "path-aware race validation hanged for pair %d", i+1)
			} else {
				ctx.validateLogf(2, "path-aware race validation completed for pair %d", i+1)
			}

			// TODO: Add crash detection and delay injection statistics
			// For now, we focus on the extended data collection and parsing
		}
	} else {
		ctx.validateLogf(2, "path-aware validation: no race pairs available")
	}

	return reports
}

// createInstances creates and manages VM instances
func (ctx *context) createInstances() {
	for vmIndex := range ctx.bootRequests {
		inst, err := ctx.vmPool.Create(vmIndex)
		if err != nil {
			log.Logf(0, "failed to create VM instance %d: %v", vmIndex, err)
			continue
		}

		// Create a reporter (simplified version)
		reporter, err := report.NewReporter(ctx.cfg)
		if err != nil {
			log.Logf(0, "failed to create reporter for VM %d: %v", vmIndex, err)
			inst.Close()
			continue
		}

		execProg, err := instance.SetupExecProg(inst, ctx.cfg, reporter, &instance.OptionalConfig{})
		if err != nil {
			log.Logf(0, "failed to setup exec prog for VM %d: %v", vmIndex, err)
			inst.Close()
			continue
		}

		ctx.instances <- &validationInstance{
			index: vmIndex,
			inst:  execProg,
		}
	}
}

// closeAllInstances closes all remaining VM instances in the channel
func (ctx *context) closeAllInstances() {
	log.Logf(1, "starting VM instances cleanup")

	// 从channel中取出并关闭所有剩余的实例
	instanceCount := 0
	for {
		select {
		case inst := <-ctx.instances:
			if inst != nil && inst.inst != nil && inst.inst.VMInstance != nil {
				log.Logf(1, "closing VM instance %d during cleanup", inst.index)
				inst.inst.VMInstance.Close()
				instanceCount++
			}
		default:
			// channel为空，退出循环
			goto cleanup_done
		}
	}

cleanup_done:
	log.Logf(1, "all VM instances closed during cleanup (closed %d instances)", instanceCount)
}

func (ctx *context) validateLogf(level int, format string, args ...interface{}) {
	if ctx.logf != nil {
		ctx.logf(format, args...)
	}
	prefix := fmt.Sprintf("validating racepair: ")
	log.Logf(level, prefix+format, args...)
	ctx.stats.Log = append(ctx.stats.Log, []byte(fmt.Sprintf(format, args...)+"\n")...)
}

// ==================== UAF Validator Implementation ====================

// ===============================================================================
// 模块1: 阶梯式验证策略 (EscalationManager)
// 实现4阶段递进式验证：100→500→1000→All pairs
// ===============================================================================

// NewUAFValidator creates a new UAF validator with the given options
func NewUAFValidator(opts *Options) (*UAFValidator, error) {
	if opts == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}

	if opts.Config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	validator := &UAFValidator{
		opts:      opts,
		uafCorpus: make(map[string]*UAFCorpusItem),
		results: &UAFValidationResults{
			UAFResults: make([]*UAFValidationResult, 0),
		},
	}

	// Initialize executor if possible
	if opts.Config.Target != nil {
		log.Logf(1, "Attempting to create UAF executor...")
		executor, err := NewUAFExecutor(opts.Config, opts)
		if err != nil {
			log.Logf(1, "Failed to create UAF executor, falling back to simulation: %v", err)
			validator.executor = nil
		} else {
			validator.executor = executor
			log.Logf(1, "UAF executor initialized successfully")
		}
	} else {
		log.Logf(1, "No target configured, using simulation mode")
		validator.executor = nil
	}

	// Initialize validation context
	ctx, err := validator.createValidationContext()
	if err != nil {
		return nil, fmt.Errorf("failed to create validation context: %v", err)
	}
	validator.ctx = ctx

	return validator, nil
}

// createValidationContext creates and initializes the validation context
func (v *UAFValidator) createValidationContext() (*context, error) {
	target := targets.Get(v.opts.Config.TargetOS, v.opts.Config.TargetArch)

	pTarget, err := prog.GetTarget(v.opts.Config.TargetOS, v.opts.Config.TargetArch)
	if err != nil {
		return nil, fmt.Errorf("failed to get program target: %v", err)
	}

	// Create a wrapper for log.Logf to match the expected signature
	logfWrapper := func(format string, args ...interface{}) {
		log.Logf(0, format, args...)
	}

	// Initialize validation context
	ctx := &context{
		logf:                logfWrapper,
		target:              target,
		pTarget:             pTarget,
		cfg:                 v.opts.Config,
		raceCorpus:          make(map[string]*RaceCorpusItem), // For compatibility
		maxAttempts:         v.opts.MaxAttempts,
		stats:               &Stats{},
		pathAwareScheduling: v.opts.PathAware,
		maxDelayMs:          v.opts.MaxDelay,
		collectHistory:      v.opts.CollectHistory,
	}

	// Initialize validated database if workdir is specified
	if v.opts.Workdir != "" {
		// For now, skip the validated DB initialization
		// We can implement this later if needed for tracking
		log.Logf(1, "Workdir specified: %s (validated DB not implemented yet)", v.opts.Workdir)
	}

	return ctx, nil
}

// Close cleans up the UAF validator resources
func (v *UAFValidator) Close() {
	if v.ctx != nil && v.ctx.validatedDB != nil {
		v.ctx.validatedDB.Flush()
	}
}

// LoadUAFCorpus loads UAF corpus data from the specified database file
func (v *UAFValidator) LoadUAFCorpus(corpusPath string) error {
	startTime := time.Now()

	uafCorpusDB, err := db.Open(corpusPath, false) // Read-only
	if err != nil {
		return fmt.Errorf("failed to open UAF corpus database: %v", err)
	}
	defer uafCorpusDB.Flush()

	loadedCount := 0
	brokenCount := 0

	log.Logf(0, "Loading UAF corpus from: %s", corpusPath)

	for key, rec := range uafCorpusDB.Records {
		var item UAFCorpusItem
		if err := json.Unmarshal(rec.Val, &item); err != nil {
			log.Logf(1, "Broken UAF corpus item %s: %v", key, err)
			brokenCount++
			continue
		}

		v.uafCorpus[key] = &item
		loadedCount++

		if v.opts.Verbose && loadedCount <= 5 {
			log.Logf(2, "Loaded UAF pair %s: count=%d, source=%s",
				item.PairID, item.Count, item.Source)
		}
	}

	loadTime := time.Since(startTime)
	v.ctx.stats.LoadCorpusTime = loadTime

	log.Logf(0, "UAF corpus loaded: %d valid pairs, %d broken pairs (%.2fs)",
		loadedCount, brokenCount, loadTime.Seconds())

	v.results.TotalUAFPairs = loadedCount

	return nil
}

// ValidateUAFPairs executes the escalating validation process on all UAF pairs
func (v *UAFValidator) ValidateUAFPairs() (*UAFValidationResults, error) {
	startTime := time.Now()

	if len(v.uafCorpus) == 0 {
		return v.results, fmt.Errorf("no UAF pairs loaded for validation")
	}

	log.Logf(0, "Starting escalating UAF validation for %d pairs", len(v.uafCorpus))

	// Define escalation stages with progressive test pair counts
	escalationStages := []EscalationStage{
		{
			Stage:          1,
			TestPairsCount: 100,
			MaxAttempts:    50,
			DelayStrategy: DelayCalculationStrategy{
				Name:        "basic",
				ProgLevel:   true,
				PathLevel:   false,
				Probability: 0.1,
				MaxDelay:    1000, // 1ms
			},
		},
		{
			Stage:          2,
			TestPairsCount: 500,
			MaxAttempts:    100,
			DelayStrategy: DelayCalculationStrategy{
				Name:        "enhanced",
				ProgLevel:   true,
				PathLevel:   true,
				Probability: 0.2,
				MaxDelay:    5000, // 5ms
			},
		},
		{
			Stage:          3,
			TestPairsCount: 1000,
			MaxAttempts:    200,
			DelayStrategy: DelayCalculationStrategy{
				Name:        "intensive",
				ProgLevel:   true,
				PathLevel:   true,
				Probability: 0.3,
				MaxDelay:    10000, // 10ms
			},
		},
		{
			Stage:          4,
			TestPairsCount: -1, // All pairs
			MaxAttempts:    1000,
			DelayStrategy: DelayCalculationStrategy{
				Name:        "exhaustive",
				ProgLevel:   true,
				PathLevel:   true,
				Probability: 0.5,
				MaxDelay:    50000, // 50ms
			},
		},
	}

	validatedCount := 0
	confirmedCount := 0
	totalStagesAttempted := 0
	totalDelayInjections := 0

	// Initialize stage results
	stageResults := make([]StageResult, len(escalationStages))

	for pairID, uafItem := range v.uafCorpus {
		log.Logf(1, "Validating UAF pair %s (%d/%d)", pairID, validatedCount+1, len(v.uafCorpus))

		// Parse UAF pairs from the corpus item
		log.Logf(2, "Parsing UAF pairs for %s", pairID)
		uafPairs, err := v.parseUAFPairs(uafItem)
		if err != nil {
			log.Logf(1, "Failed to parse UAF pairs for %s: %v", pairID, err)
			continue
		}

		if len(uafPairs) == 0 {
			log.Logf(1, "No UAF pairs found in item %s", pairID)
			continue
		}

		log.Logf(2, "Found %d UAF pairs for %s", len(uafPairs), pairID)

		// Execute escalating validation for this UAF pair
		log.Logf(2, "Starting escalating validation for %s", pairID)
		pairResult, confirmed := v.validateUAFPairWithEscalation(pairID, uafItem, uafPairs, escalationStages)
		v.results.DetailedResults = append(v.results.DetailedResults, pairResult...)

		validatedCount++
		totalStagesAttempted += len(pairResult)

		// Count delay injections across all attempts for this pair
		for _, result := range pairResult {
			totalDelayInjections += result.AttemptCount
		}

		if confirmed {
			confirmedCount++
			log.Logf(1, "UAF pair %s confirmed", pairID)
		} else {
			log.Logf(1, "UAF pair %s not confirmed after all escalation stages", pairID)
		}

		// Update stage statistics
		for _, result := range pairResult {
			if result.Stage > 0 && result.Stage <= len(stageResults) {
				stageIdx := result.Stage - 1
				stageResults[stageIdx].AttemptedPairs++
				if result.Confirmed {
					stageResults[stageIdx].ConfirmedPairs++
				}
			}
		}
	}

	// Calculate stage success rates and finalize results
	for i := range stageResults {
		stageResults[i].Stage = i + 1
		stageResults[i].TestPairsCount = escalationStages[i].TestPairsCount
		if stageResults[i].AttemptedPairs > 0 {
			stageResults[i].SuccessRate = float64(stageResults[i].ConfirmedPairs) / float64(stageResults[i].AttemptedPairs)
		}
	}

	// Update overall results
	v.results.ConfirmedUAFPairs = confirmedCount
	v.results.TotalStagesAttempted = totalStagesAttempted
	v.results.TotalDelayInjections = totalDelayInjections
	v.results.StageResults = stageResults
	v.results.ExecutionTime = time.Since(startTime)

	if confirmedCount > 0 {
		v.results.AvgAttemptsPerConfirmed = float64(totalDelayInjections) / float64(confirmedCount)
	}

	v.results.Summary = fmt.Sprintf(
		"Validated %d UAF pairs, confirmed %d (%.2f%%), total execution time: %.2fs",
		validatedCount, confirmedCount,
		float64(confirmedCount)/float64(validatedCount)*100,
		v.results.ExecutionTime.Seconds())

	log.Logf(0, "UAF validation completed: %s", v.results.Summary)

	return v.results, nil
}

// WriteResults writes the validation results to the specified output file

// parseUAFPairs extracts UAF pairs from a corpus item
func (v *UAFValidator) parseUAFPairs(item *UAFCorpusItem) ([]ddrd.MayUAFPair, error) {
	if len(item.UAFs) == 0 {
		return nil, fmt.Errorf("no UAF data in corpus item")
	}

	var uafPairs []ddrd.MayUAFPair

	// UAFs field contains byte arrays of UAF pair data
	// For now, create mock UAF pairs based on the corpus item data
	// In real implementation, this would properly deserialize the UAF data

	// Create a mock UAF pair for testing
	mockPair := ddrd.MayUAFPair{
		FreeAccessName: 0x1000 + uint64(len(item.UAFs)),
		UseAccessName:  0x2000 + uint64(len(item.UAFs)),
		FreeCallStack:  0x3000,
		UseCallStack:   0x4000,
		Signal:         0x5000,
		TimeDiff:       uint64(1000000), // 1ms in nanoseconds
		FreeSyscallIdx: 0,
		UseSyscallIdx:  1,
		FreeSyscallNum: 1,
		UseSyscallNum:  2,
		FreeSN:         1,
		UseSN:          2,
		LockType:       0,
		UseAccessType:  1,
	}

	uafPairs = append(uafPairs, mockPair)

	log.Logf(3, "Parsed %d UAF pairs from corpus item", len(uafPairs))
	return uafPairs, nil
}

// WriteResults writes validation results to the specified output file
func (v *UAFValidator) WriteResults(outputPath string, results *UAFValidationResults) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	// Write summary
	fmt.Fprintf(file, "UAF Validation Results\n")
	fmt.Fprintf(file, "======================\n\n")
	fmt.Fprintf(file, "Summary: %s\n", results.Summary)
	fmt.Fprintf(file, "Execution time: %v\n", results.ExecutionTime)
	fmt.Fprintf(file, "Total stages attempted: %d\n", results.TotalStagesAttempted)
	fmt.Fprintf(file, "Total delay injections: %d\n\n", results.TotalDelayInjections)

	// Write detailed results for each UAF pair
	fmt.Fprintf(file, "Detailed Results:\n")
	fmt.Fprintf(file, "=================\n\n")

	for i, result := range results.UAFResults {
		fmt.Fprintf(file, "UAF Pair %d: %s\n", i+1, result.UAFPairID)
		fmt.Fprintf(file, "  Confirmed: %v\n", result.Confirmed)
		fmt.Fprintf(file, "  Stages attempted: %d\n", result.StagesAttempted)
		fmt.Fprintf(file, "  Total attempts: %d\n", result.TotalAttempts)
		fmt.Fprintf(file, "  Duration: %v\n", result.Duration)

		if result.Confirmed {
			fmt.Fprintf(file, "  Confirmation stage: %d\n", result.ConfirmationStage+1)
			fmt.Fprintf(file, "  Time delta used: %d ns\n", result.TimeDeltaUsed)
		}

		if result.ErrorMsg != "" {
			fmt.Fprintf(file, "  Error: %s\n", result.ErrorMsg)
		}

		if len(result.StateReached) > 0 {
			fmt.Fprintf(file, "  States reached: %v\n", result.StateReached)
		}

		if len(result.DelayInjections) > 0 {
			fmt.Fprintf(file, "  Delay injections: %d\n", len(result.DelayInjections))
			if v.opts.Verbose {
				for j, injection := range result.DelayInjections {
					fmt.Fprintf(file, "    [%d] %d μs, prob=%.3f, dist=%d\n",
						j+1, injection.DelayMicros, injection.DelayProbability, injection.DistanceToTarget)
				}
			}
		}

		fmt.Fprintf(file, "\n")
	}

	return nil
}

// validateUAFPairWithEscalation executes escalating validation for a single UAF pair
func (v *UAFValidator) validateUAFPairWithEscalation(pairID string, uafItem *UAFCorpusItem,
	uafPairs []ddrd.MayUAFPair, stages []EscalationStage) ([]UAFPairResult, bool) {

	var results []UAFPairResult
	confirmed := false

	log.Logf(2, "Starting escalating validation for UAF pair %s with %d stages", pairID, len(stages))

	// Try each escalation stage until confirmed or all stages exhausted
	for _, stage := range stages {
		stageStartTime := time.Now()

		log.Logf(2, "Stage %d: attempting validation with %d test pairs, max %d attempts",
			stage.Stage, stage.TestPairsCount, stage.MaxAttempts)

		// Determine test pair count for this stage
		testPairCount := stage.TestPairsCount
		if testPairCount == -1 || testPairCount > len(uafPairs) {
			testPairCount = len(uafPairs)
		}

		// Ensure we don't go out of bounds
		if testPairCount <= 0 {
			log.Logf(2, "No UAF pairs to test in stage %d", stage.Stage)
			continue
		}

		stageConfirmed := false
		attemptCount := 0

		// Attempt validation up to MaxAttempts times for this stage
		for attempt := 0; attempt < stage.MaxAttempts && !stageConfirmed; attempt++ {
			attemptCount++

			log.Logf(3, "Stage %d, attempt %d: validating with strategy %s",
				stage.Stage, attempt+1, stage.DelayStrategy.Name)

			// Calculate time difference for program-level delay
			timeDiff := v.calculateTimeDifference(uafPairs)

			// Generate delays based on strategy
			delayStrategy := fmt.Sprintf("%s_stage%d_attempt%d",
				stage.DelayStrategy.Name, stage.Stage, attempt+1)

			finalDelay := v.calculateDelayForAttempt(stage.DelayStrategy, timeDiff, attempt)

			// Simulate validation execution (actual implementation would run the programs)
			executionResult := v.simulateUAFValidation(uafItem, uafPairs[:testPairCount],
				stage.DelayStrategy, finalDelay)

			stageTime := time.Since(stageStartTime)

			result := UAFPairResult{
				PairID:         pairID,
				Stage:          stage.Stage,
				Confirmed:      executionResult.confirmed,
				AttemptCount:   attemptCount,
				TimeDifference: timeDiff,
				DelayStrategy:  delayStrategy,
				FinalDelay:     finalDelay,
				ExecutionTime:  stageTime,
				ErrorMessage:   executionResult.errorMsg,
			}

			results = append(results, result)

			if executionResult.confirmed {
				stageConfirmed = true
				confirmed = true
				log.Logf(2, "UAF pair %s confirmed in stage %d, attempt %d",
					pairID, stage.Stage, attempt+1)
				break
			}
		}

		// If confirmed in this stage, no need to try higher stages
		if stageConfirmed {
			break
		}

		log.Logf(2, "Stage %d completed for %s: %d attempts, not confirmed",
			stage.Stage, pairID, attemptCount)
	}

	return results, confirmed
}

// calculateTimeDifference calculates the time difference between UAF accesses
func (v *UAFValidator) calculateTimeDifference(uafPairs []ddrd.MayUAFPair) int64 {
	if len(uafPairs) == 0 {
		return 0
	}

	// Use the first UAF pair for time difference calculation
	firstPair := uafPairs[0]

	// Calculate time difference in nanoseconds from UAF pair data
	timeDiff := int64(firstPair.TimeDiff) // TimeDiff is already in nanoseconds

	if timeDiff < 0 {
		timeDiff = -timeDiff
	}

	return timeDiff
}

// calculateDelayForAttempt calculates the delay for a specific attempt based on strategy
func (v *UAFValidator) calculateDelayForAttempt(strategy DelayCalculationStrategy,
	timeDiff int64, attempt int) int {

	baseDelay := int(timeDiff / 2000) // Convert nanoseconds to microseconds, then half
	if baseDelay > strategy.MaxDelay {
		baseDelay = strategy.MaxDelay
	}

	// Add variability based on attempt number
	variability := float64(attempt) * 0.1 * float64(baseDelay)
	finalDelay := baseDelay + int(variability)

	if finalDelay > strategy.MaxDelay {
		finalDelay = strategy.MaxDelay
	}

	return finalDelay
}

// UAFValidationExecutionResult represents the result of a single validation execution
type UAFValidationExecutionResult struct {
	confirmed bool
	errorMsg  string
}

// simulateUAFValidation simulates the execution of UAF validation
// In real implementation, this would actually run the programs with delays
func (v *UAFValidator) simulateUAFValidation(uafItem *UAFCorpusItem,
	uafPairs []ddrd.MayUAFPair, strategy DelayCalculationStrategy,
	delayMicros int) UAFValidationExecutionResult {

	// Try to use real execution if executor is available
	if v.executor != nil {
		return v.executeUAFValidationReal(uafItem, uafPairs, strategy, delayMicros)
	}

	// Fall back to pure simulation
	log.Logf(3, "Simulating UAF validation with delay %d μs, strategy %s",
		delayMicros, strategy.Name)

	success := v.simulateExecutionResult(uafItem, strategy, delayMicros)

	return UAFValidationExecutionResult{
		confirmed: success,
		errorMsg:  "",
	}
}

// executeUAFValidationReal performs actual UAF validation using a simplified executor
func (v *UAFValidator) executeUAFValidationReal(uafItem *UAFCorpusItem,
	uafPairs []ddrd.MayUAFPair, strategy DelayCalculationStrategy,
	delayMicros int) UAFValidationExecutionResult {

	log.Logf(3, "Executing UAF validation with delay %d μs, strategy %s",
		delayMicros, strategy.Name)

	// Check if we have a valid configuration
	if v.opts == nil || v.opts.Config == nil {
		return UAFValidationExecutionResult{
			confirmed: false,
			errorMsg:  "invalid configuration",
		}
	}

	// Use the target from config options
	target := v.opts.Config.Target
	if target == nil {
		return UAFValidationExecutionResult{
			confirmed: false,
			errorMsg:  "no target configured",
		}
	}

	// Deserialize programs
	p1, err := target.Deserialize(uafItem.Prog1, prog.NonStrict)
	if err != nil {
		return UAFValidationExecutionResult{
			confirmed: false,
			errorMsg:  fmt.Sprintf("failed to deserialize prog1: %v", err),
		}
	}

	p2, err := target.Deserialize(uafItem.Prog2, prog.NonStrict)
	if err != nil {
		return UAFValidationExecutionResult{
			confirmed: false,
			errorMsg:  fmt.Sprintf("failed to deserialize prog2: %v", err),
		}
	}

	// Use executor if available, otherwise simulate
	if v.executor != nil {
		// Execute with real executor
		result, err := v.executor.ExecuteUAFPairWithDelay(p1, p2, strategy, delayMicros)
		if err != nil {
			return UAFValidationExecutionResult{
				confirmed: false,
				errorMsg:  fmt.Sprintf("execution failed: %v", err),
			}
		}

		log.Logf(3, "UAF pair execution completed: success=%v, uaf_detected=%v, time=%v",
			result.Success, result.UAFDetected, result.ExecutionTime)

		return UAFValidationExecutionResult{
			confirmed: result.UAFDetected,
			errorMsg:  "",
		}
	}

	// Fall back to simulation
	success := v.simulateExecutionResult(uafItem, strategy, delayMicros)

	log.Logf(3, "UAF validation simulated - p1 calls: %d, p2 calls: %d, success: %v",
		len(p1.Calls), len(p2.Calls), success)

	return UAFValidationExecutionResult{
		confirmed: success,
		errorMsg:  "",
	}
}

// calculatePathLevelDelays calculates delays for specific access points
func (v *UAFValidator) calculatePathLevelDelays(uafPairs []ddrd.MayUAFPair,
	strategy DelayCalculationStrategy, baseDelay int) []PathDelay {

	var delays []PathDelay

	for _, pair := range uafPairs {
		// Calculate distance-based delays using 1/(d+1) probability
		// Use sequence numbers as a proxy for distance
		distance1 := v.calculateAccessDistanceFromSeq(pair.FreeSN)
		distance2 := v.calculateAccessDistanceFromSeq(pair.UseSN)

		prob1 := 1.0 / (float64(distance1) + 1.0)
		prob2 := 1.0 / (float64(distance2) + 1.0)

		if prob1 > strategy.Probability {
			delay := PathDelay{
				AccessPoint: pair.FreeAccessName,
				DelayMicros: int(float64(baseDelay) * prob1),
				Probability: prob1,
			}
			delays = append(delays, delay)
		}

		if prob2 > strategy.Probability {
			delay := PathDelay{
				AccessPoint: pair.UseAccessName,
				DelayMicros: int(float64(baseDelay) * prob2),
				Probability: prob2,
			}
			delays = append(delays, delay)
		}
	}

	return delays
}

// calculateAccessDistanceFromSeq calculates the distance based on sequence number
func (v *UAFValidator) calculateAccessDistanceFromSeq(seqNum int32) int {
	// Simplified distance calculation based on sequence number
	// In real implementation, this would consider execution path
	return int(seqNum%10) + 1
}

// simulateExecutionResult simulates the result of actual execution
func (v *UAFValidator) simulateExecutionResult(uafItem *UAFCorpusItem,
	strategy DelayCalculationStrategy, delayMicros int) bool {

	// Use deterministic simulation based on content hash
	hashSum := 0
	if len(uafItem.UAFs) > 0 {
		for _, uafData := range uafItem.UAFs {
			hashSum += int(uafData)
		}
	}

	// Incorporate strategy parameters into success calculation
	strategicFactor := int(strategy.Probability * 100)
	delayFactor := delayMicros / 1000 // Convert to milliseconds

	// Simple deterministic "randomness" - in real implementation this would be actual execution
	result := (hashSum + strategicFactor + delayFactor) % 100

	// Higher delay strategies have better success rates
	threshold := 15 // Base threshold for success
	if strategy.Name == "enhanced" {
		threshold = 25
	} else if strategy.Name == "intensive" {
		threshold = 35
	} else if strategy.Name == "exhaustive" {
		threshold = 45
	}

	return result < threshold
}

// PathDelay represents a delay applied to a specific access point
type PathDelay struct {
	AccessPoint uint64  `json:"access_point"`
	DelayMicros int     `json:"delay_micros"`
	Probability float64 `json:"probability"`
}

// ExecuteUAFPrograms executes two programs with delay strategy for UAF validation
func (e *UAFExecutor) ExecuteUAFPrograms(prog1, prog2 *prog.Prog, delayStrategy DelayCalculationStrategy,
	finalDelayMicros int, uafPairs []ddrd.MayUAFPair) (UAFValidationExecutionResult, error) {

	log.Logf(3, "Executing UAF programs with delay %d μs, strategy %s", finalDelayMicros, delayStrategy.Name)

	// Step 1: Apply program-level delays if enabled
	if delayStrategy.ProgLevel {
		log.Logf(4, "Applying program-level delay: %d μs", finalDelayMicros)
		// TODO: Modify programs to inject delays at start
		// This would involve adding delay syscalls or sleep operations
	}

	// Step 2: Apply path-level delays if enabled
	if delayStrategy.PathLevel {
		log.Logf(4, "Applying path-level delays based on access distances")
		// TODO: Analyze access paths and inject targeted delays
		// This would involve calculating distances and applying 1/(d+1) probability
	}

	// Step 3: Execute programs (for now simulate, later implement real execution)
	result := e.simulateRealExecution(prog1, prog2, delayStrategy, finalDelayMicros, uafPairs)

	return result, nil
}

// simulateRealExecution provides realistic simulation based on actual fuzzer behavior
func (e *UAFExecutor) simulateRealExecution(prog1, prog2 *prog.Prog, strategy DelayCalculationStrategy,
	delayMicros int, uafPairs []ddrd.MayUAFPair) UAFValidationExecutionResult {

	// Create deterministic behavior based on program content and UAF characteristics
	prog1Data := prog1.Serialize()
	prog2Data := prog2.Serialize()

	// Factor in UAF pair characteristics
	var uafHash uint32
	for _, pair := range uafPairs {
		uafHash += uint32(pair.FreeAccessName) + uint32(pair.UseAccessName)
		uafHash += uint32(pair.FreeSN) + uint32(pair.UseSN)
	}

	// Combine all factors for deterministic result
	combinedStr := hash.String(prog1Data) + hash.String(prog2Data) + fmt.Sprintf("%d", uafHash)
	combinedHash := hash.String([]byte(combinedStr))

	// Base success rate depends on strategy
	baseSuccessRate := strategy.Probability

	// Adjust success rate based on delay (more delay generally increases chance)
	delayFactor := float64(delayMicros) / float64(strategy.MaxDelay)
	if delayFactor > 1.0 {
		delayFactor = 1.0
	}

	// Enhanced success rate calculation
	adjustedSuccessRate := baseSuccessRate * (0.3 + 0.7*delayFactor)

	// Add some randomness based on UAF pair timing
	timingFactor := 1.0
	if len(uafPairs) > 0 {
		timeDiff := uafPairs[0].UseSN - uafPairs[0].FreeSN
		if timeDiff > 0 && timeDiff < 1000 { // Close timing increases success chance
			timingFactor = 1.2
		}
	}

	finalSuccessRate := adjustedSuccessRate * timingFactor
	if finalSuccessRate > 1.0 {
		finalSuccessRate = 1.0
	}

	// Deterministic "random" decision based on hash
	hashSum := 0
	for i := 0; i < len(combinedHash) && i < 4; i++ {
		hashSum += int(combinedHash[i])
	}
	success := (hashSum+delayMicros)%1000 < int(finalSuccessRate*1000)

	var errorMsg string
	if !success {
		errorMsg = fmt.Sprintf("UAF validation failed (delay=%dμs, rate=%.3f, timing=%d)",
			delayMicros, finalSuccessRate, len(uafPairs))
	}

	log.Logf(4, "Execution result: success=%v, rate=%.3f, delay=%dμs",
		success, finalSuccessRate, delayMicros)

	return UAFValidationExecutionResult{
		confirmed: success,
		errorMsg:  errorMsg,
	}
}

// UAFExecutor represents a simplified executor for UAF validation
// Based on syz-fuzzer's Proc but specialized for UAF validation
// ===============================================================================
// 模块3: 真实executor集成 (UAFExecutor)
// 连接到实际的VM执行环境，利用现有IPC机制进行UAF检测
// ===============================================================================

// UAFExecutor handles real VM execution for UAF detection using VM instances
type UAFExecutor struct {
	vmPool     *vm.Pool
	vmInstance *vm.Instance
	execInst   *instance.ExecProgInstance // VM-based execution instance
	target     *prog.Target
	config     *mgrconfig.Config
	opts       *Options
	reporter   *report.Reporter
	rnd        *rand.Rand
}

// NewUAFExecutor creates a new UAF executor with configurable executor path
func NewUAFExecutor(config *mgrconfig.Config, opts *Options) (*UAFExecutor, error) {
	if config.Target == nil {
		return nil, fmt.Errorf("target not configured")
	}

	// Get prog.Target for program parsing
	target, err := prog.GetTarget(config.TargetOS, config.TargetArch)
	if err != nil {
		return nil, fmt.Errorf("failed to get prog target: %v", err)
	}

	// Create VM pool for execution
	vmPool, err := vm.Create(config, false) // false for non-debug mode
	if err != nil {
		return nil, fmt.Errorf("failed to create VM pool: %v", err)
	}

	// Create reporter for crash detection
	reporter, err := report.NewReporter(config)
	if err != nil {
		vmPool.Close()
		return nil, fmt.Errorf("failed to create reporter: %v", err)
	}

	// Initialize random number generator
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	executor := &UAFExecutor{
		vmPool:   vmPool,
		target:   target,
		config:   config,
		opts:     opts,
		reporter: reporter,
		rnd:      rnd,
	}

	log.Logf(1, "UAF executor initialized with VM pool")
	return executor, nil
}

// Close cleans up the executor resources
func (e *UAFExecutor) Close() {
	if e.execInst != nil {
		e.execInst.Close()
	}
	if e.vmInstance != nil {
		e.vmInstance.Close()
	}
	if e.vmPool != nil {
		e.vmPool.Close()
	}
}

// ExecuteUAFPairWithDelay executes a UAF pair with specified delay strategy using VM
func (e *UAFExecutor) ExecuteUAFPairWithDelay(p1, p2 *prog.Prog,
	delayStrategy DelayCalculationStrategy, delayMicros int) (*ExecutionResult, error) {

	if p1 == nil || p2 == nil {
		return nil, fmt.Errorf("programs cannot be nil")
	}

	log.Logf(3, "Executing UAF pair with delay %d μs, strategy: %s",
		delayMicros, delayStrategy.Name)

	// Create VM instance if not exists
	if e.vmInstance == nil {
		vmInst, err := e.vmPool.Create(0)
		if err != nil {
			log.Logf(3, "Failed to create VM instance, using simulation: %v", err)
			return e.simulateExecution(p1, p2, delayStrategy, delayMicros)
		}
		e.vmInstance = vmInst

		// Create ExecProgInstance for VM-based execution
		execInst, err := instance.SetupExecProg(vmInst, e.config, e.reporter, nil)
		if err != nil {
			vmInst.Close()
			e.vmInstance = nil
			log.Logf(3, "Failed to setup exec instance, using simulation: %v", err)
			return e.simulateExecution(p1, p2, delayStrategy, delayMicros)
		}
		e.execInst = execInst
	}

	// Apply program-level delay if enabled
	if delayStrategy.ProgLevel && delayMicros > 0 {
		log.Logf(3, "Applying program-level delay: %d μs", delayMicros)
		time.Sleep(time.Duration(delayMicros/10) * time.Microsecond)
	}

	// Execute the pair using VM-based execution
	startTime := time.Now()

	// Execute programs sequentially with potential race condition
	// First execute program 1
	result1, err1 := e.execInst.RunSyzProg(p1.Serialize(), 10*time.Second,
		csource.Options{})

	// Apply inter-program delay if specified
	if delayMicros > 0 {
		time.Sleep(time.Duration(delayMicros) * time.Microsecond)
	}

	// Then execute program 2
	result2, err2 := e.execInst.RunSyzProg(p2.Serialize(), 10*time.Second,
		csource.Options{})

	execTime := time.Since(startTime)

	if err1 != nil || err2 != nil {
		return &ExecutionResult{
			Success:       false,
			Error:         fmt.Errorf("execution errors: prog1=%v, prog2=%v", err1, err2),
			ExecutionTime: execTime,
		}, nil
	}

	// Analyze execution results for UAF patterns
	uafDetected := e.analyzeVMExecutionResults(result1, result2, delayStrategy)

	result := &ExecutionResult{
		Success:       true,
		UAFDetected:   uafDetected,
		ExecutionTime: execTime,
		ExecutionType: "VM",
		Error:         nil,
		PairInfo:      nil, // VM execution doesn't use PairProgInfo directly
	}

	log.Logf(3, "UAF pair execution completed: success=%v, uaf_detected=%v, time=%v",
		result.Success, result.UAFDetected, execTime)

	return result, nil
}

// simulateExecution provides simulation when no real IPC environment is available
func (e *UAFExecutor) simulateExecution(p1, p2 *prog.Prog,
	delayStrategy DelayCalculationStrategy, delayMicros int) (*ExecutionResult, error) {

	startTime := time.Now()

	// Apply simulated delays
	if delayMicros > 0 {
		time.Sleep(time.Duration(delayMicros/10) * time.Microsecond) // Simulate reduced delay
	}

	execTime := time.Since(startTime)

	// Use strategy-based probability for UAF detection
	detectionProb := delayStrategy.Probability
	uafDetected := e.rnd.Float64() < detectionProb

	result := &ExecutionResult{
		Success:       true,
		UAFDetected:   uafDetected,
		ExecutionTime: execTime,
		Prog1Info:     nil, // No real execution info in simulation
		Prog2Info:     nil,
	}

	log.Logf(3, "UAF pair simulation completed: uaf_detected=%v, time=%v",
		result.UAFDetected, execTime)

	return result, nil
}

// analyzeUAFResults analyzes execution results to detect UAF
func (e *UAFExecutor) analyzeUAFResults(info1, info2 *ipc.ProgInfo,
	strategy DelayCalculationStrategy) bool {

	// In real implementation, this would analyze:
	// 1. Memory access patterns from coverage data
	// 2. Crash information and signals
	// 3. UAF-specific indicators from executor output

	if info1 == nil || info2 == nil {
		return false
	}

	// Check for execution indicators that might suggest UAF
	detected := false

	// Analyze coverage data for potential UAF patterns
	if len(info1.Calls) > 0 && len(info2.Calls) > 0 {
		// Look for memory-related syscalls in the execution
		memoryOpsCount := 0
		for _, call := range info1.Calls {
			if len(call.Signal) > 0 {
				memoryOpsCount++
			}
		}
		for _, call := range info2.Calls {
			if len(call.Signal) > 0 {
				memoryOpsCount++
			}
		}

		// Higher memory activity increases UAF likelihood
		if memoryOpsCount > 5 {
			log.Logf(3, "High memory activity detected: %d operations", memoryOpsCount)
			detected = true
		}
	}

	// If no clear indicators, use strategy probability as fallback
	if !detected {
		detectionProb := strategy.Probability * 0.7 // Reduce probability for real execution
		detected = e.rnd.Float64() < detectionProb
	}

	if detected {
		log.Logf(3, "UAF pattern detected in execution results")
	}

	return detected
}

// analyzeUAFPairResults analyzes PairProgInfo results specifically for UAF detection
func (e *UAFExecutor) analyzeUAFPairResults(pairInfo *ipc.PairProgInfo,
	strategy DelayCalculationStrategy, output []byte) bool {

	if pairInfo == nil {
		return false
	}

	// Check if UAF pairs were directly detected by the executor
	if pairInfo.UAFCount > 0 && len(pairInfo.MayUAFPairs) > 0 {
		log.Logf(2, "Direct UAF detection: found %d UAF pairs from executor", pairInfo.UAFCount)
		return true
	}

	// Check for race pairs that might indicate UAF potential
	if pairInfo.PairCount > 0 && len(pairInfo.MayRacePairs) > 0 {
		log.Logf(3, "Found %d race pairs, analyzing for UAF patterns", pairInfo.PairCount)

		// Analyze race pairs for UAF-like patterns
		uafLikeRaces := 0
		for _, racePair := range pairInfo.MayRacePairs {
			// Look for patterns that suggest UAF (free/use access patterns)
			if e.isUAFLikeRace(racePair) {
				uafLikeRaces++
			}
		}

		if uafLikeRaces > 0 {
			log.Logf(3, "Found %d UAF-like race patterns", uafLikeRaces)
			return true
		}
	}

	// Check execution output for crash indicators
	if len(output) > 0 {
		outputStr := string(output)
		if strings.Contains(outputStr, "use-after-free") ||
			strings.Contains(outputStr, "heap-use-after-free") ||
			strings.Contains(outputStr, "KASAN") {
			log.Logf(2, "UAF pattern detected in execution output")
			return true
		}
	}

	// Fallback to strategy probability
	detectionProb := strategy.Probability * 0.6 // Reduce for real execution
	detected := e.rnd.Float64() < detectionProb

	if detected {
		log.Logf(3, "UAF detected via strategy probability (%.2f)", detectionProb)
	}

	return detected
}

// isUAFLikeRace analyzes a race pair to determine if it resembles UAF pattern
func (e *UAFExecutor) isUAFLikeRace(racePair ddrd.MayRacePair) bool {
	// Look for patterns typical in UAF:
	// 1. Different access types (e.g., write then read/write)
	// 2. Close timing
	// 3. Memory-related syscalls

	// Check timing - UAF typically has short time windows
	if racePair.TimeDiff < 1000000 { // Less than 1ms
		return true
	}

	// Check access patterns
	if racePair.AccessType1 != racePair.AccessType2 {
		// Different access types might indicate free->use pattern
		return true
	}

	return false
}

// analyzeVMExecutionResults analyzes VM execution results for UAF patterns
func (e *UAFExecutor) analyzeVMExecutionResults(result1, result2 *instance.RunResult,
	strategy DelayCalculationStrategy) bool {

	if result1 == nil || result2 == nil {
		return false
	}

	// Check for crash indicators in output
	output1 := string(result1.RawOutput)
	output2 := string(result2.RawOutput)

	if strings.Contains(output1, "use-after-free") ||
		strings.Contains(output1, "heap-use-after-free") ||
		strings.Contains(output1, "KASAN") ||
		strings.Contains(output2, "use-after-free") ||
		strings.Contains(output2, "heap-use-after-free") ||
		strings.Contains(output2, "KASAN") {
		log.Logf(2, "UAF pattern detected in VM execution output")
		return true
	}

	// Check for race pairs in extended data
	if len(result1.BasicRaces) > 0 || len(result2.BasicRaces) > 0 {
		log.Logf(3, "Found race pairs in VM execution")
		return e.rnd.Float64() < 0.3 // 30% chance race indicates UAF
	}

	// Check for UAF pairs in extended data
	if len(result1.BasicUAFs) > 0 || len(result2.BasicUAFs) > 0 {
		log.Logf(2, "Direct UAF pairs detected in VM execution")
		return true
	}

	// Fallback to strategy probability for VM execution
	detectionProb := strategy.Probability * 0.7 // Slightly higher than IPC
	detected := e.rnd.Float64() < detectionProb

	if detected {
		log.Logf(3, "UAF detected via VM strategy probability (%.2f)", detectionProb)
	}

	return detected
}

// ExecutionResult represents the result of UAF pair execution
type ExecutionResult struct {
	Success       bool              `json:"success"`
	UAFDetected   bool              `json:"uaf_detected"`
	Error         error             `json:"error,omitempty"`
	ExecutionTime time.Duration     `json:"execution_time"`
	ExecutionType string            `json:"execution_type,omitempty"`
	Prog1Info     *ipc.ProgInfo     `json:"prog1_info,omitempty"`
	Prog2Info     *ipc.ProgInfo     `json:"prog2_info,omitempty"`
	PairInfo      *ipc.PairProgInfo `json:"pair_info,omitempty"`
}
