// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package racevalidate

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
)

// // validationContext manages the race validation process
// type validationContext struct {
// }

// RaceResult contains validation result for a single race
type RaceResult struct {
	PairID    string
	Confirmed bool
	Attempts  int
	Duration  time.Duration
	Reports   []*report.Report
	ErrorMsg  string
	Report    *report.Report // Add Report field
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
	FirstSeen   time.Time `json:"first_seen"`
	LastUpdated time.Time `json:"last_updated"`
	Source      string    `json:"source"` // source fuzzer name
	Count       int       `json:"count"`  // discovery count
}

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
	// Prepare context
	ctx, err := prepareCtx(corpusPath, cfg, hostFeatures, reporter, vmPool, len(vmIndexes), maxAttempts)
	if err != nil {
		return nil, nil, err
	}

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

func prepareCtx(corpusPath string, cfg *mgrconfig.Config, features *host.Features, reporter *report.Reporter,
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
	} else {
		ctx.validateLogf(1, "race pair %s has no race data", raceItem.PairID)
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

	result.Duration = time.Since(startTime)
	return result
}

// attemptValidation performs a single race validation attempt
func (ctx *context) attemptValidation(prog1, prog2 *prog.Prog, raceItem *RaceCorpusItem, racePairs []ddrd.MayRacePair) []*report.Report {
	// Get VM instance
	inst := <-ctx.instances
	defer func() {
		ctx.instances <- inst
	}()

	// Create temporary files for the programs
	prog1Data := prog1.Serialize()
	prog2Data := prog2.Serialize()

	prog1File, err := osutil.WriteTempFile(prog1Data)
	if err != nil {
		log.Logf(0, "failed to write prog1 temp file: %v", err)
		return nil
	}
	defer os.Remove(prog1File)

	prog2File, err := osutil.WriteTempFile(prog2Data)
	if err != nil {
		log.Logf(0, "failed to write prog2 temp file: %v", err)
		return nil
	}
	defer os.Remove(prog2File)

	// Copy programs to VM
	_, err = inst.inst.VMInstance.Copy(prog1File)
	if err != nil {
		log.Logf(0, "failed to copy prog1 to VM: %v", err)
		return nil
	}

	_, err = inst.inst.VMInstance.Copy(prog2File)
	if err != nil {
		log.Logf(0, "failed to copy prog2 to VM: %v", err)
		return nil
	}

	// Execute race validation through VM instance
	// Use actual race information if available, otherwise use defaults
	var reports []*report.Report

	if len(racePairs) > 0 {
		// Try validation for each race pair
		for i, racePair := range racePairs {
			ctx.validateLogf(2, "validating race pair %d/%d: signal=0x%x, vars=[%d,%d], callstacks=[0x%x,0x%x], sn=[%d,%d], lock=%d",
				i+1, len(racePairs), racePair.Signal, racePair.VarName1, racePair.VarName2,
				racePair.CallStack1, racePair.CallStack2, racePair.Sn1, racePair.Sn2, racePair.LockType)

			result, err := inst.inst.RunRaceValidation(prog1Data, prog2Data, 30*time.Second,
				racePair.Signal, racePair.VarName1, racePair.VarName2,
				racePair.CallStack1, racePair.CallStack2, uint64(racePair.Sn1), uint64(racePair.Sn2),
				racePair.LockType, ctx.maxAttempts)

			if err != nil {
				ctx.validateLogf(0, "race validation execution failed for pair %d: %v", i+1, err)
				continue
			}

			// Process results for this race pair
			if result.Report != nil {
				reports = append(reports, result.Report)
				ctx.validateLogf(1, "race validation detected crash for pair %d: %v", i+1, result.Report.Title)
			} else {
				ctx.validateLogf(1, "race validation completed without crash for pair %d", i+1)
			}
		}
	} else {
		// Fallback when no race pairs are available
		ctx.validateLogf(2, "have no may race pair!")
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
