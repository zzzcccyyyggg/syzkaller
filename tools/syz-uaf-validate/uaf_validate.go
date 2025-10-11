// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/racevalidate"
	"github.com/google/syzkaller/pkg/vmexec"
)

// ExecutionRecord represents a single VM execution record (from vmexec package)
type ExecutionRecord vmexec.ExecutionRecord

// Keep the same with UAFCorpusItem in syz-manager.go
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

// Command line flags
var (
	flagConfig   = flag.String("config", "", "manager configuration file (manager.cfg)")
	flagCount    = flag.Int("count", 0, "number of VMs to use (overrides config count param)")
	flagVerbose  = flag.Bool("verbose", false, "print verbose output")
	flagAttempts = flag.Int("attempts", 3, "number of validation attempts per race")
	flagForce    = flag.Bool("force", false, "force re-validation of already validated pairs (not implemented)")
	flagHelp     = flag.Bool("help", false, "show detailed usage information")
	// Path-distance-aware scheduling options
	flagPathAware      = flag.Bool("path-aware", false, "enable path-distance-aware scheduling for better race reproduction")
	flagCollectHistory = flag.Bool("collect-history", false, "collect and use access history for delay injection")
)

func usage() {
	flag.PrintDefaults()
}

// runUAFValidation executes the complete UAF validation pipeline
func runUAFValidation(cfg *mgrconfig.Config, corpusPath string) error {
	log.Logf(0, "Starting UAF validation pipeline")
	log.Logf(0, "Configuration: config=%s, corpus=%s", *flagConfig, corpusPath)
	log.Logf(0, "Parameters: count=%d, attempts=%d, verbose=%v", *flagCount, *flagAttempts, *flagVerbose)

	// Import racevalidate package functionality
	return runUAFValidationWithRaceValidate(cfg, corpusPath)
}

// runUAFValidationWithRaceValidate implements UAF validation using the racevalidate package
func runUAFValidationWithRaceValidate(cfg *mgrconfig.Config) error {
	log.Logf(0, "Initializing UAF validation context")

	// Initialize validation options
	validationOpts := &racevalidate.Options{
		Config:         cfg,
		MaxAttempts:    *flagAttempts,
		Verbose:        *flagVerbose,
		VMCount:      	*flagCount,
		PathAware:      *flagPathAware,
		CollectHistory: *flagCollectHistory,
	}

	if *flagCount > 0 {
		validationOpts.VMCount = *flagCount
	}
	validator, err := racevalidate.NewUAFValidator(validationOpts)
	if err != nil {
		return fmt.Errorf("failed to create UAF validator: %v", err)
	}
	defer validator.Close()

	// Load UAF corpus data
	err = validator.LoadUAFCorpus(corpusPath)
	if err != nil {
		return fmt.Errorf("failed to load UAF corpus: %v", err)
	}

	// Execute escalating UAF validation
	log.Logf(0, "Starting escalating UAF validation process")
	results, err := validator.ValidateUAFPairs()
	if err != nil {
		return fmt.Errorf("UAF validation failed: %v", err)
	}

	// Output results
	log.Logf(0, "UAF validation completed successfully")
	log.Logf(0, "Total UAF pairs validated: %d", results.TotalUAFPairs)
	log.Logf(0, "Confirmed UAF pairs: %d", results.ConfirmedUAFPairs)
	log.Logf(0, "Success rate: %.2f%%",
		float64(results.ConfirmedUAFPairs)/float64(results.TotalUAFPairs)*100)

	if *flagVerbose {
		log.Logf(0, "Validation stages attempted across all pairs: %d", results.TotalStagesAttempted)
		log.Logf(0, "Total delay injections performed: %d", results.TotalDelayInjections)
		log.Logf(0, "Average attempts per confirmed UAF: %.2f", results.AvgAttemptsPerConfirmed)
	}

	// Write detailed results to output file
	err = validator.WriteResults(*flagOutput, results)
	if err != nil {
		log.Logf(0, "Warning: failed to write results to file %s: %v", *flagOutput, err)
	} else {
		log.Logf(0, "Detailed results written to: %s", *flagOutput)
	}

	return nil
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Fatalf("panic: %v", r)
		}
	}()

	flag.Usage = usage
	flag.Parse()

	if *flagHelp {
		usage()
		return
	}

	if *flagConfig == "" {
		log.Fatalf("manager config file (-config) is required")
	}

	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("Failed to load config %v: %v", *flagConfig, err)
	}

	// Determine corpus path
	corpusPath := mgrconfig.
	if *flagValidateUAF && (*flagCorpus == "uaf-corpus.db" || *flagUAFCorpus != "uaf-corpus.db") {
		corpusPath = *flagUAFCorpus
	}

	// Auto-locate corpus in workdir if needed
	if !filepath.IsAbs(corpusPath) {
		workdir := *flagWorkdir
		if workdir == "" {
			workdir = cfg.Workdir
		}

		// Only prepend workdir if corpusPath doesn't already include it
		if !filepath.IsAbs(corpusPath) && !filepath.HasPrefix(corpusPath, workdir) {
			corpusPath = filepath.Join(workdir, filepath.Base(corpusPath))
		}
	}

	// Validate corpus exists
	if !osutil.IsExist(corpusPath) {
		log.Fatalf("Corpus database not found: %s", corpusPath)
	}

	log.Logf(0, "Loading %s corpus from: %s",
		map[bool]string{true: "UAF", false: "race"}[*flagValidateUAF], corpusPath)

	// If not stats-only, proceed with validation
	if *flagValidateUAF {
		err := runUAFValidation(cfg, corpusPath)
		if err != nil {
			log.Fatalf("UAF validation failed: %v", err)
		}
	} else {
		log.Fatalf("Race validation not implemented in this version - use -validate-uaf=true")
	}
}
