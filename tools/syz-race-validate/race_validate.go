// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/racevalidate"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig    = flag.String("config", "", "manager configuration file (manager.cfg)")
	flagCorpus    = flag.String("corpus", filepath.Join("race-corpus.db"), "race corpus database file (race-corpus.db)")
	flagCount     = flag.Int("count", 0, "number of VMs to use (overrides config count param)")
	flagDebug     = flag.Bool("debug", false, "print debug output")
	flagAttempts  = flag.Int("attempts", 3, "number of validation attempts per race")
	flagOutput    = flag.String("output", filepath.Join("race-validation-results.txt"), "output results file")
	flagWorkdir   = flag.String("workdir", "", "working directory (for validation database), defaults to config workdir")
	flagForce     = flag.Bool("force", false, "force re-validation of already validated pairs (not implemented)")
	flagStatsOnly = flag.Bool("stats-only", false, "only show validation database statistics without running validation")
	flagHelp      = flag.Bool("help", false, "show detailed usage information")
)

func usage() {
	fmt.Fprintf(os.Stderr, "syz-race-validate: validates race conditions from a race corpus\n\n")
	fmt.Fprintf(os.Stderr, "This tool validates race conditions found in the race corpus database,\n")
	fmt.Fprintf(os.Stderr, "automatically skipping pairs that have already been validated.\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  %s -config=manager.cfg -corpus=race-corpus.db [options]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  # Basic validation\n")
	fmt.Fprintf(os.Stderr, "  %s -config=my.cfg -corpus=workdir/race-corpus.db\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  # Show only database statistics\n")
	fmt.Fprintf(os.Stderr, "  %s -config=my.cfg -corpus=workdir/race-corpus.db -stats-only\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  # Use fewer VMs and more attempts\n")
	fmt.Fprintf(os.Stderr, "  %s -config=my.cfg -corpus=workdir/race-corpus.db -count=2 -attempts=5\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nValidation Database:\n")
	fmt.Fprintf(os.Stderr, "  The tool maintains a validation database (race_validated.db) to track\n")
	fmt.Fprintf(os.Stderr, "  which race pairs have been validated, preventing duplicate work.\n")
	fmt.Fprintf(os.Stderr, "  Location: {workdir}/race_validated.db\n\n")
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if *flagHelp {
		usage()
		return
	}

	if *flagConfig == "" || *flagCorpus == "" {
		fmt.Fprintf(os.Stderr, "Error: -config and -corpus are required\n\n")
		usage()
		os.Exit(1)
	}

	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("Failed to load config %v: %v", *flagConfig, err)
	}

	// Override workdir if specified
	workdir := cfg.Workdir
	if *flagWorkdir != "" {
		workdir = *flagWorkdir
		cfg.Workdir = workdir
	}

	if !osutil.IsExist(*flagCorpus) {
		log.Fatalf("Race corpus file doesn't exist: %s", *flagCorpus)
	}

	// Open validation database for statistics or force mode handling
	validatedDB, err := racevalidate.OpenValidatedDB(workdir)
	if err != nil {
		log.Fatalf("Failed to open validation database: %v", err)
	}
	defer validatedDB.Close()

	// Show validation database statistics
	total, valid, invalid, err := validatedDB.GetValidationStats()
	if err != nil {
		log.Logf(0, "Warning: failed to get validation stats: %v", err)
	} else {
		fmt.Printf("Validation Database Statistics:\n")
		fmt.Printf("  Database location: %s/race_validated.db\n", workdir)
		fmt.Printf("  Total validated pairs: %d\n", total)
		fmt.Printf("  Valid pairs: %d\n", valid)
		fmt.Printf("  Invalid pairs: %d\n", invalid)
		if total > 0 {
			fmt.Printf("  Success rate: %.2f%%\n", float64(valid)/float64(total)*100)
		}
		fmt.Printf("\n")
	}

	// If only showing stats, exit here
	if *flagStatsOnly {
		return
	}

	// Handle force mode - this would require clearing validation database
	// For now, just print a warning
	if *flagForce {
		fmt.Printf("Warning: Force mode is not yet implemented\n")
		fmt.Printf("To re-validate all pairs, manually delete: %s/race_validated.db\n\n", workdir)
	}

	// Create VM pool
	vmPool, err := vm.Create(cfg, *flagDebug)
	if err != nil {
		log.Fatalf("Failed to create VM pool: %v", err)
	}
	defer vmPool.Close()

	vmCount := vmPool.Count()
	if *flagCount > 0 && *flagCount < vmCount {
		vmCount = *flagCount
	}
	if vmCount > 4 {
		vmCount = 4
	}

	vmIndexes := make([]int, vmCount)
	for i := range vmIndexes {
		vmIndexes[i] = i
	}
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("Failed to create reporter: %v", err)
	}
	osutil.HandleInterrupts(vm.Shutdown)

	// Get target and host features
	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		log.Fatalf("Failed to get target: %v", err)
	}

	hostFeatures, err := host.Check(target)
	if err != nil {
		log.Fatalf("Failed to check host features: %v", err)
	}

	fmt.Printf("Starting race validation with %d VMs, %d attempts per race...\n\n", vmCount, *flagAttempts)

	// Run race validation
	results, stats, err := racevalidate.Run(*flagCorpus, cfg, hostFeatures, reporter, vmPool, vmIndexes, *flagAttempts)
	if err != nil {
		log.Logf(0, "Race validation failed: %v", err)
		os.Exit(1)
	}

	// Print timing statistics
	if stats != nil {
		fmt.Printf("Timing Statistics:\n")
		fmt.Printf("  Loading corpus: %v\n", stats.LoadCorpusTime)
		fmt.Printf("  Validating races: %v\n", stats.ValidateTime)
		fmt.Printf("  Total time: %v\n", stats.TotalTime)
		fmt.Printf("\n")
	}

	if results == nil {
		fmt.Printf("No race validation results\n")
		return
	}

	// Print validation results
	fmt.Printf("Validation Results:\n")
	fmt.Printf("  Total races attempted: %d\n", results.TotalRaces)
	fmt.Printf("  Confirmed races: %d\n", results.ConfirmedRaces)
	fmt.Printf("  Failed validations: %d\n", results.TotalRaces-results.ConfirmedRaces)

	// Calculate success rate for this run
	if results.TotalRaces > 0 {
		successRate := float64(results.ConfirmedRaces) / float64(results.TotalRaces) * 100
		fmt.Printf("  Success rate (this run): %.2f%%\n", successRate)
	}

	// Show updated database statistics
	totalAfter, validAfter, invalidAfter, err := validatedDB.GetValidationStats()
	if err == nil {
		fmt.Printf("\nUpdated Database Statistics:\n")
		fmt.Printf("  Total validated pairs: %d (was %d, +%d)\n", totalAfter, total, totalAfter-total)
		fmt.Printf("  Valid pairs: %d (was %d, +%d)\n", validAfter, valid, validAfter-valid)
		fmt.Printf("  Invalid pairs: %d (was %d, +%d)\n", invalidAfter, invalid, invalidAfter-invalid)
		if totalAfter > 0 {
			fmt.Printf("  Overall success rate: %.2f%%\n", float64(validAfter)/float64(totalAfter)*100)
		}
	}

	// Show sample of failed validations
	failedCount := 0
	fmt.Printf("\nFailed Validations (sample):\n")
	for _, result := range results.RaceResults {
		if !result.Confirmed && result.ErrorMsg != "" {
			failedCount++
			if failedCount <= 5 { // Show first 5 failures
				fmt.Printf("  %s: %s\n", result.PairID, result.ErrorMsg)
			}
		}
	}
	if failedCount > 5 {
		fmt.Printf("  ... and %d more failures (see output file for details)\n", failedCount-5)
	} else if failedCount == 0 {
		fmt.Printf("  None (all validations succeeded)\n")
	}

	// Save detailed results to file
	if err := saveResults(results, *flagOutput); err != nil {
		log.Logf(0, "Failed to save results: %v", err)
	} else {
		fmt.Printf("\nDetailed results saved to: %s\n", *flagOutput)
	}

	// Final summary
	fmt.Printf("\nSummary:\n")
	if results.TotalRaces == 0 {
		fmt.Printf("  No new race pairs to validate (all already validated)\n")
		fmt.Printf("  Use -stats-only to view database statistics\n")
	} else {
		fmt.Printf("  Validated %d race pairs in this run\n", results.TotalRaces)
		fmt.Printf("  Database now contains %d total validated pairs\n", totalAfter)
	}
}

func saveResults(results *racevalidate.Results, filename string) error {
	// Create enhanced results with more metadata
	enhancedResults := map[string]interface{}{
		"summary": map[string]interface{}{
			"total_races":     results.TotalRaces,
			"confirmed_races": results.ConfirmedRaces,
			"success_rate":    0.0,
		},
		"results":   results.RaceResults,
		"timestamp": fmt.Sprintf("%v", os.Getpid()), // Simple timestamp alternative
	}

	if results.TotalRaces > 0 {
		enhancedResults["summary"].(map[string]interface{})["success_rate"] =
			float64(results.ConfirmedRaces) / float64(results.TotalRaces) * 100
	}

	data, err := json.MarshalIndent(enhancedResults, "", "  ")
	if err != nil {
		return err
	}
	return osutil.WriteFile(filename, data)
}
