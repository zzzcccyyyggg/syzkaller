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
	flagConfig   = flag.String("config", "", "manager configuration file (manager.cfg)")
	flagCorpus   = flag.String("corpus", filepath.Join("race-corpus.db"), "race corpus database file (race-corpus.db)")
	flagCount    = flag.Int("count", 0, "number of VMs to use (overrides config count param)")
	flagDebug    = flag.Bool("debug", false, "print debug output")
	flagAttempts = flag.Int("attempts", 3, "number of validation attempts per race")
	flagOutput   = flag.String("output", filepath.Join("race-validation-results.txt"), "output results file")
)

func main() {
	flag.Parse()

	if *flagConfig == "" || *flagCorpus == "" {
		log.Fatalf("usage: syz-race-validate -config=manager.cfg -corpus=race-corpus.db")
	}

	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v: %v", *flagConfig, err)
	}

	if !osutil.IsExist(*flagCorpus) {
		log.Fatalf("race corpus file doesn't exist: %s", *flagCorpus)
	}

	// Create VM pool
	vmPool, err := vm.Create(cfg, *flagDebug)
	if err != nil {
		log.Fatalf("failed to create VM pool: %v", err)
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
		log.Fatalf("%v", err)
	}
	osutil.HandleInterrupts(vm.Shutdown)

	// Get target and host features
	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		log.Fatalf("failed to get target: %v", err)
	}

	hostFeatures, err := host.Check(target)
	if err != nil {
		log.Fatalf("failed to check host features: %v", err)
	}

	// Run race validation
	results, stats, err := racevalidate.Run(*flagCorpus, cfg, hostFeatures, reporter, vmPool, vmIndexes, *flagAttempts)
	if err != nil {
		log.Logf(0, "race validation failed: %v", err)
		os.Exit(1)
	}

	// Print statistics
	if stats != nil {
		fmt.Printf("loading corpus: %v\n", stats.LoadCorpusTime)
		fmt.Printf("validating races: %v\n", stats.ValidateTime)
		fmt.Printf("total time: %v\n", stats.TotalTime)
	}

	if results == nil {
		fmt.Printf("no race validation results\n")
		return
	}

	// Print results
	fmt.Printf("Race Validation Results:\n")
	fmt.Printf("Total Races: %d\n", results.TotalRaces)
	fmt.Printf("Confirmed Races: %d\n", results.ConfirmedRaces)
	fmt.Printf("Race Results: %d\n", len(results.RaceResults))

	// Calculate success rate
	if results.TotalRaces > 0 {
		successRate := float64(results.ConfirmedRaces) / float64(results.TotalRaces) * 100
		fmt.Printf("Success Rate: %.2f%%\n", successRate)
	}

	// Save results to file
	if err := saveResults(results, *flagOutput); err != nil {
		log.Logf(0, "failed to save results: %v", err)
	} else {
		fmt.Printf("results saved to %s\n", *flagOutput)
	}
}

func saveResults(results *racevalidate.Results, filename string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return osutil.WriteFile(filename, data)
}
