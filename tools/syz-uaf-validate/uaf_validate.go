// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
)

// UAFCorpusItem represents a UAF corpus item stored in the database.
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
	// Display options
	flagShowDetails = flag.Bool("show-details", false, "only display UAF pair details without validation")
	flagOutput      = flag.String("output", "uaf-validation-results.json", "output file for validation results or UAF details")
)

func usage() {
	flag.PrintDefaults()
}

// parseUAFPairs parses UAF pairs from JSON data
// The UAFs field in UAFCorpusItem is JSON-encoded []ddrd.MayUAFPair
func parseUAFPairs(data []byte) []ddrd.MayUAFPair {
	var pairs []ddrd.MayUAFPair

	// Unmarshal JSON data
	if err := json.Unmarshal(data, &pairs); err != nil {
		log.Logf(1, "Warning: failed to unmarshal UAF pairs: %v", err)
		return nil
	}

	return pairs
}

// showUAFDetails reads and displays UAF pair details without validation
func showUAFDetails(corpusPath string) error {
	log.Logf(0, "Reading UAF corpus details from: %s", corpusPath)

	// Open the corpus database file using pkg/db
	corpusDB, err := db.Open(corpusPath, false)
	if err != nil {
		return fmt.Errorf("failed to open corpus database: %v", err)
	}

	// Iterate through all entries
	var pairs []UAFCorpusItem
	for key, record := range corpusDB.Records {
		var item UAFCorpusItem
		if err := json.Unmarshal(record.Val, &item); err != nil {
			log.Logf(1, "Warning: failed to unmarshal item with key %s: %v", key, err)
			continue
		}
		pairs = append(pairs, item)
	}

	log.Logf(0, "========== UAF Corpus Summary ==========")
	log.Logf(0, "Total UAF pairs: %d", len(pairs))
	log.Logf(0, "")

	// Display each UAF pair details
	for i, pair := range pairs {
		log.Logf(0, "========== UAF Pair #%d ==========", i+1)
		log.Logf(0, "Pair ID: %s", pair.PairID)
		log.Logf(0, "Source: %s", pair.Source)
		log.Logf(0, "First seen: %s", pair.FirstSeen.Format(time.RFC3339))
		log.Logf(0, "Last updated: %s", pair.LastUpdated.Format(time.RFC3339))
		log.Logf(0, "Discovery count: %d", pair.Count)

		// Parse and display UAF pairs information
		if len(pair.UAFs) > 0 {
			uafPairs := parseUAFPairs(pair.UAFs)
			if len(uafPairs) > 0 {
				log.Logf(0, "UAF Details (%d pairs):", len(uafPairs))
				for j, uaf := range uafPairs {
					log.Logf(0, "  [%d] Free VarName: 0x%016x, Use VarName: 0x%016x",
						j+1, uaf.FreeAccessName, uaf.UseAccessName)
					log.Logf(0, "      Free CallStack: 0x%016x, Use CallStack: 0x%016x",
						uaf.FreeCallStack, uaf.UseCallStack)
					log.Logf(0, "      Signal: 0x%016x, TimeDiff: %d ns",
						uaf.Signal, uaf.TimeDiff)
					log.Logf(0, "      Free Syscall: idx=%d num=%d sn=%d",
						uaf.FreeSyscallIdx, uaf.FreeSyscallNum, uaf.FreeSN)
					log.Logf(0, "      Use Syscall: idx=%d num=%d sn=%d",
						uaf.UseSyscallIdx, uaf.UseSyscallNum, uaf.UseSN)
					log.Logf(0, "      Lock Type: %d, Use Access Type: %d",
						uaf.LockType, uaf.UseAccessType)
				}
			}
		}

		if *flagVerbose {
			log.Logf(0, "Program 1 size: %d bytes", len(pair.Prog1))
			log.Logf(0, "Program 2 size: %d bytes", len(pair.Prog2))
			log.Logf(0, "UAF signal size: %d bytes", len(pair.UAFSignal))
			log.Logf(0, "UAFs data size: %d bytes", len(pair.UAFs))
			if pair.LogPath != "" {
				log.Logf(0, "Log path: %s", pair.LogPath)
			}
			if len(pair.Output) > 0 {
				outputPreview := string(pair.Output)
				if len(outputPreview) > 200 {
					outputPreview = outputPreview[:200] + "..."
				}
				log.Logf(0, "Output preview: %s", outputPreview)
			}
		}
		log.Logf(0, "")
	}

	log.Logf(0, "========== Summary ==========")
	log.Logf(0, "Displayed %d UAF pairs", len(pairs))

	return nil
}

// runUAFValidation executes the complete UAF validation pipeline
func runUAFValidation(cfg *mgrconfig.Config, corpusPath string) error {
	log.Logf(0, "Starting UAF validation pipeline")
	log.Logf(0, "Configuration: config=%s, corpus=%s", *flagConfig, corpusPath)
	log.Logf(0, "Parameters: count=%d, attempts=%d, verbose=%v", *flagCount, *flagAttempts, *flagVerbose)

	// For now, just log that validation is not implemented
	// TODO: Implement actual UAF validation logic
	log.Logf(0, "UAF validation functionality is under development")
	log.Logf(0, "Please use -show-details flag to view UAF corpus contents")

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

	// Determine corpus path - default to uaf-corpus.db in workdir
	corpusPath := filepath.Join(cfg.Workdir, "uaf-corpus.db")

	// Validate corpus exists
	if !osutil.IsExist(corpusPath) {
		log.Fatalf("Corpus database not found: %s", corpusPath)
	}

	log.Logf(0, "Loading UAF corpus from: %s", corpusPath)

	// If show-details flag is set, only display UAF pair details
	if *flagShowDetails {
		err := showUAFDetails(corpusPath)
		if err != nil {
			log.Fatalf("Failed to show UAF details: %v", err)
		}
		return
	}

	// Otherwise proceed with validation
	err = runUAFValidation(cfg, corpusPath)
	if err != nil {
		log.Fatalf("UAF validation failed: %v", err)
	}
}
