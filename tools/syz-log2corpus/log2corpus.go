// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-log2corpus extracts programs from crash logs and converts them to corpus format.
package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagLogFile   = flag.String("log", "", "path to crash log file (required)")
	flagTarget    = flag.String("target", "linux/amd64", "target OS/arch")
	flagOutputDir = flag.String("output", "", "output corpus directory (required)")
	flagVerbose   = flag.Bool("v", false, "verbose output")
)

// Program represents an extracted program with its metadata
type Program struct {
	ID   int      // Program number (order in log)
	Text []string // Program lines
}

func main() {
	flag.Parse()

	if *flagLogFile == "" {
		log.Fatalf("--log flag is required")
	}
	if *flagOutputDir == "" {
		log.Fatalf("--output flag is required")
	}

	if *flagVerbose {
		log.EnableLogCaching(1000, 1<<20)
	}

	// Parse target OS and arch
	parts := strings.Split(*flagTarget, "/")
	if len(parts) != 2 {
		log.Fatalf("invalid target format, expected OS/arch: %s", *flagTarget)
	}

	// Load target
	target, err := prog.GetTarget(parts[0], parts[1])
	if err != nil {
		log.Fatalf("failed to load target: %v", err)
	}

	// Extract programs from log
	programs, err := extractPrograms(*flagLogFile)
	if err != nil {
		log.Fatalf("failed to extract programs: %v", err)
	}

	if len(programs) == 0 {
		log.Logf(0, "no programs found in log file")
		return
	}

	log.Logf(0, "extracted %d programs from log", len(programs))

	// Create output directory
	if err := os.MkdirAll(*flagOutputDir, 0755); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}

	// Open corpus database
	corpusDB, err := db.Open(filepath.Join(*flagOutputDir, "corpus.db"), false)
	if err != nil {
		log.Fatalf("failed to open corpus database: %v", err)
	}
	defer func() {
		if err := corpusDB.Flush(); err != nil {
			log.Logf(0, "warning: failed to flush corpus database: %v", err)
		}
	}()

	// Process each program
	successful := 0
	for _, program := range programs {
		if err := processProgram(target, corpusDB, program); err != nil {
			log.Logf(0, "warning: failed to process program %d: %v", program.ID, err)
			continue
		}
		successful++
	}

	log.Logf(0, "successfully converted %d/%d programs to corpus", successful, len(programs))
}

// extractPrograms extracts all programs from the crash log file
func extractPrograms(logFile string) ([]Program, error) {
	file, err := os.Open(logFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	var programs []Program
	var currentProgram *Program

	// Regex to match "executing program N:" lines
	execPattern := regexp.MustCompile(`^(\d{2}:\d{2}:\d{2}\s+)?executing program (\d+):$`)
	// Regex to match syscall lines (starts with syscall name or variable assignment)
	syscallPattern := regexp.MustCompile(`^(r\d+\s*=\s*)?[a-z_][a-z0-9_$]*\(`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Check if this is a program header
		if matches := execPattern.FindStringSubmatch(line); matches != nil {
			// Save previous program if exists
			if currentProgram != nil && len(currentProgram.Text) > 0 {
				programs = append(programs, *currentProgram)
			}

			// Start new program
			programID := len(programs) + 1
			currentProgram = &Program{
				ID:   programID,
				Text: make([]string, 0),
			}
			continue
		}

		// If we're in a program, check if this is a syscall line
		if currentProgram != nil {
			if syscallPattern.MatchString(line) {
				currentProgram.Text = append(currentProgram.Text, line)
			} else if len(currentProgram.Text) > 0 && line != "" {
				// Empty line or non-syscall after syscalls means end of program
				programs = append(programs, *currentProgram)
				currentProgram = nil
			}
		}
	}

	// Save last program if exists
	if currentProgram != nil && len(currentProgram.Text) > 0 {
		programs = append(programs, *currentProgram)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading log file: %w", err)
	}

	return programs, nil
}

// processProgram parses and stores a program in the corpus
func processProgram(target *prog.Target, corpusDB *db.DB, program Program) error {
	// Join program lines into a single string
	progText := strings.Join(program.Text, "\n")

	// Parse program
	p, err := target.Deserialize([]byte(progText), prog.NonStrict)
	if err != nil {
		return fmt.Errorf("failed to parse program: %w", err)
	}

	// Serialize in canonical format
	progData := p.Serialize()

	// Calculate program signature (hash)
	hash := sha1.Sum(progData)
	sig := hex.EncodeToString(hash[:])

	// Check if program already exists in corpus
	if existing, ok := corpusDB.Records[sig]; ok {
		if *flagVerbose {
			log.Logf(1, "program %d already exists in corpus (sig=%s, seq=%d)",
				program.ID, sig[:16], existing.Seq)
		}
		return nil
	}

	// Store program in corpus
	corpusDB.Save(sig, progData, 0)

	log.Logf(0, "program %d: saved to corpus (sig=%s, %d calls)",
		program.ID, sig[:16], len(p.Calls))

	// Also save as plain text file for easier inspection
	textFile := filepath.Join(*flagOutputDir, fmt.Sprintf("prog-%03d.txt", program.ID))
	if err := os.WriteFile(textFile, progData, 0644); err != nil {
		log.Logf(0, "warning: failed to save text file: %v", err)
	}

	return nil
}
