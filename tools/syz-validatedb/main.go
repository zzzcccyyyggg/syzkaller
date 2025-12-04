package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
)

var (
	dbPath  = flag.String("db", "validated_uaf.db", "path to validated_uaf.db")
	summary = flag.Bool("summary", false, "only print record metadata, skip report bodies")
	format  = flag.Bool("format", false, "prettify report output for easier reading")
	manager = flag.String("manager_cfg", "", "optional syz-manager config for symbolization")
)

func main() {
	flag.Parse()
	if *dbPath == "" {
		log.Fatal("db path must be provided")
	}

	reporter, err := initReporter(*manager)
	if err != nil {
		log.Fatalf("failed to initialize reporter: %v", err)
	}

	database, err := db.Open(*dbPath, true)
	if err != nil {
		log.Fatalf("failed to open db %q: %v", *dbPath, err)
	}

	keys := make([]string, 0, len(database.Records))
	for key := range database.Records {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	fmt.Printf("validated records: %d\n", len(keys))
	for idx, key := range keys {
		rec := database.Records[key]
		fmt.Printf("[%d] key=%s seq=%d size=%d bytes\n", idx+1, key, rec.Seq, len(rec.Val))
		if *summary || len(rec.Val) == 0 {
			continue
		}
		fmt.Println("-----BEGIN REPORT-----")
		body := rec.Val
		if reporter != nil {
			if symBody, err := symbolizeBody(reporter, body); err != nil {
				log.Printf("warn: failed to symbolize key=%s: %v", key, err)
			} else if len(symBody) != 0 {
				body = symBody
			}
		}
		if *format {
			body = formatReport(body)
		}
		if _, err := os.Stdout.Write(body); err != nil {
			log.Fatalf("failed to write report for key %s: %v", key, err)
		}
		if len(body) == 0 || body[len(body)-1] != '\n' {
			fmt.Println()
		}
		fmt.Println("-----END REPORT-----")
	}
}

func initReporter(path string) (*report.Reporter, error) {
	if path == "" {
		return nil, nil
	}
	cfg, err := mgrconfig.LoadPartialFile(path)
	if err != nil {
		return nil, fmt.Errorf("load manager config: %w", err)
	}
	cfg.CompleteKernelDirs()
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		return nil, fmt.Errorf("create reporter: %w", err)
	}
	return reporter, nil
}

func symbolizeBody(reporter *report.Reporter, body []byte) ([]byte, error) {
	if reporter == nil || len(body) == 0 {
		return body, nil
	}
	reps := report.ParseAll(reporter, body)
	if len(reps) == 0 {
		rep := &report.Report{Report: append([]byte{}, body...), Output: append([]byte{}, body...)}
		if err := reporter.Symbolize(rep); err != nil {
			return nil, err
		}
		return append([]byte{}, rep.Report...), nil
	}
	var buf bytes.Buffer
	for i, rep := range reps {
		if err := reporter.Symbolize(rep); err != nil {
			return nil, err
		}
		if i != 0 {
			buf.WriteString("\n\n")
		}
		buf.Write(rep.Report)
	}
	return buf.Bytes(), nil
}

func formatReport(raw []byte) []byte {
	return raw
}
