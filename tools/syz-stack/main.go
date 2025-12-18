// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-stack is a tool to symbolize and format kernel stack traces.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/tool"
)

var (
	flagOS        = flag.String("os", runtime.GOOS, "target os")
	flagArch      = flag.String("arch", runtime.GOARCH, "target arch")
	flagKernelObj = flag.String("kernel_obj", "", "path to kernel build/obj dir (contains vmlinux)")
	flagKernelSrc = flag.String("kernel_src", "", "path to kernel sources (defaults to kernel_obj)")
	flagConfig    = flag.String("config", "", "use configuration file for kernel paths")
	flagOnlyStack = flag.Bool("stack-only", false, "only extract and symbolize call trace sections")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "syz-stack - Kernel stack trace symbolizer\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  syz-stack [flags] [file]         Read from file or stdin if no file given\n")
		fmt.Fprintf(os.Stderr, "  syz-stack [flags] < kernel.log   Read from stdin\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  syz-stack -kernel_obj=/path/to/linux kernel.log\n")
		fmt.Fprintf(os.Stderr, "  syz-stack -config=wifi.cfg kernel.log\n")
		fmt.Fprintf(os.Stderr, "  cat /var/log/kern.log | syz-stack -kernel_obj=/path/to/linux\n")
		fmt.Fprintf(os.Stderr, "  syz-stack -stack-only -kernel_obj=/path/to/linux kernel.log\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	kernelObj := *flagKernelObj
	kernelSrc := *flagKernelSrc

	if *flagConfig != "" {
		cfg, err := mgrconfig.LoadPartialFile(*flagConfig)
		if err != nil {
			tool.Failf("failed to load config: %v", err)
		}
		cfg.CompleteKernelDirs()
		if kernelObj == "" {
			kernelObj = cfg.KernelObj
		}
		if kernelSrc == "" {
			kernelSrc = cfg.KernelSrc
		}
	}

	if kernelObj == "" {
		tool.Failf("kernel_obj is required (use -kernel_obj or -config)")
	}
	if kernelSrc == "" {
		kernelSrc = kernelObj
	}

	vmlinux := filepath.Join(kernelObj, "vmlinux")
	if _, err := os.Stat(vmlinux); os.IsNotExist(err) {
		matches, _ := filepath.Glob(filepath.Join(kernelObj, "vmlinux*"))
		if len(matches) > 0 {
			vmlinux = matches[0]
			fmt.Fprintf(os.Stderr, "Using vmlinux: %s\n", vmlinux)
		} else {
			tool.Failf("vmlinux not found in %s", kernelObj)
		}
	}

	var input []byte
	var err error
	if len(flag.Args()) > 0 {
		input, err = os.ReadFile(flag.Args()[0])
		if err != nil {
			tool.Failf("failed to read file: %v", err)
		}
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 10*1024*1024)
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			tool.Failf("failed to read stdin: %v", err)
		}
		input = []byte(strings.Join(lines, "\n"))
	}

	if *flagOnlyStack {
		input = extractStackTraces(input)
	}

	symbolizeWithReporter(kernelObj, kernelSrc, input)
}

func symbolizeWithReporter(kernelObj, kernelSrc string, input []byte) {
	cfg, err := mgrconfig.LoadPartialData([]byte(fmt.Sprintf(`{
		"kernel_obj": %q,
		"kernel_src": %q,
		"target": "%s/%s"
	}`, kernelObj, kernelSrc, *flagOS, *flagArch)))
	if err != nil {
		tool.Failf("failed to create config: %v", err)
	}
	cfg.CompleteKernelDirs()

	reporter, err := report.NewReporter(cfg)
	if err != nil {
		tool.Failf("failed to create reporter: %v", err)
	}

	reps := report.ParseAll(reporter, input)
	if len(reps) == 0 {
		rep := &report.Report{Report: input}
		if err := reporter.Symbolize(rep); err != nil {
			fmt.Fprintf(os.Stderr, "warning: symbolization failed: %v\n", err)
			os.Stdout.Write(input)
			return
		}
		os.Stdout.Write(rep.Report)
		return
	}

	for i, rep := range reps {
		if err := reporter.Symbolize(rep); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to symbolize report %d: %v\n", i+1, err)
		}
		if len(reps) > 1 {
			fmt.Printf("=== Report %d/%d ===\n", i+1, len(reps))
		}
		if rep.Title != "" {
			fmt.Printf("TITLE: %s\n", rep.Title)
		}
		fmt.Printf("\n")
		os.Stdout.Write(rep.Report)
		fmt.Printf("\n")
	}
}

func extractStackTraces(input []byte) []byte {
	lines := strings.Split(string(input), "\n")
	var result []string
	inStack := false

	stackStartPatterns := []string{
		"Call Trace:",
		"Call trace:",
		"Backtrace:",
		"<TASK>",
	}
	stackEndPatterns := []string{
		"</TASK>",
		"---[ end trace",
		"Code:",
	}

	addrLine := regexp.MustCompile(`\[\s*\d+\.\d+\]\s+\S+\+0x[0-9a-fA-F]+/`)

	for _, line := range lines {
		for _, pattern := range stackStartPatterns {
			if strings.Contains(line, pattern) {
				inStack = true
				break
			}
		}

		if inStack {
			result = append(result, line)
		} else if addrLine.MatchString(line) {
			result = append(result, line)
		}

		for _, pattern := range stackEndPatterns {
			if strings.Contains(line, pattern) {
				inStack = false
				result = append(result, "")
				break
			}
		}
	}

	return []byte(strings.Join(result, "\n"))
}
