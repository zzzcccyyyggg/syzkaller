// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-llm-candidate-check validates LLM-generated program-group candidates for
// the offline MRPFuzz input-construction pilot.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type payload struct {
	Target           string    `json:"target"`
	EnabledSyscalls  []string  `json:"enabled_syscalls"`
	MountPrefix      string    `json:"mount_prefix"`
	MaxCalls         int       `json:"max_calls"`
	AllowDevicePaths bool      `json:"allow_device_paths,omitempty"`
	Variants         []variant `json:"variants"`
}

type variant struct {
	ID     string `json:"id"`
	Intent string `json:"intent,omitempty"`
	ProgA  string `json:"prog_a"`
	ProgB  string `json:"prog_b"`
}

type output struct {
	Accepted []checkedVariant `json:"accepted"`
	Rejected []checkedVariant `json:"rejected"`
	Summary  summary          `json:"summary"`
}

type checkedVariant struct {
	ID      string   `json:"id"`
	Intent  string   `json:"intent,omitempty"`
	ProgA   string   `json:"prog_a,omitempty"`
	ProgB   string   `json:"prog_b,omitempty"`
	CallsA  []string `json:"calls_a,omitempty"`
	CallsB  []string `json:"calls_b,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
}

type summary struct {
	Total    int `json:"total"`
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
}

func main() {
	flag.Parse()
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		tool.Failf("failed to read stdin: %v", err)
	}
	var in payload
	if err := json.Unmarshal(data, &in); err != nil {
		tool.Failf("failed to parse payload JSON: %v", err)
	}
	if in.Target == "" {
		in.Target = "linux/amd64"
	}
	parts := strings.Split(in.Target, "/")
	if len(parts) != 2 {
		tool.Failf("bad target %q, want os/arch", in.Target)
	}
	target, err := prog.GetTarget(parts[0], parts[1])
	if err != nil {
		tool.Failf("failed to get target: %v", err)
	}
	if in.MountPrefix == "" {
		in.MountPrefix = "/mnt/kccwf"
	}
	if in.MaxCalls <= 0 {
		in.MaxCalls = 10
	}
	enabled := make(map[string]bool)
	for _, name := range in.EnabledSyscalls {
		enabled[name] = true
	}
	allowDevicePaths := in.AllowDevicePaths || hasDeviceOpeners(in.EnabledSyscalls)

	out := output{}
	for _, v := range in.Variants {
		cv := checkedVariant{ID: v.ID, Intent: v.Intent}
		progA, callsA, reasonsA := checkProgram(target, enabled, in.MountPrefix, in.MaxCalls, allowDevicePaths, v.ProgA, "A")
		progB, callsB, reasonsB := checkProgram(target, enabled, in.MountPrefix, in.MaxCalls, allowDevicePaths, v.ProgB, "B")
		cv.CallsA = callsA
		cv.CallsB = callsB
		cv.Reasons = append(cv.Reasons, reasonsA...)
		cv.Reasons = append(cv.Reasons, reasonsB...)
		if progA != nil && progB != nil && len(cv.Reasons) == 0 {
			cv.ProgA = string(progA.Serialize())
			cv.ProgB = string(progB.Serialize())
			out.Accepted = append(out.Accepted, cv)
		} else {
			out.Rejected = append(out.Rejected, cv)
		}
	}
	out.Summary.Total = len(in.Variants)
	out.Summary.Accepted = len(out.Accepted)
	out.Summary.Rejected = len(out.Rejected)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		tool.Failf("failed to encode output: %v", err)
	}
}

func checkProgram(target *prog.Target, enabled map[string]bool, mountPrefix string, maxCalls int, allowDevicePaths bool, text, label string) (*prog.Prog, []string, []string) {
	text = strings.TrimSpace(text)
	var reasons []string
	if text == "" {
		return nil, nil, []string{fmt.Sprintf("%s: empty program", label)}
	}
	p, err := target.Deserialize([]byte(text+"\n"), prog.NonStrict)
	if err != nil {
		return nil, nil, []string{fmt.Sprintf("%s: parse failed: %v", label, err)}
	}
	if len(p.Calls) == 0 {
		reasons = append(reasons, fmt.Sprintf("%s: no calls", label))
	}
	if len(p.Calls) > maxCalls {
		reasons = append(reasons, fmt.Sprintf("%s: too many calls: %d > %d", label, len(p.Calls), maxCalls))
	}
	calls := make([]string, 0, len(p.Calls))
	for _, call := range p.Calls {
		calls = append(calls, call.Meta.Name)
		if len(enabled) != 0 && !enabled[call.Meta.Name] {
			reasons = append(reasons, fmt.Sprintf("%s: syscall %s is not enabled", label, call.Meta.Name))
		}
		reasons = append(reasons, checkPaths(call, mountPrefix, allowDevicePaths, label)...)
		reasons = append(reasons, checkFDDependencies(call, label)...)
	}
	sort.Strings(reasons)
	return p, calls, dedupStrings(reasons)
}

func checkPaths(call *prog.Call, mountPrefix string, allowDevicePaths bool, label string) []string {
	var reasons []string
	prog.ForeachArg(call, func(arg prog.Arg, ctx *prog.ArgCtx) {
		dataArg, ok := arg.(*prog.DataArg)
		if !ok || dataArg.Dir() == prog.DirOut {
			return
		}
		s := strings.TrimRight(string(dataArg.Data()), "\x00")
		if s == "" {
			return
		}
		if strings.Contains(s, "/mnt/") && !strings.HasPrefix(s, mountPrefix+"/") && s != mountPrefix {
			reasons = append(reasons, fmt.Sprintf("%s: %s path outside %s: %q", label, call.Meta.Name, mountPrefix, s))
		}
		if allowDevicePaths && (strings.HasPrefix(s, "/dev/") || strings.HasPrefix(s, "/proc/asound/")) {
			return
		}
		if strings.HasPrefix(s, "/tmp/") || strings.HasPrefix(s, "/dev/") || strings.HasPrefix(s, "/proc/") || strings.HasPrefix(s, "/sys/") {
			reasons = append(reasons, fmt.Sprintf("%s: %s forbidden absolute path: %q", label, call.Meta.Name, s))
		}
	})
	return reasons
}

func hasDeviceOpeners(names []string) bool {
	for _, name := range names {
		if strings.HasPrefix(name, "syz_open_dev$") {
			return true
		}
		switch name {
		case "openat$ptmx", "openat$tty", "openat$ttyS3", "openat$ttynull", "openat$ttyprintk", "syz_open_pts",
			"openat$mixer", "openat$dsp", "openat$dsp1", "openat$adsp1", "openat$audio", "openat$audio1",
			"openat$proc_mixer":
			return true
		}
	}
	return false
}

func checkFDDependencies(call *prog.Call, label string) []string {
	var reasons []string
	for _, idx := range fdInputArgIndexes(call.Meta.Name) {
		if idx < 0 || idx >= len(call.Args) {
			continue
		}
		if !isGeneratedResource(call.Args[idx]) {
			reasons = append(reasons, fmt.Sprintf("%s: %s arg%d must use an fd/resource returned by an earlier call", label, call.Meta.Name, idx))
		}
	}
	return reasons
}

func isGeneratedResource(arg prog.Arg) bool {
	res, ok := arg.(*prog.ResultArg)
	if !ok {
		return false
	}
	return res.Res != nil
}

func fdInputArgIndexes(name string) []int {
	if strings.HasPrefix(name, "ioctl$") || strings.HasPrefix(name, "fcntl$") {
		return []int{0}
	}
	switch name {
	case "syz_open_pts":
		return []int{0}
	case "close$kccwf",
		"dup$kccwf",
		"fsync$kccwf",
		"fdatasync$kccwf",
		"syncfs$kccwf",
		"sync_file_range$kccwf",
		"getdents$kccwf",
		"getdents64$kccwf",
		"fchdir$kccwf",
		"read$kccwf",
		"pread64$kccwf",
		"readv$kccwf",
		"preadv$kccwf",
		"preadv2$kccwf",
		"write$kccwf",
		"pwrite64$kccwf",
		"writev$kccwf",
		"pwritev2$kccwf",
		"lseek$kccwf",
		"vmsplice$kccwf",
		"sendfile$kccwf",
		"readahead$kccwf",
		"fstat$kccwf",
		"cachestat$kccwf",
		"fadvise64$kccwf",
		"fchmod$kccwf",
		"fchown$kccwf",
		"fallocate$kccwf",
		"fsetxattr$kccwf":
		return []int{0}
	case "dup2$kccwf", "dup3$kccwf":
		return []int{0}
	case "copy_file_range$kccwf", "tee$kccwf", "splice$kccwf":
		return []int{0, 2}
	default:
		return nil
	}
}

func dedupStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := items[:0]
	var prev string
	for i, item := range items {
		if i == 0 || item != prev {
			out = append(out, item)
			prev = item
		}
	}
	return out
}
