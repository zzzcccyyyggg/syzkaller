// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-merge-policy dumps the merge policy classification for all resource-producing
// syscalls. The output can be used for:
//  1. Manual review of classification correctness
//  2. Feeding to an LLM for automated validation
//  3. Generating override entries for edge cases
//
// Usage:
//
//	go run ./tools/syz-merge-policy [-format=table|json|prompt] [-filter=always|never]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagFormat = flag.String("format", "table", "output format: table, json, prompt")
	flagFilter = flag.String("filter", "", "filter by merge class: always, never, or empty for all")
)

type SyscallEntry struct {
	Name          string `json:"name"`
	CallName      string `json:"call_name"`
	ReturnType    string `json:"return_type"`
	MergeClass    string `json:"merge_class"`
	Reason        string `json:"reason"`
	Params        string `json:"params"`
	HasFilename   bool   `json:"has_filename"`
	IsSpecialized bool   `json:"is_specialized"`
}

func main() {
	flag.Parse()

	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get target: %v\n", err)
		os.Exit(1)
	}

	var entries []SyscallEntry
	for _, meta := range target.Syscalls {
		if meta.Ret == nil {
			continue
		}
		rt, ok := meta.Ret.(*prog.ResourceType)
		if !ok {
			continue
		}
		// Only fd-family resources
		if len(rt.Desc.Kind) == 0 || rt.Desc.Kind[0] != "fd" {
			continue
		}

		mergeClass := prog.ClassifyMergePolicy(meta)

		// Apply filter
		if *flagFilter != "" && mergeClass.String() != *flagFilter {
			continue
		}

		entry := SyscallEntry{
			Name:          meta.Name,
			CallName:      meta.CallName,
			ReturnType:    rt.TypeName,
			MergeClass:    mergeClass.String(),
			Reason:        classifyReason(meta),
			Params:        describeParams(meta),
			HasFilename:   hasFilenameParam(meta),
			IsSpecialized: strings.Contains(meta.Name, "$"),
		}
		entries = append(entries, entry)
	}

	// Sort by merge class then name for readability
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].MergeClass != entries[j].MergeClass {
			return entries[i].MergeClass < entries[j].MergeClass
		}
		return entries[i].Name < entries[j].Name
	})

	switch *flagFormat {
	case "table":
		printTable(entries)
	case "json":
		printJSON(entries)
	case "prompt":
		printLLMPrompt(entries)
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", *flagFormat)
		os.Exit(1)
	}
}

func printTable(entries []SyscallEntry) {
	fmt.Printf("%-8s | %-60s | %-15s | %-20s | %-25s | %s\n",
		"CLASS", "SYSCALL", "CALL_NAME", "RETURN_TYPE", "REASON", "KEY_PARAMS")
	fmt.Println(strings.Repeat("-", 180))
	for _, e := range entries {
		params := e.Params
		if len(params) > 60 {
			params = params[:60] + "..."
		}
		fmt.Printf("%-8s | %-60s | %-15s | %-20s | %-25s | %s\n",
			e.MergeClass, e.Name, e.CallName, e.ReturnType, e.Reason, params)
	}
	fmt.Printf("\nTotal: %d syscalls\n", len(entries))

	// Print summary
	always, never := 0, 0
	for _, e := range entries {
		if e.MergeClass == "always" {
			always++
		} else {
			never++
		}
	}
	fmt.Printf("  ALWAYS: %d, NEVER: %d\n", always, never)
}

func printJSON(entries []SyscallEntry) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(entries)
}

func printLLMPrompt(entries []SyscallEntry) {
	fmt.Println(generateLLMPrompt(entries))
}

func generateLLMPrompt(entries []SyscallEntry) string {
	var sb strings.Builder

	sb.WriteString(`# Syscall Merge Policy Validation Task

## Context

We are building a fork-barrier execution model for kernel fuzzing (UAF race detection).
When two programs are merged for concurrent execution:

1. **Parent process** executes "setup" calls (resource creators: open, socket, etc.)
2. Parent calls **fork()** — children inherit the fd table
3. **Child 0** and **Child 1** execute their syscalls concurrently using inherited fds

The key decision: when prog2 has the same resource-creating syscall as prog1's setup phase,
should we **unify** (prog2 reuses setup's fd) or **keep separate** (prog2 creates its own)?

### Why this matters for UAF detection:
- **Unified fd**: Both children share the SAME struct file/socket object.
  If child0 calls close() and child1 uses the fd → USE-AFTER-FREE detected!
- **Separate fd**: Each child has its own object. close() by one doesn't affect the other.
  No UAF possible on this object.

### Classification Rules:

**ALWAYS merge** (safe to unify):
- The syscall creates DETERMINISTIC objects: all identity-determining params are const/fixed
- Or the syscall creates ANONYMOUS objects: no identity params (eventfd, pipe, etc.)
- Result: two calls always create equivalent kernel objects

**NEVER merge** (unsafe to unify):
- The syscall has RANDOM/VARIABLE identity params (random filename, flags choosing different subsystems)
- Result: two calls may create completely different kernel objects
- Unifying would force prog2 to use an object it wasn't designed for → reduced diversity

### Heuristic Rules We Use:
1. Manual override table → highest priority
2. Known anonymous creators (eventfd, pipe, epoll_create, etc.) → ALWAYS
3. Has BufferFilename-type param (generates random ./fileN paths) → NEVER
4. Has "$" in name (specialized variant) → ALWAYS ($ encodes identity)
5. No "$" in name (generic) → NEVER

## Your Task

Review each syscall classification below. For each entry, determine if our heuristic
classification is CORRECT or INCORRECT.

If INCORRECT, provide:
1. The correct classification (always/never)
2. A brief reason why

Focus especially on:
- $-specialized variants that might not be truly specialized (e.g., $auto with random params)
- Generic variants that might actually be safe to merge
- Edge cases where params look variable but don't affect object identity

## Syscall List

Format: CURRENT_CLASS | SYSCALL_NAME | REASON | KEY_PARAMS

`)

	// Group by classification
	sb.WriteString("### Classified as ALWAYS (safe to merge):\n\n")
	sb.WriteString("```\n")
	count := 0
	for _, e := range entries {
		if e.MergeClass == "always" {
			sb.WriteString(fmt.Sprintf("ALWAYS | %-55s | %-22s | %s\n",
				e.Name, e.Reason, truncate(e.Params, 80)))
			count++
		}
	}
	sb.WriteString(fmt.Sprintf("```\n(%d entries)\n\n", count))

	sb.WriteString("### Classified as NEVER (unsafe to merge):\n\n")
	sb.WriteString("```\n")
	count = 0
	for _, e := range entries {
		if e.MergeClass == "never" {
			sb.WriteString(fmt.Sprintf("NEVER  | %-55s | %-22s | %s\n",
				e.Name, e.Reason, truncate(e.Params, 80)))
			count++
		}
	}
	sb.WriteString(fmt.Sprintf("```\n(%d entries)\n\n", count))

	sb.WriteString(`## Required Output Format

Output a Go map literal for any entries that should be OVERRIDDEN:

` + "```go" + `
// LLM-validated merge policy overrides
var llmOverrides = map[string]prog.MergeClass{
    // Example: "syscall$name": prog.MergeNever, // reason: has random struct param
    "SYSCALL_NAME": prog.MergeAlways, // or MergeNever, with reason
}
` + "```" + `

If all classifications are correct, output:
` + "```" + `
// All heuristic classifications validated - no overrides needed.
` + "```" + `

## Additional Notes
- The total number of resource-producing fd syscalls reviewed: ` + fmt.Sprintf("%d", len(entries)) + `
- Pay special attention to $auto variants (auto-generated, may NOT be truly specialized)
- openat$xxx with string["/dev/..."] are truly specialized (fixed device path)
- socket$xxx with const params are truly specialized
- Syscalls with struct params: the struct contents may be variable even if the cmd is const
`)

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func classifyReason(meta *prog.Syscall) string {
	// Reproduce the classification logic to get the reason
	if strings.Contains(meta.Name, "$") {
		if hasFilenameParam(meta) {
			return "specialized_with_filename"
		}
		return "specialized_variant"
	}
	return "generic_syscall"
}

func hasFilenameParam(meta *prog.Syscall) bool {
	found := false
	prog.ForeachCallType(meta, func(t prog.Type, ctx *prog.TypeCtx) {
		if found {
			return
		}
		if ctx.Dir == prog.DirOut {
			return
		}
		if bt, ok := t.(*prog.BufferType); ok && bt.Kind == prog.BufferFilename {
			found = true
			ctx.Stop = true
		}
	})
	return found
}

func describeParams(meta *prog.Syscall) string {
	var parts []string
	for _, field := range meta.Args {
		dir := field.Dir(prog.DirIn)
		if dir == prog.DirOut {
			continue
		}
		t := field.Type
		if pt, ok := t.(*prog.PtrType); ok {
			t = pt.Elem
		}
		parts = append(parts, fmt.Sprintf("%s:%s", field.Name, describeType(t)))
	}
	return strings.Join(parts, ", ")
}

func describeType(t prog.Type) string {
	switch typ := t.(type) {
	case *prog.ConstType:
		return fmt.Sprintf("const[%d]", typ.Val)
	case *prog.FlagsType:
		return fmt.Sprintf("flags[%s]", typ.Name())
	case *prog.IntType:
		if typ.Kind == prog.IntRange {
			return fmt.Sprintf("int[%d:%d]", typ.RangeBegin, typ.RangeEnd)
		}
		return "int"
	case *prog.ResourceType:
		return fmt.Sprintf("res[%s]", typ.Name())
	case *prog.BufferType:
		switch typ.Kind {
		case prog.BufferFilename:
			return "filename"
		case prog.BufferString:
			if len(typ.Values) == 1 {
				v := typ.Values[0]
				if len(v) > 30 {
					v = v[:30] + "..."
				}
				return fmt.Sprintf("string[%q]", v)
			}
			return fmt.Sprintf("string[%d_values]", len(typ.Values))
		case prog.BufferGlob:
			return "glob"
		default:
			return "buffer"
		}
	case *prog.LenType:
		return "len"
	case *prog.ProcType:
		return "proc"
	case *prog.StructType:
		return fmt.Sprintf("struct[%s]", typ.Name())
	case *prog.UnionType:
		return fmt.Sprintf("union[%s]", typ.Name())
	case *prog.ArrayType:
		return fmt.Sprintf("array[%s]", describeType(typ.Elem))
	default:
		return "?"
	}
}
