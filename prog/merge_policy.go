// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"strings"
)

// MergeClass describes how a resource-producing syscall's fd should be
// handled during fork-barrier merge fd unification.
//
// When merging two programs for fork-barrier execution, setup-phase calls
// from prog1 create fds that are inherited by both child processes via fork().
// For prog2's resource-creating calls, we must decide: should prog2's call
// be replaced by a reference to the setup phase's fd (unification), or should
// prog2 keep its own call (each child has its own fd)?
//
// The answer depends on whether the two calls create "equivalent" kernel objects:
//   - If yes → unify (both children share the same struct file/socket/etc.)
//   - If no → keep separate (each child has its own object)
//
// For UAF detection, sharing the same kernel object is essential: close() by
// one child frees the object, and use by the other child triggers UAF.
type MergeClass int

const (
	// MergeAlways means the syscall creates deterministic or anonymous kernel objects.
	// Two calls to this syscall (with the same Name) always produce functionally
	// equivalent kernel objects. It is safe to unify: skip prog2's call and reuse
	// the setup phase's fd.
	//
	// Examples:
	//   - openat$null("/dev/null") — fixed device path, always same inode
	//   - socket$inet_tcp(AF_INET, SOCK_STREAM, 0) — all const params
	//   - eventfd(initval) — anonymous object, no identity params
	//   - pipe() — anonymous paired object
	MergeAlways MergeClass = iota

	// MergeNever means the syscall creates objects whose identity depends on
	// random or variable parameters. Two calls may create completely different
	// kernel objects. Each prog should keep its own call to preserve diversity.
	//
	// Examples:
	//   - open(filename) — random ./fileN path, different files
	//   - socket(flags, flags, int) — random domain/type, different socket types
	//   - openat$auto(filename) — auto-generated generic, still random path
	MergeNever
)

func (mc MergeClass) String() string {
	switch mc {
	case MergeAlways:
		return "always"
	case MergeNever:
		return "never"
	default:
		return "unknown"
	}
}

// anonymousCreators maps CallNames of syscalls that create anonymous kernel objects.
// These objects have no externally-determined identity — any two calls create
// functionally interchangeable objects for UAF detection purposes.
// The initial value or configuration flags may differ, but the kernel object
// type and code paths are the same.
var anonymousCreators = map[string]bool{
	// Event notification
	"eventfd":  true,
	"eventfd2": true,

	// Epoll
	"epoll_create":  true,
	"epoll_create1": true,

	// Timer
	"timerfd_create": true,

	// Signal
	"signalfd":  true,
	"signalfd4": true,

	// Memory
	"memfd_create": true,
	"memfd_secret": true,

	// Userfaultfd
	"userfaultfd": true,

	// Inotify
	"inotify_init":  true,
	"inotify_init1": true,

	// Pipe (creates paired read/write fds)
	"pipe":  true,
	"pipe2": true,

	// Dup (derives new fd from existing — identity follows source)
	"dup":  true,
	"dup2": true,
	"dup3": true,

	// Accept (derives connection fd from listening socket)
	"accept":  true,
	"accept4": true,

	// Socket pair
	"socketpair": true,

	// Fanotify
	"fanotify_init": true,

	// IO uring
	"io_uring_setup": true,

	// Landlock
	"landlock_create_ruleset": true,
}

// mergePolicyOverrides provides manual overrides for syscalls where the
// heuristic classification is known to be incorrect.
// Key: Syscall.Name (full name including $ suffix).
//
// These overrides take highest priority in ClassifyMergePolicy.
// They are typically identified through LLM-assisted analysis or
// production log review.
var mergePolicyOverrides = map[string]MergeClass{
	// socket$auto is an auto-generated generic socket with random int params
	// (family, type, protocol are all plain int, not const).
	// Despite having $ in the name, it's NOT truly specialized.
	"socket$auto": MergeNever,

	// bpf$auto is an auto-generated generic bpf with random int params.
	"bpf$auto": MergeNever,

	// fcntl$auto has random cmd param.
	"fcntl$auto": MergeNever,

	// prctl$auto has random option param.
	"prctl$auto": MergeNever,

	// seccomp$auto has random op param.
	"seccomp$auto": MergeNever,

	// getsockopt$auto has random level/optname.
	"getsockopt$auto": MergeNever,

	// ioctl with random cmd — the generic ioctl variants.
	"ioctl$auto": MergeNever,
}

// ClassifyMergePolicy determines whether a resource-producing syscall's fd
// can be safely unified between two programs during fork-barrier merge.
//
// Classification rules (in priority order):
//  1. Manual override table (mergePolicyOverrides) → use override
//  2. Known anonymous creators (anonymousCreators) → ALWAYS
//  3. Has filename-type param (random file path) → NEVER
//  4. Specialized $-variant (without filename) → ALWAYS
//     The $ suffix means the syscall targets a specific kernel subsystem
//     with deterministic identity (e.g., fixed device path, const params).
//     Remaining non-const params (like open_flags) are configuration, not identity.
//  5. Generic syscall (no $) → NEVER
//
// This function operates on syscall metadata (Type info from syzlang),
// not on runtime argument values. It inspects the type structure to determine
// if any parameter uses the filename type (which generates random paths).
func ClassifyMergePolicy(meta *Syscall) MergeClass {
	if meta == nil {
		return MergeNever
	}

	// Rule 1: Check manual override (highest priority)
	if override, ok := mergePolicyOverrides[meta.Name]; ok {
		return override
	}

	// Rule 2: Known anonymous creators
	if anonymousCreators[meta.CallName] {
		return MergeAlways
	}

	// Rule 3: Has filename-type param → random file path → NEVER
	// This catches: open(), openat(), creat(), open$dir(), openat$dir(),
	// openat$auto(), open$auto(), and any other variant using filename type.
	if hasFilenameParam(meta) {
		return MergeNever
	}

	// Rule 4: Specialized ($-variant) without filename → ALWAYS
	// The $ suffix indicates the syscall targets a specific subsystem/device
	// with deterministic identity params. Examples:
	//   openat$null → string["/dev/null"] (fixed path)
	//   socket$inet_tcp → const[AF_INET], const[SOCK_STREAM], const[0]
	//   bpf$MAP_CREATE → const[BPF_MAP_CREATE]
	//   ioctl$KVM_CREATE_VM → const[KVM_CREATE_VM]
	// The remaining non-const params (like open_flags, bpf_attr fields)
	// are configuration that doesn't change the kernel object's identity.
	if strings.Contains(meta.Name, "$") {
		return MergeAlways
	}

	// Rule 5: Generic syscall without $ → NEVER
	// Examples: open(), socket(), bpf(), ioctl()
	// All identity-determining params may be random.
	return MergeNever
}

// hasFilenameParam checks if any input parameter of the syscall uses the
// filename type (BufferFilename), which generates random file paths
// like ./file0, ./file1 at runtime.
//
// This is the key signal for "non-deterministic identity": two calls
// to the same syscall will open different random files, creating
// different struct file objects in the kernel.
func hasFilenameParam(meta *Syscall) bool {
	found := false
	ForeachCallType(meta, func(t Type, ctx *TypeCtx) {
		if found {
			return
		}
		if ctx.Dir == DirOut {
			return
		}
		if bt, ok := t.(*BufferType); ok && bt.Kind == BufferFilename {
			found = true
			ctx.Stop = true
		}
	})
	return found
}

// AddMergePolicyOverride adds or updates a manual override for a specific syscall.
// This can be called at init time to incorporate LLM-generated classifications.
func AddMergePolicyOverride(syscallName string, policy MergeClass) {
	mergePolicyOverrides[syscallName] = policy
}

// DescribeMergePolicy returns a human-readable description of the merge policy
// classification for a syscall, including the reason for the classification.
// This is useful for debugging and for generating LLM review reports.
func DescribeMergePolicy(meta *Syscall) string {
	if meta == nil {
		return "nil syscall → never"
	}

	if override, ok := mergePolicyOverrides[meta.Name]; ok {
		return fmt.Sprintf("%s: %s (manual override)", meta.Name, override)
	}
	if anonymousCreators[meta.CallName] {
		return fmt.Sprintf("%s: always (anonymous creator: %s)", meta.Name, meta.CallName)
	}
	if hasFilenameParam(meta) {
		return fmt.Sprintf("%s: never (has filename param → random file path)", meta.Name)
	}
	if strings.Contains(meta.Name, "$") {
		return fmt.Sprintf("%s: always (specialized $-variant, deterministic identity)", meta.Name)
	}
	return fmt.Sprintf("%s: never (generic syscall, variable identity params)", meta.Name)
}

// DumpMergePolicyTable generates a classification report for all resource-producing
// syscalls in the target. This output can be fed to an LLM for review and validation.
//
// Output format per line:
//
//	MERGE_CLASS | SYSCALL_NAME | CALL_NAME | RETURN_RESOURCE | REASON | PARAM_SUMMARY
//
// Usage:
//
//	table := DumpMergePolicyTable(target)
//	// Feed 'table' to LLM with the review prompt for validation
func DumpMergePolicyTable(target *Target) string {
	var sb strings.Builder
	sb.WriteString("# Fork-Barrier Merge Policy Classification Report\n")
	sb.WriteString("# MERGE_CLASS | SYSCALL_NAME | CALL_NAME | RETURN_TYPE | REASON | PARAMS\n")
	sb.WriteString("#\n")

	for _, meta := range target.Syscalls {
		if meta.Ret == nil {
			continue
		}
		rt, ok := meta.Ret.(*ResourceType)
		if !ok {
			continue
		}
		// Only classify fd-family resources
		if len(rt.Desc.Kind) == 0 || rt.Desc.Kind[0] != "fd" {
			continue
		}

		mergeClass := ClassifyMergePolicy(meta)
		reason := classifyReason(meta)
		params := describeTopLevelParams(meta)

		sb.WriteString(fmt.Sprintf("%s | %s | %s | %s | %s | %s\n",
			mergeClass, meta.Name, meta.CallName, rt.TypeName, reason, params))
	}
	return sb.String()
}

func classifyReason(meta *Syscall) string {
	if _, ok := mergePolicyOverrides[meta.Name]; ok {
		return "manual_override"
	}
	if anonymousCreators[meta.CallName] {
		return "anonymous_creator"
	}
	if hasFilenameParam(meta) {
		return "has_filename_param"
	}
	if strings.Contains(meta.Name, "$") {
		return "specialized_variant"
	}
	return "generic_syscall"
}

func describeTopLevelParams(meta *Syscall) string {
	var parts []string
	for _, field := range meta.Args {
		dir := field.Dir(DirIn)
		if dir == DirOut {
			continue
		}
		t := field.Type
		// Unwrap one level of pointer
		if pt, ok := t.(*PtrType); ok {
			t = pt.Elem
		}
		parts = append(parts, fmt.Sprintf("%s:%s", field.Name, describeArgType(t)))
	}
	return strings.Join(parts, ", ")
}

func describeArgType(t Type) string {
	switch typ := t.(type) {
	case *ConstType:
		return fmt.Sprintf("const[%d]", typ.Val)
	case *FlagsType:
		return fmt.Sprintf("flags[%s]", typ.TypeName)
	case *IntType:
		if typ.Kind == IntRange {
			return fmt.Sprintf("int[%d:%d]", typ.RangeBegin, typ.RangeEnd)
		}
		return "int"
	case *ResourceType:
		return fmt.Sprintf("res[%s]", typ.TypeName)
	case *BufferType:
		switch typ.Kind {
		case BufferFilename:
			return "filename"
		case BufferString:
			if len(typ.Values) == 1 {
				v := typ.Values[0]
				if len(v) > 40 {
					v = v[:40] + "..."
				}
				return fmt.Sprintf("string[%q]", v)
			}
			return fmt.Sprintf("string[%d_values]", len(typ.Values))
		case BufferGlob:
			return "glob"
		default:
			return "buffer"
		}
	case *LenType:
		return "len"
	case *ProcType:
		return "proc"
	case *StructType:
		return fmt.Sprintf("struct[%s]", typ.Name())
	case *UnionType:
		return fmt.Sprintf("union[%s]", typ.Name())
	case *ArrayType:
		return fmt.Sprintf("array[%s]", describeArgType(typ.Elem))
	default:
		return "?"
	}
}
