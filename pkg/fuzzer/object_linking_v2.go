// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// ============================================================================
// Object-Level Program Linking V2 - Syscall Variant Unification
// ============================================================================
// New strategy: Instead of matching paths between programs, we unify the
// resource arguments of SAME-TYPE syscalls to increase the probability
// of accessing the same kernel objects.
//
// Example: If prog1 has open$kccwf(testfile#0), and prog2 has open$kccwf(testfile#3),
// we modify prog2 to use testfile#0, so both programs access the same file.
//
// This is simpler and more effective than the old path-matching approach.
// ============================================================================

// SyscallResourceInfo stores resource info extracted from a syscall.
type SyscallResourceInfo struct {
	SyscallName    string        // Full syscall name (e.g., "open$kccwf")
	CallIndex      int           // Index in the program
	ResourceArg    prog.Arg      // The resource argument (e.g., path pointer)
	ResourceArgIdx int           // Index of the resource arg in Args[]
	DataArg        *prog.DataArg // The actual DataArg containing the string
}

// LinkProgramsV2 unifies resource arguments between two programs.
// For each syscall in prog2 that also exists in prog1, we copy prog1's
// resource argument to prog2 to ensure they access the same kernel object.
func (ol *ObjectLinker) LinkProgramsV2(prog1, prog2 *prog.Prog) *prog.Prog {
	if prog1 == nil || prog2 == nil {
		return prog2
	}

	ol.mu.Lock()
	ol.linkAttempts++
	attempt := ol.linkAttempts
	ol.mu.Unlock()

	// 1. Extract resource info from prog1's file-related syscalls
	prog1Resources := extractSyscallResources(prog1)
	if len(prog1Resources) == 0 {
		return prog2.Clone()
	}

	// 2. Clone prog2 and unify resources
	linked := prog2.Clone()
	unified := unifyResourcesByType(linked, prog1Resources)

	if unified > 0 {
		ol.mu.Lock()
		ol.linkSuccesses++
		ol.pathsUnified += unified
		ol.mu.Unlock()

		log.Logf(0, "[OBJLINK-V2] unified %d resources between prog1 and prog2 (attempt=%d)",
			unified, attempt)
	}

	return linked
}

// extractSyscallResources extracts resource information from file-related syscalls.
func extractSyscallResources(p *prog.Prog) map[string]SyscallResourceInfo {
	resources := make(map[string]SyscallResourceInfo)

	for callIdx, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}

		// Check if this is a file-related syscall
		if !isFileRelatedSyscall(call.Meta.Name) {
			continue
		}

		// Find the path/filename argument (usually first or second arg)
		for argIdx, arg := range call.Args {
			if argIdx >= 3 { // Only check first 3 args
				break
			}

			dataArg := findDataArg(arg)
			if dataArg != nil && len(dataArg.Data()) > 0 {
				// Store this resource info, keyed by syscall name
				// If multiple calls of same type, keep the first one
				if _, exists := resources[call.Meta.Name]; !exists {
					resources[call.Meta.Name] = SyscallResourceInfo{
						SyscallName:    call.Meta.Name,
						CallIndex:      callIdx,
						ResourceArg:    arg,
						ResourceArgIdx: argIdx,
						DataArg:        dataArg,
					}
				}
				break
			}
		}
	}

	return resources
}

// findDataArg recursively finds the DataArg within an argument.
func findDataArg(arg prog.Arg) *prog.DataArg {
	if arg == nil {
		return nil
	}

	switch a := arg.(type) {
	case *prog.DataArg:
		return a
	case *prog.PointerArg:
		if a.Res != nil {
			return findDataArg(a.Res)
		}
	case *prog.GroupArg:
		for _, inner := range a.Inner {
			if result := findDataArg(inner); result != nil {
				return result
			}
		}
	}
	return nil
}

// unifyResourcesByType modifies prog to use the same resources as in sourceResources.
func unifyResourcesByType(p *prog.Prog, sourceResources map[string]SyscallResourceInfo) int {
	unified := 0

	for _, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}

		// Check if prog1 has the same syscall type
		sourceInfo, exists := sourceResources[call.Meta.Name]
		if !exists {
			continue
		}

		// Find the path argument in this call
		for argIdx, arg := range call.Args {
			if argIdx >= 3 {
				break
			}

			targetDataArg := findDataArg(arg)
			if targetDataArg == nil || len(targetDataArg.Data()) == 0 {
				continue
			}

			// Copy data from source to target
			sourceData := sourceInfo.DataArg.Data()
			targetData := targetDataArg.Data()

			// Only unify if they're different
			if !dataEqual(sourceData, targetData) {
				// Clone the source data to target
				newData := make([]byte, len(sourceData))
				copy(newData, sourceData)
				targetDataArg.SetData(newData)
				unified++

				// Log the unification
				srcStr := trimNullBytes(sourceData)
				tgtStr := trimNullBytes(targetData)
				log.Logf(1, "[OBJLINK-V2] unified %s: %q -> %q",
					call.Meta.Name, tgtStr, srcStr)
			}
			break
		}
	}

	return unified
}

// dataEqual checks if two byte slices are equal.
func dataEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// trimNullBytes removes trailing null bytes from a byte slice for display.
func trimNullBytes(data []byte) string {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			return string(data[:i+1])
		}
	}
	return ""
}
