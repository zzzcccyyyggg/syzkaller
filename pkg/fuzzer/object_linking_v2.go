// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// ============================================================================
// Object-Level Program Linking V2 - Resource-Aware Cross-Syscall Alignment
// ============================================================================
// Strategy: Unify object identifiers between two programs so they are more
// likely to access the same kernel object when executed concurrently.
//
// Alignment proceeds in two tiers:
//   1. Same-name match: prog2's syscall has the exact same name as prog1's.
//   2. Cross-syscall compatible match: prog2's syscall belongs to the same
//      object family (e.g., open$kccwf ↔ stat$kccwf both use kccwf_file).
//
// The object family table and compatibility rules are defined in
// object_family.go. Only syscalls with directly rewritable object
// identifiers (paths, socket addresses) are eligible; fd-dependent
// syscalls are intentionally excluded (they inherit via fd chains).
// ============================================================================

// SyscallResourceInfo stores resource info extracted from a syscall.
type SyscallResourceInfo struct {
	SyscallName    string        // Full syscall name (e.g., "open$kccwf")
	CallIndex      int           // Index in the program
	ResourceArg    prog.Arg      // The resource argument (e.g., path pointer)
	ResourceArgIdx int           // Index of the resource arg in Args[]
	DataArg        *prog.DataArg // The actual DataArg containing the string
	Family         objectFamily  // Object family this syscall belongs to
	FamilyArgIndex int           // Arg index within the family definition
}

// LinkProgramsV2 unifies resource arguments between two programs.
// It performs two-tier alignment:
//   1. Same-name: for each syscall in prog2 that shares the exact name with
//      a prog1 syscall, copy the object identifier directly.
//   2. Cross-syscall: for remaining unmatched syscalls in prog2, check if any
//      prog1 resource belongs to the same object family and align them.
func (ol *ObjectLinker) LinkProgramsV2(prog1, prog2 *prog.Prog) *prog.Prog {
	if prog1 == nil || prog2 == nil {
		return prog2
	}

	ol.mu.Lock()
	ol.linkAttempts++
	attempt := ol.linkAttempts
	ol.mu.Unlock()

	// 1. Extract resource info from prog1's eligible syscalls
	prog1Resources := extractSyscallResources(prog1)
	if len(prog1Resources) == 0 {
		return prog2.Clone()
	}

	// 2. Build family index: family -> []SyscallResourceInfo for cross-matching
	familyIndex := buildFamilyIndex(prog1Resources)

	// 3. Clone prog2 and apply two-tier unification
	linked := prog2.Clone()
	unified := unifyResourcesTwoTier(linked, prog1Resources, familyIndex)

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

// extractSyscallResources extracts resource information from eligible syscalls.
// It uses the object family table for family-registered syscalls, and falls back
// to the legacy isFileRelatedSyscall check for broader coverage.
func extractSyscallResources(p *prog.Prog) map[string]SyscallResourceInfo {
	resources := make(map[string]SyscallResourceInfo)

	for callIdx, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}

		name := call.Meta.Name

		// Try family table first (covers kccwf, bluetooth, unix socket, etc.)
		if famInfo, ok := getSyscallFamily(name); ok {
			if famInfo.ArgIndex < len(call.Args) {
				dataArg := findDataArg(call.Args[famInfo.ArgIndex])
				if dataArg != nil && len(dataArg.Data()) > 0 {
					if _, exists := resources[name]; !exists {
						resources[name] = SyscallResourceInfo{
							SyscallName:    name,
							CallIndex:      callIdx,
							ResourceArg:    call.Args[famInfo.ArgIndex],
							ResourceArgIdx: famInfo.ArgIndex,
							DataArg:        dataArg,
							Family:         famInfo.Family,
							FamilyArgIndex: famInfo.ArgIndex,
						}
					}
				}
			}
			continue
		}

		// Fallback: legacy file-related syscall check (first DataArg in args[0..2])
		if !isFileRelatedSyscall(name) {
			continue
		}
		// Skip dirfd-dependent syscalls in the fallback path
		if isUnsafeAlignment(name) {
			continue
		}
		for argIdx, arg := range call.Args {
			if argIdx >= 3 {
				break
			}
			dataArg := findDataArg(arg)
			if dataArg != nil && len(dataArg.Data()) > 0 {
				if _, exists := resources[name]; !exists {
					resources[name] = SyscallResourceInfo{
						SyscallName:    name,
						CallIndex:      callIdx,
						ResourceArg:    arg,
						ResourceArgIdx: argIdx,
						DataArg:        dataArg,
						Family:         familyNone,
						FamilyArgIndex: argIdx,
					}
				}
				break
			}
		}
	}

	return resources
}

// buildFamilyIndex groups prog1 resources by object family for cross-matching.
// Each family maps to the first eligible resource found (to avoid over-rewriting).
func buildFamilyIndex(resources map[string]SyscallResourceInfo) map[objectFamily]SyscallResourceInfo {
	index := make(map[objectFamily]SyscallResourceInfo)
	for _, info := range resources {
		if info.Family == familyNone {
			continue
		}
		if _, exists := index[info.Family]; !exists {
			index[info.Family] = info
		}
	}
	return index
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

// unifyResourcesTwoTier applies two-tier alignment to the target program:
//   Tier 1 (same-name): exact syscall name match — highest confidence.
//   Tier 2 (cross-family): same object family match — enables e.g. open$kccwf → stat$kccwf alignment.
//
// A per-family rewrite counter prevents over-rewriting: at most maxRewritesPerFamily
// calls per family are rewritten in the partner program.
func unifyResourcesTwoTier(p *prog.Prog, sourceResources map[string]SyscallResourceInfo, familyIndex map[objectFamily]SyscallResourceInfo) int {
	const maxRewritesPerFamily = 3
	unified := 0
	familyRewriteCount := make(map[objectFamily]int)

	for _, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		name := call.Meta.Name

		// --- Tier 1: exact same-name match ---
		if sourceInfo, exists := sourceResources[name]; exists {
			if n := rewriteObjectIdentifier(call, sourceInfo); n > 0 {
				unified += n
				if sourceInfo.Family != familyNone {
					familyRewriteCount[sourceInfo.Family]++
				}
				continue
			}
		}

		// --- Tier 2: cross-syscall family match ---
		targetFamInfo, ok := getSyscallFamily(name)
		if !ok || targetFamInfo.Family == familyNone {
			continue
		}
		// Check rewrite budget
		if familyRewriteCount[targetFamInfo.Family] >= maxRewritesPerFamily {
			continue
		}
		sourceInfo, exists := familyIndex[targetFamInfo.Family]
		if !exists {
			continue
		}
		// Don't cross-align to itself (already handled in tier 1)
		if sourceInfo.SyscallName == name {
			continue
		}
		if n := rewriteObjectIdentifierAtArg(call, targetFamInfo.ArgIndex, sourceInfo); n > 0 {
			unified += n
			familyRewriteCount[targetFamInfo.Family]++
		}
	}

	return unified
}

// rewriteObjectIdentifier rewrites the object identifier in a call using exact
// same-name matching (source and target share the same arg layout).
func rewriteObjectIdentifier(call *prog.Call, sourceInfo SyscallResourceInfo) int {
	return rewriteObjectIdentifierAtArg(call, sourceInfo.FamilyArgIndex, sourceInfo)
}

// rewriteObjectIdentifierAtArg rewrites the DataArg at the given argument index
// in the call with the source's object identifier bytes.
// Returns 0 if the rewrite is skipped (unsafe path, equal data, missing arg).
func rewriteObjectIdentifierAtArg(call *prog.Call, argIndex int, sourceInfo SyscallResourceInfo) int {
	if argIndex >= len(call.Args) {
		return 0
	}
	targetDataArg := findDataArg(call.Args[argIndex])
	if targetDataArg == nil || len(targetDataArg.Data()) == 0 {
		return 0
	}

	sourceData := sourceInfo.DataArg.Data()
	targetData := targetDataArg.Data()

	// Skip if source or target path is in an unsafe prefix (e.g., /proc/self/)
	if isUnsafePathForAlignment(sourceData) || isUnsafePathForAlignment(targetData) {
		return 0
	}

	if dataEqual(sourceData, targetData) {
		return 0
	}

	newData := make([]byte, len(sourceData))
	copy(newData, sourceData)
	targetDataArg.SetData(newData)

	srcStr := trimNullBytes(sourceData)
	tgtStr := trimNullBytes(targetData)
	log.Logf(1, "[OBJLINK-V2] unified %s (from %s): %q -> %q",
		call.Meta.Name, sourceInfo.SyscallName, tgtStr, srcStr)
	return 1
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
