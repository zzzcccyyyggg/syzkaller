// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// ============================================================================
// Object-Level Program Linking
// ============================================================================
// This module ensures that two programs access the same kernel objects
// (e.g., same inode) by unifying their file path parameters.
// This increases the probability of triggering real cross-program races.
// ============================================================================

// ObjectLinker is responsible for unifying object references between programs.
type ObjectLinker struct {
	mu sync.RWMutex
	// Statistics
	linkAttempts   int
	linkSuccesses  int
	pathsUnified   int
}

// NewObjectLinker creates a new ObjectLinker instance.
func NewObjectLinker() *ObjectLinker {
	return &ObjectLinker{}
}

// LinkPrograms unifies file paths between two programs to ensure they access
// the same kernel objects. Returns a modified clone of prog2 (prog1 is kept as reference).
func (ol *ObjectLinker) LinkPrograms(prog1, prog2 *prog.Prog) *prog.Prog {
	if prog1 == nil || prog2 == nil {
		return prog2
	}

	ol.mu.Lock()
	ol.linkAttempts++
	attempt := ol.linkAttempts
	ol.mu.Unlock()

	// 1. Extract file paths from prog1
	prog1Paths := ol.extractFilePaths(prog1)
	if len(prog1Paths) == 0 {
		// prog1 has no file-related syscalls with paths
		if attempt <= 5 || attempt%100 == 0 {
			log.Logf(1, "[OBJLINK-DBG] attempt=%d: prog1 has no file paths (prog1=%d calls)", attempt, len(prog1.Calls))
		}
		return prog2.Clone()
	}

	// 2. Clone prog2 and unify paths
	linked := prog2.Clone()
	unified := ol.unifyPaths(linked, prog1Paths)

	if unified > 0 {
		ol.mu.Lock()
		ol.linkSuccesses++
		ol.pathsUnified += unified
		success := ol.linkSuccesses
		ol.mu.Unlock()

		log.Logf(0, "[OBJLINK] success: attempt=%d paths_unified=%d prog1_paths=%d (total_success=%d)",
			attempt, unified, len(prog1Paths), success)
	} else if attempt <= 5 || attempt%100 == 0 {
		log.Logf(1, "[OBJLINK-DBG] attempt=%d: prog1 has %d paths but no matches in prog2",
			attempt, len(prog1Paths))
	}

	return linked
}

// PathInfo stores information about a file path parameter.
type PathInfo struct {
	OriginalPath string
	BaseName     string // Normalized path without suffix
	CallIndex    int
}

// extractFilePaths extracts all file paths from file-related syscalls in a program.
func (ol *ObjectLinker) extractFilePaths(p *prog.Prog) map[string]PathInfo {
	paths := make(map[string]PathInfo)

	for callIdx, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}

		// Check if this is a file-related syscall
		if !isFileRelatedSyscall(call.Meta.Name) {
			continue
		}

		// Extract path argument
		pathStr := extractPathFromCall(call)
		if pathStr == "" {
			continue
		}

		// Normalize path to get base name
		baseName := normalizePathName(pathStr)
		paths[baseName] = PathInfo{
			OriginalPath: pathStr,
			BaseName:     baseName,
			CallIndex:    callIdx,
		}
	}

	return paths
}

// unifyPaths replaces path arguments in prog to match targetPaths.
// Returns the number of paths unified.
func (ol *ObjectLinker) unifyPaths(p *prog.Prog, targetPaths map[string]PathInfo) int {
	unified := 0

	for _, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}

		if !isFileRelatedSyscall(call.Meta.Name) {
			continue
		}

		pathStr := extractPathFromCall(call)
		if pathStr == "" {
			continue
		}

		baseName := normalizePathName(pathStr)
		if targetInfo, exists := targetPaths[baseName]; exists {
			if pathStr != targetInfo.OriginalPath {
				if setPathInCall(call, targetInfo.OriginalPath) {
					unified++
				}
			}
		}
	}

	return unified
}

// isFileRelatedSyscall checks if a syscall is file-related.
func isFileRelatedSyscall(name string) bool {
	// Extract base syscall name (before $)
	baseName := name
	if idx := strings.Index(name, "$"); idx > 0 {
		baseName = name[:idx]
	}

	fileRelated := map[string]bool{
		"open":      true,
		"openat":    true,
		"openat2":   true,
		"creat":     true,
		"mkdir":     true,
		"mkdirat":   true,
		"mknod":     true,
		"mknodat":   true,
		"link":      true,
		"linkat":    true,
		"symlink":   true,
		"symlinkat": true,
		"rename":    true,
		"renameat":  true,
		"renameat2": true,
		"unlink":    true,
		"unlinkat":  true,
		"rmdir":     true,
		"chmod":     true,
		"fchmodat":  true,
		"chown":     true,
		"fchownat":  true,
		"truncate":  true,
		"access":    true,
		"faccessat": true,
		"stat":      true,
		"lstat":     true,
		"fstatat":   true,
	}

	return fileRelated[baseName]
}

// normalizePathName removes numeric suffixes from path names.
// Example: "/mnt/kccwf/testfile#1" → "/mnt/kccwf/testfile"
func normalizePathName(path string) string {
	// Remove #N suffix (used by syzkaller for path variation)
	if idx := strings.LastIndex(path, "#"); idx > 0 {
		return path[:idx]
	}
	// Remove trailing digits that look like suffixes
	// Example: "/mnt/kccwf/testfile1" → "/mnt/kccwf/testfile"
	result := path
	for len(result) > 0 {
		lastChar := result[len(result)-1]
		if lastChar >= '0' && lastChar <= '9' {
			result = result[:len(result)-1]
		} else {
			break
		}
	}
	if result == "" {
		return path // Don't return empty string
	}
	return result
}

// extractPathFromCall extracts the path string from a syscall's arguments.
// This is a simplified implementation that handles common cases.
func extractPathFromCall(call *prog.Call) string {
	if call == nil || len(call.Args) == 0 {
		return ""
	}

	// For most file syscalls, the path is the first or second argument
	for i := 0; i < len(call.Args) && i < 3; i++ {
		arg := call.Args[i]
		if pathStr := extractStringFromArg(arg); pathStr != "" {
			// Check if it looks like a file path
			if strings.HasPrefix(pathStr, "/") || strings.HasPrefix(pathStr, "./") {
				return pathStr
			}
		}
	}

	return ""
}

// extractStringFromArg recursively extracts a string value from an argument.
func extractStringFromArg(arg prog.Arg) string {
	if arg == nil {
		return ""
	}

	switch a := arg.(type) {
	case *prog.PointerArg:
		if a.Res != nil {
			return extractStringFromArg(a.Res)
		}
	case *prog.DataArg:
		if data := a.Data(); len(data) > 0 {
			// Remove null terminator if present
			if data[len(data)-1] == 0 {
				data = data[:len(data)-1]
			}
			return string(data)
		}
	case *prog.GroupArg:
		// For arrays of bytes (strings)
		if len(a.Inner) > 0 {
			var buf []byte
			for _, inner := range a.Inner {
				if constArg, ok := inner.(*prog.ConstArg); ok {
					if constArg.Val < 256 {
						if constArg.Val == 0 {
							break // Null terminator
						}
						buf = append(buf, byte(constArg.Val))
					}
				}
			}
			if len(buf) > 0 {
				return string(buf)
			}
		}
	}

	return ""
}

// setPathInCall attempts to set a new path value in a syscall's argument.
// Returns true if successful.
func setPathInCall(call *prog.Call, newPath string) bool {
	if call == nil || len(call.Args) == 0 {
		return false
	}

	// Find the path argument and replace it
	for i := 0; i < len(call.Args) && i < 3; i++ {
		if setStringInArg(call.Args[i], newPath) {
			return true
		}
	}

	return false
}

// setStringInArg recursively sets a string value in an argument.
func setStringInArg(arg prog.Arg, newValue string) bool {
	if arg == nil {
		return false
	}

	switch a := arg.(type) {
	case *prog.PointerArg:
		if a.Res != nil {
			return setStringInArg(a.Res, newValue)
		}
	case *prog.DataArg:
		currentData := a.Data()
		if len(currentData) > 0 {
			// Check if current data looks like a path
			if currentData[0] == '/' || (len(currentData) > 1 && currentData[0] == '.' && currentData[1] == '/') {
				// Create new data with null terminator
				newData := append([]byte(newValue), 0)
				a.SetData(newData)
				return true
			}
		}
	}

	return false
}

// GetStats returns linking statistics.
func (ol *ObjectLinker) GetStats() (attempts, successes, pathsUnified int) {
	ol.mu.RLock()
	defer ol.mu.RUnlock()
	return ol.linkAttempts, ol.linkSuccesses, ol.pathsUnified
}
