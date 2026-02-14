// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"strings"
	"sync"
)

// ============================================================================
// Object-Level Program Linking — Shared Infrastructure
// ============================================================================
// This file contains the ObjectLinker struct, constructor, and shared helpers
// used by the V2 linking strategy in object_linking_v2.go.
//
// The original V1 path-matching strategy (LinkPrograms) has been removed
// as dead code — only V2 (LinkProgramsV2) is used in production.
// ============================================================================

// ObjectLinker is responsible for unifying object references between programs.
type ObjectLinker struct {
	mu sync.RWMutex
	// Statistics
	linkAttempts  int
	linkSuccesses int
	pathsUnified  int
}

// NewObjectLinker creates a new ObjectLinker instance.
func NewObjectLinker() *ObjectLinker {
	return &ObjectLinker{}
}

// GetStats returns linking statistics.
func (ol *ObjectLinker) GetStats() (attempts, successes, pathsUnified int) {
	ol.mu.RLock()
	defer ol.mu.RUnlock()
	return ol.linkAttempts, ol.linkSuccesses, ol.pathsUnified
}

// isFileRelatedSyscall checks if a syscall is file-related.
// Used by both V1 (removed) and V2 linking strategies.
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

