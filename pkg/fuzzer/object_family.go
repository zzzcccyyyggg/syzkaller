// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import "strings"

// ============================================================================
// Object Family & Cross-Syscall Compatibility Table
// ============================================================================
// This file defines the object family concept and the compatibility table
// used by ObjectLinker V2 for resource-aware cross-syscall alignment.
//
// An "object family" groups syscalls that operate on the same kind of kernel
// object (e.g., a mounted test file, a UNIX socket path, a Bluetooth address).
// Within a family, different syscalls can be aligned: the object identifier
// (path, address) from the main program is copied to compatible positions
// in the partner program, even when the syscall names differ.
//
// Example: open$kccwf("/mnt/kccwf/testfile#0") and stat$kccwf("/mnt/kccwf/testfile#3")
// belong to the same family "kccwf_file". The path from open$kccwf in prog1
// can be used to rewrite stat$kccwf in prog2, making both programs access
// the same file object.
// ============================================================================

// objectFamily identifies which kernel object family a syscall belongs to.
// Syscalls in the same family can have their object identifiers cross-aligned.
type objectFamily string

const (
	familyNone objectFamily = ""

	// kccwf file-system families (btrfs, xfs, f2fs, jfs, ...)
	familyKccwfFile objectFamily = "kccwf_file" // /mnt/kccwf/testfile#
	familyKccwfDir  objectFamily = "kccwf_dir"  // /mnt/kccwf/testdir, /mnt/kccwf

	// Bluetooth address families
	familyBtSco    objectFamily = "bt_sco"    // sockaddr_sco.addr
	familyBtL2cap  objectFamily = "bt_l2cap"  // sockaddr_l2
	familyBtRfcomm objectFamily = "bt_rfcomm" // sockaddr_rc

	// UNIX socket path family
	familyUnixSock objectFamily = "unix_sock" // sockaddr_un path
)

// objectFamilyInfo describes how to extract the object identifier from a syscall.
type objectFamilyInfo struct {
	Family   objectFamily
	ArgIndex int // which argument holds the object identifier (0-based)
}

// syscallFamilyTable maps full syscall names to their object family info.
// Only syscalls whose object identifier can be directly rewritten are listed.
// FD-dependent syscalls (openat$kccwf with dirfd, fstat$kccwf, etc.) are
// intentionally excluded — they inherit alignment through their fd chain.
var syscallFamilyTable = buildSyscallFamilyTable()

func buildSyscallFamilyTable() map[string]objectFamilyInfo {
	table := make(map[string]objectFamilyInfo)

	// --- kccwf file family: path is arg[0] ---
	for _, name := range []string{
		"open$kccwf",
		"chmod$kccwf",
		"chown$kccwf",
		"truncate$kccwf",
		"unlink$kccwf",
		"setxattr$kccwf",
		"stat$kccwf",
		"utimes$kccwf",
	} {
		table[name] = objectFamilyInfo{Family: familyKccwfFile, ArgIndex: 0}
	}

	// --- kccwf directory family: path is arg[0] ---
	for _, name := range []string{
		"open$kccwf_dir",
		"mkdir$kccwf",
		"rmdir$kccwf",
	} {
		table[name] = objectFamilyInfo{Family: familyKccwfDir, ArgIndex: 0}
	}

	// --- Bluetooth SCO: address struct is arg[1] (arg[0] is fd) ---
	for _, name := range []string{
		"bind$bt_sco",
		"connect$bt_sco",
	} {
		table[name] = objectFamilyInfo{Family: familyBtSco, ArgIndex: 1}
	}

	// --- Bluetooth L2CAP: address struct is arg[1] ---
	for _, name := range []string{
		"bind$bt_l2cap",
		"connect$bt_l2cap",
	} {
		table[name] = objectFamilyInfo{Family: familyBtL2cap, ArgIndex: 1}
	}

	// --- Bluetooth RFCOMM: address struct is arg[1] ---
	for _, name := range []string{
		"bind$bt_rfcomm",
		"connect$bt_rfcomm",
	} {
		table[name] = objectFamilyInfo{Family: familyBtRfcomm, ArgIndex: 1}
	}

	// --- UNIX socket: address struct is arg[1] ---
	for _, name := range []string{
		"bind$unix",
		"connect$unix",
	} {
		table[name] = objectFamilyInfo{Family: familyUnixSock, ArgIndex: 1}
	}

	return table
}

// getSyscallFamily returns the object family for a given syscall name.
// Returns familyNone if the syscall is not in the compatibility table.
func getSyscallFamily(syscallName string) (objectFamilyInfo, bool) {
	info, ok := syscallFamilyTable[syscallName]
	return info, ok
}

// isCompatibleSyscall checks if two syscalls belong to the same object family,
// meaning their object identifiers can be cross-aligned.
func isCompatibleSyscall(name1, name2 string) bool {
	info1, ok1 := syscallFamilyTable[name1]
	info2, ok2 := syscallFamilyTable[name2]
	if !ok1 || !ok2 {
		return false
	}
	return info1.Family == info2.Family
}

// isUnsafeAlignment checks if rewriting the object identifier at argIndex
// in the given syscall is potentially unsafe. This catches cases where
// the object identity depends on additional context (dirfd, parent fd).
func isUnsafeAlignment(syscallName string) bool {
	// These syscalls have a dirfd parameter that determines the actual path.
	// Rewriting just the filename without matching the dirfd is misleading.
	baseName := syscallName
	if idx := strings.Index(syscallName, "$"); idx > 0 {
		baseName = syscallName[:idx]
	}
	unsafe := map[string]bool{
		"openat":    true,
		"mkdirat":   true,
		"mknodat":   true,
		"linkat":    true,
		"symlinkat": true,
		"renameat":  true,
		"renameat2": true,
		"unlinkat":  true,
		"fchmodat":  true,
		"fchownat":  true,
		"faccessat": true,
		"fstatat":   true,
	}
	return unsafe[baseName]
}
