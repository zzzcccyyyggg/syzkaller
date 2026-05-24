// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import "strings"

type objectFamily string

const (
	familyNone objectFamily = ""

	familyKccwfFile    objectFamily = "kccwf_file"
	familyKccwfFileRel objectFamily = "kccwf_file_rel"
	familyKccwfDir     objectFamily = "kccwf_dir"

	familyBtSco    objectFamily = "bt_sco"
	familyBtL2cap  objectFamily = "bt_l2cap"
	familyBtRfcomm objectFamily = "bt_rfcomm"
	familyUnixSock objectFamily = "unix_sock"

	familyDspPCM0  objectFamily = "dsp_pcm0"
	familyDspPCM1  objectFamily = "dsp_pcm1"
	familyDspMixer objectFamily = "dsp_mixer"
)

type objectFamilyInfo struct {
	Family   objectFamily
	ArgIndex int
}

var syscallFamilyTable = buildSyscallFamilyTable()

func buildSyscallFamilyTable() map[string]objectFamilyInfo {
	table := make(map[string]objectFamilyInfo)

	for _, name := range []string{
		"open$kccwf",
		"chmod$kccwf",
		"chown$kccwf",
		"truncate$kccwf",
		"setxattr$kccwf",
		"stat$kccwf",
		"utimes$kccwf",
	} {
		table[name] = objectFamilyInfo{Family: familyKccwfFile, ArgIndex: 0}
	}
	for _, name := range []string{
		"openat$kccwf",
		"faccessat$kccwf",
		"fchmodat$kccwf",
		"fchownat$kccwf",
		"fstatat$kccwf",
	} {
		table[name] = objectFamilyInfo{Family: familyKccwfFileRel, ArgIndex: 1}
	}

	for _, name := range []string{"bind$bt_sco", "connect$bt_sco"} {
		table[name] = objectFamilyInfo{Family: familyBtSco, ArgIndex: 1}
	}
	for _, name := range []string{"bind$bt_l2cap", "connect$bt_l2cap"} {
		table[name] = objectFamilyInfo{Family: familyBtL2cap, ArgIndex: 1}
	}
	for _, name := range []string{"bind$bt_rfcomm", "connect$bt_rfcomm"} {
		table[name] = objectFamilyInfo{Family: familyBtRfcomm, ArgIndex: 1}
	}
	for _, name := range []string{"bind$unix", "connect$unix"} {
		table[name] = objectFamilyInfo{Family: familyUnixSock, ArgIndex: 1}
	}

	table["openat$dsp"] = objectFamilyInfo{Family: familyDspPCM0, ArgIndex: 1}
	table["openat$audio"] = objectFamilyInfo{Family: familyDspPCM0, ArgIndex: 1}
	table["openat$dsp1"] = objectFamilyInfo{Family: familyDspPCM1, ArgIndex: 1}
	table["openat$adsp1"] = objectFamilyInfo{Family: familyDspPCM1, ArgIndex: 1}
	table["openat$audio1"] = objectFamilyInfo{Family: familyDspPCM1, ArgIndex: 1}
	table["openat$mixer"] = objectFamilyInfo{Family: familyDspMixer, ArgIndex: 1}

	return table
}

func getSyscallFamily(syscallName string) (objectFamilyInfo, bool) {
	info, ok := syscallFamilyTable[syscallName]
	return info, ok
}

func isCompatibleSyscall(name1, name2 string) bool {
	info1, ok1 := syscallFamilyTable[name1]
	info2, ok2 := syscallFamilyTable[name2]
	if !ok1 || !ok2 {
		return false
	}
	return info1.Family == info2.Family
}

// isUnsafeAlignment reports syscalls whose object identity depends on context
// beyond a directly rewritable identifier. The semantic FS adapter handles a
// small kccwf openat/statat subset separately; this guard remains for tests and
// for avoiding accidental fallback linking in future adapters.
func isUnsafeAlignment(syscallName string) bool {
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

var unsafePathPrefixes = []string{
	"/proc/self/",
	"/proc/thread-self/",
	"/sys/kernel/debug/",
	"/sys/kernel/security/",
	"/dev/pts/",
}

func isUnsafePathForAlignment(data []byte) bool {
	s := trimNullBytesRaw(data)
	for _, prefix := range unsafePathPrefixes {
		if len(s) >= len(prefix) && string(s[:len(prefix)]) == prefix {
			return true
		}
	}
	return false
}

func trimNullBytesRaw(data []byte) []byte {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			return data[:i+1]
		}
	}
	return nil
}
