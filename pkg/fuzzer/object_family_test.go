package fuzzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSyscallFamilyTable(t *testing.T) {
	// kccwf file family
	info, ok := getSyscallFamily("open$kccwf")
	assert.True(t, ok)
	assert.Equal(t, familyKccwfFile, info.Family)
	assert.Equal(t, 0, info.ArgIndex)

	info, ok = getSyscallFamily("stat$kccwf")
	assert.True(t, ok)
	assert.Equal(t, familyKccwfFile, info.Family)

	info, ok = getSyscallFamily("chmod$kccwf")
	assert.True(t, ok)
	assert.Equal(t, familyKccwfFile, info.Family)

	// kccwf dir family
	info, ok = getSyscallFamily("mkdir$kccwf")
	assert.True(t, ok)
	assert.Equal(t, familyKccwfDir, info.Family)

	info, ok = getSyscallFamily("open$kccwf_dir")
	assert.True(t, ok)
	assert.Equal(t, familyKccwfDir, info.Family)

	// bluetooth
	info, ok = getSyscallFamily("bind$bt_sco")
	assert.True(t, ok)
	assert.Equal(t, familyBtSco, info.Family)
	assert.Equal(t, 1, info.ArgIndex)

	info, ok = getSyscallFamily("connect$bt_sco")
	assert.True(t, ok)
	assert.Equal(t, familyBtSco, info.Family)

	// unix socket
	info, ok = getSyscallFamily("bind$unix")
	assert.True(t, ok)
	assert.Equal(t, familyUnixSock, info.Family)

	info, ok = getSyscallFamily("connect$unix")
	assert.True(t, ok)
	assert.Equal(t, familyUnixSock, info.Family)

	// unknown syscall
	_, ok = getSyscallFamily("read$kccwf")
	assert.False(t, ok)
}

func TestIsCompatibleSyscall(t *testing.T) {
	// Same family: kccwf file
	assert.True(t, isCompatibleSyscall("open$kccwf", "stat$kccwf"))
	assert.True(t, isCompatibleSyscall("open$kccwf", "chmod$kccwf"))
	assert.True(t, isCompatibleSyscall("stat$kccwf", "unlink$kccwf"))
	assert.True(t, isCompatibleSyscall("open$kccwf", "truncate$kccwf"))

	// Same family: kccwf dir
	assert.True(t, isCompatibleSyscall("mkdir$kccwf", "open$kccwf_dir"))
	assert.True(t, isCompatibleSyscall("mkdir$kccwf", "rmdir$kccwf"))

	// Same family: bluetooth
	assert.True(t, isCompatibleSyscall("bind$bt_sco", "connect$bt_sco"))
	assert.True(t, isCompatibleSyscall("bind$bt_l2cap", "connect$bt_l2cap"))
	assert.True(t, isCompatibleSyscall("bind$bt_rfcomm", "connect$bt_rfcomm"))

	// Same family: unix socket
	assert.True(t, isCompatibleSyscall("bind$unix", "connect$unix"))

	// Cross-family: should NOT be compatible
	assert.False(t, isCompatibleSyscall("open$kccwf", "mkdir$kccwf"))         // file vs dir
	assert.False(t, isCompatibleSyscall("open$kccwf", "bind$bt_sco"))         // file vs bt
	assert.False(t, isCompatibleSyscall("bind$bt_sco", "bind$bt_l2cap"))      // different bt families
	assert.False(t, isCompatibleSyscall("bind$unix", "bind$bt_sco"))          // unix vs bt
	assert.False(t, isCompatibleSyscall("open$kccwf", "open$kccwf_dir"))      // file vs dir

	// Unknown syscalls
	assert.False(t, isCompatibleSyscall("read$kccwf", "write$kccwf"))
	assert.False(t, isCompatibleSyscall("open$kccwf", "read$kccwf"))
}

func TestIsUnsafeAlignment(t *testing.T) {
	assert.True(t, isUnsafeAlignment("openat$kccwf"))
	assert.True(t, isUnsafeAlignment("faccessat$kccwf"))
	assert.True(t, isUnsafeAlignment("fchmodat$kccwf"))
	assert.True(t, isUnsafeAlignment("renameat2$kccwf"))
	assert.True(t, isUnsafeAlignment("unlinkat$kccwf"))

	assert.False(t, isUnsafeAlignment("open$kccwf"))
	assert.False(t, isUnsafeAlignment("stat$kccwf"))
	assert.False(t, isUnsafeAlignment("bind$bt_sco"))
	assert.False(t, isUnsafeAlignment("chmod$kccwf"))
}

func TestBuildFamilyIndex(t *testing.T) {
	resources := map[string]SyscallResourceInfo{
		"open$kccwf": {
			SyscallName: "open$kccwf",
			Family:      familyKccwfFile,
			DataArg:     nil,
		},
		"mkdir$kccwf": {
			SyscallName: "mkdir$kccwf",
			Family:      familyKccwfDir,
			DataArg:     nil,
		},
		"bind$bt_sco": {
			SyscallName: "bind$bt_sco",
			Family:      familyBtSco,
			DataArg:     nil,
		},
		// No-family entry should be excluded from index
		"rename": {
			SyscallName: "rename",
			Family:      familyNone,
			DataArg:     nil,
		},
	}

	index := buildFamilyIndex(resources)

	assert.Contains(t, index, familyKccwfFile)
	assert.Contains(t, index, familyKccwfDir)
	assert.Contains(t, index, familyBtSco)
	assert.NotContains(t, index, familyNone)
	assert.Equal(t, "open$kccwf", index[familyKccwfFile].SyscallName)
}
