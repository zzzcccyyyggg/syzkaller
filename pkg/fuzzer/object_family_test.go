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

	// Destructive path operations are fuzzed normally but are not ObjectLinker targets.
	_, ok = getSyscallFamily("rename$kccwf")
	assert.False(t, ok)

	_, ok = getSyscallFamily("link$kccwf")
	assert.False(t, ok)

	_, ok = getSyscallFamily("unlink$kccwf")
	assert.False(t, ok)

	_, ok = getSyscallFamily("mkdir$kccwf")
	assert.False(t, ok)

	_, ok = getSyscallFamily("open$kccwf_dir")
	assert.False(t, ok)

	// kccwf relative-path family (dirfd-dependent)
	info, ok = getSyscallFamily("openat$kccwf")
	assert.True(t, ok)
	assert.Equal(t, familyKccwfFileRel, info.Family)
	assert.Equal(t, 1, info.ArgIndex) // filename is arg[1], dirfd is arg[0]

	info, ok = getSyscallFamily("faccessat$kccwf")
	assert.True(t, ok)
	assert.Equal(t, familyKccwfFileRel, info.Family)

	info, ok = getSyscallFamily("fchmodat$kccwf")
	assert.True(t, ok)
	assert.Equal(t, familyKccwfFileRel, info.Family)

	_, ok = getSyscallFamily("unlinkat$kccwf")
	assert.False(t, ok)

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

	// dsp device families
	info, ok = getSyscallFamily("openat$dsp")
	assert.True(t, ok)
	assert.Equal(t, familyDspPCM0, info.Family)
	assert.Equal(t, 1, info.ArgIndex)

	info, ok = getSyscallFamily("openat$audio")
	assert.True(t, ok)
	assert.Equal(t, familyDspPCM0, info.Family)

	info, ok = getSyscallFamily("openat$mixer")
	assert.True(t, ok)
	assert.Equal(t, familyDspMixer, info.Family)

	// floppy / BSD pty families are intentionally disabled
	_, ok = getSyscallFamily("syz_open_dev$floppy")
	assert.False(t, ok)

	_, ok = getSyscallFamily("syz_open_dev$ttys")
	assert.False(t, ok)

	_, ok = getSyscallFamily("syz_open_dev$ptys")
	assert.False(t, ok)

	// unknown syscall
	_, ok = getSyscallFamily("read$kccwf")
	assert.False(t, ok)
}

func TestIsCompatibleSyscall(t *testing.T) {
	// Same family: kccwf file, excluding destructive path operations.
	assert.True(t, isCompatibleSyscall("open$kccwf", "stat$kccwf"))
	assert.True(t, isCompatibleSyscall("open$kccwf", "chmod$kccwf"))
	assert.True(t, isCompatibleSyscall("open$kccwf", "truncate$kccwf"))
	assert.False(t, isCompatibleSyscall("stat$kccwf", "unlink$kccwf"))
	assert.False(t, isCompatibleSyscall("open$kccwf", "rename$kccwf"))
	assert.False(t, isCompatibleSyscall("stat$kccwf", "link$kccwf"))

	// kccwf dir/lifecycle operations are not linked by the generic table.
	assert.False(t, isCompatibleSyscall("mkdir$kccwf", "open$kccwf_dir"))
	assert.False(t, isCompatibleSyscall("mkdir$kccwf", "rmdir$kccwf"))

	// Same family: kccwf relative-path (dirfd-dependent)
	assert.True(t, isCompatibleSyscall("openat$kccwf", "faccessat$kccwf"))
	assert.True(t, isCompatibleSyscall("openat$kccwf", "fchmodat$kccwf"))
	assert.False(t, isCompatibleSyscall("openat$kccwf", "unlinkat$kccwf"))

	// Same family: bluetooth
	assert.True(t, isCompatibleSyscall("bind$bt_sco", "connect$bt_sco"))
	assert.True(t, isCompatibleSyscall("bind$bt_l2cap", "connect$bt_l2cap"))
	assert.True(t, isCompatibleSyscall("bind$bt_rfcomm", "connect$bt_rfcomm"))

	// Same family: unix socket
	assert.True(t, isCompatibleSyscall("bind$unix", "connect$unix"))
	assert.True(t, isCompatibleSyscall("openat$dsp", "openat$audio"))
	assert.True(t, isCompatibleSyscall("openat$dsp1", "openat$audio1"))
	assert.False(t, isCompatibleSyscall("syz_open_dev$ttys", "syz_open_dev$ptys"))

	// Cross-family: should NOT be compatible
	assert.False(t, isCompatibleSyscall("open$kccwf", "mkdir$kccwf"))     // file vs dir
	assert.False(t, isCompatibleSyscall("open$kccwf", "bind$bt_sco"))     // file vs bt
	assert.False(t, isCompatibleSyscall("bind$bt_sco", "bind$bt_l2cap"))  // different bt families
	assert.False(t, isCompatibleSyscall("bind$unix", "bind$bt_sco"))      // unix vs bt
	assert.False(t, isCompatibleSyscall("open$kccwf", "open$kccwf_dir"))  // file vs dir
	assert.False(t, isCompatibleSyscall("open$kccwf", "openat$kccwf"))    // absolute vs relative!
	assert.False(t, isCompatibleSyscall("stat$kccwf", "faccessat$kccwf")) // absolute vs relative!
	assert.False(t, isCompatibleSyscall("openat$dsp", "openat$mixer"))    // pcm vs mixer

	// Unknown syscalls
	assert.False(t, isCompatibleSyscall("read$kccwf", "write$kccwf"))
	assert.False(t, isCompatibleSyscall("open$kccwf", "read$kccwf"))
}

func TestIsUnsafeAlignment(t *testing.T) {
	// isUnsafeAlignment still reports true for *at base names
	// (used in the fallback path for non-family-registered syscalls)
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

func TestIsUnsafePathForAlignment(t *testing.T) {
	// Unsafe paths
	assert.True(t, isUnsafePathForAlignment([]byte("/proc/self/maps\x00")))
	assert.True(t, isUnsafePathForAlignment([]byte("/proc/thread-self/fd\x00")))
	assert.True(t, isUnsafePathForAlignment([]byte("/sys/kernel/debug/tracing\x00")))
	assert.True(t, isUnsafePathForAlignment([]byte("/sys/kernel/security/lsm\x00")))
	assert.True(t, isUnsafePathForAlignment([]byte("/dev/pts/0\x00")))

	// Safe paths
	assert.False(t, isUnsafePathForAlignment([]byte("/mnt/kccwf/testfile#0\x00")))
	assert.False(t, isUnsafePathForAlignment([]byte("/dev/fd0\x00")))
	assert.False(t, isUnsafePathForAlignment([]byte("/proc/sys/kernel/shmmax\x00")))
	assert.False(t, isUnsafePathForAlignment([]byte("testfile#0\x00")))
	assert.False(t, isUnsafePathForAlignment([]byte("")))
	assert.False(t, isUnsafePathForAlignment([]byte("\x00")))
}

func TestSemanticRefsByFamilyKeepsAllSources(t *testing.T) {
	refs := []semanticObjectRef{
		{Domain: objectDomainFS, Kind: objectKindFSFile, Scope: "/mnt/kccwf", SyscallName: "open$kccwf"},
		{Domain: objectDomainFS, Kind: objectKindFSFile, Scope: "/mnt/kccwf", SyscallName: "stat$kccwf"},
		{Domain: objectDomainFS, Kind: objectKindFSFile, Scope: "/mnt/kccwf", SyscallName: "openat$kccwf", Relative: true},
	}

	index := semanticRefsByFamily(refs)

	assert.Len(t, index["fs:fs_file:/mnt/kccwf:abs"], 2)
	assert.Len(t, index["fs:fs_file:/mnt/kccwf:rel"], 1)
}
