package qemu

import "testing"

func TestMergeKernelCmdlineOverridesRoot(t *testing.T) {
	defaults := []string{"root=/dev/sda", "console=ttyS0"}
	got := mergeKernelCmdline(defaults, "root=/dev/vda nokaslr panic=1")
	want := []string{"console=ttyS0", "root=/dev/vda", "nokaslr", "panic=1"}
	if len(got) != len(want) {
		t.Fatalf("unexpected cmdline length: got %v want %v (%q)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected cmdline[%d]: got %q want %q (full=%q)", i, got[i], want[i], got)
		}
	}
}

func TestMergeKernelCmdlineKeepsDefaultsWithoutRootOverride(t *testing.T) {
	defaults := []string{"root=/dev/sda", "console=ttyS0"}
	got := mergeKernelCmdline(defaults, "nokaslr panic=1")
	want := []string{"root=/dev/sda", "console=ttyS0", "nokaslr", "panic=1"}
	if len(got) != len(want) {
		t.Fatalf("unexpected cmdline length: got %v want %v (%q)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected cmdline[%d]: got %q want %q (full=%q)", i, got[i], want[i], got)
		}
	}
}
