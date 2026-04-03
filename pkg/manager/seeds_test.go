package manager

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnqueueSeedDirLoadsOnlyFiles(t *testing.T) {
	seedDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(seedDir, "external_seed.prog"), []byte("getpid()\ngettid()\n"), 0o600); err != nil {
		t.Fatalf("failed to write seed: %v", err)
	}
	if err := os.Mkdir(filepath.Join(seedDir, "subdir"), 0o755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	inputs := make(chan *input, 4)
	if err := enqueueSeedDir(inputs, seedDir, filepath.Join("uaf_hunter", "seed_program_dir")); err != nil {
		t.Fatalf("enqueueSeedDir failed: %v", err)
	}
	close(inputs)

	var queued []*input
	for item := range inputs {
		queued = append(queued, item)
	}
	if len(queued) != 1 {
		t.Fatalf("got %d queued seeds, want 1", len(queued))
	}
	if queued[0].Path != filepath.Join("uaf_hunter", "seed_program_dir", "external_seed.prog") {
		t.Fatalf("unexpected seed path %q", queued[0].Path)
	}
	if string(queued[0].Data) != "getpid()\ngettid()\n" {
		t.Fatalf("unexpected seed contents %q", string(queued[0].Data))
	}
}
