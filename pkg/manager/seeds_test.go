package manager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
)

func TestLoadSeedsLoadsUAFHunterSeedProgramDir(t *testing.T) {
	workdir := t.TempDir()
	syzkallerDir := t.TempDir()
	seedDir := t.TempDir()

	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}
	if err := osWriteFile(filepath.Join(seedDir, "external_seed.prog"), []byte("getpid()\ngettid()\n")); err != nil {
		t.Fatalf("failed to write seed: %v", err)
	}

	cfg := &mgrconfig.Config{
		Workdir:   workdir,
		Syzkaller: syzkallerDir,
		TargetOS:  "linux",
		Target:    target,
		UAFHunter: mgrconfig.UAFHunterConfig{
			SeedProgramDir: seedDir,
		},
	}
	info, err := LoadSeeds(cfg, true)
	if err != nil {
		t.Fatalf("LoadSeeds failed: %v", err)
	}
	if len(info.Candidates) != 1 {
		t.Fatalf("got %d candidates, want 1", len(info.Candidates))
	}
	if got := info.Candidates[0].Prog.String(); got != "getpid-gettid" {
		t.Fatalf("bad program %q", got)
	}
}

func osWriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
