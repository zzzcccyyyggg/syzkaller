// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig_test

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/config"
	. "github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/vm/gce"
	"github.com/google/syzkaller/vm/proxyapp"
	"github.com/google/syzkaller/vm/qemu"
)

func TestCanned(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.cfg"))
	if err != nil || len(files) == 0 {
		t.Fatalf("failed to read input files: %v", err)
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			cfg, err := LoadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var vmCfg any
			switch cfg.Type {
			case "qemu":
				vmCfg = new(qemu.Config)
			case "gce":
				vmCfg = new(gce.Config)
			case "proxyapp":
				vmCfg = new(proxyapp.Config)
			default:
				t.Fatalf("unknown VM type: %v", cfg.Type)
			}
			if err := config.LoadData(cfg.VM, vmCfg); err != nil {
				t.Fatalf("failed to load %v config: %v", cfg.Type, err)
			}
		})
	}
}

func TestLoadPartialDataAllowsUAFHunterBlock(t *testing.T) {
	seedDir := t.TempDir()
	cfg := DefaultValues()
	err := config.LoadData([]byte(`{
		"uaf_hunter": {
			"target": "btrfs-qgroup-disable-vs-rescan",
			"artifact_root": "/tmp/uaf-hunter-artifacts",
			"seed_program_dir": "`+seedDir+`",
			"observation_gates": [
				{
					"name": "same-filesystem-object-family",
					"required_probe_ids": ["shared_object:qgroup_rescan_zero_tracking:3970"]
				}
			]
		}
	}`), cfg)
	if err != nil {
		t.Fatalf("failed to load config with uaf_hunter block: %v", err)
	}
	if cfg.UAFHunter.Target != "btrfs-qgroup-disable-vs-rescan" {
		t.Fatalf("bad uaf_hunter target: %q", cfg.UAFHunter.Target)
	}
	if cfg.UAFHunter.SeedProgramDir != seedDir {
		t.Fatalf("bad seed_program_dir: %q", cfg.UAFHunter.SeedProgramDir)
	}
	if len(cfg.UAFHunter.ObservationGates) != 1 {
		t.Fatalf("bad observation gate count: %d", len(cfg.UAFHunter.ObservationGates))
	}
}

func TestCompleteRejectsMissingUAFHunterSeedDir(t *testing.T) {
	workdir := t.TempDir()
	syzkallerDir := t.TempDir()
	cfg := DefaultValues()
	err := config.LoadData([]byte(`{
		"name": "test",
		"workdir": "`+workdir+`",
		"syzkaller": "`+syzkallerDir+`",
		"type": "none",
		"uaf_hunter": {
			"seed_program_dir": "/tmp/does-not-exist-uaf-hunter"
		}
	}`), cfg)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}
	cfg.TargetOS = "linux"
	cfg.TargetArch = "amd64"
	cfg.TargetVMArch = "amd64"
	if err := Complete(cfg); err == nil {
		t.Fatalf("expected Complete to reject missing uaf_hunter.seed_program_dir")
	}
}

func TestMatchSyscall(t *testing.T) {
	tests := []struct {
		pattern string
		call    string
		result  bool
	}{
		{"foo", "foo", true},
		{"foo", "bar", false},
		{"foo", "foo$BAR", true},
		{"foo*", "foo", true},
		{"foo*", "foobar", true},
		{"foo*", "foo$BAR", true},
		{"foo$*", "foo", false},
		{"foo$*", "foo$BAR", true},
	}
	for i, test := range tests {
		res := MatchSyscall(test.call, test.pattern)
		if res != test.result {
			t.Errorf("#%v: pattern=%q call=%q want=%v got=%v",
				i, test.pattern, test.call, test.result, res)
		}
	}
}
