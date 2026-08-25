// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import "testing"

func TestNormalizeRaceModeAliases(t *testing.T) {
	cfg := &Config{
		Experimental: Experimental{
			RaceMode:                  true,
			DisableRaceValidateQueue:  true,
			SkipRaceActivationRestart: true,
			DisableRaceHistory:        true,
		},
	}
	cfg.normalizeRaceModeAliases()
	if !cfg.Experimental.UAFMode {
		t.Fatal("expected race_mode to enable legacy UAFMode field")
	}
	if !cfg.Experimental.DisableUAFValidateQueue {
		t.Fatal("expected disable_race_validate_queue to enable legacy validate queue field")
	}
	if !cfg.Experimental.SkipUAFActivationRestart {
		t.Fatal("expected skip_race_activation_restart to enable legacy restart field")
	}
	if !cfg.Experimental.DisableUAFHistory {
		t.Fatal("expected disable_race_history to enable legacy history field")
	}

	legacy := &Config{
		Experimental: Experimental{
			UAFMode:                  true,
			DisableUAFValidateQueue:  true,
			SkipUAFActivationRestart: true,
			DisableUAFHistory:        true,
		},
	}
	legacy.normalizeRaceModeAliases()
	if !legacy.Experimental.RaceMode {
		t.Fatal("expected legacy uaf_mode to enable RaceMode field")
	}
	if !legacy.Experimental.DisableRaceValidateQueue {
		t.Fatal("expected legacy validate queue field to enable race alias")
	}
	if !legacy.Experimental.SkipRaceActivationRestart {
		t.Fatal("expected legacy restart field to enable race alias")
	}
	if !legacy.Experimental.DisableRaceHistory {
		t.Fatal("expected legacy history field to enable race alias")
	}
}

func TestRaceModeInitializesBarrierMask(t *testing.T) {
	cfg := &Config{
		Procs: 2,
		Experimental: Experimental{
			RaceMode:     true,
			BarrierMode:  true,
			BarrierProcs: []int{0, 1},
		},
	}
	cfg.normalizeRaceModeAliases()
	if err := cfg.initBarrierMask(); err != nil {
		t.Fatal(err)
	}
	if cfg.BarrierMask != 0x3 {
		t.Fatalf("barrier mask = %#x, want 0x3", cfg.BarrierMask)
	}
	if !cfg.Experimental.UAFMode {
		t.Fatal("expected race_mode to keep legacy UAFMode enabled internally")
	}
}

func TestFuzzVMStallTimeoutRejectsNegativeValue(t *testing.T) {
	cfg := &Config{
		Experimental: Experimental{FuzzVMStallTimeoutSeconds: -1},
	}
	if err := cfg.initBarrierMask(); err == nil {
		t.Fatal("expected a negative fuzz VM stall timeout to be rejected")
	}
}
