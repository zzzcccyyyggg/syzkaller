// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"testing"

	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/assert"
)

func TestCrashList(t *testing.T) {
	crashStore := &CrashStore{
		BaseDir:      t.TempDir(),
		MaxCrashLogs: 10,
	}

	first, err := crashStore.SaveCrash(&Crash{Report: &report.Report{
		Title:  "Title A",
		Output: []byte("ABCD"),
	}})
	assert.NoError(t, err)
	assert.True(t, first)
	for i := 0; i < 2; i++ {
		first, err := crashStore.SaveCrash(&Crash{Report: &report.Report{
			Title:  "Title B",
			Output: []byte("ABCD"),
		}})
		assert.NoError(t, err)
		assert.Equal(t, i == 0, first)
	}
	for i := 0; i < 3; i++ {
		first, err := crashStore.SaveCrash(&Crash{Report: &report.Report{
			Title:  "Title C",
			Output: []byte("ABCD"),
		}})
		assert.NoError(t, err)
		assert.Equal(t, i == 0, first)
	}

	list, err := crashStore.BugList()
	assert.NoError(t, err)
	assert.Len(t, list, 3)

	assert.Equal(t, "Title A", list[0].Title)
	assert.Len(t, list[0].Crashes, 1)
	assert.Equal(t, "Title B", list[1].Title)
	assert.Len(t, list[1].Crashes, 2)
	assert.Equal(t, "Title C", list[2].Title)
	assert.Len(t, list[2].Crashes, 3)
}

func TestEmptyCrashList(t *testing.T) {
	crashStore := &CrashStore{
		BaseDir:      t.TempDir(),
		MaxCrashLogs: 10,
	}
	_, err := crashStore.BugList()
	assert.NoError(t, err)
}

func TestMaxCrashLogs(t *testing.T) {
	crashStore := &CrashStore{
		BaseDir:      t.TempDir(),
		MaxCrashLogs: 5,
	}

	for i := 0; i < 20; i++ {
		_, err := crashStore.SaveCrash(&Crash{Report: &report.Report{
			Title:  "Title A",
			Output: []byte("ABCD"),
		}})
		assert.NoError(t, err)
	}

	info, err := crashStore.BugInfo(crashHash("Title A"), false)
	assert.NoError(t, err)
	assert.Len(t, info.Crashes, 5)
}

func TestCrashRepro(t *testing.T) {
	crashStore := &CrashStore{
		Tag:          "abcd",
		BaseDir:      t.TempDir(),
		MaxCrashLogs: 5,
	}

	_, err := crashStore.SaveCrash(&Crash{Report: &report.Report{
		Title:  "Some title",
		Output: []byte("Some output"),
	}})
	assert.NoError(t, err)

	err = crashStore.SaveRepro(&ReproResult{
		Repro: &repro.Result{
			Report: &report.Report{
				Title:  "Some title",
				Report: []byte("Some report"),
			},
			Prog: &prog.Prog{},
		},
	}, []byte("prog text"), []byte("c prog text"))
	assert.NoError(t, err)

	report, err := crashStore.Report(crashHash("Some title"))
	assert.NoError(t, err)
	assert.Equal(t, "Some title", report.Title)
	assert.Equal(t, "abcd", report.Tag)
	assert.Equal(t, []byte("prog text"), report.Prog)
	assert.Equal(t, []byte("c prog text"), report.CProg)
	assert.Equal(t, []byte("Some report"), report.Report)
}

func TestBugInfoDisplayTitleForDataRace(t *testing.T) {
	crashStore := &CrashStore{
		BaseDir:      t.TempDir(),
		MaxCrashLogs: 3,
	}
	const (
		title      = "DATARACE 1 vs 2"
		reportBody = `============ DATARACE ============
VarName 1, BlockLineNumber 100, IrLineNumber 10, is write 1
Function: primary_fn
============OTHER_INFO============
VarName 2, BlockLineNumber 200, IrLineNumber 20, watchpoint index 7
Function: secondary_fn
=================END`
	)
	_, err := crashStore.SaveCrash(&Crash{Report: &report.Report{
		Title:  title,
		Output: []byte("log"),
		Report: []byte(reportBody),
	}})
	assert.NoError(t, err)

	info, err := crashStore.BugInfo(crashHash(title), false)
	assert.NoError(t, err)
	assert.Equal(t, title, info.Title)
	assert.Equal(t, "DATARACE 1 vs 2", info.DisplayTitle)
}
