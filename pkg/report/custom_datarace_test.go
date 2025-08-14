package report

import (
	"testing"

	"github.com/google/syzkaller/pkg/report/crash"
)

func TestCustomDataraceReport(t *testing.T) {
	// Sample custom datarace report
	customDataraceOutput := []byte(`Kernel panic: ============ DATARACE ============
VarName 17363501701721901078, BlockLineNumber 20, IrLineNumber 2, is write 0
Function: watchpoints_monitor+0x1340/0x17c0 kernel/kccwf/wp_checker.c:73
Function: kccwf_rec_mem_access+0x7ec/0xab0 kernel/kccwf/core.c:359
Function: xfs_file_release+0x39e/0x910 fs/xfs/xfs_file.c:1325
Function: __fput+0x40b/0x970
Function: task_work_run+0x1ce/0x260
Function: do_exit+0x88c/0x2520
Function: do_group_exit+0x1d4/0x290
Function: get_signal+0xf7e/0x1060
Function: arch_do_signal_or_restart+0x44/0x600
Function: syscall_exit_to_user_mode+0x62/0x110
Function: do_syscall_64+0xd6/0x1a0
Function: entry_SYSCALL_64_after_hwframe+0x77/0x7f
Function: 0x0
============OTHER_INFO============
VarName 16100634012471765034, BlockLineNumber 44, IrLineNumber 6,
watchpoint index 22144
Function: set_report_info+0xa6/0x1f0 kernel/kccwf/report.c:49
Function: watchpoints_monitor+0x7e8/0x17c0 kernel/kccwf/wp_checker.c:100
Function: kccwf_rec_mem_access+0x7ec/0xab0 kernel/kccwf/core.c:359
Function: xfs_bmap_del_extent_delay+0x91a/0x1cf0 fs/xfs/libxfs/xfs_bmap.c:4981
Function: __xfs_bunmapi+0x2c50/0x54f0 fs/xfs/libxfs/xfs_bmap.c:5673
Function: xfs_bunmapi_range+0x170/0x2c0 fs/xfs/libxfs/xfs_bmap.c:6437
Function: xfs_itruncate_extents_flags+0x50a/0x1070 fs/xfs/xfs_inode.c:1066
Function: xfs_itruncate_extents fs/xfs/xfs_inode.h:603 [inline]
Function: xfs_setattr_size+0xd78/0x1c80 fs/xfs/xfs_iops.c:1003
Function: xfs_vn_setattr_size+0x321/0x590 fs/xfs/xfs_iops.c:1054
Function: xfs_vn_setattr+0x2f4/0x910 fs/xfs/xfs_iops.c:1079
Function: notify_change+0x9f9/0xca0
Function: do_truncate+0x18d/0x220
Function: path_openat+0x2741/0x2db0
Function: do_filp_open+0x230/0x440
Function: do_sys_openat2+0xab/0x110
Function: __x64_sys_creat+0xd7/0x100
Function: do_syscall_64+0xc9/0x1a0
Function: entry_SYSCALL_64_after_hwframe+0x77/0x7f
=================END==============
`)

	cfg := &config{}
	reporter, _, err := ctorLinux(cfg)
	if err != nil {
		t.Fatalf("failed to create reporter: %v", err)
	}

	rep := reporter.Parse(customDataraceOutput)
	if rep == nil {
		t.Fatalf("expected to parse custom datarace report")
	}

	if rep.Type != crash.DataRace {
		t.Errorf("expected type DataRace, got %v", rep.Type)
	}

	if !contains(rep.Title, "CUSTOM_DATARACE") {
		t.Errorf("expected title to contain CUSTOM_DATARACE, got %q", rep.Title)
	}

	if len(rep.ReportedRaces) == 0 {
		t.Fatalf("expected at least one reported race")
	}

	race := rep.ReportedRaces[0]
	if race.VarName1 != "17363501701721901078" {
		t.Errorf("expected VarName1 to be 17363501701721901078, got %s", race.VarName1)
	}

	if race.VarName2 != "16100634012471765034" {
		t.Errorf("expected VarName2 to be 16100634012471765034, got %s", race.VarName2)
	}

	if race.BlockLineNumber1 != 20 {
		t.Errorf("expected BlockLineNumber1 to be 20, got %d", race.BlockLineNumber1)
	}

	if race.BlockLineNumber2 != 44 {
		t.Errorf("expected BlockLineNumber2 to be 44, got %d", race.BlockLineNumber2)
	}

	if race.IsWrite1 {
		t.Errorf("expected IsWrite1 to be false (read), got %v", race.IsWrite1)
	}

	if race.WatchpointIndex != 22144 {
		t.Errorf("expected WatchpointIndex to be 22144, got %d", race.WatchpointIndex)
	}

	t.Logf("Successfully parsed custom datarace: VarName1=%s, VarName2=%s", race.VarName1, race.VarName2)

	// Test the utility functions
	varNames := rep.GetRaceVarNames()
	expectedVarNames := []string{"17363501701721901078", "16100634012471765034"}
	if len(varNames) != len(expectedVarNames) {
		t.Errorf("expected %d var names, got %d", len(expectedVarNames), len(varNames))
	}
	for i, expected := range expectedVarNames {
		if i >= len(varNames) || varNames[i] != expected {
			t.Errorf("expected var name %d to be %s, got %s", i, expected, varNames[i])
		}
	}

	// Test race summary
	summary := rep.FormatRacesSummary()
	if !contains(summary, "Race 1") {
		t.Errorf("expected summary to contain 'Race 1', got %s", summary)
	}
	if !contains(summary, "17363501701721901078") {
		t.Errorf("expected summary to contain first VarName, got %s", summary)
	}

	// Test IsDataRaceReport
	if !rep.IsDataRaceReport() {
		t.Errorf("expected IsDataRaceReport to return true")
	}

	t.Logf("Race summary: %s", summary)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && s[len(s)-len(substr):] == substr ||
		(len(s) > len(substr) && len(substr) > 0 &&
			func() bool {
				for i := 0; i <= len(s)-len(substr); i++ {
					if s[i:i+len(substr)] == substr {
						return true
					}
				}
				return false
			}())
}
