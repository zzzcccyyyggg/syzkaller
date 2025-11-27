package report

import (
	"testing"

	"github.com/google/syzkaller/pkg/report/crash"
)

func TestDataRaceSignatureKCSAN(t *testing.T) {
	rep := &Report{
		Title: "KCSAN: data-race in foo",
		Frame: "foo+0x10/0x20",
		Type:  crash.KCSANDataRace,
	}
	sig := DataRaceSignature(rep)
	if sig == "" {
		t.Fatalf("expected signature for KCSAN report")
	}
	want := "KCSAN: data-race in foo|foo+0x10/0x20"
	if sig != want {
		t.Fatalf("want %q, got %q", want, sig)
	}
}

func TestDataRaceSignatureCustom(t *testing.T) {
	body := `Kernel panic: ============ DATARACE ============
VarName 3282847523607738828, BlockLineNumber 132, IrLineNumber 1, is write 1
============CURRENT_OP_VALUE============
Current Operation Variable Value: 0x0 (0) [8 bytes]
Function: watchpoints_monitor+0x10d1/0x1870 kernel/kccwf/wp_checker.c:397
============OTHER_INFO============
VarName 3282847523607738828, BlockLineNumber 132, IrLineNumber 1, watchpoint index 5527
=================END==============`
	rep := &Report{Report: []byte(body)}
	sig := DataRaceSignature(rep)
	if sig == "" {
		t.Fatalf("expected signature for custom datarace report")
	}
	want := "custom|3282847523607738828"
	if sig != want {
		t.Fatalf("want %q, got %q", want, sig)
	}
}

func TestCustomDataRaceTitle(t *testing.T) {
	body := `Kernel panic: ============ DATARACE ============
VarName 1, BlockLineNumber 100, IrLineNumber 1, is write 1
============OTHER_INFO============
VarName 2, BlockLineNumber 200, IrLineNumber 1, watchpoint index 12
=================END==============`
	rep := &Report{Report: []byte(body)}
	info := ParseCustomDataRace(rep.Report)
	if info == nil {
		t.Fatalf("expected parsed custom datarace info")
	}
	title := CustomDataRaceBugTitle(info)
	if title != "DATARACE 1 vs 2" {
		t.Fatalf("unexpected title %q", title)
	}
	if sig := customDataRaceSignature(&Report{CustomDataRace: info}); sig != "custom|1|2" {
		t.Fatalf("unexpected signature %q", sig)
	}
}

func TestParseCustomDataRace(t *testing.T) {
	body := `Kernel panic: ============ DATARACE ============
[   11.111111] VarName 1966871020471177429, BlockLineNumber 45, IrLineNumber 1, is write 0
[   11.111222] Function: watchpoints_monitor+0x1224/0x17e0
[   11.111333] Function: hci_cmd_work+0x66b/0xf40
[   11.111444] ============OTHER_INFO============
[   11.111555] VarName 3282817199247569854, BlockLineNumber 40, IrLineNumber 1, watchpoint index 39559
[   11.111666] Function: set_report_info+0xa6/0x200
[   11.111777] Function: hci_inquiry_sync+0x363/0x6b0
[   11.111888] =================END==============`
	info := ParseCustomDataRace([]byte(body))
	if info == nil {
		t.Fatalf("expected parsed custom datarace info")
	}
	if len(info.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(info.Entries))
	}
	first := info.Entries[0]
	if !first.Primary {
		t.Fatalf("expected first entry to be primary")
	}
	if first.VarName != "1966871020471177429" || first.BlockLine != "45" || first.IsWrite != "0" {
		t.Fatalf("unexpected primary entry: %+v", first)
	}
	if got := len(first.Stack); got != 2 {
		t.Fatalf("expected 2 stack frames, got %d", got)
	}
	second := info.Entries[1]
	if second.Primary {
		t.Fatalf("expected second entry to be secondary")
	}
	if second.VarName != "3282817199247569854" || second.BlockLine != "40" {
		t.Fatalf("unexpected secondary entry: %+v", second)
	}
	if info.Watchpoint != "39559" {
		t.Fatalf("unexpected watchpoint: %q", info.Watchpoint)
	}
	if got := len(second.Stack); got != 2 {
		t.Fatalf("expected 2 stack frames for secondary entry, got %d", got)
	}
}
