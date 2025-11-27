package report

import (
	"bytes"
	"regexp"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/report/crash"
)

var (
	CustomDataRaceMarker   = []byte("============ DATARACE ============")
	CustomPrimaryVarRegexp = regexpMustCompile(`VarName (\d+), BlockLineNumber (\d+), IrLineNumber \d+, is write ([01])`)
	CustomOtherVarRegexp   = regexpMustCompile(`VarName (\d+), BlockLineNumber (\d+), IrLineNumber \d+, watchpoint index (\d+)`)
)

// DataRaceSignature returns a stable identifier for known data race report
// formats (KCSAN or custom DATARACE panics). An empty string means the report
// does not look like a data race report we understand.
func DataRaceSignature(rep *Report) string {
	if rep == nil {
		return ""
	}
	if sig := kcsanDataRaceSignature(rep); sig != "" {
		return sig
	}
	if sig := customDataRaceSignature(rep); sig != "" {
		return sig
	}
	return ""
}

func kcsanDataRaceSignature(rep *Report) string {
	if !rep.Type.IsKCSAN() {
		return ""
	}
	if rep.Title == "" && rep.Frame == "" {
		return ""
	}
	sig := rep.Title
	if rep.Frame != "" {
		if sig != "" {
			sig += "|"
		}
		sig += rep.Frame
	}
	if sig == "" {
		sig = string(crash.KCSANDataRace)
	}
	return sig
}

func customDataRaceSignature(rep *Report) string {
	info := rep.CustomDataRace
	if info == nil {
		info = ParseCustomDataRace(rep.Report)
	}
	if info == nil {
		return ""
	}
	names := customDataRaceVarPair(info)
	if len(names) == 0 {
		return ""
	}
	return "custom|" + strings.Join(names, "|")
}

func customDataRaceVarPair(info *CustomDataRaceInfo) []string {
	if info == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(info.Entries))
	var names []string
	for _, entry := range info.Entries {
		if entry == nil || entry.VarName == "" {
			continue
		}
		if _, ok := seen[entry.VarName]; ok {
			continue
		}
		seen[entry.VarName] = struct{}{}
		names = append(names, entry.VarName)
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	if len(names) > 2 {
		names = names[:2]
	}
	return names
}

func CustomDataRaceBugTitle(info *CustomDataRaceInfo) string {
	names := customDataRaceVarPair(info)
	if len(names) == 0 {
		return ""
	}
	return "DATARACE " + strings.Join(names, " vs ")
}

// ParseCustomDataRace extracts structured info from custom DATARACE reports.
func ParseCustomDataRace(report []byte) *CustomDataRaceInfo {
	if len(report) == 0 || !bytes.Contains(report, CustomDataRaceMarker) {
		return nil
	}
	info := &CustomDataRaceInfo{}
	var current *CustomDataRaceEntry
	inOtherInfo := false
	lines := strings.Split(string(report), "\n")
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		switch {
		case strings.Contains(line, "============OTHER_INFO============"):
			inOtherInfo = true
			current = nil
			continue
		case strings.Contains(line, "=================END"):
			current = nil
			goto done
		}
		if idx := strings.Index(line, "VarName "); idx != -1 {
			segment := line[idx:]
			if !inOtherInfo {
				if match := CustomPrimaryVarRegexp.FindStringSubmatch(segment); match != nil {
					entry := &CustomDataRaceEntry{
						VarName:   match[1],
						BlockLine: match[2],
						IsWrite:   match[3],
						Primary:   true,
					}
					info.Entries = append(info.Entries, entry)
					current = entry
					continue
				}
			} else if match := CustomOtherVarRegexp.FindStringSubmatch(segment); match != nil {
				entry := &CustomDataRaceEntry{
					VarName:   match[1],
					BlockLine: match[2],
				}
				info.Entries = append(info.Entries, entry)
				info.Watchpoint = match[3]
				current = entry
				continue
			}
		}
		if current != nil {
			if idx := strings.Index(line, "Function:"); idx != -1 {
				fn := strings.TrimSpace(line[idx+len("Function:"):])
				if fn != "" {
					current.Stack = append(current.Stack, fn)
				}
			}
		}
	}
done:
	if len(info.Entries) == 0 {
		return nil
	}
	return info
}

func regexpMustCompile(expr string) *regexp.Regexp {
	re, err := regexp.Compile(expr)
	if err != nil {
		panic(err)
	}
	return re
}
