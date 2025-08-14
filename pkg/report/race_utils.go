package report

import (
	"fmt"
	"strings"
)

// GetReportedRaces returns a summary of all races reported in this crash report
func (r *Report) GetReportedRaces() []ReportedRace {
	return r.ReportedRaces
}

// GetRaceVarNames returns all VarNames involved in reported races
func (r *Report) GetRaceVarNames() []string {
	var varNames []string
	for _, race := range r.ReportedRaces {
		if race.VarName1 != "" {
			varNames = append(varNames, race.VarName1)
		}
		if race.VarName2 != "" && race.VarName2 != race.VarName1 {
			varNames = append(varNames, race.VarName2)
		}
	}
	return varNames
}

// FormatRacesSummary returns a human-readable summary of all reported races
func (r *Report) FormatRacesSummary() string {
	if len(r.ReportedRaces) == 0 {
		return "No reported races"
	}

	var summaries []string
	for i, race := range r.ReportedRaces {
		summary := fmt.Sprintf("Race %d: VarName1=%s (line %d, write=%v)",
			i+1, race.VarName1, race.BlockLineNumber1, race.IsWrite1)

		if race.VarName2 != "" {
			summary += fmt.Sprintf(", VarName2=%s (line %d)",
				race.VarName2, race.BlockLineNumber2)
		}

		if race.WatchpointIndex > 0 {
			summary += fmt.Sprintf(", watchpoint=%d", race.WatchpointIndex)
		}

		summaries = append(summaries, summary)
	}

	return strings.Join(summaries, "\n")
}

// IsDataRaceReport returns true if this report contains custom datarace information
func (r *Report) IsDataRaceReport() bool {
	return len(r.ReportedRaces) > 0
}
