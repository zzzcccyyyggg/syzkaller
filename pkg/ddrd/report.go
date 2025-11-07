// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ddrd

import "github.com/google/syzkaller/pkg/flatrpc"

// Report contains DDRD analysis data extracted from executor results.
type Report struct {
	UAFPairs []*MayUAFPair
	Extended []*ExtendedUAFPair
}

// FromProgInfo extracts DDRD data from ProgInfo if present.
func FromProgInfo(info *flatrpc.ProgInfo) *Report {
	if info == nil {
		return nil
	}
	return ReportFromRaw(info.Ddrd)
}

// ReportFromRaw converts FlatBuffers DDRD payload into a typed Report.
func ReportFromRaw(raw *flatrpc.DdrdRawT) *Report {
	if raw == nil {
		return nil
	}
	report := &Report{}
	if len(raw.UafPairs) != 0 {
		report.UAFPairs = make([]*MayUAFPair, 0, len(raw.UafPairs))
		for _, pair := range raw.UafPairs {
			converted := convertUAFPair(pair)
			if converted == nil {
				continue
			}
			report.UAFPairs = append(report.UAFPairs, converted)
		}
	}
	if len(raw.ExtendedUaf) != 0 {
		report.Extended = make([]*ExtendedUAFPair, 0, len(raw.ExtendedUaf))
		for _, pair := range raw.ExtendedUaf {
			converted := convertExtended(pair)
			if converted == nil {
				continue
			}
			report.Extended = append(report.Extended, converted)
		}
	}
	if len(report.UAFPairs) == 0 && len(report.Extended) == 0 {
		return nil
	}
	return report
}

func convertUAFPair(pair *flatrpc.DdrdUafPairRawT) *MayUAFPair {
	if pair == nil {
		return nil
	}
	return &MayUAFPair{
		FreeAccessName: pair.FreeAccessName,
		UseAccessName:  pair.UseAccessName,
		FreeCallStack:  pair.FreeCallStack,
		UseCallStack:   pair.UseCallStack,
		Signal:         pair.Signal,
		TimeDiff:       pair.TimeDiff,
		FreeSN:         pair.FreeSn,
		UseSN:          pair.UseSn,
		LockType:       pair.LockType,
		UseAccessType:  pair.UseAccessType,
	}
}

func convertExtended(pair *flatrpc.DdrdExtendedUafPairRawT) *ExtendedUAFPair {
	if pair == nil {
		return nil
	}
	ret := &ExtendedUAFPair{
		UseThreadHistoryCount:  pair.UseThreadHistoryCount,
		FreeThreadHistoryCount: pair.FreeThreadHistoryCount,
		UseTargetTime:          pair.UseTargetTime,
		FreeTargetTime:         pair.FreeTargetTime,
		PathDistanceUse:        pair.PathDistanceUse,
		PathDistanceFree:       pair.PathDistanceFree,
	}
	if basic := convertUAFPair(pair.Basic); basic != nil {
		ret.BasicInfo = *basic
	}
	if len(pair.AccessHistory) != 0 {
		ret.AccessHistory = make([]SerializedAccessRecord, 0, len(pair.AccessHistory))
		for _, entry := range pair.AccessHistory {
			if entry == nil {
				continue
			}
			ret.AccessHistory = append(ret.AccessHistory, SerializedAccessRecord{
				VarName:       entry.VarName,
				CallStackHash: entry.CallStackHash,
				AccessTime:    entry.AccessTime,
				SN:            entry.Sn,
				AccessType:    entry.AccessType,
			})
		}
	}
	return ret
}

// Clone returns a deep copy of the report.
func (r *Report) Clone() *Report {
	if r == nil {
		return nil
	}
	clone := &Report{}
	if len(r.UAFPairs) != 0 {
		clone.UAFPairs = make([]*MayUAFPair, 0, len(r.UAFPairs))
		for _, pair := range r.UAFPairs {
			if pair == nil {
				continue
			}
			copyPair := *pair
			clone.UAFPairs = append(clone.UAFPairs, &copyPair)
		}
	}
	if len(r.Extended) != 0 {
		clone.Extended = make([]*ExtendedUAFPair, 0, len(r.Extended))
		for _, ext := range r.Extended {
			if ext == nil {
				continue
			}
			copyExt := *ext
			if len(ext.AccessHistory) != 0 {
				copyExt.AccessHistory = append([]SerializedAccessRecord{}, ext.AccessHistory...)
			}
			clone.Extended = append(clone.Extended, &copyExt)
		}
	}
	if len(clone.UAFPairs) == 0 && len(clone.Extended) == 0 {
		return nil
	}
	return clone
}
