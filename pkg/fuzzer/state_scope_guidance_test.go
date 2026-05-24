// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStateScopeScoresGlobalInteraction(t *testing.T) {
	target := getLinuxTarget(t)
	local := deserializeProg(t, target, `
r0 = open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile1\x00', 0x2, 0x0)
write$kccwf(r0, &(0x7f0000000040)="41", 0x1)
`)
	global := deserializeProg(t, target, "sync$kccwf()")

	localFeatures := classifyStateScopeFeatures(local)
	globalFeatures := classifyStateScopeFeatures(global)

	require.Greater(t, stateScopeOperatorScore(stateScopeOperatorGlobal, localFeatures, globalFeatures), 0)
	require.Greater(t,
		stateScopeOperatorScore(stateScopeOperatorGlobal, localFeatures, globalFeatures),
		stateScopeOperatorScore(stateScopeOperatorContainer, localFeatures, globalFeatures))
}

func TestStateScopeScoresRelationInteraction(t *testing.T) {
	target := getLinuxTarget(t)
	local := deserializeProg(t, target, "stat$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile1\\x00', &(0x7f0000000040))")
	relation := deserializeProg(t, target, "symlink$kccwf(&(0x7f0000000000)='/mnt/kccwf/target_%d\\x00', &(0x7f0000000040)='/mnt/kccwf/symlink#\\x00')")

	localFeatures := classifyStateScopeFeatures(local)
	relationFeatures := classifyStateScopeFeatures(relation)

	require.Greater(t, stateScopeOperatorScore(stateScopeOperatorRelation, localFeatures, relationFeatures), 0)
	require.Greater(t,
		stateScopeOperatorScore(stateScopeOperatorRelation, localFeatures, relationFeatures),
		stateScopeOperatorScore(stateScopeOperatorContainer, localFeatures, relationFeatures))
}

func TestStateScopeScoresSameInstanceAsBudgetedOperator(t *testing.T) {
	target := getLinuxTarget(t)
	source := deserializeProg(t, target, `
r0 = open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\x00', 0x2, 0x0)
write$kccwf(r0, &(0x7f0000000040)="41", 0x1)
`)
	targetProg := deserializeProg(t, target, `
r0 = open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\x00', 0x2, 0x0)
write$kccwf(r0, &(0x7f0000000040)="42", 0x1)
`)
	applyKccwfPartnerNamespace(targetProg, 1)

	sourceFeatures := classifyStateScopeFeatures(source)
	targetFeatures := classifyStateScopeFeatures(targetProg)

	require.Greater(t, stateScopeOperatorScore(stateScopeOperatorSameInstance, sourceFeatures, targetFeatures), 0)
	require.Equal(t, []stateScopeOperator{
		stateScopeOperatorRelation,
		stateScopeOperatorContainer,
		stateScopeOperatorGlobal,
	}, stateScopeOperatorOrder(nil, 0))
}

func TestNormalizeStateScopeConfig(t *testing.T) {
	require.Equal(t, 1.0, normalizeStateScopeGuidanceRatio(0))
	require.Equal(t, 1.0, normalizeStateScopeGuidanceRatio(-0.1))
	require.Equal(t, 1.0, normalizeStateScopeGuidanceRatio(1.5))
	require.Equal(t, 0.25, normalizeStateScopeGuidanceRatio(0.25))

	require.Equal(t, 0.0, normalizeStateScopeSameInstanceRatio(0))
	require.Equal(t, 0.0, normalizeStateScopeSameInstanceRatio(-0.1))
	require.Equal(t, 0.0, normalizeStateScopeSameInstanceRatio(1.5))
	require.Equal(t, 0.2, normalizeStateScopeSameInstanceRatio(0.2))

	require.Equal(t, defaultStateScopePartnerSamples, normalizeStateScopePartnerSamples(0))
	require.Equal(t, 32, normalizeStateScopePartnerSamples(32))
	require.Equal(t, 256, normalizeStateScopePartnerSamples(300))
}
