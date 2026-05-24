package fuzzer

import (
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/stretchr/testify/require"
)

func getLinuxTarget(t *testing.T) *prog.Target {
	t.Helper()
	target, err := prog.GetTarget("linux", "amd64")
	require.NoError(t, err)
	return target
}

func deserializeProg(t *testing.T, target *prog.Target, text string) *prog.Prog {
	t.Helper()
	p, err := target.Deserialize([]byte(text), prog.NonStrict)
	require.NoError(t, err)
	return p
}

func TestLinkProgramsV2KccwfLegacyDataFamilyStillHandlesFixedPaths(t *testing.T) {
	target := getLinuxTarget(t)
	prog1 := deserializeProg(t, target, "open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', 0x0, 0x0)")
	prog2 := deserializeProg(t, target, "stat$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', &(0x7f0000000040))")

	ol := NewObjectLinker()
	linked := ol.LinkProgramsV2(prog1, prog2)
	dataArg := findDataArg(linked.Calls[0].Args[0])
	require.NotNil(t, dataArg)
	require.Equal(t, "/mnt/kccwf/testfile#", trimNullBytes(dataArg.Data()))
	_, successes, _ := ol.GetStats()
	require.Equal(t, 0, successes)
}

func TestLinkProgramsV2KccwfAlignsIsolatedPartnerPath(t *testing.T) {
	target := getLinuxTarget(t)
	prog1 := deserializeProg(t, target, "open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', 0x0, 0x0)")
	prog2 := deserializeProg(t, target, "stat$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', &(0x7f0000000040))")
	applyKccwfPartnerNamespace(prog2, 1)

	ol := NewObjectLinker()
	linked := ol.LinkProgramsV2(prog1, prog2)
	dataArg := findDataArg(linked.Calls[0].Args[0])
	require.NotNil(t, dataArg)
	require.Equal(t, "/mnt/kccwf/testfile#", trimNullBytes(dataArg.Data()))

	_, successes, _ := ol.GetStats()
	require.Equal(t, 1, successes)
}

func TestLinkProgramsV2KccwfPrefersCrossOperationOverSameRead(t *testing.T) {
	target := getLinuxTarget(t)
	prog1 := deserializeProg(t, target, `
open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile1\x00', 0x0, 0x0)
stat$kccwf(&(0x7f0000000040)='/mnt/kccwf/testfile3\x00', &(0x7f0000000080))
`)
	prog2 := deserializeProg(t, target, "stat$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile3\\x00', &(0x7f0000000040))")
	applyKccwfPartnerNamespace(prog2, 1)

	ol := NewObjectLinker()
	linked := ol.LinkProgramsV2(prog1, prog2)
	dataArg := findDataArg(linked.Calls[0].Args[0])
	require.NotNil(t, dataArg)
	require.Equal(t, "/mnt/kccwf/testfile1", trimNullBytes(dataArg.Data()))
}

func TestLinkProgramsV2KccwfLimitsSemanticRewriteBudget(t *testing.T) {
	target := getLinuxTarget(t)
	prog1 := deserializeProg(t, target, "open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', 0x0, 0x0)")
	prog2 := deserializeProg(t, target, `
stat$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile1\x00', &(0x7f0000000040))
chmod$kccwf(&(0x7f0000000080)='/mnt/kccwf/testfile2\x00', 0x0)
chown$kccwf(&(0x7f00000000c0)='/mnt/kccwf/testfile3\x00', 0x0, 0x0)
`)
	applyKccwfPartnerNamespace(prog2, 1)

	ol := NewObjectLinker()
	linked := ol.LinkProgramsV2(prog1, prog2)

	rewritten := 0
	for _, call := range linked.Calls {
		dataArg := findDataArg(call.Args[0])
		require.NotNil(t, dataArg)
		if trimNullBytes(dataArg.Data()) == "/mnt/kccwf/testfile#" {
			rewritten++
		}
	}
	require.Equal(t, 2, rewritten)
}

func TestLinkProgramsV2KccwfPrioritizesEffectfulTargetsOverOpen(t *testing.T) {
	target := getLinuxTarget(t)
	prog1 := deserializeProg(t, target, `
open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile1\x00', 0x0, 0x0)
stat$kccwf(&(0x7f0000000040)='/mnt/kccwf/testfile2\x00', &(0x7f0000000080))
`)
	prog2 := deserializeProg(t, target, `
open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile1\x00', 0x0, 0x0)
chmod$kccwf(&(0x7f0000000040)='/mnt/kccwf/testfile2\x00', 0x0)
truncate$kccwf(&(0x7f0000000080)='/mnt/kccwf/testfile3\x00', 0x0)
`)
	applyKccwfPartnerNamespace(prog2, 1)

	linked := NewObjectLinker().LinkProgramsV2(prog1, prog2)

	openArg := findDataArg(linked.Calls[0].Args[0])
	chmodArg := findDataArg(linked.Calls[1].Args[0])
	truncateArg := findDataArg(linked.Calls[2].Args[0])
	require.NotNil(t, openArg)
	require.NotNil(t, chmodArg)
	require.NotNil(t, truncateArg)

	require.Equal(t, "/mnt/kccwf/file11xxx", trimNullBytes(openArg.Data()))
	require.Equal(t, "/mnt/kccwf/testfile2", trimNullBytes(chmodArg.Data()))
	require.Equal(t, "/mnt/kccwf/testfile1", trimNullBytes(truncateArg.Data()))
}

func TestLinkProgramsV2KccwfSkipsPureOpenOnlyPair(t *testing.T) {
	target := getLinuxTarget(t)
	prog1 := deserializeProg(t, target, "open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', 0x0, 0x0)")
	prog2 := deserializeProg(t, target, "open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', 0x0, 0x0)")
	applyKccwfPartnerNamespace(prog2, 1)

	ol := NewObjectLinker()
	linked := ol.LinkProgramsV2(prog1, prog2)
	dataArg := findDataArg(linked.Calls[0].Args[0])
	require.NotNil(t, dataArg)
	require.Equal(t, "/mnt/kccwf/file10xxx", trimNullBytes(dataArg.Data()))

	_, successes, _ := ol.GetStats()
	require.Equal(t, 0, successes)
}

func TestLinkProgramsV2KccwfSkipsNamespaceLifecycleOps(t *testing.T) {
	target := getLinuxTarget(t)
	prog1 := deserializeProg(t, target, "open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', 0x0, 0x0)")
	prog2 := deserializeProg(t, target, "unlink$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00')")
	applyKccwfPartnerNamespace(prog2, 1)

	ol := NewObjectLinker()
	linked := ol.LinkProgramsV2(prog1, prog2)
	dataArg := findDataArg(linked.Calls[0].Args[0])
	require.NotNil(t, dataArg)
	require.Equal(t, "/mnt/kccwf/file10xxx", trimNullBytes(dataArg.Data()))

	_, successes, _ := ol.GetStats()
	require.Equal(t, 0, successes)
}

func TestLinkProgramsV2KccwfSkipsSameMetadataOperationPair(t *testing.T) {
	target := getLinuxTarget(t)
	prog1 := deserializeProg(t, target, "chmod$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', 0x0)")
	prog2 := deserializeProg(t, target, "setxattr$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', &(0x7f0000000040)='user.a\\x00', &(0x7f0000000080)='b\\x00', 0x1, 0x0)")
	applyKccwfPartnerNamespace(prog2, 1)

	ol := NewObjectLinker()
	linked := ol.LinkProgramsV2(prog1, prog2)
	dataArg := findDataArg(linked.Calls[0].Args[0])
	require.NotNil(t, dataArg)
	require.Equal(t, "/mnt/kccwf/file10xxx", trimNullBytes(dataArg.Data()))

	_, successes, _ := ol.GetStats()
	require.Equal(t, 0, successes)
}

func TestLinkProgramsV2KccwfKeepsOpenPairWithFdEffects(t *testing.T) {
	target := getLinuxTarget(t)
	prog1 := deserializeProg(t, target, `
r0 = open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\x00', 0x2, 0x0)
write$kccwf(r0, &(0x7f0000000040)="41", 0x1)
`)
	prog2 := deserializeProg(t, target, `
r0 = open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\x00', 0x2, 0x0)
write$kccwf(r0, &(0x7f0000000040)="42", 0x1)
`)
	applyKccwfPartnerNamespace(prog2, 1)

	ol := NewObjectLinker()
	linked := ol.LinkProgramsV2(prog1, prog2)
	dataArg := findDataArg(linked.Calls[0].Args[0])
	require.NotNil(t, dataArg)
	require.Equal(t, "/mnt/kccwf/testfile#", trimNullBytes(dataArg.Data()))

	_, successes, _ := ol.GetStats()
	require.Equal(t, 1, successes)
}

func TestSemanticPartnerSelectionPrefersFdEffectContext(t *testing.T) {
	target := getLinuxTarget(t)
	source := deserializeProg(t, target, `
r0 = open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\x00', 0x2, 0x0)
write$kccwf(r0, &(0x7f0000000040)="41", 0x1)
`)
	openOnly := deserializeProg(t, target, "open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', 0x0, 0x0)")
	withFdEffect := deserializeProg(t, target, `
r0 = open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\x00', 0x2, 0x0)
write$kccwf(r0, &(0x7f0000000040)="42", 0x1)
`)
	applyKccwfPartnerNamespace(openOnly, 1)
	applyKccwfPartnerNamespace(withFdEffect, 1)

	sourceRefs := extractSemanticObjectRefs(source)
	require.NotEmpty(t, sourceRefs)
	require.Greater(t,
		semanticPartnerSelectionScore(sourceRefs, extractSemanticObjectRefs(withFdEffect)),
		semanticPartnerSelectionScore(sourceRefs, extractSemanticObjectRefs(openOnly)))
}

func TestLinkProgramsV2KccwfIsolationWithoutLinkerKeepsPartnerSeparate(t *testing.T) {
	target := getLinuxTarget(t)
	prog2 := deserializeProg(t, target, "stat$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', &(0x7f0000000040))")
	applyKccwfPartnerNamespace(prog2, 1)

	dataArg := findDataArg(prog2.Calls[0].Args[0])
	require.NotNil(t, dataArg)
	require.Equal(t, "/mnt/kccwf/file10xxx", trimNullBytes(dataArg.Data()))
}

func TestKccwfExpandedPathRoundTripsExplicitValue(t *testing.T) {
	target := getLinuxTarget(t)
	p := deserializeProg(t, target, "stat$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile3\\x00', &(0x7f0000000040))")

	serialized := p.Serialize()
	restored := deserializeProg(t, target, string(serialized))
	dataArg := findDataArg(restored.Calls[0].Args[0])
	require.NotNil(t, dataArg)
	require.Equal(t, "/mnt/kccwf/testfile3", trimNullBytes(dataArg.Data()))
	require.Contains(t, string(serialized), "/mnt/kccwf/testfile3")
}

func TestLinkProgramsV2DspFamilyNoLongerUsesGenericPathRewrite(t *testing.T) {
	target := getLinuxTarget(t)
	prog1 := deserializeProg(t, target, "openat$dsp(0xffffffffffffff9c, &(0x7f0000000000), 0x0, 0x0)")
	prog2 := deserializeProg(t, target, "openat$audio(0xffffffffffffff9c, &(0x7f0000000000), 0x0, 0x0)")

	ol := NewObjectLinker()
	linked := ol.LinkProgramsV2(prog1, prog2)
	dataArg := findDataArg(linked.Calls[0].Args[1])
	require.NotNil(t, dataArg)
	require.Equal(t, "/dev/audio", trimNullBytes(dataArg.Data()))

	_, successes, _ := ol.GetStats()
	require.Equal(t, 0, successes)
}

func TestLinkProgramsV2BsdPtyRewriteDisabled(t *testing.T) {
	target := getLinuxTarget(t)
	prog1 := deserializeProg(t, target, "syz_open_dev$ptys(0xc, 0x3, 0x1)")
	prog2 := deserializeProg(t, target, "syz_open_dev$ttys(0xc, 0x2, 0x0)")

	ol := NewObjectLinker()
	linked := ol.LinkProgramsV2(prog1, prog2)
	minor := findConstArg(linked.Calls[0].Args[2])
	require.NotNil(t, minor)
	require.Equal(t, uint64(0), minor.Val)

	_, successes, _ := ol.GetStats()
	require.Equal(t, 0, successes)
}
