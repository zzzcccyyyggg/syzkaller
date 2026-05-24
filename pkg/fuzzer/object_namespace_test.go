package fuzzer

import (
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/assert"
)

func TestRewriteKccwfPath(t *testing.T) {
	tag := "1"
	assert.Equal(t, "/mnt/kccwf/file10xxx", rewriteKccwfPath("/mnt/kccwf/testfile#", tag))
	assert.Equal(t, "file10xx", rewriteKccwfPath("testfile", tag))
	assert.Equal(t, "file10xxx", rewriteKccwfPath("testfile#", tag))
	assert.Equal(t, "/mnt/kccwf/hard10xxx", rewriteKccwfPath("/mnt/kccwf/hardlink#", tag))
	assert.Equal(t, "/mnt/kccwf/sym10xxx", rewriteKccwfPath("/mnt/kccwf/symlink#", tag))
	assert.Equal(t, "/mnt/kccwf/tgt10xx%d", rewriteKccwfPath("/mnt/kccwf/target_%d", tag))
	assert.Equal(t, "/mnt/kccwf/dir10xx", rewriteKccwfPath("/mnt/kccwf/testdir", tag))
	assert.Equal(t, "/mnt/kccwf", rewriteKccwfPath("/mnt/kccwf", tag))
}

func TestRewriteKccwfPathIsolatesAllPoolValues(t *testing.T) {
	tag := "a"
	assert.Equal(t, "/mnt/kccwf/filea3xxx", rewriteKccwfPath("/mnt/kccwf/testfile3", tag))
	assert.Equal(t, "filea9xxx", rewriteKccwfPath("testfile9", tag))
	assert.Equal(t, "/mnt/kccwf/harda4xxx", rewriteKccwfPath("/mnt/kccwf/hardlink4", tag))
	assert.Equal(t, "/mnt/kccwf/syma5xxx", rewriteKccwfPath("/mnt/kccwf/symlink5", tag))
	assert.Equal(t, "/mnt/kccwf/dira0xx", rewriteKccwfPath("/mnt/kccwf/testdir", tag))
	assert.Equal(t, "/mnt/kccwf/dira7xx", rewriteKccwfPath("/mnt/kccwf/testdi7", tag))
	assert.Equal(t, "/mnt/kccwf/tgta8xx%d", rewriteKccwfPath("/mnt/kccwf/target8%d", tag))
}

func TestRewriteKccwfPathSkipsAlreadyIsolatedNames(t *testing.T) {
	assert.Equal(t, "/mnt/kccwf/file13xxx", rewriteKccwfPath("/mnt/kccwf/file13xxx", "2"))
	assert.Equal(t, "file13xxx", rewriteKccwfPath("file13xxx", "2"))
}

func TestRewriteKccwfDataArgSkipsOutputArg(t *testing.T) {
	target, err := getTestTarget()
	if err != nil {
		t.Fatalf("get test target: %v", err)
	}
	typ := target.SyscallMap["serialize3"].Args[0].Type.(*prog.PtrType).Elem.(*prog.BufferType)
	out := typ.DefaultArg(prog.DirOut).(*prog.DataArg)

	assert.NotPanics(t, func() {
		rewriteKccwfDataArg(out, "1")
	})
}

func TestApplyKccwfPartnerNamespace(t *testing.T) {
	target := getLinuxTarget(t)
	p := deserializeProg(t, target, "stat$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', &(0x7f0000000040))")

	applyKccwfPartnerNamespace(p, 1)

	dataArg := findDataArg(p.Calls[0].Args[0])
	assert.NotNil(t, dataArg)
	assert.Equal(t, "/mnt/kccwf/file10xxx", trimNullBytes(dataArg.Data()))
}
