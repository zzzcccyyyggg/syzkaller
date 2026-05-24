// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"strings"

	"github.com/google/syzkaller/prog"
)

const kccwfMountPrefix = "/mnt/kccwf/"

type kccwfObjectSpec struct {
	Kind      objectKind
	PoolIndex string
	RelPath   string
}

var kccwfSemanticSyscalls = map[string]struct {
	argIndex  int
	relative  bool
	operation objectOperation
}{
	"open$kccwf":     {argIndex: 0, operation: objectOpOpen},
	"stat$kccwf":     {argIndex: 0, operation: objectOpMetadataRead},
	"chmod$kccwf":    {argIndex: 0, operation: objectOpMetadataWrite},
	"chown$kccwf":    {argIndex: 0, operation: objectOpMetadataWrite},
	"utimes$kccwf":   {argIndex: 0, operation: objectOpMetadataWrite},
	"truncate$kccwf": {argIndex: 0, operation: objectOpDataMutate},
	"setxattr$kccwf": {argIndex: 0, operation: objectOpMetadataWrite},

	// Relative kccwf calls are only linked within the same relative family. They
	// all use open$kccwf_dir("/mnt/kccwf"), so the mount scope is stable enough
	// for explicit short-run fs validation, but they are kept lower confidence
	// than absolute-path operations.
	"openat$kccwf":    {argIndex: 1, relative: true, operation: objectOpOpen},
	"faccessat$kccwf": {argIndex: 1, relative: true, operation: objectOpMetadataRead},
	"fchmodat$kccwf":  {argIndex: 1, relative: true, operation: objectOpMetadataWrite},
	"fchownat$kccwf":  {argIndex: 1, relative: true, operation: objectOpMetadataWrite},
	"fstatat$kccwf":   {argIndex: 1, relative: true, operation: objectOpMetadataRead},
	"statx$kccwf":     {argIndex: 1, relative: true, operation: objectOpMetadataRead},
	"futimesat$kccwf": {argIndex: 1, relative: true, operation: objectOpMetadataWrite},
	"utimensat$kccwf": {argIndex: 1, relative: true, operation: objectOpMetadataWrite},
}

func extractSemanticObjectRefs(p *prog.Prog) []semanticObjectRef {
	var refs []semanticObjectRef
	refs = append(refs, extractKccwfFSRefs(p)...)
	return refs
}

func extractKccwfFSRefs(p *prog.Prog) []semanticObjectRef {
	if p == nil {
		return nil
	}
	var refs []semanticObjectRef
	fdContextScores := kccwfFdEffectContextScores(p)
	for callIdx, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		info, ok := kccwfSemanticSyscalls[call.Meta.Name]
		if !ok || info.argIndex >= len(call.Args) {
			continue
		}
		dataArg := findDataArg(call.Args[info.argIndex])
		if dataArg == nil || len(dataArg.Data()) == 0 {
			continue
		}
		spec, ok := parseKccwfObjectPath(trimNullBytes(dataArg.Data()))
		if !ok {
			continue
		}
		identity := spec.RelPath
		if info.relative {
			identity = spec.RelPath
		}
		confidence := 100
		if info.relative {
			confidence = 70
		}
		refs = append(refs, semanticObjectRef{
			Domain:       objectDomainFS,
			Kind:         spec.Kind,
			Scope:        "/mnt/kccwf",
			Identity:     identity,
			RelPath:      spec.RelPath,
			PoolIndex:    spec.PoolIndex,
			Operation:    info.operation,
			SyscallName:  call.Meta.Name,
			CallIndex:    callIdx,
			ArgIndex:     info.argIndex,
			DataArg:      dataArg,
			Relative:     info.relative,
			Rewritable:   true,
			Confidence:   confidence,
			ContextScore: fdContextScores[callIdx],
			Debug:        trimNullBytes(dataArg.Data()),
		})
	}
	return refs
}

func kccwfFdEffectContextScores(p *prog.Prog) map[int]int {
	openReturns := make(map[*prog.ResultArg]int)
	for callIdx, call := range p.Calls {
		if call == nil || call.Meta == nil || call.Ret == nil {
			continue
		}
		info, ok := kccwfSemanticSyscalls[call.Meta.Name]
		if ok && info.operation == objectOpOpen {
			openReturns[call.Ret] = callIdx
		}
	}
	if len(openReturns) == 0 {
		return nil
	}

	contextScores := make(map[int]int)
	for _, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		score := kccwfFdEffectScore(call.Meta.Name)
		if score == 0 {
			continue
		}
		prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
			resultArg, ok := arg.(*prog.ResultArg)
			if !ok || resultArg.Res == nil {
				return
			}
			openCallIdx, ok := openReturns[resultArg.Res]
			if !ok {
				return
			}
			if score > contextScores[openCallIdx] {
				contextScores[openCallIdx] = score
			}
		})
	}
	return contextScores
}

func kccwfFdEffectScore(syscallName string) int {
	switch syscallName {
	case "write$kccwf", "pwrite64$kccwf", "writev$kccwf", "pwritev2$kccwf",
		"copy_file_range$kccwf", "splice$kccwf", "vmsplice$kccwf",
		"sendfile$kccwf", "sendfile64$kccwf", "fallocate$kccwf",
		"ftruncate$kccwf":
		return 140
	case "fsetxattr$kccwf", "fchmod$kccwf", "fchown$kccwf",
		"futimesat$kccwf", "utimensat$kccwf", "sync_file_range$kccwf":
		return 120
	case "read$kccwf", "pread64$kccwf", "readv$kccwf", "preadv$kccwf",
		"preadv2$kccwf", "readahead$kccwf", "fstat$kccwf",
		"fstat64$kccwf", "cachestat$kccwf", "fadvise64$kccwf",
		"fsync$kccwf", "fdatasync$kccwf", "syncfs$kccwf":
		return 80
	}
	if strings.HasPrefix(syscallName, "ioctl$") && strings.HasSuffix(syscallName, "$kccwf") {
		return 80
	}
	if strings.HasPrefix(syscallName, "fcntl$") && strings.HasSuffix(syscallName, "$kccwf") {
		return 80
	}
	return 0
}

func parseKccwfObjectPath(path string) (kccwfObjectSpec, bool) {
	if strings.HasPrefix(path, kccwfMountPrefix) {
		path = path[len(kccwfMountPrefix):]
	}
	if path == "" || path == "/mnt/kccwf" {
		return kccwfObjectSpec{}, false
	}
	if idx, ok := kccwfNumberedNameIndex(path, "testfile", false); ok {
		return kccwfObjectSpec{Kind: objectKindFSFile, PoolIndex: idx, RelPath: "testfile" + idx}, true
	}
	if path == "testfile" {
		return kccwfObjectSpec{Kind: objectKindFSFile, PoolIndex: "0", RelPath: "testfile0"}, true
	}
	if idx, ok := kccwfIsolatedNameIndex(path, "file", false); ok {
		return kccwfObjectSpec{Kind: objectKindFSFile, PoolIndex: idx, RelPath: "testfile" + idx}, true
	}
	if idx, ok := kccwfNumberedNameIndex(path, "file", false); ok {
		return kccwfObjectSpec{Kind: objectKindFSFile, PoolIndex: idx, RelPath: "testfile" + idx}, true
	}
	if idx, ok := kccwfNumberedNameIndex(path, "hardlink", false); ok {
		return kccwfObjectSpec{Kind: objectKindFSHardlink, PoolIndex: idx, RelPath: "hardlink" + idx}, true
	}
	if idx, ok := kccwfIsolatedNameIndex(path, "hard", false); ok {
		return kccwfObjectSpec{Kind: objectKindFSHardlink, PoolIndex: idx, RelPath: "hardlink" + idx}, true
	}
	if idx, ok := kccwfNumberedNameIndex(path, "hard", false); ok {
		return kccwfObjectSpec{Kind: objectKindFSHardlink, PoolIndex: idx, RelPath: "hardlink" + idx}, true
	}
	if idx, ok := kccwfNumberedNameIndex(path, "symlink", false); ok {
		return kccwfObjectSpec{Kind: objectKindFSSymlink, PoolIndex: idx, RelPath: "symlink" + idx}, true
	}
	if idx, ok := kccwfIsolatedNameIndex(path, "sym", false); ok {
		return kccwfObjectSpec{Kind: objectKindFSSymlink, PoolIndex: idx, RelPath: "symlink" + idx}, true
	}
	if idx, ok := kccwfNumberedNameIndex(path, "sym", false); ok {
		return kccwfObjectSpec{Kind: objectKindFSSymlink, PoolIndex: idx, RelPath: "symlink" + idx}, true
	}
	if idx, ok := kccwfDirNameIndex(path); ok {
		return kccwfObjectSpec{Kind: objectKindFSDir, PoolIndex: idx, RelPath: "testdir" + idx}, true
	}
	if idx, ok := kccwfIsolatedNameIndex(path, "dir", false); ok {
		return kccwfObjectSpec{Kind: objectKindFSDir, PoolIndex: idx, RelPath: "testdir" + idx}, true
	}
	if idx, ok := kccwfNumberedNameIndex(path, "dir", false); ok {
		return kccwfObjectSpec{Kind: objectKindFSDir, PoolIndex: idx, RelPath: "testdir" + idx}, true
	}
	if idx, ok := kccwfTargetNameIndex(path); ok {
		return kccwfObjectSpec{Kind: objectKindFSTarget, PoolIndex: idx, RelPath: "target" + idx}, true
	}
	if idx, ok := kccwfIsolatedNameIndex(path, "tgt", true); ok {
		return kccwfObjectSpec{Kind: objectKindFSTarget, PoolIndex: idx, RelPath: "target" + idx}, true
	}
	if idx, ok := kccwfNumberedNameIndex(strings.TrimSuffix(path, "%d"), "tgt", false); ok {
		return kccwfObjectSpec{Kind: objectKindFSTarget, PoolIndex: idx, RelPath: "target" + idx}, true
	}
	return kccwfObjectSpec{}, false
}

func kccwfIsolatedNameIndex(name, prefix string, hasFormat bool) (string, bool) {
	if hasFormat {
		if !strings.HasSuffix(name, "%d") {
			return "", false
		}
		name = strings.TrimSuffix(name, "%d")
	}
	if !strings.HasPrefix(name, prefix) || len(name) < len(prefix)+2 {
		return "", false
	}
	idx := name[len(prefix)+1]
	if !isKccwfPoolIndexByte(idx) {
		return "", false
	}
	for i := len(prefix) + 2; i < len(name); i++ {
		if name[i] != 'x' {
			return "", false
		}
	}
	return string(idx), true
}

func isKccwfPoolIndexByte(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

func rewriteSemanticObjectRef(target, source semanticObjectRef) bool {
	if !target.Rewritable || target.DataArg == nil || source.DataArg == nil {
		return false
	}
	if target.Domain != source.Domain || target.Kind != source.Kind {
		return false
	}
	if target.Relative != source.Relative {
		return false
	}
	if isUnsafePathForAlignment(source.DataArg.Data()) || isUnsafePathForAlignment(target.DataArg.Data()) {
		return false
	}
	if len(source.DataArg.Data()) != len(target.DataArg.Data()) {
		return false
	}
	if dataEqual(target.DataArg.Data(), source.DataArg.Data()) {
		return false
	}
	target.DataArg.SetData(source.DataArg.Data())
	return true
}

func semanticRefsBySyscall(refs []semanticObjectRef) map[string][]semanticObjectRef {
	byName := make(map[string][]semanticObjectRef)
	for _, ref := range refs {
		byName[ref.SyscallName] = append(byName[ref.SyscallName], ref)
	}
	return byName
}

func semanticRefsByFamily(refs []semanticObjectRef) map[string][]semanticObjectRef {
	byFamily := make(map[string][]semanticObjectRef)
	for _, ref := range refs {
		key := string(ref.Domain) + ":" + string(ref.Kind) + ":" + ref.Scope
		if ref.Relative {
			key += ":rel"
		} else {
			key += ":abs"
		}
		byFamily[key] = append(byFamily[key], ref)
	}
	return byFamily
}
