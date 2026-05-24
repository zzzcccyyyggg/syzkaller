// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/google/syzkaller/prog"
)

const kccwfNamespaceSlotAlphabet = "123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func applyKccwfPartnerNamespace(p *prog.Prog, slot int) *prog.Prog {
	if p == nil {
		return nil
	}
	tag := kccwfNamespaceSlotChar(slot)
	for _, call := range p.Calls {
		if call == nil {
			continue
		}
		for _, arg := range call.Args {
			rewriteKccwfArgNamespace(arg, tag)
		}
	}
	return p
}

func rewriteKccwfArgNamespace(arg prog.Arg, tag string) {
	if arg == nil {
		return
	}
	switch a := arg.(type) {
	case *prog.DataArg:
		rewriteKccwfDataArg(a, tag)
	case *prog.PointerArg:
		if a.Res != nil {
			rewriteKccwfArgNamespace(a.Res, tag)
		}
	case *prog.GroupArg:
		for _, inner := range a.Inner {
			rewriteKccwfArgNamespace(inner, tag)
		}
	case *prog.UnionArg:
		if a.Option != nil {
			rewriteKccwfArgNamespace(a.Option, tag)
		}
	}
}

func rewriteKccwfDataArg(arg *prog.DataArg, tag string) {
	if arg == nil {
		return
	}
	if arg.Dir() == prog.DirOut {
		return
	}
	data := arg.Data()
	if len(data) == 0 {
		return
	}
	hasNull := data[len(data)-1] == 0
	raw := string(bytesTrimTrailingNull(data))
	rewrite := rewriteKccwfPath(raw, tag)
	if rewrite == raw {
		return
	}
	if hasNull {
		rewrite += "\x00"
	}
	arg.SetData([]byte(rewrite))
}

func rewriteKccwfPath(path string, tag string) string {
	if tag == "" {
		return path
	}
	const mountPrefix = "/mnt/kccwf/"
	if strings.HasPrefix(path, mountPrefix) {
		if rewritten, ok := rewriteKccwfName(path[len(mountPrefix):], tag); ok {
			return mountPrefix + rewritten
		}
		return path
	}
	if rewritten, ok := rewriteKccwfName(path, tag); ok {
		return rewritten
	}
	return path
}

func rewriteKccwfName(name string, tag string) (string, bool) {
	if idx, ok := kccwfNumberedNameIndex(name, "testfile", false); ok {
		return namespaceKccwfName("file", tag, idx, len(name)), true
	}
	if name == "testfile" {
		return namespaceKccwfName("file", tag, "0", len(name)), true
	}
	if idx, ok := kccwfNumberedNameIndex(name, "hardlink", false); ok {
		return namespaceKccwfName("hard", tag, idx, len(name)), true
	}
	if idx, ok := kccwfNumberedNameIndex(name, "symlink", false); ok {
		return namespaceKccwfName("sym", tag, idx, len(name)), true
	}
	if idx, ok := kccwfDirNameIndex(name); ok {
		return namespaceKccwfName("dir", tag, idx, len(name)), true
	}
	if idx, ok := kccwfTargetNameIndex(name); ok {
		baseLen := len(name) - len("%d")
		return namespaceKccwfName("tgt", tag, idx, baseLen) + "%d", true
	}
	return "", false
}

func namespaceKccwfName(prefix, tag, idx string, totalLen int) string {
	base := fmt.Sprintf("%s%s%s", prefix, tag, idx)
	if len(base) >= totalLen {
		return base[:totalLen]
	}
	return base + strings.Repeat("x", totalLen-len(base))
}

func kccwfNumberedNameIndex(name, prefix string, _ bool) (string, bool) {
	if name == prefix+"#" {
		return "0", true
	}
	if len(name) == len(prefix)+1 && strings.HasPrefix(name, prefix) && isKccwfDigit(name[len(prefix)]) {
		return name[len(prefix):], true
	}
	return "", false
}

func kccwfDirNameIndex(name string) (string, bool) {
	if name == "testdir" {
		return "0", true
	}
	const prefix = "testdi"
	if len(name) == len(prefix)+1 && strings.HasPrefix(name, prefix) && isKccwfDigit(name[len(prefix)]) {
		return name[len(prefix):], true
	}
	return "", false
}

func kccwfTargetNameIndex(name string) (string, bool) {
	if name == "target_%d" {
		return "0", true
	}
	const prefix = "target"
	const suffix = "%d"
	if len(name) == len(prefix)+1+len(suffix) &&
		strings.HasPrefix(name, prefix) &&
		strings.HasSuffix(name, suffix) &&
		isKccwfDigit(name[len(prefix)]) {
		return name[len(prefix) : len(prefix)+1], true
	}
	return "", false
}

func isKccwfDigit(ch byte) bool {
	return ch >= '1' && ch <= '9'
}

func kccwfNamespaceSlotChar(slot int) string {
	if slot <= 0 {
		slot = 1
	}
	return kccwfNamespaceSlotAlphabet[(slot-1)%len(kccwfNamespaceSlotAlphabet) : (slot-1)%len(kccwfNamespaceSlotAlphabet)+1]
}

func randomKccwfNamespaceSlot(rnd *rand.Rand) int {
	if rnd == nil {
		return 1
	}
	return rnd.Intn(len(kccwfNamespaceSlotAlphabet)) + 1
}

func bytesTrimTrailingNull(data []byte) []byte {
	end := len(data)
	for end > 0 && data[end-1] == 0 {
		end--
	}
	return data[:end]
}
