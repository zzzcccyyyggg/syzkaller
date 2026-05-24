// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import "github.com/google/syzkaller/prog"

type objectDomain string

const (
	objectDomainFS objectDomain = "fs"
)

type objectKind string

const (
	objectKindFSFile     objectKind = "fs_file"
	objectKindFSDir      objectKind = "fs_dir"
	objectKindFSHardlink objectKind = "fs_hardlink"
	objectKindFSSymlink  objectKind = "fs_symlink"
	objectKindFSTarget   objectKind = "fs_target"
)

type objectOperation string

const (
	objectOpOpen          objectOperation = "open"
	objectOpMetadataRead  objectOperation = "metadata_read"
	objectOpMetadataWrite objectOperation = "metadata_write"
	objectOpDataMutate    objectOperation = "data_mutate"
)

type semanticObjectRef struct {
	Domain       objectDomain
	Kind         objectKind
	Scope        string
	Identity     string
	RelPath      string
	PoolIndex    string
	Operation    objectOperation
	SyscallName  string
	CallIndex    int
	ArgIndex     int
	DataArg      *prog.DataArg
	Relative     bool
	Rewritable   bool
	Confidence   int
	ContextScore int
	Debug        string
}

func (ref semanticObjectRef) key() string {
	return string(ref.Domain) + ":" + string(ref.Kind) + ":" + ref.Scope + ":" + ref.Identity
}
