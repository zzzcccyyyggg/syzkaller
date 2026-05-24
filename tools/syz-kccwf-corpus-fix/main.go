// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	var (
		flagOS   = flag.String("os", runtime.GOOS, "target OS")
		flagArch = flag.String("arch", runtime.GOARCH, "target arch")
		flagDB   = flag.String("db", "", "corpus.db path to rewrite in place")
	)
	flag.Parse()
	if *flagDB == "" {
		tool.Failf("missing -db")
	}

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		tool.Failf("failed to find target: %v", err)
	}
	corpusDB, err := db.Open(*flagDB, false)
	if err != nil {
		tool.Failf("failed to open corpus db: %v", err)
	}

	var records []db.Record
	var progs, fixedProgs, fixedArgs int
	for _, rec := range corpusDB.Records {
		p, err := target.Deserialize(rec.Val, prog.NonStrict)
		if err != nil {
			tool.Failf("failed to deserialize corpus program: %v\n%s", err, rec.Val)
		}
		progs++
		if n := fixProg(p); n != 0 {
			fixedProgs++
			fixedArgs += n
		}
		records = append(records, db.Record{Val: p.Serialize(), Seq: rec.Seq})
	}

	tmp := *flagDB + ".tmp-kccwf-fix"
	if err := db.Create(tmp, corpusDB.Version, records); err != nil {
		tool.Failf("failed to create fixed corpus db: %v", err)
	}
	if err := os.Rename(tmp, *flagDB); err != nil {
		tool.Failf("failed to replace corpus db: %v", err)
	}
	fmt.Printf("kccwf corpus fix: db=%s progs=%d fixed_progs=%d fixed_args=%d records=%d\n",
		*flagDB, progs, fixedProgs, fixedArgs, len(records))
}

func fixProg(p *prog.Prog) int {
	var fixed int
	for _, call := range p.Calls {
		if call == nil || call.Meta == nil || !strings.Contains(call.Meta.Name, "$kccwf") {
			continue
		}
		prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
			data, ok := arg.(*prog.DataArg)
			if !ok || data.Dir() == prog.DirOut || !isZeroData(data.Data()) {
				return
			}
			typ, ok := data.Type().(*prog.BufferType)
			if !ok || typ.Kind != prog.BufferString || len(typ.Values) == 0 {
				return
			}
			value := typ.Values[0]
			if !isKccwfStringValue(value) {
				return
			}
			data.SetData([]byte(value))
			fixed++
		})
	}
	return fixed
}

func isZeroData(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func isKccwfStringValue(value string) bool {
	return value == "/mnt/kccwf" ||
		strings.HasPrefix(value, "/mnt/kccwf/") ||
		strings.HasPrefix(value, "testfile")
}
