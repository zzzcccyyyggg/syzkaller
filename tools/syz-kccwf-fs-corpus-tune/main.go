package main

import (
	"flag"
	"fmt"
	"hash/crc32"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	var (
		flagIn     = flag.String("in", "", "input corpus.db")
		flagOut    = flag.String("out", "", "output tuned corpus.db")
		flagModule = flag.String("module", "", "module profile to tune (jfs, f2fs, xfs, btrfs)")
		flagMode   = flag.String("mode", "repair", "tuning mode: repair, lite, or dense")
		flagOS     = flag.String("os", "linux", "target OS")
		flagArch   = flag.String("arch", "amd64", "target arch")
	)
	flag.Parse()
	if *flagIn == "" || *flagOut == "" || *flagModule == "" {
		flag.Usage()
		os.Exit(2)
	}

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		tool.Failf("failed to get target: %v", err)
	}
	inDB, err := db.Open(*flagIn, false)
	if err != nil {
		tool.Failf("failed to open input corpus: %v", err)
	}

	records := make([]db.Record, 0, len(inDB.Records))
	seen := make(map[string]bool, len(inDB.Records))
	keys := make([]string, 0, len(inDB.Records))
	for key := range inDB.Records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	shapeCounts := make(map[string]int)
	var keptInput, repairedInput, droppedInput int
	for recIdx, key := range keys {
		rec := inDB.Records[key]
		data := rec.Val
		if *flagMode == "repair" {
			var changed, keep bool
			data, changed, keep = repairInputRecord(target, rec.Val, recIdx, shapeCounts, *flagModule)
			if !keep {
				droppedInput++
				continue
			}
			if changed {
				repairedInput++
			}
		}
		sig := hash.String(data)
		if seen[sig] {
			continue
		}
		records = append(records, db.Record{Val: data, Seq: rec.Seq})
		seen[sig] = true
		keptInput++
	}

	seedTexts := buildSeeds(*flagModule, *flagMode)
	if len(seedTexts) == 0 {
		tool.Failf("unknown module/mode profile: module=%s mode=%s", *flagModule, *flagMode)
	}
	added := 0
	for i, text := range seedTexts {
		p, err := target.Deserialize([]byte(text), prog.NonStrict)
		if err != nil {
			tool.Failf("failed to deserialize generated seed #%d:\n%s\n%v", i, text, err)
		}
		data := p.Serialize()
		sig := hash.String(data)
		if seen[sig] {
			continue
		}
		records = append(records, db.Record{Val: data})
		seen[sig] = true
		added++
	}
	if err := db.Create(*flagOut, inDB.Version, records); err != nil {
		tool.Failf("failed to create tuned corpus: %v", err)
	}
	fmt.Printf("kccwf fs corpus tune: module=%s mode=%s input_records=%d kept_input=%d repaired_input=%d dropped_input=%d generated=%d added=%d output_records=%d output=%s\n",
		*flagModule, *flagMode, len(inDB.Records), keptInput, repairedInput, droppedInput, len(seedTexts), added, len(seen), *flagOut)
}

func buildSeeds(module, mode string) []string {
	switch module {
	case "jfs":
		return buildJFSSeeds(mode)
	case "f2fs":
		return buildF2FSSeeds(mode)
	case "xfs":
		return buildXFSSeeds(mode)
	case "btrfs":
		return buildBTRFSSeeds(mode)
	default:
		return nil
	}
}

func buildJFSSeeds(mode string) []string {
	return buildSemanticFSSeeds(true, mode)
}

func buildF2FSSeeds(mode string) []string {
	return buildSemanticFSSeeds(false, mode)
}

func buildXFSSeeds(mode string) []string {
	return buildSemanticFSSeeds(true, mode)
}

func buildBTRFSSeeds(mode string) []string {
	return buildSemanticFSSeeds(false, mode)
}

func buildSemanticFSSeeds(preferRelative bool, mode string) []string {
	if mode == "repair" {
		return buildSemanticFSRepairSeeds(preferRelative)
	}
	if mode == "lite" {
		return buildSemanticFSLiteSeeds(preferRelative)
	}
	if mode != "dense" {
		return nil
	}
	var seeds []string
	for i := 0; i < 10; i++ {
		abs := kccwfAbsFile(i)
		rel := kccwfRelFile(i)
		seeds = append(seeds, absolutePathSeeds(abs)...)
		seeds = append(seeds, absoluteFdSeeds(abs)...)
		if preferRelative {
			seeds = append(seeds, relativePathSeeds(rel)...)
			seeds = append(seeds, relativeFdSeeds(rel)...)
		} else if i < 5 {
			seeds = append(seeds, relativePathSeeds(rel)...)
			seeds = append(seeds, relativeFdSeeds(rel)...)
		}
	}
	return seeds
}

func buildSemanticFSLiteSeeds(preferRelative bool) []string {
	var seeds []string
	for i := 0; i < 10; i++ {
		abs := kccwfAbsFile(i)
		rel := kccwfRelFile(i)
		if preferRelative {
			seeds = append(seeds, pickSeeds(relativePathSeeds(rel), 0, 1, 2, 4)...)
			seeds = append(seeds, pickSeeds(relativeFdSeeds(rel), 0, 2, 3, 4)...)
			if i < 5 {
				seeds = append(seeds, pickSeeds(absolutePathSeeds(abs), 0, 3)...)
				seeds = append(seeds, pickSeeds(absoluteFdSeeds(abs), 0, 3)...)
			}
		} else {
			seeds = append(seeds, pickSeeds(absolutePathSeeds(abs), 0, 1, 3, 4, 5)...)
			seeds = append(seeds, pickSeeds(absoluteFdSeeds(abs), 0, 2, 3, 4, 5)...)
		}
	}
	return seeds
}

func buildSemanticFSRepairSeeds(preferRelative bool) []string {
	seeds := buildSemanticFSLiteSeeds(preferRelative)
	for i := 0; i < 10; i++ {
		abs := kccwfAbsFile(i)
		nextAbs := kccwfAbsFile((i + 1) % 10)
		rel := kccwfRelFile(i)
		dir := kccwfAbsDir(i)
		hard := kccwfAbsHardlink(i)
		sym := kccwfAbsSymlink(i)
		target := kccwfAbsTarget(i)
		seeds = append(seeds,
			fmt.Sprintf("mkdir$kccwf(&(0x7f0000000000)='%s\\x00', 0x1ff)", dir),
			fmt.Sprintf("link$kccwf(&(0x7f0000000000)='%s\\x00', &(0x7f0000000040)='%s\\x00')", abs, hard),
			fmt.Sprintf("symlink$kccwf(&(0x7f0000000000)='%s\\x00', &(0x7f0000000040)='%s\\x00')", target, sym),
		)
		if preferRelative {
			seeds = append(seeds,
				fmt.Sprintf("mknodat$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x81a4, 0x0)", rel),
			)
		}
		if i < 4 {
			seeds = append(seeds,
				fmt.Sprintf("rename$kccwf(&(0x7f0000000000)='%s\\x00', &(0x7f0000000040)='%s\\x00')", abs, nextAbs),
			)
		}
	}
	return seeds
}

func pickSeeds(seeds []string, indexes ...int) []string {
	selected := make([]string, 0, len(indexes))
	for _, idx := range indexes {
		if idx >= 0 && idx < len(seeds) {
			selected = append(selected, seeds[idx])
		}
	}
	return selected
}

func absolutePathSeeds(path string) []string {
	return []string{
		fmt.Sprintf("stat$kccwf(&(0x7f0000000000)='%s\\x00', &(0x7f0000000040))", path),
		fmt.Sprintf("chmod$kccwf(&(0x7f0000000000)='%s\\x00', 0x1ff)", path),
		fmt.Sprintf("chown$kccwf(&(0x7f0000000000)='%s\\x00', 0x0, 0x0)", path),
		fmt.Sprintf("truncate$kccwf(&(0x7f0000000000)='%s\\x00', 0x100)", path),
		fmt.Sprintf("setxattr$kccwf(&(0x7f0000000000)='%s\\x00', &(0x7f0000000040)='user.test\\x00', &(0x7f0000000080)=\"41424344\", 0x4, 0x0)", path),
		fmt.Sprintf("open$kccwf(&(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nstat$kccwf(&(0x7f0000000040)='%s\\x00', &(0x7f0000000080))", path, path),
		fmt.Sprintf("open$kccwf(&(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nchmod$kccwf(&(0x7f0000000040)='%s\\x00', 0x1a4)", path, path),
		fmt.Sprintf("open$kccwf(&(0x7f0000000000)='%s\\x00', 0x2, 0x0)\ntruncate$kccwf(&(0x7f0000000040)='%s\\x00', 0x200)", path, path),
	}
}

func absoluteFdSeeds(path string) []string {
	return []string{
		fmt.Sprintf("r0 = open$kccwf(&(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nwrite$kccwf(r0, &(0x7f0000000040)=\"41424344\", 0x4)", path),
		fmt.Sprintf("r0 = open$kccwf(&(0x7f0000000000)='%s\\x00', 0x2, 0x0)\npwrite64$kccwf(r0, &(0x7f0000000040)=\"41424344\", 0x4, 0x0)", path),
		fmt.Sprintf("r0 = open$kccwf(&(0x7f0000000000)='%s\\x00', 0x0, 0x0)\nfstat$kccwf(r0, &(0x7f0000000040))", path),
		fmt.Sprintf("r0 = open$kccwf(&(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nfsetxattr$kccwf(r0, &(0x7f0000000040)='user.test\\x00', &(0x7f0000000080)=\"4142\", 0x2, 0x0)", path),
		fmt.Sprintf("r0 = open$kccwf(&(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nftruncate$kccwf(r0, 0x200)", path),
		fmt.Sprintf("r0 = open$kccwf(&(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nfallocate$kccwf(r0, 0x0, 0x0, 0x200)", path),
		fmt.Sprintf("r0 = open$kccwf(&(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nfchmod$kccwf(r0, 0x1a4)", path),
		fmt.Sprintf("r0 = open$kccwf(&(0x7f0000000000)='%s\\x00', 0x0, 0x0)\nread$kccwf(r0, &(0x7f0000000040), 0x20)", path),
	}
}

func relativePathSeeds(path string) []string {
	return []string{
		fmt.Sprintf("faccessat$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x0)", path),
		fmt.Sprintf("fchmodat$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x1a4)", path),
		fmt.Sprintf("statx$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x0, 0x7ff, &(0x7f0000000040))", path),
		fmt.Sprintf("openat$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nfaccessat$kccwf(0xffffffffffffff9c, &(0x7f0000000040)='%s\\x00', 0x0)", path, path),
		fmt.Sprintf("openat$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nfchmodat$kccwf(0xffffffffffffff9c, &(0x7f0000000040)='%s\\x00', 0x1ff)", path, path),
	}
}

func relativeFdSeeds(path string) []string {
	return []string{
		fmt.Sprintf("r0 = openat$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nwrite$kccwf(r0, &(0x7f0000000040)=\"41424344\", 0x4)", path),
		fmt.Sprintf("r0 = openat$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x2, 0x0)\npwrite64$kccwf(r0, &(0x7f0000000040)=\"41424344\", 0x4, 0x0)", path),
		fmt.Sprintf("r0 = openat$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x0, 0x0)\nfstat$kccwf(r0, &(0x7f0000000040))", path),
		fmt.Sprintf("r0 = openat$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nfsetxattr$kccwf(r0, &(0x7f0000000040)='user.test\\x00', &(0x7f0000000080)=\"4142\", 0x2, 0x0)", path),
		fmt.Sprintf("r0 = openat$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nftruncate$kccwf(r0, 0x200)", path),
		fmt.Sprintf("r0 = openat$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nfallocate$kccwf(r0, 0x0, 0x0, 0x200)", path),
		fmt.Sprintf("r0 = openat$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x2, 0x0)\nfchmod$kccwf(r0, 0x1a4)", path),
		fmt.Sprintf("r0 = openat$kccwf(0xffffffffffffff9c, &(0x7f0000000000)='%s\\x00', 0x0, 0x0)\nread$kccwf(r0, &(0x7f0000000040), 0x20)", path),
	}
}

func kccwfAbsFile(idx int) string {
	if idx == 0 {
		return "/mnt/kccwf/testfile#"
	}
	return fmt.Sprintf("/mnt/kccwf/testfile%d", idx)
}

func kccwfRelFile(idx int) string {
	if idx == 0 {
		return "testfile"
	}
	return fmt.Sprintf("testfile%d", idx)
}

func kccwfAbsDir(idx int) string {
	if idx == 0 {
		return "/mnt/kccwf/testdir"
	}
	return fmt.Sprintf("/mnt/kccwf/testdi%d", idx)
}

func kccwfAbsHardlink(idx int) string {
	if idx == 0 {
		return "/mnt/kccwf/hardlink#"
	}
	return fmt.Sprintf("/mnt/kccwf/hardlink%d", idx)
}

func kccwfAbsSymlink(idx int) string {
	if idx == 0 {
		return "/mnt/kccwf/symlink#"
	}
	return fmt.Sprintf("/mnt/kccwf/symlink%d", idx)
}

func kccwfAbsTarget(idx int) string {
	if idx == 0 {
		return "/mnt/kccwf/target_%d"
	}
	return fmt.Sprintf("/mnt/kccwf/target%d%%d", idx)
}

type repairInfo struct {
	class string
	shape string
}

func repairInputRecord(target *prog.Target, data []byte, recIdx int, shapeCounts map[string]int, module string) ([]byte, bool, bool) {
	text := string(data)
	repairedText := diversifyKccwfObjects(text, recIdx)
	var programChanged bool
	repairedText, programChanged = repairKccwfProgramText(repairedText, recIdx, module)
	p, err := target.Deserialize([]byte(repairedText), prog.NonStrict)
	if err != nil {
		p, err = target.Deserialize(data, prog.NonStrict)
		if err != nil {
			tool.Failf("failed to deserialize input corpus program during repair: %v\n%s", err, data)
		}
		repairedText = string(data)
		programChanged = false
	}
	info := inspectRepairProg(p)
	limit := repairShapeLimitForModule(module, info.class)
	if shapeCounts[info.shape] >= limit {
		return nil, repairedText != text || programChanged, false
	}
	shapeCounts[info.shape]++
	return p.Serialize(), repairedText != text || programChanged, true
}

var (
	assignCallRe = regexp.MustCompile(`^\s*(r[0-9]+)\s*=\s*([A-Za-z0-9_]+\$[A-Za-z0-9_]+|[A-Za-z0-9_]+)\(`)
	callNameRe   = regexp.MustCompile(`^\s*(?:r[0-9]+\s*=\s*)?([A-Za-z0-9_]+\$[A-Za-z0-9_]+|[A-Za-z0-9_]+)\(`)
	resRefRe     = regexp.MustCompile(`\br([0-9]+)\b`)
)

func repairKccwfProgramText(text string, recIdx int, module string) (string, bool) {
	lines := splitProgramLines(text)
	nextRes := nextResourceID(lines)
	fdKind := make(map[string]string)
	var primaryFile, primaryDir string
	var changed bool
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		call := callName(line)
		if call == "" {
			continue
		}
		if strings.Contains(call, "$kccwf") {
			var lineChanged bool
			line, lineChanged = repairKccwfPointerArgs(line, call, recIdx)
			if lineChanged {
				lines[i] = line
				changed = true
			}
		}
		if isKccwfOpenCall(call) {
			if res := assignedResource(line); res != "" {
				if call == "open$kccwf_dir" {
					fdKind[res] = "kccwf_dir"
					if primaryDir == "" {
						primaryDir = res
					}
				} else {
					fdKind[res] = "kccwf_file"
					if primaryFile == "" {
						primaryFile = res
					}
				}
			}
			continue
		}
		if isKccwfDupCall(call) {
			if res := assignedResource(line); res != "" {
				oldfd := firstCallArg(line, call)
				if kind := fdKind[oldfd]; kind != "" {
					fdKind[res] = kind
				}
			}
			continue
		}
		fdIndexes := kccwfFDArgIndexes(call)
		if len(fdIndexes) == 0 {
			continue
		}
		args := callArgs(line, call)
		if len(args) == 0 {
			continue
		}
		for _, argIdx := range fdIndexes {
			if argIdx >= len(args) || !needsKccwfFDReplacement(args[argIdx], fdKind) {
				continue
			}
			wantDir := wantsDirFD(call, argIdx)
			replacement := primaryFile
			if wantDir && primaryDir != "" {
				replacement = primaryDir
			}
			if replacement == "" {
				res := fmt.Sprintf("r%d", nextRes)
				nextRes++
				insertCall := "open$kccwf"
				path := kccwfAbsFile(recIdx % 10)
				kind := "kccwf_file"
				if wantDir && moduleSupportsKccwfDirOpen(module) {
					insertCall = "open$kccwf_dir"
					path = "/mnt/kccwf"
					kind = "kccwf_dir"
				}
				insert := fmt.Sprintf("%s = %s(&(0x%012x)='%s\\x00', 0x2, 0x0)",
					res, insertCall, repairAddr(recIdx, nextRes, argIdx), path)
				lines = insertLine(lines, i, insert)
				i++
				fdKind[res] = kind
				if kind == "kccwf_dir" {
					primaryDir = res
				} else {
					primaryFile = res
				}
				replacement = res
				changed = true
			}
			args[argIdx] = replacement
			line = replaceCallArgs(line, call, args)
			lines[i] = line
			changed = true
		}
		if res := assignedResource(lines[i]); res != "" {
			if call == "fcntl$dupfd$kccwf" {
				fdKind[res] = "kccwf_file"
			}
		}
	}
	return strings.Join(lines, "\n"), changed
}

func repairKccwfPointerArgs(line, call string, recIdx int) (string, bool) {
	args := callArgs(line, call)
	if len(args) == 0 {
		return line, false
	}
	changed := false
	setPath := func(idx int, value string) {
		if idx < len(args) && isBadPathArg(args[idx]) {
			args[idx] = fmt.Sprintf("&(0x%012x)='%s\\x00'", repairAddr(recIdx, 0, idx), value)
			changed = true
		}
	}
	setRel := func(idx int) {
		if idx < len(args) && isBadPathArg(args[idx]) {
			args[idx] = fmt.Sprintf("&(0x%012x)='%s\\x00'", repairAddr(recIdx, 0, idx), kccwfRelFile(recIdx%10))
			changed = true
		}
	}
	setBytes := func(idx int, value string) {
		if idx < len(args) && isBadPathArg(args[idx]) {
			args[idx] = fmt.Sprintf("&(0x%012x)=%s", repairAddr(recIdx, 0, idx), value)
			changed = true
		}
	}
	switch call {
	case "open$kccwf", "stat$kccwf", "chmod$kccwf", "chown$kccwf", "utimes$kccwf", "truncate$kccwf", "unlink$kccwf":
		setPath(0, kccwfAbsFile(recIdx%10))
	case "open$kccwf_dir":
		setPath(0, "/mnt/kccwf")
	case "mkdir$kccwf", "rmdir$kccwf":
		setPath(0, kccwfAbsDir(recIdx%10))
	case "rename$kccwf":
		setPath(0, kccwfAbsFile(recIdx%10))
		setPath(1, kccwfAbsFile((recIdx+1)%10))
	case "link$kccwf":
		setPath(0, kccwfAbsFile(recIdx%10))
		setPath(1, kccwfAbsHardlink(recIdx%10))
	case "symlink$kccwf":
		setPath(0, kccwfAbsTarget(recIdx%10))
		setPath(1, kccwfAbsSymlink(recIdx%10))
	case "setxattr$kccwf":
		setPath(0, kccwfAbsFile(recIdx%10))
		if len(args) > 1 && isBadPathArg(args[1]) {
			args[1] = fmt.Sprintf("&(0x%012x)='user.test\\x00'", repairAddr(recIdx, 0, 1))
			changed = true
		}
		if len(args) > 3 && isBadPathArg(args[2]) {
			args[2] = fmt.Sprintf("&(0x%012x)=\"41424344\"", repairAddr(recIdx, 0, 2))
			args[3] = "0x4"
			changed = true
		}
	case "fsetxattr$kccwf":
		if len(args) > 1 && isBadPathArg(args[1]) {
			args[1] = fmt.Sprintf("&(0x%012x)='user.test\\x00'", repairAddr(recIdx, 0, 1))
			changed = true
		}
		if len(args) > 3 && isBadPathArg(args[2]) {
			args[2] = fmt.Sprintf("&(0x%012x)=\"4142\"", repairAddr(recIdx, 0, 2))
			args[3] = "0x2"
			changed = true
		}
	case "openat$kccwf", "faccessat$kccwf", "fchmodat$kccwf", "fchownat$kccwf", "fstatat$kccwf",
		"statx$kccwf", "mknodat$kccwf", "mknodat$loop$kccwf", "mknodat$null$kccwf",
		"name_to_handle_at$kccwf", "futimesat$kccwf", "utimensat$kccwf":
		setRel(1)
	case "read$kccwf", "pread64$kccwf", "write$kccwf", "pwrite64$kccwf":
		if len(args) > 1 {
			setBytes(1, `"41424344"`)
		}
	}
	if !changed {
		return line, false
	}
	return replaceCallArgs(line, call, args), true
}

func splitProgramLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func nextResourceID(lines []string) int {
	next := 0
	for _, line := range lines {
		for _, match := range resRefRe.FindAllStringSubmatch(line, -1) {
			id, err := strconv.Atoi(match[1])
			if err == nil && id >= next {
				next = id + 1
			}
		}
	}
	return next
}

func callName(line string) string {
	match := callNameRe.FindStringSubmatch(line)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

func assignedResource(line string) string {
	match := assignCallRe.FindStringSubmatch(line)
	if len(match) != 3 {
		return ""
	}
	return match[1]
}

func insertLine(lines []string, idx int, line string) []string {
	lines = append(lines, "")
	copy(lines[idx+1:], lines[idx:])
	lines[idx] = line
	return lines
}

func firstCallArg(line, call string) string {
	args := callArgs(line, call)
	if len(args) == 0 {
		return ""
	}
	return strings.TrimSpace(args[0])
}

func callArgs(line, call string) []string {
	start := strings.Index(line, call+"(")
	if start == -1 {
		return nil
	}
	argStart := start + len(call) + 1
	argEnd := findMatchingParen(line, argStart-1)
	if argEnd == -1 {
		return nil
	}
	return splitTopLevelArgs(line[argStart:argEnd])
}

func replaceCallArgs(line, call string, args []string) string {
	start := strings.Index(line, call+"(")
	if start == -1 {
		return line
	}
	argStart := start + len(call) + 1
	argEnd := findMatchingParen(line, argStart-1)
	if argEnd == -1 {
		return line
	}
	return line[:argStart] + strings.Join(args, ", ") + line[argEnd:]
}

func splitTopLevelArgs(args string) []string {
	var out []string
	start := 0
	parenDepth, braceDepth, bracketDepth := 0, 0, 0
	inQuote := byte(0)
	escaped := false
	for i := 0; i < len(args); i++ {
		ch := args[i]
		if inQuote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"':
			inQuote = ch
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case ',':
			if parenDepth == 0 && braceDepth == 0 && bracketDepth == 0 {
				out = append(out, strings.TrimSpace(args[start:i]))
				start = i + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(args[start:]))
	return out
}

func findMatchingParen(s string, open int) int {
	depth := 0
	inQuote := byte(0)
	escaped := false
	for i := open; i < len(s); i++ {
		ch := s[i]
		if inQuote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"':
			inQuote = ch
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isBadPathArg(arg string) bool {
	arg = strings.TrimSpace(arg)
	return arg == "0x0" || arg == "0xffffffffffffffff" ||
		(!strings.Contains(arg, "'") && !strings.Contains(arg, "\""))
}

func needsKccwfFDReplacement(arg string, fdKind map[string]string) bool {
	arg = strings.TrimSpace(arg)
	if arg == "" || arg == "0x0" || arg == "0xffffffffffffffff" {
		return true
	}
	if !strings.HasPrefix(arg, "r") {
		return false
	}
	kind := fdKind[arg]
	return kind != "kccwf_file" && kind != "kccwf_dir"
}

func isKccwfOpenCall(name string) bool {
	return name == "open$kccwf" || name == "openat$kccwf" || name == "open$kccwf_dir"
}

func isKccwfDupCall(name string) bool {
	return name == "dup$kccwf" || name == "dup2$kccwf" || name == "dup3$kccwf"
}

func kccwfFDArgIndexes(call string) []int {
	if strings.HasPrefix(call, "ioctl$") {
		return []int{0}
	}
	switch call {
	case "read$kccwf", "pread64$kccwf", "readv$kccwf", "preadv$kccwf", "preadv2$kccwf",
		"write$kccwf", "pwrite64$kccwf", "writev$kccwf", "pwritev2$kccwf",
		"lseek$kccwf", "fstat$kccwf", "cachestat$kccwf", "fadvise64$kccwf",
		"fchmod$kccwf", "fchown$kccwf", "fallocate$kccwf", "ftruncate$kccwf",
		"flock$kccwf", "fsync$kccwf", "fdatasync$kccwf", "syncfs$kccwf",
		"sync_file_range$kccwf", "fsetxattr$kccwf", "fgetxattr$kccwf",
		"flistxattr$kccwf", "fremovexattr$kccwf", "fchdir$kccwf", "close$kccwf",
		"dup$kccwf", "dup2$kccwf", "dup3$kccwf":
		return []int{0}
	case "copy_file_range$kccwf", "splice$kccwf":
		return []int{0, 2}
	case "sendfile$kccwf", "sendfile64$kccwf":
		return []int{0, 1}
	case "tee$kccwf":
		return []int{0, 1}
	case "vmsplice$kccwf":
		return []int{0}
	case "getdents$kccwf", "getdents64$kccwf", "name_to_handle_at$kccwf",
		"faccessat$kccwf", "fchmodat$kccwf", "fchownat$kccwf", "fstatat$kccwf",
		"statx$kccwf", "futimesat$kccwf", "utimensat$kccwf", "mknodat$kccwf",
		"mknodat$loop$kccwf", "mknodat$null$kccwf":
		return []int{0}
	default:
		return nil
	}
}

func wantsDirFD(call string, argIdx int) bool {
	if argIdx != 0 {
		return false
	}
	switch call {
	case "getdents$kccwf", "getdents64$kccwf", "name_to_handle_at$kccwf",
		"faccessat$kccwf", "fchmodat$kccwf", "fchownat$kccwf", "fstatat$kccwf",
		"statx$kccwf", "futimesat$kccwf", "utimensat$kccwf", "mknodat$kccwf",
		"mknodat$loop$kccwf", "mknodat$null$kccwf":
		return true
	default:
		return false
	}
}

func moduleSupportsKccwfDirOpen(module string) bool {
	return module == "xfs" || module == "jfs" || module == "f2fs"
}

func repairAddr(recIdx, resIdx, argIdx int) int {
	return 0x7f0000000000 + ((recIdx%64)*0x1000 + resIdx*0x100 + argIdx*0x40)
}

// The original kccwf syscalls used a very small fixed object pool. That made
// many independently generated FS programs collapse onto the same path, which
// is unlike native syzkaller filename generation. This deterministic rewrite
// restores object-space diversity while preserving each program's operation
// sequence and all repeated references inside that program.
func diversifyKccwfObjects(text string, recIdx int) string {
	idx := int(crc32.ChecksumIEEE([]byte(fmt.Sprintf("%d:%s", recIdx, text))) % 10)
	replacements := []string{
		"/mnt/kccwf/testfile#", kccwfAbsFile(idx),
		"'testfile#\\x00'", fmt.Sprintf("'%s\\x00'", kccwfRelFile(idx)),
		"'testfile\\x00'", fmt.Sprintf("'%s\\x00'", kccwfRelFile(idx)),
		"/mnt/kccwf/testdir", kccwfAbsDir(idx),
		"/mnt/kccwf/hardlink#", kccwfAbsHardlink(idx),
		"/mnt/kccwf/symlink#", kccwfAbsSymlink(idx),
		"/mnt/kccwf/target_%d", kccwfAbsTarget(idx),
	}
	return strings.NewReplacer(replacements...).Replace(text)
}

func inspectRepairProg(p *prog.Prog) repairInfo {
	var calls []string
	var hasKccwf, hasOpen, hasFDEffect, hasPathEffect, hasStructure bool
	for _, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		name := call.Meta.CallName
		fullName := call.Meta.Name
		calls = append(calls, name)
		if strings.Contains(fullName, "$kccwf") {
			hasKccwf = true
		}
		if repairOpenCalls[name] {
			hasOpen = true
		}
		if repairFDEffectCalls[name] {
			hasFDEffect = true
		}
		if repairPathEffectCalls[name] {
			hasPathEffect = true
		}
		if repairStructureCalls[name] {
			hasStructure = true
		}
	}
	class := "non_kccwf_support"
	switch {
	case hasStructure:
		class = "structure"
	case hasOpen && hasFDEffect:
		class = "open_fd_effect"
	case hasOpen && hasPathEffect:
		class = "open_path_effect"
	case hasPathEffect:
		class = "path_effect"
	case hasKccwf && hasOpen:
		class = "open_low_context"
	case hasKccwf:
		class = "other_kccwf"
	}
	return repairInfo{
		class: class,
		shape: class + "|" + strings.Join(calls, "/"),
	}
}

func repairShapeLimit(class string) int {
	switch class {
	case "structure":
		return 18
	case "open_fd_effect":
		return 14
	case "open_path_effect", "path_effect":
		return 10
	case "other_kccwf":
		return 8
	case "open_low_context":
		return 4
	default:
		return 6
	}
}

func repairShapeLimitForModule(module, class string) int {
	switch module {
	case "btrfs":
		switch class {
		case "non_kccwf_support":
			return 256
		case "structure":
			return 128
		case "open_fd_effect":
			return 128
		case "open_path_effect", "path_effect":
			return 96
		case "other_kccwf":
			return 64
		case "open_low_context":
			return 32
		default:
			return 64
		}
	case "xfs":
		switch class {
		case "non_kccwf_support":
			return 128
		case "structure":
			return 96
		case "open_fd_effect":
			return 96
		case "open_path_effect", "path_effect":
			return 64
		case "other_kccwf":
			return 48
		case "open_low_context":
			return 24
		default:
			return 48
		}
	default:
		return repairShapeLimit(class)
	}
}

var repairOpenCalls = map[string]bool{
	"open":   true,
	"openat": true,
}

var repairFDEffectCalls = map[string]bool{
	"read":              true,
	"pread64":           true,
	"readv":             true,
	"preadv":            true,
	"preadv2":           true,
	"write":             true,
	"pwrite64":          true,
	"writev":            true,
	"pwritev2":          true,
	"lseek":             true,
	"copy_file_range":   true,
	"tee":               true,
	"splice":            true,
	"vmsplice":          true,
	"sendfile":          true,
	"sendfile64":        true,
	"readahead":         true,
	"fstat":             true,
	"fstat64":           true,
	"cachestat":         true,
	"fadvise64":         true,
	"fchmod":            true,
	"fchown":            true,
	"fallocate":         true,
	"ftruncate":         true,
	"flock":             true,
	"ioctl":             true,
	"fcntl":             true,
	"fsync":             true,
	"fdatasync":         true,
	"syncfs":            true,
	"sync_file_range":   true,
	"fsetxattr":         true,
	"fgetxattr":         true,
	"flistxattr":        true,
	"fremovexattr":      true,
	"getdents":          true,
	"getdents64":        true,
	"name_to_handle_at": true,
	"fchdir":            true,
	"dup":               true,
	"dup2":              true,
	"dup3":              true,
}

var repairPathEffectCalls = map[string]bool{
	"stat":        true,
	"lstat":       true,
	"statx":       true,
	"chmod":       true,
	"chown":       true,
	"lchown":      true,
	"utimes":      true,
	"truncate":    true,
	"setxattr":    true,
	"getxattr":    true,
	"listxattr":   true,
	"removexattr": true,
	"faccessat":   true,
	"futimesat":   true,
	"utimensat":   true,
	"fchmodat":    true,
	"mknodat":     true,
}

var repairStructureCalls = map[string]bool{
	"mknodat":   true,
	"mkdir":     true,
	"rmdir":     true,
	"rename":    true,
	"renameat":  true,
	"renameat2": true,
	"link":      true,
	"linkat":    true,
	"unlink":    true,
	"unlinkat":  true,
	"symlink":   true,
	"symlinkat": true,
}
