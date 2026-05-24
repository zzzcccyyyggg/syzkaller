// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in
// the LICENSE file.

package main

import (
	"flag"
	"fmt"
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
		flagModule = flag.String("module", "", "device profile to tune (ptmx, floppy, dsp, bt-stack)")
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
	classCounts := make(map[string]int)
	var keptInput, normalizedInput, droppedInput int
	for recIdx, key := range keys {
		rec := inDB.Records[key]
		data, changed, keep := tuneInputRecord(target, rec.Val, *flagModule, *flagMode, recIdx, shapeCounts, classCounts)
		if !keep {
			droppedInput++
			continue
		}
		sig := hash.String(data)
		if seen[sig] {
			continue
		}
		records = append(records, db.Record{Val: data, Seq: rec.Seq})
		seen[sig] = true
		keptInput++
		if changed {
			normalizedInput++
		}
	}

	seedTexts := buildDeviceSeeds(*flagModule, *flagMode)
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
	fmt.Printf("device corpus tune: module=%s mode=%s input_records=%d kept_input=%d normalized_input=%d dropped_input=%d generated=%d added=%d output_records=%d output=%s\n",
		*flagModule, *flagMode, len(inDB.Records), keptInput, normalizedInput, droppedInput, len(seedTexts), added, len(records), *flagOut)
	printClassSummary(classCounts)
}

func tuneInputRecord(target *prog.Target, data []byte, module, mode string, recIdx int, shapeCounts, classCounts map[string]int) ([]byte, bool, bool) {
	text := string(data)
	var repairChanged bool
	if mode == "repair" {
		text, repairChanged = repairDeviceProgramText(module, text, recIdx)
	}
	p, err := target.Deserialize([]byte(text), prog.NonStrict)
	if err != nil {
		tool.Failf("failed to deserialize input corpus program during device tune: %v\n%s", err, text)
	}
	info := inspectDeviceProg(module, p)
	if info.class == "" {
		tool.Failf("unknown module profile: %s", module)
	}
	classCounts[info.class]++
	if mode == "dense" {
		return p.Serialize(), true, true
	}
	limit := deviceShapeLimit(module, mode, info.class)
	if shapeCounts[info.shape] >= limit {
		return nil, false, false
	}
	shapeCounts[info.shape]++
	serialized := p.Serialize()
	return serialized, repairChanged || string(data) != string(serialized), true
}

var (
	assignCallRe = regexp.MustCompile(`^\s*(r[0-9]+)\s*=\s*([A-Za-z0-9_]+\$[A-Za-z0-9_]+|[A-Za-z0-9_]+)\(`)
	callNameRe   = regexp.MustCompile(`^\s*(?:r[0-9]+\s*=\s*)?([A-Za-z0-9_]+\$[A-Za-z0-9_]+|[A-Za-z0-9_]+)\(`)
	resRefRe     = regexp.MustCompile(`\br([0-9]+)\b`)
)

func repairDeviceProgramText(module, text string, recIdx int) (string, bool) {
	switch module {
	case "ptmx":
		return repairPTMXProgramText(text, recIdx)
	case "floppy":
		return repairFloppyProgramText(text, recIdx)
	case "dsp":
		return repairDSPProgramText(text, recIdx)
	case "bt-stack":
		return repairBTStackProgramText(text, recIdx)
	default:
		return text, false
	}
}

func repairPTMXProgramText(text string, recIdx int) (string, bool) {
	lines := splitProgramLines(text)
	nextRes := nextResourceID(lines)
	fdKind := make(map[string]string)
	var changed bool
	var primaryPTMX string
	hasPeer := false

	for i, line := range lines {
		line, changed = replaceLineDevicePath(line, "openat$ptmx", "/dev/ptmx", changed)
		line, changed = replaceLineDevicePath(line, "openat$tty", "/dev/tty", changed)
		line, changed = replaceLineDevicePath(line, "openat$ttyS3", "/dev/ttyS3", changed)
		line, changed = replaceLineDevicePath(line, "openat$ttynull", "/dev/ttynull", changed)
		line, changed = replaceLineDevicePath(line, "openat$ttyprintk", "/dev/ttyprintk", changed)
		lines[i] = line
	}

	for i, line := range lines {
		call := callName(line)
		if call == "" {
			continue
		}
		if call == "syz_open_pts" || call == "ioctl$TIOCGPTPEER" {
			hasPeer = true
		}
		if isTTYOpenCall(call) {
			if res := assignedResource(line); res != "" {
				fdKind[res] = "tty"
				if call == "openat$ptmx" && primaryPTMX == "" {
					primaryPTMX = res
				}
			} else if call == "openat$ptmx" && primaryPTMX == "" {
				res := fmt.Sprintf("r%d", nextRes)
				nextRes++
				lines[i] = res + " = " + line
				fdKind[res] = "tty"
				primaryPTMX = res
				changed = true
			}
			continue
		}
		if !isTTYIOCTLCall(call) {
			continue
		}
		fd := firstCallArg(line, call)
		if needsReplacementFD(fd, fdKind, "tty") {
			if primaryPTMX == "" {
				res := fmt.Sprintf("r%d", nextRes)
				nextRes++
				insert := fmt.Sprintf("%s = openat$ptmx(0xffffffffffffff9c, &(0x%012x)='/dev/ptmx\\x00', 0x2, 0x0)",
					res, repairAddr(recIdx, nextRes, 0))
				lines = insertLine(lines, i, insert)
				i++
				fdKind[res] = "tty"
				primaryPTMX = res
				changed = true
			}
			lines[i] = replaceFirstCallArg(line, call, primaryPTMX)
			changed = true
		}
		if res := assignedResource(lines[i]); res != "" && call == "ioctl$TIOCGPTPEER" {
			fdKind[res] = "tty"
		}
	}

	if primaryPTMX != "" && !hasPeer {
		peer := fmt.Sprintf("r%d", nextRes)
		lines = append(lines,
			fmt.Sprintf("ioctl$TIOCSPTLCK(%s, 0x40045431, &(0x%012x)=0x0)", primaryPTMX, repairAddr(recIdx, nextRes, 1)),
			fmt.Sprintf("%s = syz_open_pts(%s, 0x2)", peer, primaryPTMX),
			fmt.Sprintf("ioctl$TCGETS(%s, 0x5401, &(0x%012x))", peer, repairAddr(recIdx, nextRes, 2)),
		)
		changed = true
	}
	return strings.Join(lines, "\n"), changed
}

func repairFloppyProgramText(text string, recIdx int) (string, bool) {
	lines := splitProgramLines(text)
	nextRes := nextResourceID(lines)
	fdKind := make(map[string]string)
	var changed bool
	var primaryFloppy, primaryKccwf string
	kccwfPath := kccwfRepairAbsFile(recIdx)

	for i, line := range lines {
		line, changed = replaceLineDevicePath(line, "syz_open_dev$floppy", "/dev/fd#", changed)
		line, changed = repairKccwfPathLine(line, recIdx, changed)
		lines[i] = line
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		call := callName(line)
		if call == "" {
			continue
		}
		if call == "syz_open_dev$floppy" {
			if res := assignedResource(line); res != "" {
				fdKind[res] = "floppy"
				if primaryFloppy == "" {
					primaryFloppy = res
				}
			} else if primaryFloppy == "" {
				res := fmt.Sprintf("r%d", nextRes)
				nextRes++
				lines[i] = res + " = " + line
				fdKind[res] = "floppy"
				primaryFloppy = res
				changed = true
			}
			continue
		}
		if isKccwfOpenCall(call) {
			if res := assignedResource(line); res != "" {
				fdKind[res] = "kccwf"
				if primaryKccwf == "" {
					primaryKccwf = res
				}
			}
			continue
		}
		if isFloppyIOCTLCall(call) {
			fd := firstCallArg(line, call)
			if needsReplacementFD(fd, fdKind, "floppy") {
				if primaryFloppy == "" {
					res := fmt.Sprintf("r%d", nextRes)
					nextRes++
					insert := fmt.Sprintf("%s = syz_open_dev$floppy(&(0x%012x)='/dev/fd#\\x00', 0x0, 0x2)",
						res, repairAddr(recIdx, nextRes, 0))
					lines = insertLine(lines, i, insert)
					i++
					fdKind[res] = "floppy"
					primaryFloppy = res
					changed = true
				}
				lines[i] = replaceFirstCallArg(line, call, primaryFloppy)
				changed = true
			}
			continue
		}
		if !isKccwfFDCall(call) {
			continue
		}
		fd := firstCallArg(line, call)
		if needsReplacementFD(fd, fdKind, "kccwf") {
			if primaryKccwf == "" {
				res := fmt.Sprintf("r%d", nextRes)
				nextRes++
				insert := fmt.Sprintf("%s = open$kccwf(&(0x%012x)='%s\\x00', 0x2, 0x0)",
					res, repairAddr(recIdx, nextRes, 1), kccwfPath)
				lines = insertLine(lines, i, insert)
				i++
				fdKind[res] = "kccwf"
				primaryKccwf = res
				changed = true
			}
			lines[i] = replaceFirstCallArg(lines[i], call, primaryKccwf)
			changed = true
		}
	}
	return strings.Join(lines, "\n"), changed
}

func repairDSPProgramText(text string, recIdx int) (string, bool) {
	lines := splitProgramLines(text)
	nextRes := nextResourceID(lines)
	fdKind := make(map[string]string)
	var changed bool
	var primaryDSP, primaryMixer, primaryProcMixer string

	filtered := lines[:0]
	for _, line := range lines {
		if isDSPUnstableCall(callName(line)) {
			changed = true
			continue
		}
		filtered = append(filtered, line)
	}
	lines = filtered
	if len(lines) == 0 {
		lines = append(lines, "openat$mixer(0xffffffffffffff9c, &(0x7f0000000000)='/dev/mixer\\x00', 0x2, 0x0)")
		changed = true
	}

	for i, line := range lines {
		switch callName(line) {
		case "openat$dsp1", "openat$adsp1":
			if replaced, ok := replaceCallName(line, callName(line), "openat$dsp"); ok {
				line = replaced
				changed = true
			}
		case "openat$audio1":
			if replaced, ok := replaceCallName(line, "openat$audio1", "openat$audio"); ok {
				line = replaced
				changed = true
			}
		}
		line, changed = replaceLineDevicePath(line, "openat$dsp", "/dev/dsp", changed)
		line, changed = replaceLineDevicePath(line, "openat$audio", "/dev/audio", changed)
		line, changed = replaceLineDevicePath(line, "openat$mixer", "/dev/mixer", changed)
		line, changed = replaceLineDevicePath(line, "openat$proc_mixer", "/proc/asound/card0/oss_mixer", changed)
		lines[i] = line
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		call := callName(line)
		if call == "" {
			continue
		}
		switch {
		case isDSPOpenCall(call):
			res := assignedResource(line)
			if res == "" {
				if call == "openat$dsp" || call == "openat$audio" {
					if primaryDSP == "" {
						res = fmt.Sprintf("r%d", nextRes)
						nextRes++
						lines[i] = res + " = " + line
						fdKind[res] = "dsp"
						primaryDSP = res
						changed = true
					}
				} else if call == "openat$mixer" {
					if primaryMixer == "" {
						res = fmt.Sprintf("r%d", nextRes)
						nextRes++
						lines[i] = res + " = " + line
						fdKind[res] = "mixer"
						primaryMixer = res
						changed = true
					}
				} else if call == "openat$proc_mixer" {
					if primaryProcMixer == "" {
						res = fmt.Sprintf("r%d", nextRes)
						nextRes++
						lines[i] = res + " = " + line
						fdKind[res] = "proc_mixer"
						primaryProcMixer = res
						changed = true
					}
				}
				continue
			}
			switch call {
			case "openat$dsp", "openat$audio":
				fdKind[res] = "dsp"
				if primaryDSP == "" {
					primaryDSP = res
				}
			case "openat$mixer":
				fdKind[res] = "mixer"
				if primaryMixer == "" {
					primaryMixer = res
				}
			case "openat$proc_mixer":
				fdKind[res] = "proc_mixer"
				if primaryProcMixer == "" {
					primaryProcMixer = res
				}
			}
			continue
		case isDSPFDCall(call):
			args := callArgs(line, call)
			if len(args) == 0 {
				continue
			}
			fdArg := 0
			if call == "mmap$dsp" {
				fdArg = 4
			}
			if len(args) <= fdArg {
				continue
			}
			if !fdKindAllowed(args[fdArg], fdKind, "dsp") {
				if primaryDSP == "" {
					res := fmt.Sprintf("r%d", nextRes)
					nextRes++
					insert := fmt.Sprintf("%s = openat$dsp(0xffffffffffffff9c, &(0x%012x)='/dev/dsp\\x00', 0x2, 0x0)",
						res, repairAddr(recIdx, nextRes, 0))
					lines = insertLine(lines, i, insert)
					i++
					fdKind[res] = "dsp"
					primaryDSP = res
					changed = true
					args = callArgs(lines[i], call)
					if len(args) <= fdArg {
						continue
					}
				}
				args[fdArg] = primaryDSP
				lines[i] = replaceCallArgs(lines[i], call, args)
				changed = true
			}
			if repaired, ok := repairDSPDataArgs(lines[i], call, recIdx, i); ok {
				lines[i] = repaired
				changed = true
			}
		case isDSPMixerIOCTLCall(call):
			args := callArgs(line, call)
			if len(args) == 0 {
				continue
			}
			if !fdKindAllowed(args[0], fdKind, "mixer") {
				if primaryMixer == "" {
					res := fmt.Sprintf("r%d", nextRes)
					nextRes++
					insert := fmt.Sprintf("%s = openat$mixer(0xffffffffffffff9c, &(0x%012x)='/dev/mixer\\x00', 0x2, 0x0)",
						res, repairAddr(recIdx, nextRes, 1))
					lines = insertLine(lines, i, insert)
					i++
					fdKind[res] = "mixer"
					primaryMixer = res
					changed = true
					args = callArgs(lines[i], call)
					if len(args) == 0 {
						continue
					}
				}
				args[0] = primaryMixer
				lines[i] = replaceCallArgs(lines[i], call, args)
				changed = true
			}
			if repaired, ok := repairDSPDataArgs(lines[i], call, recIdx, i); ok {
				lines[i] = repaired
				changed = true
			}
		case isProcMixerFDCall(call):
			args := callArgs(line, call)
			if len(args) == 0 {
				continue
			}
			if !fdKindAllowed(args[0], fdKind, "proc_mixer") {
				if primaryProcMixer == "" {
					res := fmt.Sprintf("r%d", nextRes)
					nextRes++
					insert := fmt.Sprintf("%s = openat$proc_mixer(0xffffffffffffff9c, &(0x%012x)='/proc/asound/card0/oss_mixer\\x00', 0x2, 0x0)",
						res, repairAddr(recIdx, nextRes, 2))
					lines = insertLine(lines, i, insert)
					i++
					fdKind[res] = "proc_mixer"
					primaryProcMixer = res
					changed = true
					args = callArgs(lines[i], call)
					if len(args) == 0 {
						continue
					}
				}
				args[0] = primaryProcMixer
				lines[i] = replaceCallArgs(lines[i], call, args)
				changed = true
			}
			if repaired, ok := repairDSPDataArgs(lines[i], call, recIdx, i); ok {
				lines[i] = repaired
				changed = true
			}
		}
	}
	return strings.Join(lines, "\n"), changed
}

func repairBTStackProgramText(text string, recIdx int) (string, bool) {
	lines := splitProgramLines(text)
	nextRes := nextResourceID(lines)
	fdKind := make(map[string]string)
	var changed bool
	primary := make(map[string]string)
	filtered := lines[:0]
	for _, line := range lines {
		call := callName(line)
		if isUnsupportedBTCall(call) {
			changed = true
			continue
		}
		filtered = append(filtered, line)
	}
	lines = filtered
	if len(lines) == 0 {
		lines = append(lines, "syz_emit_vhci(0x0, 0x0)")
		changed = true
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		call := callName(line)
		if call == "" {
			continue
		}
		if kind := btInitKind(call); kind != "" {
			if res := assignedResource(line); res != "" {
				fdKind[res] = kind
				if primary[kind] == "" {
					primary[kind] = res
				}
			}
			continue
		}
		want, generic := btWantedKind(call)
		if want == "" && !generic {
			continue
		}
		args := callArgs(line, call)
		if len(args) == 0 {
			continue
		}
		if generic {
			if !fdKindAllowedBT(args[0], fdKind) {
				if primary["l2cap"] == "" {
					res := fmt.Sprintf("r%d", nextRes)
					nextRes++
					insert := makeBTInitLine(res, "l2cap")
					lines = insertLine(lines, i, insert)
					i++
					fdKind[res] = "l2cap"
					primary["l2cap"] = res
					changed = true
					args = callArgs(lines[i], call)
					if len(args) == 0 {
						continue
					}
				}
				args[0] = primary["l2cap"]
				lines[i] = replaceCallArgs(lines[i], call, args)
				changed = true
			}
		} else if !fdKindAllowed(args[0], fdKind, want) {
			if primary[want] == "" {
				res := fmt.Sprintf("r%d", nextRes)
				nextRes++
				insert := makeBTInitLine(res, want)
				lines = insertLine(lines, i, insert)
				i++
				fdKind[res] = want
				primary[want] = res
				changed = true
				args = callArgs(lines[i], call)
				if len(args) == 0 {
					continue
				}
			}
			args[0] = primary[want]
			lines[i] = replaceCallArgs(lines[i], call, args)
			changed = true
		}
		if repaired, ok := repairBTCallArgs(lines[i], call, recIdx, i); ok {
			lines[i] = repaired
			changed = true
		}
	}
	return strings.Join(lines, "\n"), changed
}

func replaceCallName(line, oldName, newName string) (string, bool) {
	idx := strings.Index(line, oldName+"(")
	if idx == -1 {
		return line, false
	}
	return line[:idx] + newName + line[idx+len(oldName):], true
}

func isDSPOpenCall(name string) bool {
	switch name {
	case "openat$dsp", "openat$audio", "openat$mixer", "openat$proc_mixer":
		return true
	default:
		return false
	}
}

func isDSPFDCall(name string) bool {
	return name == "write$dsp" || name == "read$dsp" || name == "mmap$dsp" ||
		strings.HasPrefix(name, "ioctl$SNDCTL_DSP_") || strings.HasPrefix(name, "ioctl$SOUND_PCM_")
}

func isDSPMixerIOCTLCall(name string) bool {
	return name == "ioctl$SOUND_OLD_MIXER_INFO" || name == "ioctl$SOUND_MIXER_INFO" ||
		strings.HasPrefix(name, "ioctl$SOUND_MIXER_") || strings.HasPrefix(name, "ioctl$mixer_")
}

func isDSPUnstableCall(name string) bool {
	return name == "ioctl$SOUND_MIXER_READ_RECSRC" || name == "ioctl$SOUND_MIXER_WRITE_RECSRC"
}

func isProcMixerFDCall(name string) bool {
	return name == "read$proc_mixer" || name == "write$proc_mixer"
}

func repairDSPDataArgs(line, call string, recIdx, lineIdx int) (string, bool) {
	args := callArgs(line, call)
	if len(args) == 0 {
		return line, false
	}
	var changed bool
	addr := func(slot int) string {
		return fmt.Sprintf("0x%012x", repairAddr(recIdx, lineIdx+1, slot))
	}
	switch call {
	case "write$dsp":
		if len(args) >= 3 && (isBadPointerArg(args[1]) || isZeroLike(args[2])) {
			args[1] = fmt.Sprintf("&(%s)=\"41424344\"", addr(0))
			args[2] = "0x4"
			changed = true
		}
	case "read$dsp":
		if len(args) >= 3 {
			if isBadPointerArg(args[1]) {
				args[1] = fmt.Sprintf("&(%s)=\"\"/64", addr(0))
				changed = true
			}
			if isZeroLike(args[2]) {
				args[2] = "0x40"
				changed = true
			}
		}
	case "read$proc_mixer":
		if len(args) >= 3 {
			if isBadPointerArg(args[1]) {
				args[1] = fmt.Sprintf("&(%s)=\"\"/256", addr(0))
				changed = true
			}
			if isZeroLike(args[2]) {
				args[2] = "0x100"
				changed = true
			}
		}
	case "write$proc_mixer":
		if len(args) >= 3 && (isBadPointerArg(args[1]) || isZeroLike(args[2])) {
			args[1] = fmt.Sprintf("&(%s)=[{'VOLUME', @void}]", addr(0))
			args[2] = "0x7"
			changed = true
		}
	default:
		if len(args) >= 3 && dspIOCTLNeedsPointer(call) && isBadPointerArg(args[2]) {
			if strings.Contains(call, "WRITE") || call == "ioctl$SNDCTL_DSP_SPEED" ||
				call == "ioctl$SNDCTL_DSP_STEREO" || call == "ioctl$SNDCTL_DSP_CHANNELS" ||
				call == "ioctl$SNDCTL_DSP_SUBDIVIDE" || call == "ioctl$SNDCTL_DSP_SETFRAGMENT" ||
				call == "ioctl$SNDCTL_DSP_SETFMT" || call == "ioctl$SNDCTL_DSP_SETTRIGGER" {
				args[2] = fmt.Sprintf("&(%s)=0x1", addr(0))
			} else {
				args[2] = fmt.Sprintf("&(%s)", addr(0))
			}
			changed = true
		}
	}
	if !changed {
		return line, false
	}
	return replaceCallArgs(line, call, args), true
}

func dspIOCTLNeedsPointer(call string) bool {
	switch call {
	case "ioctl$SNDCTL_DSP_RESET", "ioctl$SNDCTL_DSP_SYNC", "ioctl$SNDCTL_DSP_POST",
		"ioctl$SNDCTL_DSP_NONBLOCK", "ioctl$SNDCTL_DSP_SETDUPLEX":
		return false
	default:
		return strings.HasPrefix(call, "ioctl$SNDCTL_DSP_") || strings.HasPrefix(call, "ioctl$SOUND_PCM_") ||
			isDSPMixerIOCTLCall(call)
	}
}

func isUnsupportedBTCall(name string) bool {
	return name == "openat$6lowpan_enable" || name == "openat$6lowpan_control" ||
		name == "write$6lowpan_enable" || name == "write$6lowpan_control" ||
		name == "syz_init_net_socket$bt_cmtp" || strings.HasPrefix(name, "ioctl$sock_bt_cmtp_")
}

func btInitKind(name string) string {
	switch name {
	case "syz_init_net_socket$bt_hci":
		return "hci"
	case "syz_init_net_socket$bt_sco":
		return "sco"
	case "syz_init_net_socket$bt_l2cap":
		return "l2cap"
	case "syz_init_net_socket$bt_rfcomm":
		return "rfcomm"
	case "syz_init_net_socket$bt_hidp":
		return "hidp"
	case "syz_init_net_socket$bt_bnep":
		return "bnep"
	default:
		return ""
	}
}

func btWantedKind(name string) (kind string, generic bool) {
	switch {
	case name == "bind$bt_hci" || strings.HasPrefix(name, "ioctl$sock_bt_hci") ||
		name == "ioctl$HCIINQUIRY" || strings.HasPrefix(name, "setsockopt$bt_hci_") ||
		name == "getsockopt$bt_hci" || name == "write$bt_hci":
		return "hci", false
	case name == "bind$bt_sco" || name == "connect$bt_sco" || strings.HasPrefix(name, "getsockopt$bt_sco_"):
		return "sco", false
	case name == "bind$bt_l2cap" || name == "connect$bt_l2cap" || name == "accept4$bt_l2cap" ||
		strings.HasPrefix(name, "setsockopt$bt_l2cap_") || strings.HasPrefix(name, "getsockopt$bt_l2cap_"):
		return "l2cap", false
	case name == "bind$bt_rfcomm" || name == "connect$bt_rfcomm" ||
		strings.HasPrefix(name, "setsockopt$bt_rfcomm_") || strings.HasPrefix(name, "getsockopt$bt_rfcomm_"):
		return "rfcomm", false
	case strings.HasPrefix(name, "ioctl$sock_bt_hidp_"):
		return "hidp", false
	case strings.HasPrefix(name, "ioctl$sock_bt_bnep_"):
		return "bnep", false
	case strings.HasPrefix(name, "setsockopt$bt_BT_") || strings.HasPrefix(name, "getsockopt$bt_BT_"):
		return "", true
	default:
		return "", false
	}
}

func makeBTInitLine(res, kind string) string {
	switch kind {
	case "hci":
		return fmt.Sprintf("%s = syz_init_net_socket$bt_hci(0x1f, 0x3, 0x1)", res)
	case "sco":
		return fmt.Sprintf("%s = syz_init_net_socket$bt_sco(0x1f, 0x5, 0x2)", res)
	case "l2cap":
		return fmt.Sprintf("%s = syz_init_net_socket$bt_l2cap(0x1f, 0x5, 0x0)", res)
	case "rfcomm":
		return fmt.Sprintf("%s = syz_init_net_socket$bt_rfcomm(0x1f, 0x1, 0x3)", res)
	case "hidp":
		return fmt.Sprintf("%s = syz_init_net_socket$bt_hidp(0x1f, 0x3, 0x6)", res)
	case "bnep":
		return fmt.Sprintf("%s = syz_init_net_socket$bt_bnep(0x1f, 0x3, 0x4)", res)
	default:
		return fmt.Sprintf("%s = syz_init_net_socket$bt_l2cap(0x1f, 0x5, 0x0)", res)
	}
}

func repairBTCallArgs(line, call string, recIdx, lineIdx int) (string, bool) {
	args := callArgs(line, call)
	if len(args) == 0 {
		return line, false
	}
	var changed bool
	addr := func(slot int) string {
		return fmt.Sprintf("0x%012x", repairAddr(recIdx, lineIdx+1, slot))
	}
	switch call {
	case "bind$bt_hci":
		if len(args) >= 3 && btAddrArgBad(args[1]) {
			args[1] = fmt.Sprintf("&(%s)={0x1f, 0xffffffffffffffff, 0x3}", addr(0))
			args[2] = "0x6"
			changed = true
		}
	case "bind$bt_sco", "connect$bt_sco":
		if len(args) >= 3 && btAddrArgBad(args[1]) {
			args[1] = fmt.Sprintf("&(%s)={0x1f, @fixed={'\\xaa\\xaa\\xaa\\xaa\\xaa', 0x10}}", addr(0))
			args[2] = "0x8"
			changed = true
		}
	case "bind$bt_l2cap", "connect$bt_l2cap":
		if len(args) >= 3 && btAddrArgBad(args[1]) {
			args[1] = fmt.Sprintf("&(%s)={0x1f, 0x0, @fixed={'\\xaa\\xaa\\xaa\\xaa\\xaa', 0x10}, 0x3}", addr(0))
			args[2] = "0xe"
			changed = true
		}
	case "bind$bt_rfcomm", "connect$bt_rfcomm":
		if len(args) >= 3 && btAddrArgBad(args[1]) {
			args[1] = fmt.Sprintf("&(%s)={0x1f, @fixed={'\\xaa\\xaa\\xaa\\xaa\\xaa', 0x10}, 0x9}", addr(0))
			args[2] = "0xa"
			changed = true
		}
	case "ioctl$HCIINQUIRY":
		if len(args) >= 3 && isBadPointerArg(args[2]) {
			args[2] = fmt.Sprintf("&(%s)={0x0, 0x0, \"9e8b33\", 0x8, 0x1}", addr(0))
			changed = true
		}
	case "write$bt_hci":
		if len(args) >= 3 && (isBadPointerArg(args[1]) || isZeroLike(args[2])) {
			args[1] = fmt.Sprintf("&(%s)={0x1, @read_local_version={0x1001}}", addr(0))
			args[2] = "0x4"
			changed = true
		}
	default:
		if len(args) >= 3 && strings.HasPrefix(call, "ioctl$sock_bt_hci") && isBadPointerArg(args[2]) {
			args[2] = fmt.Sprintf("&(%s)=\"00000000\"", addr(0))
			changed = true
		}
		if len(args) >= 4 && strings.HasPrefix(call, "getsockopt$bt_") && isBadPointerArg(args[3]) {
			args[3] = fmt.Sprintf("&(%s)=\"\"/16", addr(1))
			if len(args) >= 5 && isBadPointerArg(args[4]) {
				args[4] = fmt.Sprintf("&(%s)=0x10", addr(2))
			}
			changed = true
		}
		if len(args) >= 5 && strings.HasPrefix(call, "setsockopt$bt_") && (isBadPointerArg(args[3]) || isZeroLike(args[4])) {
			args[3] = fmt.Sprintf("&(%s)=0x1", addr(1))
			args[4] = "0x4"
			if call == "setsockopt$bt_BT_POWER" {
				args[4] = "0x1"
			} else if call == "setsockopt$bt_BT_VOICE" || call == "setsockopt$bt_BT_SECURITY" {
				args[4] = "0x2"
			}
			changed = true
		}
		if len(args) >= 3 && strings.HasPrefix(call, "ioctl$sock_bt_hidp_HIDPGETCONNLIST") && isBadPointerArg(args[2]) {
			args[2] = fmt.Sprintf("&(%s)={0x1, &(%s)=[{@none}]}", addr(0), addr(1))
			changed = true
		}
		if len(args) >= 3 && strings.HasPrefix(call, "ioctl$sock_bt_bnep_BNEPGETCONNLIST") && isBadPointerArg(args[2]) {
			args[2] = fmt.Sprintf("&(%s)={0x1, &(%s)=[{}]}", addr(0), addr(1))
			changed = true
		}
		if len(args) >= 3 && strings.HasPrefix(call, "ioctl$sock_bt_bnep_BNEPGETSUPPFEAT") && isBadPointerArg(args[2]) {
			args[2] = fmt.Sprintf("&(%s)=0x0", addr(0))
			changed = true
		}
	}
	if !changed {
		return line, false
	}
	return replaceCallArgs(line, call, args), true
}

func btAddrArgBad(arg string) bool {
	arg = strings.TrimSpace(arg)
	return isBadPointerArg(arg) || !strings.Contains(arg, "{")
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

func replaceLineDevicePath(line, call, path string, changed bool) (string, bool) {
	idx := strings.Index(line, call+"(")
	if idx == -1 {
		return line, changed
	}
	start := idx + len(call) + 1
	argsEnd := findMatchingParen(line, start-1)
	if argsEnd == -1 {
		return line, changed
	}
	args := splitTopLevelArgs(line[start:argsEnd])
	pathArg := 1
	if call == "syz_open_dev$floppy" {
		pathArg = 0
	}
	if len(args) <= pathArg {
		return line, changed
	}
	if strings.Contains(args[pathArg], path+"\\x00") {
		return line, changed
	}
	args[pathArg] = fmt.Sprintf("&(0x%012x)='%s\\x00'", stableArgAddr(line, pathArg), path)
	return line[:start] + strings.Join(args, ", ") + line[argsEnd:], true
}

func repairKccwfPathLine(line string, recIdx int, changed bool) (string, bool) {
	call := callName(line)
	if call == "" || !strings.Contains(call, "$kccwf") {
		return line, changed
	}
	start := strings.Index(line, call+"(")
	if start == -1 {
		return line, changed
	}
	argStart := start + len(call) + 1
	argEnd := findMatchingParen(line, argStart-1)
	if argEnd == -1 {
		return line, changed
	}
	args := splitTopLevelArgs(line[argStart:argEnd])
	if len(args) == 0 {
		return line, changed
	}
	newArgs := append([]string(nil), args...)
	switch call {
	case "open$kccwf", "truncate$kccwf", "unlink$kccwf", "setxattr$kccwf":
		if isBadPointerArg(newArgs[0]) {
			newArgs[0] = fmt.Sprintf("&(0x%012x)='%s\\x00'", repairAddr(recIdx, 0, 0), kccwfRepairAbsFile(recIdx))
		}
	case "link$kccwf":
		if len(newArgs) >= 2 {
			if isBadPointerArg(newArgs[0]) {
				newArgs[0] = fmt.Sprintf("&(0x%012x)='%s\\x00'", repairAddr(recIdx, 0, 0), kccwfRepairAbsFile(recIdx))
			}
			if isBadPointerArg(newArgs[1]) {
				newArgs[1] = fmt.Sprintf("&(0x%012x)='%s\\x00'", repairAddr(recIdx, 0, 1), kccwfRepairHardlink(recIdx))
			}
		}
	case "fsetxattr$kccwf":
		if len(newArgs) >= 5 {
			if isBadPointerArg(newArgs[1]) {
				newArgs[1] = fmt.Sprintf("&(0x%012x)='user.test\\x00'", repairAddr(recIdx, 0, 2))
			}
			if isBadPointerArg(newArgs[2]) {
				newArgs[2] = fmt.Sprintf("&(0x%012x)=\"4142\"", repairAddr(recIdx, 0, 3))
				newArgs[3] = "0x2"
			}
		}
	}
	if strings.Join(args, ", ") == strings.Join(newArgs, ", ") {
		return line, changed
	}
	return line[:argStart] + strings.Join(newArgs, ", ") + line[argEnd:], true
}

func firstCallArg(line, call string) string {
	args := callArgs(line, call)
	if len(args) == 0 {
		return ""
	}
	return strings.TrimSpace(args[0])
}

func replaceFirstCallArg(line, call, arg string) string {
	args := callArgs(line, call)
	if len(args) == 0 {
		return line
	}
	args[0] = arg
	return replaceCallArgs(line, call, args)
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

func needsReplacementFD(fd string, fdKind map[string]string, want string) bool {
	fd = strings.TrimSpace(fd)
	if fd == "" || fd == "0xffffffffffffffff" || fd == "0x0" {
		return true
	}
	if !strings.HasPrefix(fd, "r") {
		return false
	}
	return fdKind[fd] != want
}

func fdKindAllowed(fd string, fdKind map[string]string, allowed ...string) bool {
	fd = strings.TrimSpace(fd)
	if fd == "" || fd == "0xffffffffffffffff" || fd == "0x0" {
		return false
	}
	if !strings.HasPrefix(fd, "r") {
		return false
	}
	kind := fdKind[fd]
	for _, want := range allowed {
		if kind == want {
			return true
		}
	}
	return false
}

func fdKindAllowedBT(fd string, fdKind map[string]string) bool {
	fd = strings.TrimSpace(fd)
	if fd == "" || fd == "0xffffffffffffffff" || fd == "0x0" {
		return false
	}
	if !strings.HasPrefix(fd, "r") {
		return false
	}
	switch fdKind[fd] {
	case "hci", "sco", "l2cap", "rfcomm", "hidp", "bnep":
		return true
	default:
		return false
	}
}

func isBadPointerArg(arg string) bool {
	arg = strings.TrimSpace(arg)
	return arg == "0x0" || arg == "0xffffffffffffffff"
}

func isZeroLike(arg string) bool {
	arg = strings.TrimSpace(arg)
	return arg == "0x0" || arg == "0" || arg == "0x00"
}

func isTTYOpenCall(name string) bool {
	return name == "openat$ptmx" || name == "syz_open_pts" || name == "ioctl$TIOCGPTPEER" ||
		strings.HasPrefix(name, "openat$tty") || strings.HasPrefix(name, "syz_open_dev$tty") ||
		name == "syz_open_dev$ttys" || name == "syz_open_dev$ptys"
}

func isTTYIOCTLCall(name string) bool {
	return strings.HasPrefix(name, "ioctl$TC") || strings.HasPrefix(name, "ioctl$TIOC") ||
		strings.HasPrefix(name, "ioctl$KD") || strings.HasPrefix(name, "ioctl$VT") ||
		strings.HasPrefix(name, "ioctl$PIO_") || strings.HasPrefix(name, "ioctl$GIO_") ||
		strings.HasPrefix(name, "ioctl$KDFONTOP")
}

func isFloppyIOCTLCall(name string) bool {
	return strings.HasPrefix(name, "ioctl$FLOPPY_")
}

func isKccwfOpenCall(name string) bool {
	return name == "open$kccwf" || name == "openat$kccwf"
}

func isKccwfFDCall(name string) bool {
	switch name {
	case "read$kccwf", "write$kccwf", "close$kccwf", "fchmod$kccwf", "ftruncate$kccwf",
		"fallocate$kccwf", "fsetxattr$kccwf", "fsync$kccwf":
		return true
	default:
		return false
	}
}

func stableArgAddr(line string, idx int) int {
	base := 0x7f0000000000
	sum := idx * 0x80
	for i := 0; i < len(line); i++ {
		sum += int(line[i])
	}
	return base + (sum%0x40)*0x40
}

func repairAddr(recIdx, resIdx, argIdx int) int {
	return 0x7f0000000000 + ((recIdx%64)*0x1000 + resIdx*0x100 + argIdx*0x40)
}

func kccwfRepairAbsFile(recIdx int) string {
	idx := recIdx % 10
	if idx == 0 {
		return "/mnt/kccwf/testfile#"
	}
	return fmt.Sprintf("/mnt/kccwf/testfile%d", idx)
}

func kccwfRepairHardlink(recIdx int) string {
	idx := recIdx % 10
	if idx == 0 {
		return "/mnt/kccwf/hardlink#"
	}
	return fmt.Sprintf("/mnt/kccwf/hardlink%d", idx)
}

type deviceProgInfo struct {
	class string
	shape string
}

func inspectDeviceProg(module string, p *prog.Prog) deviceProgInfo {
	var calls []string
	counts := make(map[string]int)
	for _, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		name := call.Meta.Name
		counts[name]++
		calls = append(calls, name)
	}
	switch module {
	case "ptmx":
		return inspectPTMXProg(calls, counts)
	case "floppy":
		return inspectFloppyProg(calls, counts)
	case "dsp":
		return inspectDSPProg(calls, counts)
	case "bt-stack":
		return inspectBTStackProg(calls, counts)
	default:
		return deviceProgInfo{}
	}
}

func inspectPTMXProg(calls []string, counts map[string]int) deviceProgInfo {
	hasPTMX := counts["openat$ptmx"] != 0
	hasPTS := counts["syz_open_pts"] != 0 || counts["ioctl$TIOCGPTPEER"] != 0
	hasBSDPair := (counts["syz_open_dev$ttys"] != 0 && counts["syz_open_dev$ptys"] != 0)
	hasTTY20 := counts["syz_open_dev$tty20"] != 0
	hasTIOCSTI := counts["ioctl$TIOCSTI"] != 0
	hasPeerLock := counts["ioctl$TIOCSPTLCK"] != 0 || counts["ioctl$TIOCGPTLCK"] != 0
	hasConsole := false
	hasTermios := false
	for name := range counts {
		if strings.HasPrefix(name, "ioctl$KD") || strings.HasPrefix(name, "ioctl$VT") ||
			strings.HasPrefix(name, "ioctl$PIO_") || strings.HasPrefix(name, "ioctl$GIO_") ||
			strings.HasPrefix(name, "ioctl$TIOCL_") {
			hasConsole = true
		}
		if strings.HasPrefix(name, "ioctl$TC") || strings.HasPrefix(name, "ioctl$TIOC") {
			hasTermios = true
		}
	}

	class := "ptmx_other"
	switch {
	case hasPTMX && hasPTS && hasPeerLock:
		class = "ptmx_peer_lock"
	case hasPTMX && hasPTS:
		class = "ptmx_peer"
	case hasBSDPair:
		class = "bsd_pty_pair"
	case hasTTY20 && hasTIOCSTI && counts["ioctl$TIOCSTI"] >= 3:
		class = "tty20_tiocsti_burst"
	case hasConsole:
		class = "console_ioctl"
	case hasTermios:
		class = "tty_state_ioctl"
	case hasTTY20 && hasTIOCSTI:
		class = "tty20_tiocsti"
	}
	return deviceProgInfo{
		class: class,
		shape: compactShape("ptmx", class, calls, counts),
	}
}

func inspectFloppyProg(calls []string, counts map[string]int) deviceProgInfo {
	hasOpen := counts["syz_open_dev$floppy"] != 0
	hasKccwf := false
	hasFloppyIOCTL := false
	for name := range counts {
		if strings.Contains(name, "$kccwf") {
			hasKccwf = true
		}
		if strings.HasPrefix(name, "ioctl$FLOPPY_") {
			hasFloppyIOCTL = true
		}
	}

	class := "floppy_other"
	switch {
	case counts["ioctl$FLOPPY_FDRAWCMD"] != 0:
		class = "rawcmd"
	case counts["ioctl$FLOPPY_FDFMTBEG"] != 0 || counts["ioctl$FLOPPY_FDFMTTRK"] != 0 || counts["ioctl$FLOPPY_FDFMTEND"] != 0:
		class = "format"
	case counts["ioctl$FLOPPY_FDSETPRM"] != 0 || counts["ioctl$FLOPPY_FDDEFPRM"] != 0 ||
		counts["ioctl$FLOPPY_FDSETDRVPRM"] != 0 || counts["ioctl$FLOPPY_FDSETMAXERRS"] != 0:
		class = "param_set"
	case counts["ioctl$FLOPPY_FDGETPRM"] != 0 || counts["ioctl$FLOPPY_FDGETDRVPRM"] != 0 ||
		counts["ioctl$FLOPPY_FDGETDRVSTAT"] != 0 || counts["ioctl$FLOPPY_FDPOLLDRVSTAT"] != 0 ||
		counts["ioctl$FLOPPY_FDGETFDCSTAT"] != 0:
		class = "status_query"
	case hasOpen && hasFloppyIOCTL:
		class = "simple_ioctl"
	case hasOpen && hasKccwf:
		class = "floppy_kccwf_mixed"
	case hasKccwf:
		class = "kccwf_only"
	}
	return deviceProgInfo{
		class: class,
		shape: compactShape("floppy", class, calls, counts),
	}
}

func inspectDSPProg(calls []string, counts map[string]int) deviceProgInfo {
	hasDSP := counts["openat$dsp"] != 0 || counts["openat$audio"] != 0
	hasMixer := counts["openat$mixer"] != 0
	hasProc := counts["openat$proc_mixer"] != 0
	hasDSPIOCTL := false
	hasMixerIOCTL := false
	for name := range counts {
		if isDSPFDCall(name) && strings.HasPrefix(name, "ioctl$") {
			hasDSPIOCTL = true
		}
		if isDSPMixerIOCTLCall(name) {
			hasMixerIOCTL = true
		}
	}
	class := "dsp_other"
	switch {
	case hasDSP && counts["mmap$dsp"] != 0:
		class = "dsp_mmap"
	case hasDSP && (counts["write$dsp"] != 0 || counts["read$dsp"] != 0):
		class = "dsp_rw"
	case hasDSP && hasDSPIOCTL:
		class = "dsp_ioctl"
	case hasMixer && hasMixerIOCTL:
		class = "dsp_mixer_ioctl"
	case hasProc && (counts["read$proc_mixer"] != 0 || counts["write$proc_mixer"] != 0):
		class = "dsp_proc_mixer"
	case hasDSP && (hasMixer || hasProc):
		class = "dsp_mixed"
	}
	return deviceProgInfo{
		class: class,
		shape: compactShape("dsp", class, calls, counts),
	}
}

func inspectBTStackProg(calls []string, counts map[string]int) deviceProgInfo {
	hasHCI := counts["syz_init_net_socket$bt_hci"] != 0
	hasSCO := counts["syz_init_net_socket$bt_sco"] != 0
	hasL2CAP := counts["syz_init_net_socket$bt_l2cap"] != 0
	hasRFCOMM := counts["syz_init_net_socket$bt_rfcomm"] != 0
	hasHIDP := counts["syz_init_net_socket$bt_hidp"] != 0
	hasBNEP := counts["syz_init_net_socket$bt_bnep"] != 0
	kinds := 0
	for _, present := range []bool{hasHCI, hasSCO, hasL2CAP, hasRFCOMM, hasHIDP, hasBNEP} {
		if present {
			kinds++
		}
	}
	class := "bt_other"
	switch {
	case kinds >= 3:
		class = "bt_mixed"
	case counts["syz_emit_vhci"] != 0 && hasHCI:
		class = "bt_hci_vhci"
	case hasL2CAP && (counts["bind$bt_l2cap"] != 0 || counts["connect$bt_l2cap"] != 0):
		class = "bt_l2cap_pair"
	case hasRFCOMM && (counts["bind$bt_rfcomm"] != 0 || counts["connect$bt_rfcomm"] != 0):
		class = "bt_rfcomm_pair"
	case hasSCO && (counts["bind$bt_sco"] != 0 || counts["connect$bt_sco"] != 0):
		class = "bt_sco_pair"
	case hasHCI:
		class = "bt_hci"
	case hasHIDP:
		class = "bt_hidp"
	case hasBNEP:
		class = "bt_bnep"
	case counts["syz_emit_vhci"] != 0:
		class = "bt_vhci_only"
	}
	return deviceProgInfo{
		class: class,
		shape: compactShape("bt-stack", class, calls, counts),
	}
}

func compactShape(module, class string, calls []string, counts map[string]int) string {
	if module == "ptmx" && class == "tty20_tiocsti_burst" {
		return fmt.Sprintf("%s|opens=%s|sti=%s", class,
			bucketCount(counts["syz_open_dev$tty20"]), bucketCount(counts["ioctl$TIOCSTI"]))
	}
	if module == "floppy" && (class == "floppy_kccwf_mixed" || class == "kccwf_only") {
		return class + "|" + compactCalls(calls, 6)
	}
	return class + "|" + compactCalls(calls, 18)
}

func compactCalls(calls []string, max int) string {
	if len(calls) <= max {
		return strings.Join(calls, "/")
	}
	head := max / 2
	tail := max - head
	return strings.Join(calls[:head], "/") + "/.../" + strings.Join(calls[len(calls)-tail:], "/")
}

func bucketCount(n int) string {
	switch {
	case n <= 1:
		return "1"
	case n <= 3:
		return "2-3"
	case n <= 7:
		return "4-7"
	default:
		return "8+"
	}
}

func deviceShapeLimit(module, mode, class string) int {
	if mode == "lite" {
		switch module {
		case "ptmx":
			return mapWithDefault(map[string]int{
				"ptmx_peer_lock":      18,
				"ptmx_peer":           18,
				"bsd_pty_pair":        12,
				"tty20_tiocsti_burst": 3,
				"tty20_tiocsti":       8,
				"console_ioctl":       10,
				"tty_state_ioctl":     10,
			}, class, 6)
		case "floppy":
			return mapWithDefault(map[string]int{
				"rawcmd":             12,
				"format":             10,
				"param_set":          10,
				"status_query":       10,
				"simple_ioctl":       8,
				"floppy_kccwf_mixed": 4,
				"kccwf_only":         2,
			}, class, 4)
		}
	}
	switch module {
	case "ptmx":
		return mapWithDefault(map[string]int{
			"ptmx_peer_lock":      32,
			"ptmx_peer":           32,
			"bsd_pty_pair":        24,
			"tty20_tiocsti_burst": 6,
			"tty20_tiocsti":       16,
			"console_ioctl":       18,
			"tty_state_ioctl":     18,
		}, class, 10)
	case "floppy":
		return mapWithDefault(map[string]int{
			"rawcmd":             24,
			"format":             20,
			"param_set":          18,
			"status_query":       18,
			"simple_ioctl":       14,
			"floppy_kccwf_mixed": 8,
			"kccwf_only":         3,
		}, class, 8)
	case "dsp":
		return mapWithDefault(map[string]int{
			"dsp_mmap":        64,
			"dsp_rw":          48,
			"dsp_ioctl":       48,
			"dsp_mixer_ioctl": 48,
			"dsp_proc_mixer":  40,
			"dsp_mixed":       64,
		}, class, 24)
	case "bt-stack":
		return mapWithDefault(map[string]int{
			"bt_mixed":       72,
			"bt_hci_vhci":    64,
			"bt_l2cap_pair":  56,
			"bt_rfcomm_pair": 48,
			"bt_sco_pair":    48,
			"bt_hci":         56,
			"bt_hidp":        40,
			"bt_bnep":        40,
			"bt_vhci_only":   32,
		}, class, 24)
	default:
		return 0
	}
}

func mapWithDefault(values map[string]int, key string, fallback int) int {
	if value, ok := values[key]; ok {
		return value
	}
	return fallback
}

func printClassSummary(classCounts map[string]int) {
	keys := make([]string, 0, len(classCounts))
	for key := range classCounts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("  class %-24s input=%d\n", key, classCounts[key])
	}
}

func buildDeviceSeeds(module, mode string) []string {
	switch module {
	case "ptmx":
		return buildPTMXSeeds(mode)
	case "floppy":
		return buildFloppySeeds(mode)
	case "dsp":
		return buildDSPSeeds(mode)
	case "bt-stack":
		return buildBTStackSeeds(mode)
	default:
		return nil
	}
}

func buildPTMXSeeds(mode string) []string {
	seeds := []string{
		"r0 = openat$ptmx(0xffffffffffffff9c, &(0x7f0000000000)='/dev/ptmx\\x00', 0x2, 0x0)\nioctl$TIOCSPTLCK(r0, 0x40045431, &(0x7f0000000040)=0x0)\nr1 = syz_open_pts(r0, 0x2)\nioctl$TCGETS(r1, 0x5401, &(0x7f0000000080))\nioctl$TIOCGWINSZ(r1, 0x5413, &(0x7f00000000c0))",
		"r0 = openat$ptmx(0xffffffffffffff9c, &(0x7f0000000000)='/dev/ptmx\\x00', 0x802, 0x0)\nr1 = ioctl$TIOCGPTPEER(r0, 0x5441, 0x802)\nioctl$TIOCGPTLCK(r0, 0x80045439, &(0x7f0000000040))\nioctl$TIOCPKT(r0, 0x5420, &(0x7f0000000080)=0x1)\nioctl$TIOCGPKT(r0, 0x80045438, &(0x7f00000000c0))\nioctl$TCGETS(r1, 0x5401, &(0x7f0000000100))",
		"r0 = openat$ptmx(0xffffffffffffff9c, &(0x7f0000000000)='/dev/ptmx\\x00', 0x100002, 0x0)\nioctl$TIOCEXCL(r0, 0x540c)\nioctl$TIOCNXCL(r0, 0x540d)\nioctl$TIOCSWINSZ(r0, 0x5414, &(0x7f0000000040)={0x18, 0x50, 0x0, 0x0})\nioctl$TIOCGWINSZ(r0, 0x5413, &(0x7f0000000080))",
		"r0 = syz_open_dev$ptys(0xc, 0x3, 0x0)\nr1 = syz_open_dev$ttys(0xc, 0x2, 0x0)\nioctl$TCGETS(r0, 0x5401, &(0x7f0000000000))\nioctl$TCGETS(r1, 0x5401, &(0x7f0000000040))\nioctl$TIOCSTI(r1, 0x5412, &(0x7f0000000080)=0x41)",
		"r0 = syz_open_dev$tty20(0xc, 0x4, 0x0)\nioctl$TCGETS(r0, 0x5401, &(0x7f0000000000))\nioctl$TCSETS(r0, 0x5402, &(0x7f0000000040)={0x0, 0x5, 0xbf, 0x8a3b, 0x0, \"00040000005ffff65abf1700090450002000\"})\nioctl$TIOCOUTQ(r0, 0x5411, &(0x7f00000000c0))",
		"r0 = openat$tty(0xffffffffffffff9c, &(0x7f0000000000)='/dev/tty\\x00', 0x2, 0x0)\nioctl$TIOCGPGRP(r0, 0x540f, &(0x7f0000000040))\nioctl$TIOCSPGRP(r0, 0x5410, &(0x7f0000000080)=0x0)\nioctl$TIOCGSID(r0, 0x5429, &(0x7f00000000c0))",
		"r0 = syz_open_dev$tty1(0xc, 0x4, 0x1)\nioctl$VT_GETSTATE(r0, 0x5603, &(0x7f0000000000))\nioctl$VT_GETMODE(r0, 0x5601, &(0x7f0000000040))\nioctl$KDGETMODE(r0, 0x4b3b, &(0x7f0000000080))",
		"r0 = openat$ttynull(0xffffffffffffff9c, &(0x7f0000000000)='/dev/ttynull\\x00', 0x2, 0x0)\nioctl$TCGETS2(r0, 0x802c542a, &(0x7f0000000040))\nioctl$TIOCGDEV(r0, 0x80045432, &(0x7f00000000c0))",
	}
	if mode != "lite" {
		seeds = append(seeds,
			"r0 = openat$ptmx(0xffffffffffffff9c, &(0x7f0000000000)='/dev/ptmx\\x00', 0x2, 0x0)\nioctl$TIOCSPTLCK(r0, 0x40045431, &(0x7f0000000040)=0x1)\nioctl$TIOCGPTLCK(r0, 0x80045439, &(0x7f0000000080))\nr1 = ioctl$TIOCGPTPEER(r0, 0x5441, 0x2)\nioctl$TIOCSCTTY(r1, 0x540e, 0x0)\nioctl$TIOCNOTTY(r1, 0x5422)",
			"r0 = openat$ttyprintk(0xffffffffffffff9c, &(0x7f0000000000)='/dev/ttyprintk\\x00', 0x801, 0x0)\nioctl$TCGETA(r0, 0x5405, &(0x7f0000000040))\nioctl$TCSETA(r0, 0x5406, &(0x7f0000000080)={0x0, 0x0, 0xbf, 0x8a3b, 0x0, \"00040000005ffff65a\"})",
		)
	}
	return seeds
}

func buildFloppySeeds(mode string) []string {
	seeds := []string{
		"r0 = syz_open_dev$floppy(&(0x7f0000000000)='/dev/fd#\\x00', 0x0, 0x2)\nioctl$FLOPPY_FDGETPRM(r0, 0x80200204, &(0x7f0000000040))\nioctl$FLOPPY_FDGETDRVPRM(r0, 0x80580211, &(0x7f0000000080))\nioctl$FLOPPY_FDPOLLDRVSTAT(r0, 0x80500213, &(0x7f0000000100))\nioctl$FLOPPY_FDGETFDCSTAT(r0, 0x80280215, &(0x7f0000000180))",
		"r0 = syz_open_dev$floppy(&(0x7f0000000000)='/dev/fd#\\x00', 0x0, 0x2)\nioctl$FLOPPY_FDFMTBEG(r0, 0x247)\nioctl$FLOPPY_FDFMTTRK(r0, 0x400c0248, &(0x7f0000000040)={0x0, 0x0, 0x0})\nioctl$FLOPPY_FDFMTEND(r0, 0x249)",
		"r0 = syz_open_dev$floppy(&(0x7f0000000000)='/dev/fd#\\x00', 0x0, 0x2)\nioctl$FLOPPY_FDGETMAXERRS(r0, 0x8014020e, &(0x7f0000000040))\nioctl$FLOPPY_FDSETMAXERRS(r0, 0x4014024c, &(0x7f0000000080)={0x8, 0x20, 0x8, 0x3, 0x1})",
		"r0 = syz_open_dev$floppy(&(0x7f0000000000)='/dev/fd#\\x00', 0x0, 0x2)\nioctl$FLOPPY_FDRESET(r0, 0x254, 0x2)\nioctl$FLOPPY_FDTWADDLE(r0, 0x259)\nioctl$FLOPPY_FDWERRORCLR(r0, 0x256)\nioctl$FLOPPY_FDWERRORGET(r0, 0x80280217, &(0x7f0000000040))",
		"r0 = syz_open_dev$floppy(&(0x7f0000000000)='/dev/fd#\\x00', 0x0, 0x2)\nioctl$FLOPPY_FDRAWCMD(r0, 0x258, &(0x7f0000000100)={0x40, &(0x7f0000000000)=\"2d90d01fd1644adf12e40afd3c5d81e4\", 0x0, 0x0, 0x10, 0x0, 0x0, 0xeb, 0x7, \"af00\", 0x0, '\\x00', 0xdc})",
		"r0 = syz_open_dev$floppy(&(0x7f0000000000)='/dev/fd#\\x00', 0x0, 0x2)\nioctl$FLOPPY_FDSETPRM(r0, 0x40200242, &(0x7f0000000040)={0x200, 0x12, 0x2, 0x50, 0x0, 0x1b, 0x0, 0xcf, 0x6c, &(0x7f0000000080)='bass\\x00'})\nioctl$FLOPPY_FDDEFPRM(r0, 0x40200243, &(0x7f00000000c0)={0x200, 0x12, 0x2, 0x50, 0x0, 0x1b, 0x0, 0xcf, 0x6c, &(0x7f0000000100)='bass\\x00'})",
		"r0 = open$kccwf(&(0x7f0000000000)='/mnt/kccwf/testfile#\\x00', 0x2, 0x0)\nwrite$kccwf(r0, &(0x7f0000000040)=\"41424344\", 0x4)\nfsync$kccwf(r0)\nclose$kccwf(r0)",
		"r0 = syz_open_dev$floppy(&(0x7f0000000000)='/dev/fd#\\x00', 0x0, 0x2)\nr1 = open$kccwf(&(0x7f0000000040)='/mnt/kccwf/testfile1\\x00', 0x2, 0x0)\nioctl$FLOPPY_FDGETPRM(r0, 0x80200204, &(0x7f0000000080))\nftruncate$kccwf(r1, 0x200)\nclose$kccwf(r1)",
	}
	if mode != "lite" {
		seeds = append(seeds,
			"r0 = syz_open_dev$floppy(&(0x7f0000000000)='/dev/fd#\\x00', 0x0, 0x2)\nioctl$FLOPPY_FDCLRPRM(r0, 0x241)\nioctl$FLOPPY_FDMSGON(r0, 0x245)\nioctl$FLOPPY_FDMSGOFF(r0, 0x246)\nioctl$FLOPPY_FDFLUSH(r0, 0x24b)",
			"r0 = syz_open_dev$floppy(&(0x7f0000000000)='/dev/fd#\\x00', 0x0, 0x2)\nioctl$FLOPPY_FDGETDRVTYP(r0, 0x8010020f, &(0x7f0000000040))\nioctl$FLOPPY_FDSETEMSGTRESH(r0, 0x24a, 0x4)\nioctl$FLOPPY_FDEJECT(r0, 0x25a)",
		)
	}
	return seeds
}

func buildDSPSeeds(mode string) []string {
	seeds := []string{
		"r0 = openat$dsp(0xffffffffffffff9c, &(0x7f0000000000)='/dev/dsp\\x00', 0x2, 0x0)\nioctl$SNDCTL_DSP_SPEED(r0, 0xc0045002, &(0x7f0000000040)=0xac44)\nioctl$SNDCTL_DSP_SETFMT(r0, 0xc0045005, &(0x7f0000000080)=0x2)\nwrite$dsp(r0, &(0x7f00000000c0)=\"41424344\", 0x4)\nread$dsp(r0, &(0x7f0000000100)=\"\"/64, 0x40)",
		"r0 = openat$audio(0xffffffffffffff9c, &(0x7f0000000000)='/dev/audio\\x00', 0x2, 0x0)\nioctl$SNDCTL_DSP_SYNC(r0, 0x5001, 0x0)\nioctl$SOUND_PCM_READ_RATE(r0, 0x80045002, &(0x7f0000000040))\nmmap$dsp(&(0x7f0000ffc000/0x1000)=nil, 0x1000, 0x3, 0x12, r0, 0x0)",
		"r0 = openat$mixer(0xffffffffffffff9c, &(0x7f0000000000)='/dev/mixer\\x00', 0x2, 0x0)\nioctl$SOUND_MIXER_READ_VOLUME(r0, 0x80044d00, &(0x7f0000000040))\nioctl$SOUND_MIXER_WRITE_VOLUME(r0, 0xc0044d00, &(0x7f0000000080)=0x40)\nioctl$mixer_OSS_GETVERSION(r0, 0x80044d76, &(0x7f00000000c0))",
		"r0 = openat$proc_mixer(0xffffffffffffff9c, &(0x7f0000000000)='/proc/asound/card0/oss_mixer\\x00', 0x2, 0x0)\nwrite$proc_mixer(r0, &(0x7f0000000040)=[{'VOLUME', @void}], 0x7)\nread$proc_mixer(r0, &(0x7f0000000080)=\"\"/256, 0x100)",
	}
	if mode != "lite" {
		seeds = append(seeds,
			"r0 = openat$dsp(0xffffffffffffff9c, &(0x7f0000000000)='/dev/dsp\\x00', 0x2, 0x0)\nioctl$SNDCTL_DSP_GETOSPACE(r0, 0x8010500c, &(0x7f0000000040))\nioctl$SNDCTL_DSP_GETISPACE(r0, 0x8010500d, &(0x7f0000000080))\nioctl$SNDCTL_DSP_GETIPTR(r0, 0x800c5011, &(0x7f00000000c0))\nioctl$SNDCTL_DSP_GETOPTR(r0, 0x800c5012, &(0x7f0000000100))",
			"r0 = openat$mixer(0xffffffffffffff9c, &(0x7f0000000000)='/dev/mixer\\x00', 0x2, 0x0)\nioctl$SOUND_MIXER_READ_DEVMASK(r0, 0x80044dfe, &(0x7f0000000040))\nioctl$SOUND_MIXER_READ_RECMASK(r0, 0x80044dfd, &(0x7f0000000080))\nioctl$SOUND_MIXER_READ_CAPS(r0, 0x80044dfc, &(0x7f00000000c0))",
		)
	}
	return seeds
}

func buildBTStackSeeds(mode string) []string {
	seeds := []string{
		"r0 = syz_init_net_socket$bt_hci(0x1f, 0x3, 0x1)\nbind$bt_hci(r0, &(0x7f0000000000)={0x1f, 0xffffffffffffffff, 0x3}, 0x6)\nioctl$sock_bt_hci(r0, 0x400448e1, &(0x7f0000000040))\nsetsockopt$bt_hci_HCI_FILTER(r0, 0x0, 0x2, &(0x7f0000000080)={0x2, [0x1, 0x100], 0x758}, 0x10)",
		"r0 = syz_init_net_socket$bt_sco(0x1f, 0x5, 0x2)\nbind$bt_sco(r0, &(0x7f0000000000)={0x1f, @fixed={'\\xaa\\xaa\\xaa\\xaa\\xaa', 0x10}}, 0x8)\nconnect$bt_sco(r0, &(0x7f0000000040)={0x1f, @fixed={'\\xaa\\xaa\\xaa\\xaa\\xaa', 0x11}}, 0x8)\ngetsockopt$bt_sco_SCO_OPTIONS(r0, 0x11, 0x1, &(0x7f0000000080)=\"\"/16, &(0x7f00000000c0)=0x10)",
		"r0 = syz_init_net_socket$bt_l2cap(0x1f, 0x5, 0x0)\nsetsockopt$bt_l2cap_L2CAP_OPTIONS(r0, 0x6, 0x1, &(0x7f0000000000)={0x40, 0x1000, 0x0, 0x0, 0x3, 0x3, 0x7f}, 0xc)\nbind$bt_l2cap(r0, &(0x7f0000000040)={0x1f, 0x0, @any, 0x4, 0x0}, 0xe)\nconnect$bt_l2cap(r0, &(0x7f0000000080)={0x1f, 0x0, @fixed={'\\xaa\\xaa\\xaa\\xaa\\xaa', 0x10}, 0x3}, 0xe)",
		"r0 = syz_init_net_socket$bt_rfcomm(0x1f, 0x1, 0x3)\nbind$bt_rfcomm(r0, &(0x7f0000000000)={0x1f, @none, 0x1}, 0xa)\nconnect$bt_rfcomm(r0, &(0x7f0000000040)={0x1f, @fixed={'\\xaa\\xaa\\xaa\\xaa\\xaa', 0x10}, 0x9}, 0xa)\nsetsockopt$bt_rfcomm_RFCOMM_LM(r0, 0x12, 0x3, &(0x7f0000000080)=0x1, 0x4)",
		"r0 = syz_init_net_socket$bt_hidp(0x1f, 0x3, 0x6)\nioctl$sock_bt_hidp_HIDPGETCONNLIST(r0, 0x800448d2, &(0x7f0000000000)={0x1, &(0x7f0000000040)=[{@none}]})\nioctl$sock_bt_hidp_HIDPGETCONNINFO(r0, 0x800448d3, &(0x7f0000000080)={@fixed={'\\xaa\\xaa\\xaa\\xaa\\xaa', 0x10}})",
		"r0 = syz_init_net_socket$bt_bnep(0x1f, 0x3, 0x4)\nioctl$sock_bt_bnep_BNEPGETCONNLIST(r0, 0x800442d2, &(0x7f0000000000)={0x1, &(0x7f0000000040)=[{}]})\nioctl$sock_bt_bnep_BNEPGETSUPPFEAT(r0, 0x800442d4, &(0x7f0000000080)=0x0)",
		"syz_emit_vhci(&(0x7f0000000000)=@HCI_VENDOR_PKT={0xff, 0x1}, 0x2)\nr0 = syz_init_net_socket$bt_hci(0x1f, 0x3, 0x1)\nbind$bt_hci(r0, &(0x7f0000000040)={0x1f, 0xffffffffffffffff, 0x3}, 0x6)",
	}
	if mode != "lite" {
		seeds = append(seeds,
			"r0 = syz_init_net_socket$bt_l2cap(0x1f, 0x1, 0x0)\nbind$bt_l2cap(r0, &(0x7f0000000000)={0x1f, 0x0, @any, 0x5, 0x0}, 0xe)\naccept4$bt_l2cap(r0, &(0x7f0000000040), &(0x7f0000000080)=0xe, 0x800)",
			"r0 = syz_init_net_socket$bt_bnep(0x1f, 0x3, 0x4)\nr1 = syz_init_net_socket$bt_rfcomm(0x1f, 0x1, 0x3)\nioctl$sock_bt_bnep_BNEPCONNADD(r0, 0x400442c8, &(0x7f0000000000)={r1, 0x0, 0x2})",
		)
	}
	return seeds
}
