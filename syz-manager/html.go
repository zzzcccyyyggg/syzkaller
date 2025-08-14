// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/html/pages"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/prog"
	"github.com/gorilla/handlers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (mgr *Manager) initHTTP() {
	handle := func(pattern string, handler func(http.ResponseWriter, *http.Request)) {
		http.Handle(pattern, handlers.CompressHandler(http.HandlerFunc(handler)))
	}
	handle("/", mgr.httpSummary)
	handle("/config", mgr.httpConfig)
	handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}).ServeHTTP)
	handle("/syscalls", mgr.httpSyscalls)
	handle("/corpus", mgr.httpCorpus)
	handle("/corpus.db", mgr.httpDownloadCorpus)
	handle("/crash", mgr.httpCrash)
	handle("/cover", mgr.httpCover)
	handle("/subsystemcover", mgr.httpSubsystemCover)
	handle("/modulecover", mgr.httpModuleCover)
	handle("/prio", mgr.httpPrio)
	handle("/file", mgr.httpFile)
	handle("/report", mgr.httpReport)
	handle("/rawcover", mgr.httpRawCover)
	handle("/rawcoverfiles", mgr.httpRawCoverFiles)
	handle("/filterpcs", mgr.httpFilterPCs)
	handle("/funccover", mgr.httpFuncCover)
	handle("/filecover", mgr.httpFileCover)
	handle("/input", mgr.httpInput)
	handle("/debuginput", mgr.httpDebugInput)
	handle("/modules", mgr.modulesInfo)
	handle("/raceReports", mgr.httpRaceReports)
	handle("/racePairCoverage", mgr.httpRacePairCoverage)
	handle("/fuzzScheduler", mgr.httpFuzzScheduler)
	// Browsers like to request this, without special handler this goes to / handler.
	handle("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {})

	log.Logf(0, "serving http on http://%v", mgr.cfg.HTTP)
	go func() {
		err := http.ListenAndServe(mgr.cfg.HTTP, nil)
		if err != nil {
			log.Fatalf("failed to listen on %v: %v", mgr.cfg.HTTP, err)
		}
	}()
}

func (mgr *Manager) httpSummary(w http.ResponseWriter, r *http.Request) {
	data := &UISummaryData{
		Name:  mgr.cfg.Name,
		Log:   log.CachedLogOutput(),
		Stats: mgr.collectStats(),
	}

	var err error
	if data.Crashes, err = mgr.collectCrashes(mgr.cfg.Workdir); err != nil {
		http.Error(w, fmt.Sprintf("failed to collect crashes: %v", err), http.StatusInternalServerError)
		return
	}
	executeTemplate(w, summaryTemplate, data)
}

func (mgr *Manager) httpConfig(w http.ResponseWriter, r *http.Request) {
	data, err := json.MarshalIndent(mgr.cfg, "", "\t")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to encode json: %v", err),
			http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func (mgr *Manager) httpSyscalls(w http.ResponseWriter, r *http.Request) {
	data := &UISyscallsData{
		Name: mgr.cfg.Name,
	}
	for c, cc := range mgr.collectSyscallInfo() {
		var syscallID *int
		if syscall, ok := mgr.target.SyscallMap[c]; ok {
			syscallID = &syscall.ID
		}
		data.Calls = append(data.Calls, UICallType{
			Name:   c,
			ID:     syscallID,
			Inputs: cc.count,
			Cover:  len(cc.cov),
		})
	}
	sort.Slice(data.Calls, func(i, j int) bool {
		return data.Calls[i].Name < data.Calls[j].Name
	})
	executeTemplate(w, syscallsTemplate, data)
}

func (mgr *Manager) collectStats() []UIStat {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	configName := mgr.cfg.Name
	if configName == "" {
		configName = "config"
	}
	rawStats := mgr.stats.all()
	head := prog.GitRevisionBase
	stats := []UIStat{
		{Name: "revision", Value: fmt.Sprint(head[:8]), Link: vcs.LogLink(vcs.SyzkallerRepo, head)},
		{Name: "config", Value: configName, Link: "/config"},
		{Name: "uptime", Value: fmt.Sprint(time.Since(mgr.startTime) / 1e9 * 1e9)},
		{Name: "fuzzing", Value: fmt.Sprint(mgr.fuzzingTime / 60e9 * 60e9)},
		{Name: "corpus", Value: fmt.Sprint(len(mgr.corpus)), Link: "/corpus"},
		{Name: "triage queue", Value: fmt.Sprint(len(mgr.candidates))},
		{Name: "signal", Value: fmt.Sprint(rawStats["signal"])},
		{Name: "coverage", Value: fmt.Sprint(rawStats["coverage"]), Link: "/cover"},
	}
	if mgr.coverFilter != nil {
		stats = append(stats, UIStat{
			Name: "filtered coverage",
			Value: fmt.Sprintf("%v / %v (%v%%)",
				rawStats["filtered coverage"], len(mgr.coverFilter),
				rawStats["filtered coverage"]*100/uint64(len(mgr.coverFilter))),
			Link: "/cover?filter=yes",
		})
	}
	delete(rawStats, "signal")
	delete(rawStats, "coverage")
	delete(rawStats, "filtered coverage")
	if mgr.checkResult != nil {
		stats = append(stats, UIStat{
			Name:  "syscalls",
			Value: fmt.Sprint(len(mgr.checkResult.EnabledCalls[mgr.cfg.Sandbox])),
			Link:  "/syscalls",
		})
	}

	// 添加race报告统计
	raceStats := mgr.raceReportManager.GetRaceStats()
	if totalRaces, ok := raceStats["total_unique_races"].(int); ok && totalRaces > 0 {
		stats = append(stats, UIStat{
			Name:  "reported races",
			Value: fmt.Sprint(totalRaces),
			Link:  "/raceReports",
		})
	}

	// 添加fuzz调度器统计
	fuzzStats := mgr.fuzzScheduler.GetPhaseStats()
	currentPhase := fuzzStats["current_phase"].(FuzzPhase)
	phaseRuntime := fuzzStats["phase_runtime"].(time.Duration)
	phaseName := "Normal Fuzz"
	if currentPhase == PhaseRaceFuzz {
		phaseName = "Race Fuzz"
	}
	stats = append(stats, UIStat{
		Name:  "fuzz phase",
		Value: fmt.Sprintf("%s (%v)", phaseName, phaseRuntime/time.Second*time.Second),
		Link:  "/fuzzScheduler",
	})

	secs := uint64(1)
	if !mgr.firstConnect.IsZero() {
		secs = uint64(time.Since(mgr.firstConnect))/1e9 + 1
	}
	intStats := convertStats(rawStats, secs)
	sort.Slice(intStats, func(i, j int) bool {
		return intStats[i].Name < intStats[j].Name
	})
	stats = append(stats, intStats...)
	return stats
}

func convertStats(stats map[string]uint64, secs uint64) []UIStat {
	var intStats []UIStat
	for k, v := range stats {
		val := fmt.Sprintf("%v", v)
		if x := v / secs; x >= 10 {
			val += fmt.Sprintf(" (%v/sec)", x)
		} else if x := v * 60 / secs; x >= 10 {
			val += fmt.Sprintf(" (%v/min)", x)
		} else {
			x := v * 60 * 60 / secs
			val += fmt.Sprintf(" (%v/hour)", x)
		}
		intStats = append(intStats, UIStat{Name: k, Value: val})
	}
	return intStats
}

func (mgr *Manager) httpCrash(w http.ResponseWriter, r *http.Request) {
	crashID := r.FormValue("id")
	crash := readCrash(mgr.cfg.Workdir, crashID, nil, mgr.startTime, true)
	if crash == nil {
		http.Error(w, "failed to read crash info", http.StatusInternalServerError)
		return
	}
	executeTemplate(w, crashTemplate, crash)
}

func (mgr *Manager) httpCorpus(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	data := UICorpus{
		Call:     r.FormValue("call"),
		RawCover: mgr.cfg.RawCover,
	}
	for sig, inp := range mgr.corpus {
		if data.Call != "" && data.Call != inp.Call {
			continue
		}
		p, err := mgr.target.Deserialize(inp.Prog, prog.NonStrict)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to deserialize program: %v", err), http.StatusInternalServerError)
			return
		}
		data.Inputs = append(data.Inputs, &UIInput{
			Sig:   sig,
			Short: p.String(),
			Cover: len(inp.Cover),
		})
	}
	sort.Slice(data.Inputs, func(i, j int) bool {
		a, b := data.Inputs[i], data.Inputs[j]
		if a.Cover != b.Cover {
			return a.Cover > b.Cover
		}
		return a.Short < b.Short
	})
	executeTemplate(w, corpusTemplate, data)
}

func (mgr *Manager) httpDownloadCorpus(w http.ResponseWriter, r *http.Request) {
	corpus := filepath.Join(mgr.cfg.Workdir, "corpus.db")
	file, err := os.Open(corpus)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to open corpus : %v", err), http.StatusInternalServerError)
		return
	}
	defer file.Close()
	buf, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read corpus : %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(buf)
}

const (
	DoHTML int = iota
	DoHTMLTable
	DoModuleCover
	DoCSV
	DoCSVFiles
	DoRawCoverFiles
	DoRawCover
	DoFilterPCs
)

func (mgr *Manager) httpCover(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoHTML, true)
}

func (mgr *Manager) httpSubsystemCover(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoHTMLTable, true)
}

func (mgr *Manager) httpModuleCover(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoModuleCover, true)
}

func (mgr *Manager) httpCoverCover(w http.ResponseWriter, r *http.Request, funcFlag int, isHTMLCover bool) {
	if !mgr.cfg.Cover {
		if isHTMLCover {
			mgr.httpCoverFallback(w, r)
		} else {
			http.Error(w, "coverage is not enabled", http.StatusInternalServerError)
		}
		return
	}

	// Don't hold the mutex while creating report generator and generating the report,
	// these operations take lots of time.
	mgr.mu.Lock()
	initialized := mgr.modulesInitialized
	mgr.mu.Unlock()
	if !initialized {
		http.Error(w, "coverage is not ready, please try again later after fuzzer started", http.StatusInternalServerError)
		return
	}

	rg, err := getReportGenerator(mgr.cfg, mgr.modules)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}

	mgr.mu.Lock()
	var progs []cover.Prog
	if sig := r.FormValue("input"); sig != "" {
		inp := mgr.corpus[sig]
		if r.FormValue("update_id") != "" {
			updateID, err := strconv.Atoi(r.FormValue("update_id"))
			if err != nil || updateID < 0 || updateID >= len(inp.Updates) {
				http.Error(w, "bad call_id", http.StatusBadRequest)
			}
			progs = append(progs, cover.Prog{
				Sig:  sig,
				Data: string(inp.Prog),
				PCs:  coverToPCs(rg, inp.Updates[updateID].RawCover),
			})
		} else {
			progs = append(progs, cover.Prog{
				Sig:  sig,
				Data: string(inp.Prog),
				PCs:  coverToPCs(rg, inp.Cover),
			})
		}
	} else {
		call := r.FormValue("call")
		for sig, inp := range mgr.corpus {
			if call != "" && call != inp.Call {
				continue
			}
			progs = append(progs, cover.Prog{
				Sig:  sig,
				Data: string(inp.Prog),
				PCs:  coverToPCs(rg, inp.Cover),
			})
		}
	}
	mgr.mu.Unlock()

	var coverFilter map[uint32]uint32
	if r.FormValue("filter") != "" {
		coverFilter = mgr.coverFilter
	}

	if funcFlag == DoRawCoverFiles {
		if err := rg.DoRawCoverFiles(w, progs, coverFilter); err != nil {
			http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
			return
		}
		runtime.GC()
		return
	} else if funcFlag == DoRawCover {
		rg.DoRawCover(w, progs, coverFilter)
		return
	} else if funcFlag == DoFilterPCs {
		rg.DoFilterPCs(w, progs, coverFilter)
		return
	}

	do := rg.DoHTML
	if funcFlag == DoHTMLTable {
		do = rg.DoHTMLTable
	} else if funcFlag == DoModuleCover {
		do = rg.DoModuleCover
	} else if funcFlag == DoCSV {
		do = rg.DoCSV
	} else if funcFlag == DoCSVFiles {
		do = rg.DoCSVFiles
	}

	if err := do(w, progs, coverFilter); err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}
	runtime.GC()
}

func (mgr *Manager) httpCoverFallback(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	var maxSignal signal.Signal
	for _, inp := range mgr.corpus {
		maxSignal.Merge(inp.Signal.Deserialize())
	}
	calls := make(map[int][]int)
	for s := range maxSignal {
		id, errno := prog.DecodeFallbackSignal(uint32(s))
		calls[id] = append(calls[id], errno)
	}
	data := &UIFallbackCoverData{}
	for _, id := range mgr.checkResult.EnabledCalls[mgr.cfg.Sandbox] {
		errnos := calls[id]
		sort.Ints(errnos)
		successful := 0
		for len(errnos) != 0 && errnos[0] == 0 {
			successful++
			errnos = errnos[1:]
		}
		data.Calls = append(data.Calls, UIFallbackCall{
			Name:       mgr.target.Syscalls[id].Name,
			Successful: successful,
			Errnos:     errnos,
		})
	}
	sort.Slice(data.Calls, func(i, j int) bool {
		return data.Calls[i].Name < data.Calls[j].Name
	})
	executeTemplate(w, fallbackCoverTemplate, data)
}

func (mgr *Manager) httpFuncCover(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoCSV, false)
}

func (mgr *Manager) httpFileCover(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoCSVFiles, false)
}

func (mgr *Manager) httpPrio(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	callName := r.FormValue("call")
	call := mgr.target.SyscallMap[callName]
	if call == nil {
		http.Error(w, fmt.Sprintf("unknown call: %v", callName), http.StatusInternalServerError)
		return
	}

	var corpus []*prog.Prog
	for _, inp := range mgr.corpus {
		p, err := mgr.target.Deserialize(inp.Prog, prog.NonStrict)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to deserialize program: %v", err), http.StatusInternalServerError)
			return
		}
		corpus = append(corpus, p)
	}
	prios := mgr.target.CalculatePriorities(corpus)

	data := &UIPrioData{Call: callName}
	for i, p := range prios[call.ID] {
		data.Prios = append(data.Prios, UIPrio{mgr.target.Syscalls[i].Name, p})
	}
	sort.Slice(data.Prios, func(i, j int) bool {
		return data.Prios[i].Prio > data.Prios[j].Prio
	})
	executeTemplate(w, prioTemplate, data)
}

func (mgr *Manager) httpFile(w http.ResponseWriter, r *http.Request) {
	file := filepath.Clean(r.FormValue("name"))
	if !strings.HasPrefix(file, "crashes/") && !strings.HasPrefix(file, "corpus/") {
		http.Error(w, "oh, oh, oh!", http.StatusInternalServerError)
		return
	}
	file = filepath.Join(mgr.cfg.Workdir, file)
	f, err := os.Open(file)
	if err != nil {
		http.Error(w, "failed to open the file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.Copy(w, f)
}

func (mgr *Manager) httpInput(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	inp, ok := mgr.corpus[r.FormValue("sig")]
	if !ok {
		http.Error(w, "can't find the input", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(inp.Prog)
}

func (mgr *Manager) httpDebugInput(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	inp, ok := mgr.corpus[r.FormValue("sig")]
	if !ok {
		http.Error(w, "can't find the input", http.StatusInternalServerError)
		return
	}
	getIDs := func(callID int) []int {
		ret := []int{}
		for id, update := range inp.Updates {
			if update.CallID == callID {
				ret = append(ret, id)
			}
		}
		return ret
	}
	data := []UIRawCallCover{}
	for pos, line := range strings.Split(string(inp.Prog), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		data = append(data, UIRawCallCover{
			Sig:       r.FormValue("sig"),
			Call:      line,
			UpdateIDs: getIDs(pos),
		})
	}
	extraIDs := getIDs(-1)
	if len(extraIDs) > 0 {
		data = append(data, UIRawCallCover{
			Sig:       r.FormValue("sig"),
			Call:      ".extra",
			UpdateIDs: extraIDs,
		})
	}
	executeTemplate(w, rawCoverTemplate, data)
}

func (mgr *Manager) modulesInfo(w http.ResponseWriter, r *http.Request) {
	if mgr.serv.canonicalModules == nil {
		fmt.Fprintf(w, "module information not retrieved yet, please retry after fuzzing starts\n")
		return
	}
	// NewCanonicalizer() is initialized with serv.modules.
	modules, err := json.MarshalIndent(mgr.serv.modules, "", "\t")
	if err != nil {
		fmt.Fprintf(w, "unable to create JSON modules info: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(modules)
}

func (mgr *Manager) httpReport(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	crashID := r.FormValue("id")
	desc, err := os.ReadFile(filepath.Join(mgr.crashdir, crashID, "description"))
	if err != nil {
		http.Error(w, "failed to read description file", http.StatusInternalServerError)
		return
	}
	tag, _ := os.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.tag"))
	prog, _ := os.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.prog"))
	cprog, _ := os.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.cprog"))
	rep, _ := os.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.report"))

	commitDesc := ""
	if len(tag) != 0 {
		commitDesc = fmt.Sprintf(" on commit %s.", trimNewLines(tag))
	}
	fmt.Fprintf(w, "Syzkaller hit '%s' bug%s.\n\n", trimNewLines(desc), commitDesc)
	if len(rep) != 0 {
		fmt.Fprintf(w, "%s\n\n", rep)
	}
	if len(prog) == 0 && len(cprog) == 0 {
		fmt.Fprintf(w, "The bug is not reproducible.\n")
	} else {
		fmt.Fprintf(w, "Syzkaller reproducer:\n%s\n\n", prog)
		if len(cprog) != 0 {
			fmt.Fprintf(w, "C reproducer:\n%s\n\n", cprog)
		}
	}
}

func (mgr *Manager) httpRawCover(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoRawCover, false)
}

func (mgr *Manager) httpRawCoverFiles(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoRawCoverFiles, false)
}

func (mgr *Manager) httpFilterPCs(w http.ResponseWriter, r *http.Request) {
	if mgr.coverFilter == nil {
		fmt.Fprintf(w, "cover is not filtered in config.\n")
		return
	}
	mgr.httpCoverCover(w, r, DoFilterPCs, false)
}

func (mgr *Manager) collectCrashes(workdir string) ([]*UICrashType, error) {
	// Note: mu is not locked here.
	reproReply := make(chan map[string]bool)
	mgr.reproRequest <- reproReply
	repros := <-reproReply

	crashdir := filepath.Join(workdir, "crashes")
	dirs, err := osutil.ListDir(crashdir)
	if err != nil {
		return nil, err
	}
	var crashTypes []*UICrashType
	for _, dir := range dirs {
		crash := readCrash(workdir, dir, repros, mgr.startTime, false)
		if crash != nil {
			crashTypes = append(crashTypes, crash)
		}
	}
	sort.Slice(crashTypes, func(i, j int) bool {
		return strings.ToLower(crashTypes[i].Description) < strings.ToLower(crashTypes[j].Description)
	})
	return crashTypes, nil
}

func readCrash(workdir, dir string, repros map[string]bool, start time.Time, full bool) *UICrashType {
	if len(dir) != 40 {
		return nil
	}
	crashdir := filepath.Join(workdir, "crashes")
	descFile, err := os.Open(filepath.Join(crashdir, dir, "description"))
	if err != nil {
		return nil
	}
	defer descFile.Close()
	descBytes, err := io.ReadAll(descFile)
	if err != nil || len(descBytes) == 0 {
		return nil
	}
	desc := string(trimNewLines(descBytes))
	stat, err := descFile.Stat()
	if err != nil {
		return nil
	}
	modTime := stat.ModTime()
	descFile.Close()

	files, err := osutil.ListDir(filepath.Join(crashdir, dir))
	if err != nil {
		return nil
	}
	var crashes []*UICrash
	reproAttempts := 0
	hasRepro, hasCRepro := false, false
	strace := ""
	reports := make(map[string]bool)
	for _, f := range files {
		if strings.HasPrefix(f, "log") {
			index, err := strconv.ParseUint(f[3:], 10, 64)
			if err == nil {
				crashes = append(crashes, &UICrash{
					Index: int(index),
				})
			}
		} else if strings.HasPrefix(f, "report") {
			reports[f] = true
		} else if f == "repro.prog" {
			hasRepro = true
		} else if f == "repro.cprog" {
			hasCRepro = true
		} else if f == "repro.report" {
		} else if f == "repro0" || f == "repro1" || f == "repro2" {
			reproAttempts++
		} else if f == "strace.log" {
			strace = filepath.Join("crashes", dir, f)
		}
	}

	if full {
		for _, crash := range crashes {
			index := strconv.Itoa(crash.Index)
			crash.Log = filepath.Join("crashes", dir, "log"+index)
			if stat, err := os.Stat(filepath.Join(workdir, crash.Log)); err == nil {
				crash.Time = stat.ModTime()
				crash.Active = crash.Time.After(start)
			}
			tag, _ := os.ReadFile(filepath.Join(crashdir, dir, "tag"+index))
			crash.Tag = string(tag)
			reportFile := filepath.Join("crashes", dir, "report"+index)
			if osutil.IsExist(filepath.Join(workdir, reportFile)) {
				crash.Report = reportFile
			}
		}
		sort.Slice(crashes, func(i, j int) bool {
			return crashes[i].Time.After(crashes[j].Time)
		})
	}

	triaged := reproStatus(hasRepro, hasCRepro, repros[desc], reproAttempts >= maxReproAttempts)
	return &UICrashType{
		Description: desc,
		LastTime:    modTime,
		Active:      modTime.After(start),
		ID:          dir,
		Count:       len(crashes),
		Triaged:     triaged,
		Strace:      strace,
		Crashes:     crashes,
	}
}

func reproStatus(hasRepro, hasCRepro, reproducing, nonReproducible bool) string {
	status := ""
	if hasRepro {
		status = "has repro"
		if hasCRepro {
			status = "has C repro"
		}
	} else if reproducing {
		status = "reproducing"
	} else if nonReproducible {
		status = "non-reproducible"
	}
	return status
}

func executeTemplate(w http.ResponseWriter, templ *template.Template, data interface{}) {
	buf := new(bytes.Buffer)
	if err := templ.Execute(buf, data); err != nil {
		log.Logf(0, "failed to execute template: %v", err)
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
}

func trimNewLines(data []byte) []byte {
	for len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	return data
}

type UISummaryData struct {
	Name    string
	Stats   []UIStat
	Crashes []*UICrashType
	Log     string
}

type UISyscallsData struct {
	Name  string
	Calls []UICallType
}

type UICrashType struct {
	Description string
	LastTime    time.Time
	Active      bool
	ID          string
	Count       int
	Triaged     string
	Strace      string
	Crashes     []*UICrash
}

type UICrash struct {
	Index  int
	Time   time.Time
	Active bool
	Log    string
	Report string
	Tag    string
}

type UIStat struct {
	Name  string
	Value string
	Link  string
}

type UICallType struct {
	Name   string
	ID     *int
	Inputs int
	Cover  int
}

type UICorpus struct {
	Call     string
	RawCover bool
	Inputs   []*UIInput
}

type UIInput struct {
	Sig   string
	Short string
	Cover int
}

var summaryTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>{{.Name }} syzkaller</title>
	{{HEAD}}
</head>
<body>
<b>{{.Name }} syzkaller</b>
<br>

<table class="list_table">
	<caption>Stats:</caption>
	{{range $s := $.Stats}}
	<tr>
		<td class="stat_name">{{$s.Name}}</td>
		<td class="stat_value">
			{{if $s.Link}}
				<a href="{{$s.Link}}">{{$s.Value}}</a>
			{{else}}
				{{$s.Value}}
			{{end}}
		</td>
	</tr>
	{{end}}
</table>

<table class="list_table">
	<caption>Crashes:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Description', textSort)" href="#">Description</a></th>
		<th><a onclick="return sortTable(this, 'Count', numSort)" href="#">Count</a></th>
		<th><a onclick="return sortTable(this, 'Last Time', textSort, true)" href="#">Last Time</a></th>
		<th><a onclick="return sortTable(this, 'Report', textSort)" href="#">Report</a></th>
	</tr>
	{{range $c := $.Crashes}}
	<tr>
		<td class="title"><a href="/crash?id={{$c.ID}}">{{$c.Description}}</a></td>
		<td class="stat {{if not $c.Active}}inactive{{end}}">{{$c.Count}}</td>
		<td class="time {{if not $c.Active}}inactive{{end}}">{{formatTime $c.LastTime}}</td>
		<td>
			{{if $c.Triaged}}
				<a href="/report?id={{$c.ID}}">{{$c.Triaged}}</a>
			{{end}}
			{{if $c.Strace}}
				<a href="/file?name={{$c.Strace}}">Strace</a>
			{{end}}
		</td>
	</tr>
	{{end}}
</table>

<b>Log:</b>
<br>
<textarea id="log_textarea" readonly rows="20" wrap=off>
{{.Log}}
</textarea>
<script>
	var textarea = document.getElementById("log_textarea");
	textarea.scrollTop = textarea.scrollHeight;
</script>
</body></html>
`)

var syscallsTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>{{.Name }} syzkaller</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>Per-syscall coverage:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Syscall', textSort)" href="#">Syscall</a></th>
		<th><a onclick="return sortTable(this, 'Inputs', numSort)" href="#">Inputs</a></th>
		<th><a onclick="return sortTable(this, 'Coverage', numSort)" href="#">Coverage</a></th>
		<th>Prio</th>
	</tr>
	{{range $c := $.Calls}}
	<tr>
		<td>{{$c.Name}}{{if $c.ID }} [{{$c.ID}}]{{end}}</td>
		<td><a href='/corpus?call={{$c.Name}}'>{{$c.Inputs}}</a></td>
		<td><a href='/cover?call={{$c.Name}}'>{{$c.Cover}}</a></td>
		<td><a href='/prio?call={{$c.Name}}'>prio</a></td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var crashTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>{{.Description}}</title>
	{{HEAD}}
</head>
<body>
<b>{{.Description}}</b>

{{if .Triaged}}
Report: <a href="/report?id={{.ID}}">{{.Triaged}}</a>
{{end}}

<table class="list_table">
	<tr>
		<th>#</th>
		<th>Log</th>
		<th>Report</th>
		<th>Time</th>
		<th>Tag</th>
	</tr>
	{{range $c := $.Crashes}}
	<tr>
		<td>{{$c.Index}}</td>
		<td><a href="/file?name={{$c.Log}}">log</a></td>
		<td>
			{{if $c.Report}}
				<a href="/file?name={{$c.Report}}">report</a></td>
			{{end}}
		</td>
		<td class="time {{if not $c.Active}}inactive{{end}}">{{formatTime $c.Time}}</td>
		<td class="tag {{if not $c.Active}}inactive{{end}}" title="{{$c.Tag}}">{{formatTagHash $c.Tag}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var corpusTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>syzkaller corpus</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>Corpus{{if $.Call}} for {{$.Call}}{{end}}:</caption>
	<tr>
		<th>Coverage</th>
		<th>Program</th>
	</tr>
	{{range $inp := $.Inputs}}
	<tr>
		<td>
			<a href='/cover?input={{$inp.Sig}}'>{{$inp.Cover}}</a>
	{{if $.RawCover}}
		/ <a href="/debuginput?sig={{$inp.Sig}}">[raw]</a>
	{{end}}
		</td>
		<td><a href="/input?sig={{$inp.Sig}}">{{$inp.Short}}</a></td>
	</tr>
	{{end}}
</table>
</body></html>
`)

type UIPrioData struct {
	Call  string
	Prios []UIPrio
}

type UIPrio struct {
	Call string
	Prio int32
}

var prioTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>syzkaller priorities</title>
	{{HEAD}}
</head>
<body>
<table class="list_table">
	<caption>Priorities for {{$.Call}}:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Prio', floatSort)" href="#">Prio</a></th>
		<th><a onclick="return sortTable(this, 'Call', textSort)" href="#">Call</a></th>
	</tr>
	{{range $p := $.Prios}}
	<tr>
		<td>{{printf "%5v" $p.Prio}}</td>
		<td><a href='/prio?call={{$p.Call}}'>{{$p.Call}}</a></td>
	</tr>
	{{end}}
</table>
</body></html>
`)

type UIFallbackCoverData struct {
	Calls []UIFallbackCall
}

type UIFallbackCall struct {
	Name       string
	Successful int
	Errnos     []int
}

var fallbackCoverTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>syzkaller coverage</title>
	{{HEAD}}
</head>
<body>
<table class="list_table">
	<tr>
		<th>Call</th>
		<th>Successful</th>
		<th>Errnos</th>
	</tr>
	{{range $c := $.Calls}}
	<tr>
		<td>{{$c.Name}}</td>
		<td>{{if $c.Successful}}{{$c.Successful}}{{end}}</td>
		<td>{{range $e := $c.Errnos}}{{$e}}&nbsp;{{end}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

type UIRawCallCover struct {
	Sig       string
	Call      string
	UpdateIDs []int
}

var rawCoverTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>syzkaller raw cover</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>Raw cover</caption>
	<tr>
		<th>Line</th>
		<th>Links</th>
	</tr>
	{{range $line := .}}
	<tr>
		<td>{{$line.Call}}</td>
		<td>
		{{range $id := $line.UpdateIDs}}
		<a href="/rawcover?input={{$line.Sig}}&update_id={{$id}}">[{{$id}}]</a>
		{{end}}
</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

func (mgr *Manager) httpRaceReports(w http.ResponseWriter, r *http.Request) {
	// 获取URL参数
	viewType := r.URL.Query().Get("view")
	varName := r.URL.Query().Get("varname")
	groupKey := r.URL.Query().Get("group")

	// 获取统计信息
	stats := mgr.raceReportManager.GetRaceStats()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// 根据view类型展示不同的内容
	switch viewType {
	case "groups":
		mgr.renderRaceGroups(w, groupKey, stats)
	case "individual":
		mgr.renderIndividualRaces(w, varName, stats)
	default:
		mgr.renderRaceOverview(w, stats)
	}
}

// renderRaceOverview shows the main race reports overview with navigation
func (mgr *Manager) renderRaceOverview(w http.ResponseWriter, stats map[string]interface{}) {
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Race Reports Overview - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .nav-tabs { margin-bottom: 20px; }
        .nav-tabs a { 
            display: inline-block; 
            padding: 10px 20px; 
            margin-right: 5px; 
            background-color: #f1f1f1; 
            text-decoration: none; 
            border: 1px solid #ccc; 
        }
        .nav-tabs a.active { background-color: #007cba; color: white; }
        .stats { background-color: #f9f9f9; padding: 15px; margin-bottom: 20px; }
        .overview-section { margin-bottom: 30px; }
        table { border-collapse: collapse; width: 100%%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Race Reports for %s</h1>
    
    <div class="nav-tabs">
        <a href="/raceReports" class="active">Overview</a>
        <a href="/raceReports?view=groups">VarName Pair Groups</a>
        <a href="/raceReports?view=individual">Individual Reports</a>
    </div>
    
    <div class="stats">
        <h3>总体统计</h3>
        <p>唯一竞争总数: %v</p>
        <p>唯一变量名总数: %v</p>
        <p>总发生次数: %v</p>
        <p>VarName对分组数量: %v</p>
    </div>
    
    <div class="overview-section">
        <h3>快速导航</h3>
        <ul>
            <li><a href="/raceReports?view=groups">按VarName对查看分组</a> - 查看相同变量名对的竞争归类</li>
            <li><a href="/raceReports?view=individual">查看所有单个报告</a> - 详细的时间顺序列表</li>
        </ul>
    </div>
    
    <a href="/">返回主页</a>
</body>
</html>`, mgr.cfg.Name, mgr.cfg.Name,
		stats["total_unique_races"], stats["unique_var_names"], stats["total_occurrences"],
		len(mgr.raceReportManager.GetRaceGroups()))
}

// renderRaceGroups shows races grouped by VarName pairs
func (mgr *Manager) renderRaceGroups(w http.ResponseWriter, selectedGroup string, _ map[string]interface{}) {
	raceGroups := mgr.raceReportManager.GetRaceGroups()

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Race Groups by VarName Pairs - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .nav-tabs { margin-bottom: 20px; }
        .nav-tabs a { 
            display: inline-block; 
            padding: 10px 20px; 
            margin-right: 5px; 
            background-color: #f1f1f1; 
            text-decoration: none; 
            border: 1px solid #ccc; 
        }
        .nav-tabs a.active { background-color: #007cba; color: white; }
        table { border-collapse: collapse; width: 100%%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .varname { font-family: monospace; background-color: #fffacd; }
        .group-details { margin-top: 20px; }
    </style>
</head>
<body>
    <h1>VarName对分组 - %s</h1>
    
    <div class="nav-tabs">
        <a href="/raceReports">Overview</a>
        <a href="/raceReports?view=groups" class="active">VarName Pair Groups</a>
        <a href="/raceReports?view=individual">Individual Reports</a>
    </div>
    
    <h2>按VarName对分组的竞争报告</h2>
    <p>总共 %d 个不同的VarName对</p>
    
    <table>
        <tr>
            <th>VarName1</th>
            <th>VarName2</th>
            <th>报告数量</th>
            <th>首次发现</th>
            <th>最后发现</th>
            <th>操作</th>
        </tr>`, mgr.cfg.Name, mgr.cfg.Name, len(raceGroups))

	for _, group := range raceGroups {
		fmt.Fprintf(w, `
        <tr>
            <td class="varname">%s</td>
            <td class="varname">%s</td>
            <td>%d</td>
            <td>%s</td>
            <td>%s</td>
            <td><a href="/raceReports?view=groups&group=%s">查看详情</a></td>
        </tr>`,
			group.VarName1,
			group.VarName2,
			group.TotalCount,
			group.FirstSeen.Format("2006-01-02 15:04:05"),
			group.LastSeen.Format("2006-01-02 15:04:05"),
			group.VarNameKey)
	}

	fmt.Fprintf(w, `
    </table>`)

	// 如果选择了特定的组，显示详细信息
	if selectedGroup != "" {
		if group, exists := raceGroups[selectedGroup]; exists {
			fmt.Fprintf(w, `
    <div class="group-details">
        <h3>组详情: %s ↔ %s</h3>
        <table>
            <tr>
                <th>时间戳</th>
                <th>报告ID</th>
                <th>块行号</th>
                <th>写入标志</th>
                <th>观察点索引</th>
            </tr>`, group.VarName1, group.VarName2)

			for _, entry := range group.Entries {
				fmt.Fprintf(w, `
            <tr>
                <td>%s</td>
                <td>%s</td>
                <td>%d / %d</td>
                <td>%v / %v</td>
                <td>%d</td>
            </tr>`,
					entry.Timestamp.Format("2006-01-02 15:04:05"),
					entry.ReportID,
					entry.Race.BlockLineNumber1, entry.Race.BlockLineNumber2,
					entry.Race.IsWrite1, entry.Race.IsWrite2,
					entry.Race.WatchpointIndex)
			}

			fmt.Fprintf(w, `
        </table>
    </div>`)
		}
	}

	fmt.Fprintf(w, `
    <br>
    <a href="/raceReports">返回概览</a> | <a href="/">返回主页</a>
</body>
</html>`)
}

// renderIndividualRaces shows individual race reports with optional filtering
func (mgr *Manager) renderIndividualRaces(w http.ResponseWriter, varName string, stats map[string]interface{}) {
	// 获取所有race报告
	allRaces := mgr.raceReportManager.GetAllRaces()

	// 按VarName查询
	var filteredRaces []*ReportedRaceEntry
	if varName != "" {
		filteredRaces = mgr.raceReportManager.GetRacesByVarName(varName)
	} else {
		filteredRaces = allRaces
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Individual Race Reports - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .nav-tabs { margin-bottom: 20px; }
        .nav-tabs a { 
            display: inline-block; 
            padding: 10px 20px; 
            margin-right: 5px; 
            background-color: #f1f1f1; 
            text-decoration: none; 
            border: 1px solid #ccc; 
        }
        .nav-tabs a.active { background-color: #007cba; color: white; }
        table { border-collapse: collapse; width: 100%%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .stats { background-color: #f9f9f9; padding: 10px; margin-bottom: 20px; }
        .varname { font-family: monospace; background-color: #fffacd; }
    </style>
</head>
<body>
    <h1>单个竞争报告 - %s</h1>
    
    <div class="nav-tabs">
        <a href="/raceReports">Overview</a>
        <a href="/raceReports?view=groups">VarName Pair Groups</a>
        <a href="/raceReports?view=individual" class="active">Individual Reports</a>
    </div>
    
    <div class="stats">
        <h3>统计信息</h3>
        <p>总唯一竞争: %v</p>
        <p>唯一变量名: %v</p>
        <p>总发生次数: %v</p>
    </div>
    
    <form method="GET" style="margin-bottom: 20px;">
        <input type="hidden" name="view" value="individual">
        <label for="varname">按VarName过滤:</label>
        <input type="text" id="varname" name="varname" value="%s" placeholder="输入VarName">
        <input type="submit" value="过滤">
        <a href="/raceReports?view=individual">清除过滤</a>
    </form>
    
    <h2>竞争报告 (共%d个)</h2>
    <table>
        <tr>
            <th>时间戳</th>
            <th>报告ID</th>
            <th>VarName1</th>
            <th>VarName2</th>
            <th>块行号</th>
            <th>写入标志</th>
            <th>观察点索引</th>
            <th>次数</th>
        </tr>`,
		mgr.cfg.Name, mgr.cfg.Name,
		stats["total_unique_races"], stats["unique_var_names"], stats["total_occurrences"],
		varName, len(filteredRaces))

	for _, entry := range filteredRaces {
		fmt.Fprintf(w, `
        <tr>
            <td>%s</td>
            <td>%s</td>
            <td class="varname">%s</td>
            <td class="varname">%s</td>
            <td>%d / %d</td>
            <td>%v / %v</td>
            <td>%d</td>
            <td>%d</td>
        </tr>`,
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			entry.ReportID,
			entry.Race.VarName1,
			entry.Race.VarName2,
			entry.Race.BlockLineNumber1, entry.Race.BlockLineNumber2,
			entry.Race.IsWrite1, entry.Race.IsWrite2,
			entry.Race.WatchpointIndex,
			entry.Count)
	}

	fmt.Fprintf(w, `
    </table>
    <br>
    <a href="/raceReports">返回概览</a> | <a href="/">返回主页</a>
</body>
</html>`)
}

// httpFuzzScheduler displays the fuzz scheduler status and statistics
func (mgr *Manager) httpFuzzScheduler(w http.ResponseWriter, r *http.Request) {
	stats := mgr.fuzzScheduler.GetPhaseStats()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>Fuzz Scheduler Status</title>
    <style>
        table { border-collapse: collapse; width: 100%%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .phase-normal { background-color: #e8f5e8; }
        .phase-race { background-color: #fff8e8; }
    </style>
</head>
<body>
    <h1>Fuzz Scheduler Status</h1>
    
    <h2>Current Phase Information</h2>
    <table>
        <tr><th>Parameter</th><th>Value</th></tr>`)

	// 显示当前阶段信息
	currentPhase := stats["current_phase"].(FuzzPhase)
	phaseClass := "phase-normal"
	phaseName := "Normal Fuzz"
	if currentPhase == PhaseRaceFuzz {
		phaseName = "Race Fuzz"
		phaseClass = "phase-race"
	}

	fmt.Fprintf(w, `
        <tr class="%s"><td>Current Phase</td><td><strong>%s</strong></td></tr>
        <tr><td>Phase Start Time</td><td>%v</td></tr>
        <tr><td>Phase Runtime</td><td>%v</td></tr>
        <tr><td>Normal Fuzz Enabled</td><td>%v</td></tr>
        <tr><td>Race Fuzz Enabled</td><td>%v</td></tr>
    </table>
    
    <h2>Signal Statistics</h2>
    <table>
        <tr><th>Signal Type</th><th>Count</th><th>Last Update</th><th>Stable Time</th></tr>`,
		phaseClass, phaseName,
		stats["phase_start_time"],
		stats["phase_runtime"],
		stats["normal_fuzz_enabled"],
		stats["race_fuzz_enabled"])

	fmt.Fprintf(w, `
        <tr><td>Normal Signal</td><td>%v</td><td>%v</td><td>%v</td></tr>
        <tr><td>Race Signal</td><td>%v</td><td>%v</td><td>%v</td></tr>
    </table>
    
    <h2>Phase Logic</h2>
    <p><strong>Normal Fuzz Phase:</strong> Runs until signal is stable for 5 minutes OR 1 hour elapsed</p>
    <p><strong>Race Fuzz Phase:</strong> Runs until race signal is stable for 5 minutes OR 1 hour elapsed</p>
    <p>Race detection and collection are <strong>disabled</strong> during Normal Fuzz phase for performance.</p>
    
    <br>
    <a href="/">Back to Summary</a>
</body>
</html>`,
		stats["last_signal_count"],
		stats["last_signal_update"],
		stats["signal_stable_time"],
		stats["last_race_signal_count"],
		stats["last_race_signal_update"],
		stats["race_signal_stable_time"])
}

// httpRacePairCoverage displays race pair coverage statistics and discovered pairs
func (mgr *Manager) httpRacePairCoverage(w http.ResponseWriter, r *http.Request) {
	viewType := r.URL.Query().Get("view")
	lockStatus := r.URL.Query().Get("status")

	stats := mgr.racePairCoverageManager.GetStatistics()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	switch viewType {
	case "pairs":
		mgr.renderRacePairs(w, lockStatus, stats)
	default:
		mgr.renderRacePairOverview(w, stats)
	}
}

// renderRacePairOverview shows the race pair coverage overview
func (mgr *Manager) renderRacePairOverview(w http.ResponseWriter, stats map[string]interface{}) {
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Race Pair Coverage - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .nav-tabs { margin-bottom: 20px; }
        .nav-tabs a { 
            display: inline-block; 
            padding: 10px 20px; 
            margin-right: 5px; 
            background-color: #f1f1f1; 
            text-decoration: none; 
            border: 1px solid #ccc; 
        }
        .nav-tabs a.active { background-color: #007cba; color: white; }
        .stats { background-color: #f9f9f9; padding: 15px; margin-bottom: 20px; }
        .status-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-top: 20px; }
        .status-card { 
            border: 1px solid #ddd; 
            padding: 15px; 
            background-color: white; 
            border-radius: 5px; 
        }
        .status-card h3 { margin-top: 0; color: #007cba; }
    </style>
</head>
<body>
    <h1>Race Pair Coverage - %s</h1>
    
    <div class="nav-tabs">
        <a href="/racePairCoverage" class="active">Overview</a>
        <a href="/racePairCoverage?view=pairs">All Pairs</a>
        <a href="/raceReports">Race Reports</a>
        <a href="/fuzzScheduler">Fuzz Scheduler</a>
    </div>
    
    <div class="stats">
        <h3>总体统计</h3>
        <p>启用状态: %v</p>
        <p>总Race Pair数量: %v</p>
        <p>总覆盖率信号: %v</p>
    </div>
    
    <h3>按锁状态分类</h3>
    <div class="status-grid">`, mgr.cfg.Name, mgr.cfg.Name,
		stats["enabled"], stats["total_race_pairs"], stats["total_signal"])

	if lockStats, ok := stats["lock_status_stats"].(map[string]int); ok {
		statusColors := map[string]string{
			"No Locks":                   "#ff6b6b",
			"One-Sided Lock":             "#ffa726",
			"Unsynchronized Locks":       "#ffcc02",
			"Synchronized (Common Lock)": "#66bb6a",
		}

		for status, count := range lockStats {
			color := statusColors[status]
			if color == "" {
				color = "#757575"
			}

			fmt.Fprintf(w, `
        <div class="status-card" style="border-left: 4px solid %s;">
            <h3>%s</h3>
            <p>数量: %d</p>
            <p><a href="/racePairCoverage?view=pairs&status=%s">查看详情</a></p>
        </div>`, color, status, count, status)
		}
	}

	fmt.Fprintf(w, `
    </div>
    
    <a href="/">返回主页</a>
</body>
</html>`)
}

// renderRacePairs shows individual race pairs with optional filtering
func (mgr *Manager) renderRacePairs(w http.ResponseWriter, statusFilter string, _ map[string]interface{}) {
	var pairs []*RacePair

	if statusFilter != "" {
		// Parse status filter
		var filterStatus LockStatus
		switch statusFilter {
		case "No Locks":
			filterStatus = NoLocks
		case "One-Sided Lock":
			filterStatus = OneSidedLock
		case "Unsynchronized Locks":
			filterStatus = UnsyncLocks
		case "Synchronized (Common Lock)":
			filterStatus = SyncWithCommonLock
		default:
			pairs = mgr.racePairCoverageManager.GetAllRacePairs()
		}

		if statusFilter != "" {
			pairs = mgr.racePairCoverageManager.GetRacePairsByLockStatus(filterStatus)
		}
	} else {
		pairs = mgr.racePairCoverageManager.GetAllRacePairs()
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Race Pairs - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .nav-tabs { margin-bottom: 20px; }
        .nav-tabs a { 
            display: inline-block; 
            padding: 10px 20px; 
            margin-right: 5px; 
            background-color: #f1f1f1; 
            text-decoration: none; 
            border: 1px solid #ccc; 
        }
        .nav-tabs a.active { background-color: #007cba; color: white; }
        table { border-collapse: collapse; width: 100%%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .varname { font-family: monospace; background-color: #fffacd; }
        .status-no-locks { background-color: #ffebee; }
        .status-one-sided { background-color: #fff3e0; }
        .status-unsync { background-color: #fffde7; }
        .status-sync { background-color: #e8f5e8; }
    </style>
</head>
<body>
    <h1>Race Pairs - %s</h1>
    
    <div class="nav-tabs">
        <a href="/racePairCoverage">Overview</a>
        <a href="/racePairCoverage?view=pairs" class="active">All Pairs</a>
        <a href="/raceReports">Race Reports</a>
        <a href="/fuzzScheduler">Fuzz Scheduler</a>
    </div>
    
    <h2>发现的Race Pairs (共%d个)</h2>
    <p>过滤条件: %s</p>
    
    <table>
        <tr>
            <th>VarName1</th>
            <th>VarName2</th>
            <th>访问类型</th>
            <th>锁状态</th>
            <th>触发次数</th>
            <th>时间差(ns)</th>
            <th>首次发现</th>
            <th>最后发现</th>
        </tr>`, mgr.cfg.Name, mgr.cfg.Name, len(pairs), statusFilter)

	for _, pair := range pairs {
		var statusClass string
		switch pair.LockStatus {
		case NoLocks:
			statusClass = "status-no-locks"
		case OneSidedLock:
			statusClass = "status-one-sided"
		case UnsyncLocks:
			statusClass = "status-unsync"
		case SyncWithCommonLock:
			statusClass = "status-sync"
		}

		fmt.Fprintf(w, `
        <tr class="%s">
            <td class="varname">%d</td>
            <td class="varname">%d</td>
            <td>%c ↔ %c</td>
            <td>%s</td>
            <td>%d</td>
            <td>%d</td>
            <td>%s</td>
            <td>%s</td>
        </tr>`, statusClass,
			pair.First.VarName, pair.Second.VarName,
			pair.First.AccessType, pair.Second.AccessType,
			pair.LockStatus.String(),
			pair.TriggerCounts,
			pair.AccessTimeDiff,
			pair.FirstSeen.Format("2006-01-02 15:04:05"),
			pair.LastSeen.Format("2006-01-02 15:04:05"))
	}

	fmt.Fprintf(w, `
    </table>
    
    <br>
    <a href="/racePairCoverage">返回概览</a> | <a href="/">返回主页</a>
</body>
</html>`)
}
