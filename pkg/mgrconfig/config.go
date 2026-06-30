// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"encoding/json"

	"github.com/google/syzkaller/pkg/asset"
)

type Config struct {
	// Instance name (used for identification and as GCE instance prefix).
	Name string `json:"name"`
	// Target OS/arch, e.g. "linux/arm64" or "linux/amd64/386" (amd64 OS with 386 test process).
	RawTarget string `json:"target"`
	// URL that will display information about the running syz-manager process (e.g. "localhost:50000").
	HTTP string `json:"http"`
	// TCP address to serve RPC for fuzzer processes (optional).
	RPC string `json:"rpc,omitempty"`
	// Location of a working directory for the syz-manager process. Outputs here include:
	// - <workdir>/crashes/*: crash output files
	// - <workdir>/corpus.db: corpus with interesting programs
	// - <workdir>/instance-x: per VM instance temporary files
	Workdir string `json:"workdir"`
	// Refers to a directory. Optional.
	// Each VM will get a recursive copy of the files that are present in workdir_template.
	// VM config can then use these private copies as needed. The copy directory
	// can be referenced with "{{TEMPLATE}}" string. This is different from using
	// the files directly in that each instance will get own clean, private,
	// scratch copy of the files. Currently supported only for qemu_args argument
	// of qemu VM type. Use example:
	// Create a template dir with necessary files:
	// $ mkdir /mytemplatedir
	// $ truncate -s 64K /mytemplatedir/fd
	// Then specify the dir in the manager config:
	//	"workdir_template": "/mytemplatedir"
	// Then use these files in VM config:
	//	"qemu_args": "-fda {{TEMPLATE}}/fd"
	WorkdirTemplate string `json:"workdir_template,omitempty"`
	// Directory with kernel object files (e.g. `vmlinux` for linux)
	// (used for report symbolization, coverage reports and in tree modules finding, optional).
	KernelObj string `json:"kernel_obj"`
	// Optional explicit path to the kernel object file (e.g. vmlinux). If set,
	// syzkaller uses this file instead of deriving the path from KernelObj and
	// the target's default kernel object name.
	Vmlinux string `json:"vmlinux,omitempty"`
	// Directories with out-of-tree kernel module object files for coverage report generation (optional).
	// KernelObj is also scanned for in-tree kernel modules and does not need to be duplicated here.
	// Note: the modules need to be unstripped and contain debug info.
	ModuleObj []string `json:"module_obj,omitempty"`
	// Kernel source directory (if not set defaults to KernelObj).
	KernelSrc string `json:"kernel_src,omitempty"`
	// Location of the driectory where the kernel was built (if not set defaults to KernelSrc)
	KernelBuildSrc string `json:"kernel_build_src,omitempty"`
	// Is the kernel built separately from the modules? (Specific to Android builds)
	AndroidSplitBuild bool `json:"android_split_build"`
	// Kernel subsystem with paths to each subsystem, paths starting with "-" will be excluded
	//	"kernel_subsystem": [
	//		{ "name": "sound", "path": ["sound", "techpack/audio", "-techpack/audio/dsp"]},
	//		{ "name": "mydriver": "path": ["mydriver_path"]}
	//	]
	KernelSubsystem []Subsystem `json:"kernel_subsystem,omitempty"`
	// Arbitrary optional tag that is saved along with crash reports (e.g. branch/commit).
	Tag string `json:"tag,omitempty"`
	// Location of the disk image file.
	Image string `json:"image,omitempty"`
	// Location (on the host machine) of a root SSH identity to use for communicating with
	// the virtual machine (may be empty for some VM types).
	SSHKey string `json:"sshkey,omitempty"`
	// SSH user ("root" by default).
	SSHUser string `json:"ssh_user,omitempty"`

	HubClient string `json:"hub_client,omitempty"`
	HubAddr   string `json:"hub_addr,omitempty"`
	HubKey    string `json:"hub_key,omitempty"`
	// Hub input domain identifier (optional).
	// The domain is used to avoid duplicate work (input minimization, smashing)
	// across multiple managers testing similar kernels and connected to the same hub.
	// If two managers are in the same domain, they will not do input minimization after each other.
	// If additionally they are in the same smashing sub-domain, they will also not do smashing
	// after each other.
	// By default (empty domain) all managers testing the same OS are placed into the same domain,
	// this is a reasonable setting if managers test roughly the same kernel. In this case they
	// will not do minimization nor smashing after each other.
	// The setting can be either a single identifier (e.g. "foo") which will affect both minimization
	// and smashing; or two identifiers separated with '/' (e.g. "foo/bar"), in this case the first
	// identifier affects minimization and both affect smashing.
	// For example, if managers test different Linux kernel versions with different tools,
	// a reasonable use of domains on these managers can be:
	//  - "upstream/kasan"
	//  - "upstream/kmsan"
	//  - "upstream/kcsan"
	//  - "5.4/kasan"
	//  - "5.4/kcsan"
	//  - "4.19/kasan"
	HubDomain string `json:"hub_domain,omitempty"`

	// List of email addresses to receive notifications when bugs are encountered for the first time (optional).
	// Mailx is the only supported mailer. Please set it up prior to using this function.
	EmailAddrs []string `json:"email_addrs,omitempty"`

	DashboardClient    string `json:"dashboard_client,omitempty"`
	DashboardAddr      string `json:"dashboard_addr,omitempty"`
	DashboardKey       string `json:"dashboard_key,omitempty"`
	DashboardUserAgent string `json:"dashboard_user_agent,omitempty"`
	// If set, only consult dashboard if it needs reproducers for crashes,
	// but otherwise don't send any info to dashboard (default: false).
	DashboardOnlyRepro bool `json:"dashboard_only_repro,omitempty"`

	// Location of the syzkaller checkout, syz-manager will look
	// for binaries in bin subdir (does not have to be syzkaller checkout as
	// long as it preserves `bin` dir structure)
	Syzkaller string `json:"syzkaller"`

	// Number of parallel test processes inside of each VM.
	// Allowed values are 1-32, recommended range is ~4-8, default value is 6.
	// It should be chosen to saturate CPU inside of the VM and maximize number of test executions,
	// but to not oversubscribe CPU and memory too severe to not cause OOMs and false hangs/stalls.
	Procs int `json:"procs"`

	// Maximum number of logs to store per crash (default: 100).
	MaxCrashLogs int `json:"max_crash_logs"`

	// Type of sandbox to use during fuzzing:
	// "none": test under root;
	//      don't do anything special beyond resource sandboxing,
	//      gives the most coverage, default
	// "namespace": create a new user namespace for testing using CLONE_NEWUSER (supported only on Linux),
	//      the test process has CAP_ADMIN inside of the user namespace, but not in the init namespace,
	//      but the test process still has access to all /dev/ nodes owned by root,
	//      this is a compromise between coverage and bug impact,
	//	requires building kernel with CONFIG_USER_NS
	// "setuid": impersonate into user nobody (65534) (supported on Linux, FreeBSD, NetBSD, OpenBSD)
	//      this is the most restrictive sandbox
	// "android": emulate permissions of an untrusted Android app (supported only on Linux)
	Sandbox string `json:"sandbox"`

	// This value is passed as an argument to executor and allows to adjust sandbox behavior
	// via manager config. For example you can switch between system and user accounts based
	// on this value.
	SandboxArg int64 `json:"sandbox_arg"`

	// VM running time timeout in seconds (default: 3600, i.e. 1 hour).
	// After this time the VM is restarted to avoid accumulated state.
	VMRunningTime int `json:"vm_running_time,omitempty"`

	// Enables snapshotting mode. In this mode VM is snapshotted and restarted from the snapshot
	// before executing each test program. This provides better reproducibility and avoids global
	// accumulated state. Currently only qemu VMs and Linux support this mode.
	Snapshot bool `json:"snapshot"`

	// Use KCOV coverage (default: true).
	Cover bool `json:"cover"`

	// CovFilter used to restrict the area of the kernel visible to syzkaller.
	// DEPRECATED! Use the FocusAreas parameter instead.
	CovFilter CovFilterCfg `json:"cover_filter,omitempty"`

	// For each prog in the corpus, remember the raw array of PCs obtained from the kernel.
	// It can be useful for debugging syzkaller descriptions and syzkaller itself.
	// Disabled by default as it slows down fuzzing.
	RawCover bool `json:"raw_cover"`

	// Reproduce, localize and minimize crashers (default: true).
	Reproduce bool `json:"reproduce"`

	// The number of VMs that are reserved to only perform fuzzing and nothing else.
	// Can be helpful e.g. to ensure that the pool of fuzzing VMs is never exhausted and
	// the manager continues fuzzing no matter how many new bugs are encountered.
	// By default the value is 0, i.e. all VMs can be used for all purposes.
	FuzzingVMs int `json:"fuzzing_vms,omitempty"`

	// Keep existing programs in the corpus even if they no longer pass syscall filters.
	// By default it is true, as this is the desired behavior when executing syzkaller
	// locally.
	PreserveCorpus bool `json:"preserve_corpus"`

	// List of syscalls to test (optional). For example:
	//	"enable_syscalls": [ "mmap", "openat$ashmem", "ioctl$ASHMEM*" ]
	EnabledSyscalls []string `json:"enable_syscalls,omitempty"`
	// List of system calls that should be treated as disabled (optional).
	DisabledSyscalls []string `json:"disable_syscalls,omitempty"`
	// List of syscalls that should not be mutated by the fuzzer (optional).
	NoMutateSyscalls []string `json:"no_mutate_syscalls,omitempty"`
	// List of regexps for known bugs.
	// Don't save reports matching these regexps, but reboot VM after them,
	// matched against whole report output.
	Suppressions []string `json:"suppressions,omitempty"`
	// Completely ignore reports matching these regexps (don't save nor reboot),
	// must match the first line of crash message.
	Ignores []string `json:"ignores,omitempty"`
	// Ignore kernel WARNING splats (first line contains the word WARNING) entirely.
	IgnoreWarningCrashes bool `json:"ignore_warning_crashes,omitempty"`
	// List of regexps to select bugs of interest.
	// If this list is not empty and none of the regexps match a bug, it's suppressed.
	// Regexps are matched against bug title, guilty file and maintainer emails.
	Interests []string `json:"interests,omitempty"`

	// Path to the strace binary compiled for the target architecture.
	// If set, for each reproducer syzkaller will run it once more under strace and save
	// the output.
	StraceBin string `json:"strace_bin"`
	// If true, syzkaller will expect strace_bin to be part of the target
	// image instead of copying it from the host (default: false).
	StraceBinOnTarget bool `json:"strace_bin_on_target"`

	// File in PATH to syz-execprog/executor on the target. If set,
	// syzkaller will expect the execprog/executor binaries to be part of
	// the target image instead of copying them from the host.
	ExecprogBinOnTarget string `json:"execprog_bin_on_target"`
	ExecutorBinOnTarget string `json:"executor_bin_on_target"`

	// Whether to run fsck commands on file system images found in new crash
	// reproducers. The fsck logs get reported as assets in the dashboard.
	// Note: you may need to install 3rd-party dependencies for this to work.
	// fsck commands that can be run by syz-manager are specified in mount
	// syscall descriptions - typically in sys/linux/filesystem.txt.
	// Enabled by default.
	RunFsck bool `json:"run_fsck"`

	// Type of virtual machine to use, e.g. "qemu", "gce", "android", "isolated", etc.
	Type string `json:"type"`
	// VM-type-specific parameters.
	// Parameters for concrete types are in Config type in vm/TYPE/TYPE.go, e.g. vm/qemu/qemu.go.
	VM json.RawMessage `json:"vm"`

	// Asset storage configuration. There can be specified the upload location and crash assets
	// to upload.
	// A sample config:
	// {
	//    "upload_to": "gs://bucket",
	//    "public_access": true
	// }
	// More details can be found in pkg/asset/config.go.
	AssetStorage *asset.Config `json:"asset_storage"`

	// Experimental options.
	Experimental Experimental

	// Implementation details beyond this point. Filled after parsing.
	Derived `json:"-"`
}

// These options are not guaranteed to be backward/forward compatible and
// can be dropped at any moment.
type Experimental struct {
	// Don't let the VM state accumulate too much by restarting
	// syz-executor before most prog executions.
	ResetAccState bool `json:"reset_acc_state"`

	// Use KCOV remote coverage feature (default: true).
	RemoteCover bool `json:"remote_cover"`

	// Hash adjacent PCs to form fuzzing feedback signal, otherwise use PCs as signal (default: true).
	CoverEdges bool `json:"cover_edges"`

	// Use automatically (auto) generated or manually (manual) written descriptions or any (any) (default: manual)
	DescriptionsMode string `json:"descriptions_mode"`

	// FocusAreas configures what attention syzkaller should pay to the specific areas of the kernel.
	// The probability of selecting a program from an area is at least `Weight / sum of weights`.
	// If FocusAreas is non-empty, by default all kernel code not covered by any filter will be ignored.
	// To focus fuzzing on some areas, but to consider the rest of the code as well, add a record
	// with an empty Filter, but non-empty weight.
	// E.g. "focus_areas": [ {"filter": {"files": ["^net"]}, "weight": 10.0}, {"weight": 1.0} ].
	FocusAreas []FocusArea `json:"focus_areas,omitempty"`

	// Enable dynamic discovery and fuzzing of KFuzzTest targets.
	EnableKFuzzTest bool `json:"enable_kfuzztest"`

	// Enable synchronized barrier execution for fuzzing requests. When enabled,
	// barrier_procs must specify at least two executor proc indices.
	BarrierMode        bool    `json:"barrier_mode"`
	BarrierProcs       []int   `json:"barrier_procs,omitempty"`
	ThreadBarrier      bool    `json:"thread_barrier"`
	ThreadBarrierRatio float64 `json:"thread_barrier_ratio,omitempty"`

	// Enable the UAF-focused fuzzing mode that prioritizes DDRD results.
	UAFMode bool `json:"uaf_mode"`

	// Configure the UAF validation pipeline.
	UAFValidate *UAFValidateConfig `json:"uaf_validate,omitempty"`
	// DisableUAFValidateQueue keeps fuzzing from maintaining the persistent
	// validation queue/pair-index when no uaf_validate consumer is configured.
	// uaf_validate mode always enables the queue because it is the consumer input.
	DisableUAFValidateQueue bool `json:"disable_uaf_validate_queue,omitempty"`
	// SkipUAFActivationRestart avoids restarting all VMs when startup candidate
	// triage hands off to DDRD race fuzzing. This is intended for throughput-only
	// runs that do not consume clean validation state.
	SkipUAFActivationRestart bool `json:"skip_uaf_activation_restart,omitempty"`
	// DisableUAFHistory disables per-VM replay-history recording for discovered
	// race pairs. It removes hot-path program cloning when validation replay
	// history is not part of the experiment.
	DisableUAFHistory bool `json:"disable_uaf_history,omitempty"`

	// Skip duplicate data race reports once they've been observed.
	// When enabled, syz-manager keeps an in-memory cache of data race signatures
	// and asks VM monitors to ignore matches in that cache so that fuzzing
	// continues without rebooting the VM for already-known races.
	SkipDuplicateDataRaces bool `json:"skip_duplicate_data_races,omitempty"`
	// Bounded size for the duplicate data race signature cache. Older entries
	// are discarded once the limit is exceeded (default: 10000).
	MaxDataRaceCombinations int `json:"max_data_race_combinations,omitempty"`

	// Enable DDRD monitor mode for background race detection.
	// When enabled, the executor initializes UKC in monitor mode once at startup
	// and keeps it running throughout fuzzing. This allows passive race detection
	// without switching modes between tests.
	DdrdMonitor bool `json:"ddrd_monitor,omitempty"`

	// HistoryBufferSize specifies the size of the rolling buffer for barrier execution history.
	// This buffer maintains the last N barrier program groups during fuzzing (per VM).
	// Defaults to 1000 if unset or zero.
	HistoryBufferSize int `json:"history_buffer_size,omitempty"`
	// NewVarNamePairHistory specifies how many history records to save when a NEW VarName pair is discovered.
	// When a completely new (FreeAccessName, UseAccessName) combination is found,
	// all records up to this count are saved with the entry for replay during validation.
	// Defaults to 1000 if unset or zero.
	NewVarNamePairHistory int `json:"new_varname_pair_history,omitempty"`
	// NewStackHistory specifies how many history records to save when a new stack is discovered for an existing VarName pair.
	// When a new (FreeCallStack, UseCallStack) is found for an already-known VarName pair,
	// this many records are saved with the entry.
	// Defaults to 100 if unset or zero.
	NewStackHistory int `json:"new_stack_history,omitempty"`
	// MaxStacksPerVarNamePair limits how many unique (callstack1, callstack2) combinations
	// are tracked for each (FreeAccessName, UseAccessName) pair.
	// Once this limit is reached for a VarName pair, new stack combinations are ignored.
	// Defaults to 20 if unset or zero.
	MaxStacksPerVarNamePair int `json:"max_stacks_per_varname_pair,omitempty"`
	// NewVarNamePairAffinityWeight is the affinity score weight for discovering a NEW VarName pair.
	// When a syscall combination discovers a completely new (FreeAccessName, UseAccessName) pair,
	// the interaction is recorded with this weight to prioritize such combinations.
	// Defaults to 5 if unset or zero.
	NewVarNamePairAffinityWeight int `json:"new_varname_pair_affinity_weight,omitempty"`
	// NewStackAffinityWeight is the affinity score weight for discovering a new stack for existing VarName pair.
	// When a syscall combination discovers a new callstack for an already-known VarName pair,
	// the interaction is recorded with this weight.
	// Defaults to 1 if unset or zero.
	NewStackAffinityWeight int `json:"new_stack_affinity_weight,omitempty"`

	// Deprecated: CooldownThreshold is no longer used (M1'/M2 removed). Kept for config compatibility.
	CooldownThreshold int `json:"cooldown_threshold,omitempty"`
	// Deprecated: NewStackPenalty is no longer used (M1'/M2 removed). Kept for config compatibility.
	NewStackPenalty int `json:"new_stack_penalty,omitempty"`
	// Deprecated: NoDiscoveryPenalty is no longer used (M1'/M2 removed). Kept for config compatibility.
	NoDiscoveryPenalty int `json:"no_discovery_penalty,omitempty"`

	// EnableSoloFilter controls the legacy solo re-execution filter in UAF mode.
	// When enabled, every newly discovered barrier pair is followed by two solo
	// DDRD executions to filter out intra-program pairs before persistence.
	// Defaults to false; MRPFuzz's paper path treats May-Race Pairs as the
	// discovery artifact and leaves confirmation to the validation phase.
	EnableSoloFilter bool `json:"enable_solo_filter,omitempty"`
	// EnableCoverageTriage controls legacy pair-level coverage triage jobs in UAF mode.
	// Defaults to false when unset. Set to true only for legacy feedback
	// experiments that intentionally pay extra solo-execution cost.
	EnableCoverageTriage *bool `json:"enable_coverage_triage,omitempty"`
	// EnableAffinityTable controls the legacy syscall affinity table in UAF mode.
	// Defaults to false in the paper path and is useful only when legacy solo
	// filtering or coverage triage is explicitly enabled.
	EnableAffinityTable *bool `json:"enable_affinity_table,omitempty"`

	// StaticInputExploration makes UAF input exploration sample concurrent program
	// groups from the loaded corpus/candidate pool directly. It skips startup
	// candidate triage and disables normal single-program mutation/generation in
	// the UAF exploration source.
	StaticInputExploration bool `json:"static_input_exploration,omitempty"`
	// StaticInputSeed controls deterministic sampling from the static input pool.
	// Zero uses a fixed default seed.
	StaticInputSeed int64 `json:"static_input_seed,omitempty"`
	// StaticInputSkipBuiltinSeeds prevents sys/<os>/test seeds from being added to
	// the frozen static input pool. This keeps MRPFuzz ablations tied exactly to a
	// prepared shared corpus database.
	StaticInputSkipBuiltinSeeds bool `json:"static_input_skip_builtin_seeds,omitempty"`
	// LLMInputSeedDir is an offline-pilot hook: when set, syz-manager loads exact
	// two-program groups from this directory and enqueues them as high-priority UAF
	// barrier requests after static input exploration is activated. Normal fuzzing
	// is unchanged unless this field is explicitly configured.
	LLMInputSeedDir string `json:"llm_input_seed_dir,omitempty"`
	// LLMInputSeedPollSec enables continuous polling of LLMInputSeedDir for new
	// parser-filtered seed groups. Zero preserves the offline-pilot behavior of
	// loading the directory only once at UAF activation time.
	LLMInputSeedPollSec int `json:"llm_input_seed_poll_sec,omitempty"`
	// LLMInputSeedMaxPerPoll limits how many new seed groups are enqueued during
	// each poll. Zero means no explicit limit.
	LLMInputSeedMaxPerPoll int `json:"llm_input_seed_max_per_poll,omitempty"`

	// RandomBaselineMode marks a baseline run and forces timing exploration off.
	// Other mechanisms, such as affinity learning and object linking, remain enabled
	// unless they are disabled by their own explicit config knobs.
	RandomBaselineMode bool `json:"random_baseline_mode,omitempty"`

	// EnableObjectLinking enables resource-aware cross-syscall object linking (ObjectLinker V2).
	// When disabled, concurrent program pairs will not have their object identifiers unified,
	// which is useful for ablation experiments measuring the contribution of resource-aware
	// program group generation. Defaults to true when uaf_mode is enabled.
	EnableObjectLinking *bool `json:"enable_object_linking,omitempty"`
	// ObjectLinkAttemptRatio controls how often partner-program generation attempts
	// ObjectLinker V2 when object linking is enabled. Values in (0,1] are honored;
	// other values fall back to the default 1.0.
	ObjectLinkAttemptRatio float64 `json:"object_link_attempt_ratio,omitempty"`

	// NoObjectKccwfNamespace rewrites kccwf object names per partner program when
	// object linking is disabled. This keeps intra-program file references coherent
	// while avoiding accidental same-object reuse from the fixed kccwf path pool.
	NoObjectKccwfNamespace bool `json:"no_object_kccwf_namespace,omitempty"`
	// IsolateKccwfPartnerObjects rewrites kccwf object names per partner program
	// before optional ObjectLinker alignment. This removes fixed-name sharing as
	// a hidden baseline so ObjectLinker must explicitly align fs objects.
	IsolateKccwfPartnerObjects bool `json:"isolate_kccwf_partner_objects,omitempty"`

	// EnableStateScopeGuidance constructs concurrent program groups according to
	// overlapping kernel state scopes instead of only exact user-visible object
	// identifiers.
	EnableStateScopeGuidance bool `json:"enable_state_scope_guidance,omitempty"`
	// StateScopeGuidanceRatio controls how often state-scope partner selection is
	// used in barrier mode. Values in (0,1] are honored.
	StateScopeGuidanceRatio float64 `json:"state_scope_guidance_ratio,omitempty"`
	// StateScopeSameInstanceRatio is the operator budget for exact same-instance
	// alignment inside state-scope guidance. Zero disables exact alignment.
	StateScopeSameInstanceRatio float64 `json:"state_scope_same_instance_ratio,omitempty"`
	// StateScopePartnerSamples controls candidate sampling width for the guided
	// partner selector.
	StateScopePartnerSamples int `json:"state_scope_partner_samples,omitempty"`

	// ======== Dual-Queue Timing Exploration Configuration ========
	// EnableTimingExploration enables the timing exploration queue for race optimization.
	// When enabled, newly discovered VarName pairs are enqueued for timing optimization
	// using either syz_delay() syscalls or barrier start-delay resampling.
	// Defaults to false if unset.
	EnableTimingExploration bool `json:"enable_timing_exploration,omitempty"`
	// Deprecated: EnablePartnerSelection is no longer used (M1' removed). Kept for config compatibility.
	EnablePartnerSelection bool `json:"enable_partner_selection,omitempty"`
	// Deprecated: EnableRaceYieldFeedback is no longer used (M2 removed). Kept for config compatibility.
	EnableRaceYieldFeedback bool `json:"enable_race_yield_feedback,omitempty"`
	// TimingExplorationQueueSize is the max size of the timing exploration queue.
	// Defaults to 500 if unset or zero.
	TimingExplorationQueueSize int `json:"timing_exploration_queue_size,omitempty"`
	// TimingExplorationRatio is the fraction of executions for timing exploration (0.0-1.0).
	// Defaults to 0.1 (10%) if unset or zero.
	TimingExplorationRatio float64 `json:"timing_exploration_ratio,omitempty"`
	// DelayMinMicros is the minimum delay in microseconds for syz_delay()
	// or barrier start-delay timing exploration.
	// Defaults to 10 if unset or zero.
	DelayMinMicros int64 `json:"delay_min_micros,omitempty"`
	// DelayMaxMicros is the maximum delay in microseconds for syz_delay()
	// or barrier start-delay timing exploration.
	// Defaults to 200000 (200ms) if unset or zero.
	DelayMaxMicros int64 `json:"delay_max_micros,omitempty"`
	// MaxDelaysPerProgram limits syz_delay() calls per program.
	// Defaults to 5 if unset or zero.
	MaxDelaysPerProgram int `json:"max_delays_per_program,omitempty"`
	// TimingMutationStrategy specifies the timing mutation/resampling strategy.
	// Options: "random", "targeted", "binary_search", "timediff", "start_delay"
	// Defaults to "targeted" if unset.
	TimingMutationStrategy string `json:"timing_mutation_strategy,omitempty"`
	// NormalThresholdMicros overrides the default 10ms threshold for DDRD pair detection
	// during normal fuzzing requests. 0 uses the executor default.
	NormalThresholdMicros int64 `json:"normal_threshold_micros,omitempty"`
	// WidenedThresholdMicros is the widened timing threshold for exploration queue (microseconds).
	// This allows timing exploration to detect pairs with larger timediff that normal threshold misses.
	// When dynamic threshold is enabled, this acts as the minimum Phase 1 discovery window.
	// The generic fallback is 500000 (500ms); current MRPFuzz experiment configs set 20000.
	WidenedThresholdMicros int64 `json:"widened_threshold_micros,omitempty"`
	// MaxAttemptsPerPair is the maximum number of timing exploration attempts per unique pair.
	// Defaults to 20 if unset or zero.
	MaxAttemptsPerPair int `json:"max_attempts_per_pair,omitempty"`
	// MaxCorpusCountPerVarName: if a VarName pair already has this many entries
	// in the corpus, skip timing exploration for it. 0 means no limit.
	// This prevents wasting resources on common pairs that are already well-covered.
	MaxCorpusCountPerVarName int `json:"max_corpus_count_per_varname,omitempty"`
	// SuccessThreshold is the trigger rate threshold to consider exploration successful (0.0-1.0).
	// Defaults to 0.1 (10%) if unset or zero.
	SuccessThreshold float64 `json:"success_threshold,omitempty"`
	// ExecutionsPerAttempt is how many times to execute each delay plan.
	// Defaults to 5 if unset or zero.
	ExecutionsPerAttempt int `json:"executions_per_attempt,omitempty"`

	// ======== Dynamic Threshold Configuration ========
	// EnableDynamicThreshold enables dynamic MRP time threshold adjustment
	// based on validator supply-demand balancing.
	EnableDynamicThreshold bool `json:"enable_dynamic_threshold,omitempty"`
	// DynamicThresholdInitialUs is the starting threshold (microseconds).
	// Generic fallback: 1000 (1ms). Current MRPFuzz experiment configs set 2500.
	// Overrides NormalThresholdMicros when dynamic threshold is enabled.
	DynamicThresholdInitialUs int64 `json:"dynamic_threshold_initial_us,omitempty"`
	// DynamicThresholdMinUs is the minimum threshold (microseconds).
	// Generic fallback: 50. Current MRPFuzz experiment configs set 500.
	DynamicThresholdMinUs int64 `json:"dynamic_threshold_min_us,omitempty"`
	// DynamicThresholdMaxUs is the maximum threshold (microseconds).
	// Generic fallback: 50000 (50ms). Current MRPFuzz experiment configs set 10000.
	DynamicThresholdMaxUs int64 `json:"dynamic_threshold_max_us,omitempty"`
	// DynamicThresholdEvalSec is the evaluation interval (seconds). Paper default: 30.
	DynamicThresholdEvalSec int `json:"dynamic_threshold_eval_sec,omitempty"`
}

type UAFValidateConfig struct {
	MaxConcurrent    int `json:"max_concurrent"`
	DelayRetryBudget int `json:"delay_retry_budget"`
	TimeoutSeconds   int `json:"timeout_seconds"`
	// MaxBatchTimeoutSeconds caps one batched replay+verify RPC session.
	// When unset, the validator uses the legacy timeout_seconds*(requests+1) bound.
	MaxBatchTimeoutSeconds int `json:"max_batch_timeout_seconds,omitempty"`
	RepeatCount            int `json:"repeat_count"`
	// VerifyRepeatTimes specifies how many times to repeat each pair during verification phase.
	// Defaults to 10 if unset or zero.
	VerifyRepeatTimes             int `json:"verify_repeat_times,omitempty"`
	ExecutorProgramTimeoutSeconds int `json:"executor_program_timeout_seconds,omitempty"`
	ExecutorSyscallTimeoutMillis  int `json:"executor_syscall_timeout_millis,omitempty"`
	// ContinuousMode enables incremental corpus reloading instead of one-shot validation.
	// When enabled, the validator periodically reloads new entries from the corpus.
	ContinuousMode bool `json:"continuous_mode,omitempty"`
	// IncrementalReloadMinutes specifies how often to reload new corpus entries in continuous mode.
	// Defaults to 10 minutes if unset or zero.
	IncrementalReloadMinutes int `json:"incremental_reload_minutes,omitempty"`
	// IdleReloadSeconds specifies how long to wait before reloading when no tasks are pending.
	// Defaults to 30 seconds if unset or zero.
	IdleReloadSeconds int `json:"idle_reload_seconds,omitempty"`
	// TargetVarNamePair specifies a specific VarName pair to debug.
	// Format: "freeAccessName-useAccessName" (hex without 0x prefix, e.g. "610067002c7c8254-235d4d37a0583ad1")
	// When set, only entries containing this VarName pair are validated,
	// and all skip logic (invalid/validated/backoff) is bypassed for debugging purposes.
	TargetVarNamePair string `json:"target_varname_pair,omitempty"`
	// TargetCorpusKey specifies a specific corpus entry key to validate.
	// Format: "sig0-sig1-sig2-sig3" (hex, e.g. "d9daa1d91920e5d5-7ae0c8d447027fda-b52a7fe3d5ed9139-027653b5437bc01a")
	// When set, only this specific entry is loaded and validated.
	// Can be combined with TargetVarNamePair to validate specific pairs within the entry.
	TargetCorpusKey string `json:"target_corpus_key,omitempty"`
	// DisableAsyncSplit disables the async call splitting during verification phase.
	// By default (false), each program pair (2 programs) is expanded to 4 programs
	// by duplicating each with async calls marked, maximizing race triggering.
	// When enabled (true), programs are used as-is without async splitting.
	DisableAsyncSplit bool `json:"disable_async_split,omitempty"`
	// DisableCollectionDelay disables start_delay during the collection phase.
	// When enabled (true), programs run without artificial delays during collection,
	// allowing natural timing to determine which pairs are stable.
	// Delays are only applied during the verification phase.
	DisableCollectionDelay bool `json:"disable_collection_delay,omitempty"`
	// DisableVerifyDelay disables start_delay during the verification phase.
	// When enabled (true), verification runs without barrier start delays,
	// relying only on access_delay (kernel udelay) to create race windows.
	DisableVerifyDelay bool `json:"disable_verify_delay,omitempty"`
	// DisableAccessDelay disables the kernel-side target access delay during verification.
	DisableAccessDelay bool `json:"disable_access_delay,omitempty"`
	// DisableTargetDelay is a compatibility alias for DisableAccessDelay.
	DisableTargetDelay bool `json:"disable_target_delay,omitempty"`
	// VerifyAccessDelayMinUs floors the kernel-side target access delay during verification.
	// This does not change barrier start_delay.
	VerifyAccessDelayMinUs int64 `json:"verify_access_delay_min_us,omitempty"`
	// TargetMatchMode controls target-pair matching in UAF validation.
	// Supported values: "sn-fallback" (default), "strict-sn", "sn-range",
	// "sn-only", "sn-range-only", "stack-only", "site-only".
	// "sn-fallback" tries strict SN/TID first, bounded SN-range next, then stack-only.
	// "sn-range" matches VarName+CallStack with SN in a configured interval and treats TID as a wildcard.
	// "stack-only" matches VarName+CallStack and treats SN/TID as wildcards.
	// "sn-only"/"sn-range-only" keep SN constraints but ignore stack/TID.
	// "site-only" clears stack/SN/TID in the target request and is kept as an
	// explicit diagnostic mode for kernels that support VarName-only matching.
	TargetMatchMode string `json:"target_match_mode,omitempty"`
	// SNFallbackRange controls bounded SN drift for target_match_mode=sn-fallback/sn-range.
	// A value of N matches runtime sequence numbers in [SN-N, SN+N]. Zero disables this layer.
	SNFallbackRange int `json:"sn_fallback_range,omitempty"`
	// WildcardTargetTID clears target TID constraints while preserving VarName, stack, and SN.
	WildcardTargetTID bool `json:"wildcard_target_tid,omitempty"`
	// TargetDelaySide controls which matching side receives kernel access delay:
	// "both" (default), "use", "free", or "none".
	TargetDelaySide string `json:"target_delay_side,omitempty"`
	// TargetDelayMode controls how the matched target access applies delay:
	// "sleep" (default) or "nonblocking".
	TargetDelayMode string `json:"target_delay_mode,omitempty"`
	// EnableVMSnapshot enables VM snapshot mode for faster validation.
	// When enabled, the VM state is saved after initial boot and SSH setup,
	// then restored (instead of full reboot) between validation tasks.
	// This can reduce per-task overhead from ~30-60s to ~3-5s.
	// Requirements:
	// - QEMU VM type only
	// - Disk image must be in qcow2 format (not raw)
	// - The "snapshot" QEMU option in config should be false or omitted
	// Note: Each VM will create a copy of the disk image in the workdir.
	EnableVMSnapshot bool `json:"enable_vm_snapshot,omitempty"`
	// VerifyDelaySweep enables progressive start_delay sweep during verification.
	// When enabled, multiple verify requests are generated with different delays,
	// from 0 to VerifyDelayMaxUs using an exponential curve.
	VerifyDelaySweep bool `json:"verify_delay_sweep,omitempty"`
	// VerifyDelaySteps specifies how many delay steps to try during sweep.
	// Each step uses a different delay value. Defaults to 10 if unset or zero.
	VerifyDelaySteps int `json:"verify_delay_steps,omitempty"`
	// VerifyDelayMaxUs is the maximum start_delay in microseconds for delay sweep.
	// Defaults to 800 if unset or zero.
	VerifyDelayMaxUs int64 `json:"verify_delay_max_us,omitempty"`
	// VerifyDelayPower controls the exponential curve steepness.
	// Higher values = slower start, faster end. Defaults to 2.0.
	// Formula: delay(i) = maxDelay * (i/n)^power
	VerifyDelayPower float64 `json:"verify_delay_power,omitempty"`

	// EnableReplay enables the replay mechanism during validation.
	// When enabled, before validating each entry, the saved execution history is replayed
	// to reconstruct the system state that led to the pair's discovery.
	// This improves reproducibility of race conditions.
	EnableReplay bool `json:"enable_replay,omitempty"`
	// ReplayCollectPairs controls whether to collect race pairs during replay.
	// When false (default), replay runs in barrier mode but skips race pair collection
	// to reduce performance overhead. When true, pairs are collected during replay as well.
	ReplayCollectPairs bool `json:"replay_collect_pairs,omitempty"`
	// VerifyCollectPairs collects DDRD pairs during verification for diagnostics.
	// Observed target pairs are reported separately and do not count as validated
	// unless a matching DATARACE crash is also reported.
	VerifyCollectPairs bool `json:"verify_collect_pairs,omitempty"`
	// MaxReplayHistory limits how many saved history records are replayed per validation attempt.
	// When positive, the most recent N records are used. Zero means no limit.
	MaxReplayHistory int `json:"max_replay_history,omitempty"`
	// SnapshotCorpusWarmup enables running all corpus programs before creating the VM snapshot.
	// When enabled with EnableVMSnapshot, all programs from corpus.db are executed once
	// before saving the snapshot. This "warms up" kernel state (caches, internal structures)
	// so that subsequent tests start from a more realistic state rather than a fresh boot.
	SnapshotCorpusWarmup bool `json:"snapshot_corpus_warmup,omitempty"`

	// EnableVarNameScheduling enables VarName-based round-robin scheduling.
	// When enabled, entries are grouped by their VarName pairs and scheduled
	// in a round-robin fashion, prioritizing VarName pairs with fewer entries.
	// This ensures fair resource distribution across different VarName pairs,
	// preventing VarName pairs with many stacks from monopolizing validation.
	EnableVarNameScheduling bool `json:"enable_varname_scheduling,omitempty"`

	// PriorityLowHistory prioritizes entries with fewer replay history records.
	// When enabled, entries are sorted by ascending history count within each
	// scheduling group, so entries with less replay overhead are validated first.
	// Can be combined with EnableVarNameScheduling for fine-grained control.
	PriorityLowHistory bool `json:"priority_low_history,omitempty"`

	// RequireOriginMatch controls whether stable pairs must exist in the original corpus pairs.
	// When true (default), only runtime-discovered pairs that also exist in entry.Pairs are
	// considered stable. When false, any runtime-discovered pair meeting the stability
	// threshold is accepted, allowing discovery of new stack combinations.
	RequireOriginMatch bool `json:"require_origin_match,omitempty"`
	// OriginMatchMode controls how require_origin_match compares runtime pairs to entry.Pairs.
	// "exact" requires VarName+stack equality. "varname" allows stack changes while keeping
	// the original VarName pair. "primary-varname" uses only the entry's primary VarName pair.
	OriginMatchMode string `json:"origin_match_mode,omitempty"`
	// MaxStablePairsPerOrigin limits verification fanout after origin matching.
	// For origin_match_mode=varname, this caps stack variants per original VarName pair.
	// Zero means no limit.
	MaxStablePairsPerOrigin int `json:"max_stable_pairs_per_origin,omitempty"`
	// MaxStablePairsPerEntry limits total stable pairs verified for one corpus entry.
	// Zero means no limit.
	MaxStablePairsPerEntry int `json:"max_stable_pairs_per_entry,omitempty"`
	// CollectionOnly stops after the replay+collection phase and skips target-pair
	// verification. It is useful for no-history sensitivity probes that only need
	// to count runtime-observed pairs.
	CollectionOnly bool `json:"collection_only,omitempty"`

	// DisableBackoffSkip disables probabilistic validation backoff skip logic.
	// When enabled (true), entries and pairs are never skipped based on the
	// historical backoff score, allowing all entries to be validated regardless
	// of prior failure statistics.
	DisableBackoffSkip bool `json:"disable_backoff_skip,omitempty"`
	// DisableHBSkip is a deprecated compatibility alias for DisableBackoffSkip.
	DisableHBSkip bool `json:"disable_hb_skip,omitempty"`

	// ContinueAfterBackoff continues testing backoff-skipped entries after the
	// initial backoff-guided validation pass completes. When enabled, entries that
	// were skipped by the heuristic are re-enqueued (in random order) with backoff
	// skip disabled, allowing all pairs to be tested.
	ContinueAfterBackoff bool `json:"continue_after_backoff,omitempty"`
	// ContinueAfterHB is a deprecated compatibility alias for ContinueAfterBackoff.
	ContinueAfterHB bool `json:"continue_after_hb,omitempty"`

	// StreamingLoad enables memory-efficient streaming load for large uaf-corpus.db files.
	// When enabled, entries are loaded in batches instead of all at once,
	// preventing OOM errors on large corpora (e.g., > 1GB).
	// Recommended for corpora with 10k+ entries or > 1GB file size.
	StreamingLoad bool `json:"streaming_load,omitempty"`

	// StreamingBatchSize specifies how many entries to load per batch in streaming mode.
	// Smaller batches use less memory but may increase I/O overhead.
	// Defaults to 500 if unset or zero.
	StreamingBatchSize int `json:"streaming_batch_size,omitempty"`

	// SkipValidated skips entries that have already been validated (exist in validated_uaf.db).
	// This avoids reprocessing already validated entries when restarting validation.
	SkipValidated bool `json:"skip_validated,omitempty"`

	// SkipInvalid skips entries that have been marked as invalid (exist in invalid_uaf.db).
	// This avoids reprocessing known-bad entries.
	SkipInvalid bool `json:"skip_invalid,omitempty"`

	// MaxEntries limits the maximum number of entries to load.
	// If set to 0 (default), all entries are loaded.
	// Useful for debugging or testing with a subset of the corpus.
	MaxEntries int `json:"max_entries,omitempty"`

	// EnableHistoryMinimization enables replay history minimization after successful validation.
	// When enabled, after a pair is validated successfully, the system will attempt to find
	// the minimum subset of history records required to reproduce the race condition.
	// This makes the reproducer smaller, easier to analyze, and faster to replay.
	EnableHistoryMinimization bool `json:"enable_history_minimization,omitempty"`

	// MinimizationMaxAttempts limits the number of execution attempts per minimization step.
	// Each subset of history is tested this many times to account for race non-determinism.
	// Higher values increase reliability but slow down minimization. Defaults to 3.
	MinimizationMaxAttempts int `json:"minimization_max_attempts,omitempty"`

	// MinimizationStrategy specifies the algorithm to use for history minimization.
	// Supported values:
	// - "binary" (default): Binary search - fast but may not find optimal minimum
	// - "greedy": Greedy removal - slower but finds better minimum
	// - "hybrid": Binary first, then greedy refinement
	MinimizationStrategy string `json:"minimization_strategy,omitempty"`
}

type FocusArea struct {
	// Name allows to display detailed statistics for every focus area.
	Name string `json:"name"`

	// A coverage filter.
	// Supported filter types:
	// "files": support specifying kernel source files, support regular expression.
	// eg. "files": ["^net/core/tcp.c$", "^net/sctp/", "tcp"].
	// "functions": support specifying kernel functions, support regular expression.
	// eg. "functions": ["^foo$", "^bar", "baz"].
	// "pcs": specify raw PC table files name.
	// Each line of the file should be: "64-bit-pc:32-bit-weight\n".
	// eg. "0xffffffff81000000:0x10\n"
	// If empty, it's assumed to match the whole kernel.
	Filter CovFilterCfg `json:"filter,omitempty"`

	// Weight is a positive number that determines how much focus should be put on this area.
	Weight float64 `json:"weight"`
}

type Subsystem struct {
	Name  string   `json:"name"`
	Paths []string `json:"path"`
}

type CovFilterCfg struct {
	Files     []string `json:"files,omitempty"`
	Functions []string `json:"functions,omitempty"`
	RawPCs    []string `json:"pcs,omitempty"`
}
