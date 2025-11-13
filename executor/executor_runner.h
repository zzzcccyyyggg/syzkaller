// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <deque>
#include <functional>
#include <iomanip>
#include <memory>
#include <optional>
#include <unordered_map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include "ukc.h"
#include "ddrd/trace_manager.h"
inline std::ostream& operator<<(std::ostream& ss, const rpc::ExecRequestRawT& req)
{
	return ss << "id=" << req.id
		  << " flags=0x" << std::hex << static_cast<uint64>(req.flags)
		  << " env_flags=0x" << std::hex << static_cast<uint64>(req.exec_opts->env_flags())
		  << " exec_flags=0x" << std::hex << static_cast<uint64>(req.exec_opts->exec_flags())
		  << " data_size=" << std::dec << req.data.size()
		  << "\n";
}

// ProcIDPool allows to reuse a set of unique proc IDs across a set of subprocesses.
//
// When a subprocess hangs, it's a bit unclear what to do (we don't have means to kill
// the whole tree of its children, and waiting for all them will presumably hang as well).
// Later there may appear a "task hung" report from the kernel, so we don't want to terminate
// the VM immidiatly. But the "task hung" report may also not appear at all, so we can't
// just wait for a hanged subprocesses forever.
//
// So in that case we kill/wait just the top subprocesses, and give it a new proc ID
// (since some resources associated with the old proc ID may still be used by the old
// unterminated test processes). However, we don't have infinite number of proc IDs,
// so we recycle them in FIFO order. This is not ideal, but it looks like the best
// practical solution.
class ProcIDPool
{
public:
	ProcIDPool(int num_procs)
	{
		// Theoretically we have 32 procs (prog.MaxPids), but there are some limitations in descriptions
		// that make them work well only for up to 10 procs. For example, we form /dev/loopN
		// device name using proc['0', 1, int8]. When these limitations are fixed,
		// we can use all 32 here (prog.MaxPids)
		constexpr int kNumGoodProcs = 10;
		for (int i = 0; i < std::max(num_procs, kNumGoodProcs); i++)
			ids_.push_back(i);
		mask_ = 0;
	}

	int Alloc(int old = -1)
	{
		if (old >= 0) {
			mask_ &= ~(1UL << old);
			ids_.push_back(old);
		}
		if (ids_.empty())
			fail("out of proc ids");
		int id = ids_.front();
		ids_.pop_front();
		mask_ |= 1UL << id;
		return id;
	}

	uint64 Mask()
	{
		return mask_;
	}

private:
	std::deque<int> ids_;
	uint64 mask_;

	ProcIDPool(const ProcIDPool&) = delete;
	ProcIDPool& operator=(const ProcIDPool&) = delete;
};

class ProcOpts
{
public:
	bool use_cover_edges = false;
	bool is_kernel_64_bit = false;
	uint32 slowdown = 0;
	uint32 syscall_timeout_ms = 0;
	uint32 program_timeout_ms = 0;

private:
	friend std::ostream& operator<<(std::ostream& ss, const ProcOpts& opts)
	{
		ss << "use_cover_edges=" << opts.use_cover_edges
		   << " is_kernel_64_bit=" << opts.is_kernel_64_bit
		   << " slowdown=" << opts.slowdown
		   << " syscall_timeout_ms=" << opts.syscall_timeout_ms
		   << " program_timeout_ms=" << opts.program_timeout_ms;
		return ss;
	}
};

// Proc represents one subprocess that runs tests (re-execed syz-executor with 'exec' argument).
// Forward declaration
class Runner;

// Barrier completion notifications were previously passed via a single global
// struct. We now stage full results per-group/member, so this legacy helper
// is removed.

// Forward declarations needed before Proc uses staged result types.
// Full definition placed here so Proc methods can access fields.
struct StagedBarrierResult {
	class Proc* proc = nullptr; // forward reference to Proc
	uint32 status = 0;
	bool hanged = false;
	uint64 elapsed = 0;
	uint32 num_calls = 0;
	uint64 freshness = 0;
	uint64 req_id = 0;
	uint64 barrier_participants = 0;
	int64_t group_id = 0;
	int32_t index = 0;
	int32_t group_size = 0;
	std::vector<uint8_t> process_output; // captured process stdout/stderr if requested
};

// The object is persistent and re-starts subprocess when it crashes.
class Proc
{
public:
	Proc(Connection& conn, const char* bin, Runner* runner, ProcIDPool& proc_id_pool, int slot, int total_slots, int& restarting, const bool& corpus_triaged,
	     int max_signal_fd, int cover_filter_fd, ProcOpts opts)
	    : conn_(conn),
	      bin_(bin),
	      runner_(runner),
	      proc_id_pool_(proc_id_pool),
	      slot_(slot),
	      slots_mask_(total_slots >= 64 ? ~0ULL : ((1ull << total_slots) - 1)),
	      id_(proc_id_pool.Alloc()),
	      restarting_(restarting),
	      corpus_triaged_(corpus_triaged),
	      max_signal_fd_(max_signal_fd),
	      cover_filter_fd_(cover_filter_fd),
	      opts_(opts),
	      req_shmem_(kMaxInput),
	      resp_shmem_(kMaxOutput),
	      resp_mem_(static_cast<OutputData*>(resp_shmem_.Mem()))
	{
		Start();
	}

	bool Execute(rpc::ExecRequestRawT& msg)
	{
		if (state_ != State::Started && state_ != State::Idle)
			return false;
		if (has_pending_result_) {
			debug("proc slot %d (exec %d): cannot execute request %llu, pending barrier result not flushed\n",
			      slot_, id_, static_cast<uint64>(msg.id));
			return false;
		}
		if (((~msg.avoid) & slots_mask_) == 0)
			msg.avoid = 0;
		if (msg.avoid & (1ull << slot_))
			return false;
		if (msg_)
			fail("already have pending msg");
		if (wait_start_)
			wait_end_ = current_time_ms();
		// Restart every once in a while to not let too much state accumulate.
		// Also request if request type differs as it affects program timeout.
		constexpr uint64 kRestartEvery = 600;
		if (state_ == State::Idle && ((corpus_triaged_ && restarting_ == 0 && freshness_ >= kRestartEvery) ||
					      req_type_ != msg.type ||
					      exec_env_ != msg.exec_opts->env_flags() || sandbox_arg_ != msg.exec_opts->sandbox_arg()))
			Restart();
		attempts_ = 0;
		msg_ = std::move(msg);
		if (state_ == State::Started)
			Handshake();
		else
			Execute();
		return true;
	}

	bool IsIdle() const
	{
		return state_ == State::Idle && !msg_;
	}
	void SetStageBarrierCallback(std::function<void(const StagedBarrierResult&)> cb) { stage_barrier_cb_ = std::move(cb); }
 	bool IsAvailable() const 
	{ 
		return state_ == State::Idle || state_ == State::Started; 
	}
	int ExecId() const
	{
		return id_;
	}

	bool CanRun(const rpc::ExecRequestRawT& msg) const
	{
		if (!IsAvailable())
			return false;
		// Do not schedule new work onto a proc with a staged (unsent) barrier result.
		if (has_pending_result_)
			return false;
		if (msg.avoid & (1ull << slot_))
			return false;
		return true;
	}

	int Id() const
	{
		return slot_;
	}

	void Arm(Select& select)
	{
		select.Arm(resp_pipe_);
		select.Arm(stdout_pipe_);
	}

	void Ready(Select& select, uint64 now, bool out_of_requests)
	{
		if (state_ == State::Handshaking || state_ == State::Executing) {
			// Check if the subprocess has hung.
#if SYZ_EXECUTOR_USES_FORK_SERVER
			// Child process has an internal timeout and protects against most hangs when
			// fork server is enabled, so we use quite large timeout. Child process can be slow
			// due to global locks in namespaces and other things, so let's better wait than
			// report false misleading crashes.
			uint64 timeout = 3 * ProgramTimeoutMs();
#else
			uint64 timeout = ProgramTimeoutMs();
#endif
			// Sandbox setup can take significant time.
			if (state_ == State::Handshaking)
				timeout = 60 * 1000 * opts_.slowdown;
			if (now > exec_start_ + timeout) {
				Restart();
				return;
			}
		}

		if (select.Ready(stdout_pipe_) && !ReadOutput()) {
#if SYZ_EXECUTOR_USES_FORK_SERVER
			// In non-forking mode the subprocess exits after test execution
			// and the pipe read fails with EOF, so we rely on the resp_pipe_ instead.
			Restart();
			return;
#endif
		}
		if (select.Ready(resp_pipe_) && !ReadResponse(out_of_requests)) {
			Restart();
			return;
		}
		return;
	}

private:
	enum State : uint8 {
		// The process has just started.
		Started,
		// We sent the process env flags and waiting for handshake reply.
		Handshaking,
		// Handshaked and ready to execute programs.
		Idle,
		// Currently executing a test program.
		Executing,
	};

	Connection& conn_;
	const char* const bin_;
	Runner* runner_ = nullptr; // back-pointer used for staging barrier results
	ProcIDPool& proc_id_pool_;
	const int slot_;
	const uint64 slots_mask_;
	int id_;
	int& restarting_;
	const bool& corpus_triaged_;
	const int max_signal_fd_;
	const int cover_filter_fd_;
	const ProcOpts opts_;
	State state_ = State::Started;
	std::optional<Subprocess> process_;
	ShmemFile req_shmem_;
	ShmemFile resp_shmem_;
	OutputData* resp_mem_;
	int req_pipe_ = -1;
	int resp_pipe_ = -1;
	int stdout_pipe_ = -1;
	rpc::RequestType req_type_ = rpc::RequestType::Program;
	rpc::ExecEnv exec_env_ = rpc::ExecEnv::NONE;
	int64_t sandbox_arg_ = 0;
	std::optional<rpc::ExecRequestRawT> msg_;
	std::vector<uint8_t> output_;
	size_t debug_output_pos_ = 0;
	uint64 attempts_ = 0;
	uint64 freshness_ = 0;
	uint64 exec_start_ = 0;
	uint64 wait_start_ = 0;
	uint64 wait_end_ = 0;
	bool has_pending_result_ = false; // barrier result staged, waiting for flush
	std::function<void(const StagedBarrierResult&)> stage_barrier_cb_; // late-bound callback set by Runner

	friend std::ostream& operator<<(std::ostream& ss, const Proc& proc)
	{
		ss << "slot=" << proc.slot_
		   << " exec_id=" << proc.id_
		   << " state=" << static_cast<int>(proc.state_)
		   << " freshness=" << proc.freshness_
		   << " attempts=" << proc.attempts_
		   << " exec_start=" << current_time_ms() - proc.exec_start_
		   << "\n";
		if (proc.msg_)
			ss << "\tcurrent request: " << *proc.msg_;
		return ss;
	}

	void ChangeState(State state)
	{
		if (state_ == State::Handshaking)
			restarting_--;
		if (state == State::Handshaking)
			restarting_++;
		state_ = state;
	}

	void Restart()
	{
		debug("proc slot %d (exec %d): restarting subprocess, current state %u attempts %llu\n",
		      slot_, id_, state_, attempts_);
		int status = process_->KillAndWait();
		process_.reset();
		debug("proc slot %d (exec %d): subprocess exit status %d\n", slot_, id_, status);
		if (++attempts_ > 20) {
			while (ReadOutput())
				;
			// Write the subprocess output first. If it contains own SYFAIL,
			// we want it to be before our SYZFAIL.
			ssize_t wrote = write(STDERR_FILENO, output_.data(), output_.size());
			if (wrote != static_cast<ssize_t>(output_.size()))
				fprintf(stderr, "output truncated: %zd/%zd (errno=%d)\n",
					wrote, output_.size(), errno);
			uint64 req_id = msg_ ? msg_->id : -1;
			failmsg("repeatedly failed to execute the program", "slot=%d exec=%d req=%lld state=%d status=%d",
				slot_, id_, req_id, state_, status);
		}
		// Ignore all other errors.
		// Without fork server executor can legitimately exit (program contains exit_group),
		// with fork server the top process can exit with kFailStatus if it wants special handling.
		if (status != kFailStatus)
			status = 0;
		if (FailCurrentRequest(status == kFailStatus)) {
			// Read out all pening output until EOF.
			if (IsSet(msg_->flags, rpc::RequestFlag::ReturnOutput)) {
				while (ReadOutput())
					;
			}
			bool hanged = SYZ_EXECUTOR_USES_FORK_SERVER && state_ == State::Executing;
			HandleCompletion(status, hanged);
			if (hanged) {
				// If the process has hanged, it may still be using per-proc resources,
				// so allocate a fresh proc id.
				int new_id = proc_id_pool_.Alloc(id_);
				debug("proc slot %d (exec %d): changing exec id to %d\n", slot_, id_, new_id);
				id_ = new_id;
			}
		} else if (attempts_ > 3)
			sleep_ms(100 * attempts_);
		Start();
	}

	bool FailCurrentRequest(bool failed)
	{
		if (state_ == State::Handshaking)
			return IsSet(msg_->flags, rpc::RequestFlag::ReturnError);
		if (state_ == State::Executing)
			return !failed || IsSet(msg_->flags, rpc::RequestFlag::ReturnError);
		return false;
	}

	void Start()
	{
		ChangeState(State::Started);
		freshness_ = 0;
		int req_pipe[2];
		if (pipe(req_pipe))
			fail("pipe failed");
		int resp_pipe[2];
		if (pipe(resp_pipe))
			fail("pipe failed");
		int stdout_pipe[2];
		if (pipe(stdout_pipe))
			fail("pipe failed");

		std::vector<std::pair<int, int>> fds = {
		    {req_pipe[0], STDIN_FILENO},
		    {resp_pipe[1], STDOUT_FILENO},
		    {stdout_pipe[1], STDERR_FILENO},
		    {req_shmem_.FD(), kInFd},
		    {resp_shmem_.FD(), kOutFd},
		    {max_signal_fd_, kMaxSignalFd},
		    {cover_filter_fd_, kCoverFilterFd},
		};
		const char* argv[] = {bin_, "exec", nullptr};
		process_.emplace(argv, fds);

		Select::Prepare(resp_pipe[0]);
		Select::Prepare(stdout_pipe[0]);

		close(req_pipe[0]);
		close(resp_pipe[1]);
		close(stdout_pipe[1]);

		close(req_pipe_);
		close(resp_pipe_);
		close(stdout_pipe_);

		req_pipe_ = req_pipe[1];
		resp_pipe_ = resp_pipe[0];
		stdout_pipe_ = stdout_pipe[0];

		has_pending_result_ = false;
		resp_mem_->Reset();
		output_.clear();
		debug_output_pos_ = 0;

		if (msg_)
			Handshake();
	}

	void Handshake()
	{
		if (state_ != State::Started || !msg_)
			fail("wrong handshake state");
		debug("proc slot %d (exec %d): handshaking to execute request %llu\n",
			  slot_, id_, static_cast<uint64>(msg_->id));
		ChangeState(State::Handshaking);
		exec_start_ = current_time_ms();
		req_type_ = msg_->type;
		exec_env_ = msg_->exec_opts->env_flags() & ~rpc::ExecEnv::ResetState;
		sandbox_arg_ = msg_->exec_opts->sandbox_arg();
		handshake_req req = {
		    .magic = kInMagic,
		    .use_cover_edges = opts_.use_cover_edges,
		    .is_kernel_64_bit = opts_.is_kernel_64_bit,
		    .flags = exec_env_,
		    .pid = static_cast<uint64>(id_),
		    .sandbox_arg = static_cast<uint64>(sandbox_arg_),
		    .syscall_timeout_ms = opts_.syscall_timeout_ms,
		    .program_timeout_ms = ProgramTimeoutMs(),
		    .slowdown_scale = opts_.slowdown,
		};
		if (write(req_pipe_, &req, sizeof(req)) != sizeof(req)) {
			debug("request pipe write failed (errno=%d)\n", errno);
			Restart();
		}
	}

	void Execute()
	{
		if (state_ != State::Idle || !msg_)
			fail("wrong state for execute");

		debug("proc slot %d (exec %d): start executing request %llu\n",
		      slot_, id_, static_cast<uint64>(msg_->id));

		rpc::ExecutingMessageRawT exec;
		exec.id = msg_->id;
		exec.proc_id = id_;
		exec.try_ = attempts_;

		if (wait_start_) {
			exec.wait_duration = (wait_end_ - wait_start_) * 1000 * 1000;
			wait_end_ = wait_start_ = 0;
		}

		rpc::ExecutorMessageRawT raw;
		raw.msg.Set(std::move(exec));
		conn_.Send(raw);

		uint64 all_call_signal = 0;
		bool all_extra_signal = false;
		for (int32_t call : msg_->all_signal) {
			// This code assumes that call indices can be represented as bits in uint64 all_call_signal.
			static_assert(kMaxCalls == 64);
			if (call < -1 || call >= static_cast<int32_t>(kMaxCalls))
				failmsg("bad all_signal call", "call=%d", call);
			if (call < 0)
				all_extra_signal = true;
			else
				all_call_signal |= 1ull << call;
		}
		memcpy(req_shmem_.Mem(), msg_->data.data(), std::min(msg_->data.size(), kMaxInput));
		execute_req req{
		    .magic = kInMagic,
		    .id = static_cast<uint64>(msg_->id),
		    .type = msg_->type,
		    .exec_flags = static_cast<uint64>(msg_->exec_opts->exec_flags()),
		    .all_call_signal = all_call_signal,
		    .all_extra_signal = all_extra_signal,
		    .barrier_group_id = msg_->barrier_group_id,
		    .barrier_index = msg_->barrier_index,
		    .barrier_group_size = msg_->barrier_group_size,
		};
		exec_start_ = current_time_ms();
		ChangeState(State::Executing);
		if (write(req_pipe_, &req, sizeof(req)) != sizeof(req)) {
			debug("request pipe write failed (errno=%d)\n", errno);
			Restart();
		}
	}

	void HandleCompletion(uint32 status, bool hanged = false)
	{
		if (!msg_)
			fail("don't have executed msg");

		// Note: if the child process crashed during handshake and the request has ReturnError flag,
		// we have not started executing the request yet.
		uint64 elapsed = (current_time_ms() - exec_start_) * 1000 * 1000;
		uint8* prog_data = msg_->data.data();
		input_data = prog_data;
		std::vector<uint8_t>* output = nullptr;
		if (IsSet(msg_->flags, rpc::RequestFlag::ReturnOutput)) {
			output = &output_;
			if (status) {
				char tmp[128];
				snprintf(tmp, sizeof(tmp), "\nprocess exited with status %d\n", status);
				output_.insert(output_.end(), tmp, tmp + strlen(tmp));
			}
		}
		uint32 num_calls = 0;
		if (msg_->type == rpc::RequestType::Program)
			num_calls = read_input(&prog_data);

		bool is_barrier = msg_->barrier_group_size > 0;
		if (is_barrier) {
			// Stage result instead of sending now.
			StagedBarrierResult staged;
			staged.proc = this;
			staged.status = status;
			staged.hanged = hanged;
			staged.elapsed = elapsed;
			staged.num_calls = num_calls;
			staged.req_id = msg_->id;
			staged.freshness = freshness_++;
			staged.barrier_participants = msg_->barrier_participants;
			staged.group_id = msg_->barrier_group_id;
			staged.index = msg_->barrier_index;
			staged.group_size = msg_->barrier_group_size;
			if (output)
				staged.process_output = *output; // copy
			else
				staged.process_output.clear();
			// Register into active barrier execution via Runner helper.
			if (stage_barrier_cb_)
				stage_barrier_cb_(staged);
			has_pending_result_ = true;
			// Do NOT reset resp_mem_ or clear output_ yet; we need them for serialization.
			msg_.reset(); // release request (we stored needed fields)
			ChangeState(State::Idle); // mark idle but unavailable via has_pending_result_
			return; // defer send
		}

		// Non-barrier: build and send immediately
		auto data = finish_output(resp_mem_, id_, msg_->id, num_calls, elapsed, freshness_++, status, hanged, output,
				 msg_->barrier_participants, msg_->barrier_group_id, msg_->barrier_index, msg_->barrier_group_size);
		conn_.Send(data.data(), data.size());
		resp_mem_->Reset();
		msg_.reset();
		output_.clear();
		debug_output_pos_ = 0;
		ChangeState(State::Idle);
	#if !SYZ_EXECUTOR_USES_FORK_SERVER
		if (process_)
			Restart();
	#endif
	}

	public: // reopen public section for flush helper
	// Flush a previously staged barrier result (public for Runner).
	void FlushPendingResult(const StagedBarrierResult& staged, const DdrdOutputState* ddrd_output_injection)
	{
		if (!has_pending_result_)
			return;
#if GOOS_linux
		if (ddrd_output_injection)
			ddrd_set_runner_output(ddrd_output_injection);
		else
			ddrd_clear_runner_output();
#endif
		// Reconstruct output vector pointer (may be empty)
		const std::vector<uint8_t>* out_ptr = staged.process_output.empty() ? nullptr : &staged.process_output;
		auto data = finish_output(resp_mem_, id_, staged.req_id, staged.num_calls, staged.elapsed, staged.freshness,
				staged.status, staged.hanged, out_ptr, staged.barrier_participants,
				staged.group_id, staged.index, staged.group_size);
		conn_.Send(data.data(), data.size());
		resp_mem_->Reset();
		output_.clear();
		debug_output_pos_ = 0;
		has_pending_result_ = false;
#if GOOS_linux
		ddrd_clear_runner_output(); // ensure cleared for next non-barrier request
#endif
	}

	bool ReadResponse(bool out_of_requests)
	{
		uint32 status;
		ssize_t n;
		while ((n = read(resp_pipe_, &status, sizeof(status))) == -1) {
			if (errno != EINTR && errno != EAGAIN)
				break;
		}
		if (n == 0) {
			debug("proc slot %d (exec %d): response pipe EOF\n", slot_, id_);
			return false;
		}
		if (n != sizeof(status))
			failmsg("proc resp pipe read failed", "n=%zd", n);
		if (state_ == State::Handshaking) {
			debug("proc slot %d (exec %d): got handshake reply\n", slot_, id_);
			ChangeState(State::Idle);
			Execute();
		} else if (state_ == State::Executing) {
			debug("proc slot %d (exec %d): got execute reply\n", slot_, id_);
			HandleCompletion(status);
			if (out_of_requests)
				wait_start_ = current_time_ms();
		} else {
			debug("got data on response pipe in wrong state %d\n", state_);
			return false;
		}
		return true;
	}

	bool ReadOutput()
	{
		const size_t kChunk = 1024;
		output_.resize(output_.size() + kChunk);
		ssize_t n = read(stdout_pipe_, output_.data() + output_.size() - kChunk, kChunk);
		output_.resize(output_.size() - kChunk + std::max<ssize_t>(n, 0));
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				return true;
			fail("proc stdout read failed");
		}
		if (n == 0) {
			debug("proc slot %d (exec %d): output pipe EOF\n", slot_, id_);
			return false;
		}
		if (flag_debug) {
			output_.resize(output_.size() + 1);
			char* output = reinterpret_cast<char*>(output_.data()) + debug_output_pos_;
			// During machine check we can execute some requests that legitimately fail.
			// These requests have ReturnError flag, so that the failure is returned
			// to the caller for analysis. Don't print SYZFAIL in these requests,
			// otherwise it will be detected as a bug.
			if (msg_ && IsSet(msg_->flags, rpc::RequestFlag::ReturnError)) {
				char* syzfail = strstr(output, "SYZFAIL");
				if (syzfail)
					memcpy(syzfail, "NOTFAIL", strlen("NOTFAIL"));
			}
			debug("proc slot %d (exec %d): %s", slot_, id_, output);
			output_.resize(output_.size() - 1);
			debug_output_pos_ = output_.size();
		}
		return true;
	}

	uint32 ProgramTimeoutMs() const
	{
		// Glob requests can expand to >10K files and can take a while to run.
		return opts_.program_timeout_ms * (req_type_ == rpc::RequestType::Program ? 1 : 10);
	}
};

// Runner manages a set of test subprocesses (Proc's), receives new test requests from the manager,
// and dispatches them to subprocesses.

#if GOOS_linux
// DDRD types - shared with executor.cc
#ifndef SYZ_EXECUTOR_DDRD_TYPES_DEFINED
#define SYZ_EXECUTOR_DDRD_TYPES_DEFINED
struct DdrdSerializedAccessEntry {
	uint64_t var_name = 0;
	uint64_t call_stack_hash = 0;
	uint64_t access_time = 0;
	uint32_t sn = 0;
	uint32_t access_type = 0;
};

struct DdrdExtendedUafRecord {
	size_t basic_index = 0;
	uint32_t use_thread_history_count = 0;
	uint32_t free_thread_history_count = 0;
	uint64_t use_target_time = 0;
	uint64_t free_target_time = 0;
	double path_distance_use = 0.0;
	double path_distance_free = 0.0;
	std::vector<DdrdSerializedAccessEntry> history;
};

struct DdrdOutputState {
	std::vector<may_uaf_pair_t> basic_pairs;
	std::vector<DdrdExtendedUafRecord> extended_pairs;
	bool has_results = false;
};
#endif // SYZ_EXECUTOR_DDRD_TYPES_DEFINED

// DDRD controller that manages race detection state for runner
class RunnerDdrdController {
public:
	RunnerDdrdController()
	    : initialized_(false), available_(false), warned_unavailable_(false),
	      extended_requested_(false), active_for_group_(false)
	{
	}

	~RunnerDdrdController()
	{
		if (initialized_)
			race_detector_cleanup(&detector_);
		ukc_enter_monitor_mode();
	}

	// Prepare DDRD for a barrier group execution
	void PrepareForGroup(bool collect_uaf, bool collect_extended)
	{
		ClearOutput();
		active_for_group_ = false;
		extended_requested_ = collect_extended;

		if (!collect_uaf && !collect_extended)
			return;

		// Lazy init
		if (!initialized_) {
			race_detector_init(&detector_);
			initialized_ = true;
			available_ = race_detector_is_available(&detector_);
			if (!available_ && !warned_unavailable_) {
				debug("ddrd: race detector unavailable on this system\n");
				warned_unavailable_ = true;
			}
		}

		if (!available_) {
			ukc_enter_monitor_mode();
			return;
		}

		active_for_group_ = true;

		// Switch to LOG mode
		ukc_enter_log_mode();
		debug("ddrd: clearing trace buffer before barrier execution\n");
		trace_manager_clear(nullptr);

		// Reset detector state
		if (extended_requested_)
			race_detector_enable_history(&detector_);
		else
			race_detector_disable_history(&detector_);
		race_detector_reset(&detector_);
	}

	// Collect results after all barrier members complete
	void CollectResults()
	{
		if (!active_for_group_)
			return;

		if (!available_) {
			ukc_enter_monitor_mode();
			active_for_group_ = false;
			return;
		}

		// Switch back to MONITOR mode
		ukc_enter_monitor_mode();
		debug("ddrd: collecting results\n");

		std::vector<may_uaf_pair_t> pairs(kDdrdMaxUafPairs);
		int count = race_detector_analyze_and_generate_uaf_infos(&detector_, pairs.data(),
		                                                          (int)kDdrdMaxUafPairs);
		if (count <= 0) {
			ClearOutput();
			active_for_group_ = false;
			return;
		}

		output_.basic_pairs.assign(pairs.begin(), pairs.begin() + count);
		debug("ddrd: detected %d UAF pair(s)\n", count);

		for (int i = 0; i < count; i++) {
			const may_uaf_pair_t& pair = output_.basic_pairs[i];
			debug("ddrd: pair[%d] free_access=0x%016llx use_access=0x%016llx free_tid=%d use_tid=%d free_sn=%d use_sn=%d signal=0x%016llx time_diff=%llu lock_type=%u use_access_type=%u\n",
			      i,
			      static_cast<unsigned long long>(pair.free_access_name),
			      static_cast<unsigned long long>(pair.use_access_name),
			      pair.free_tid,
			      pair.use_tid,
			      pair.free_sn,
			      pair.use_sn,
			      static_cast<unsigned long long>(pair.signal),
			      static_cast<unsigned long long>(pair.time_diff),
			      pair.lock_type,
			      pair.use_access_type);
		}

		// Collect extended info if requested
		if (extended_requested_) {
			output_.extended_pairs.clear();
			output_.extended_pairs.reserve(count);
			for (int i = 0; i < count; i++) {
				const may_uaf_pair_t& pair = output_.basic_pairs[i];
				DdrdExtendedUafRecord ext{};
				ext.basic_index = (size_t)i;
				ThreadAccessHistory* use_hist = race_detector_find_thread_history(&detector_, pair.use_tid);
				ThreadAccessHistory* free_hist = race_detector_find_thread_history(&detector_, pair.free_tid);
				ext.use_thread_history_count = HistoryCopyCount(use_hist);
				ext.free_thread_history_count = HistoryCopyCount(free_hist);
				ext.use_target_time = pair.time_diff;
				ext.free_target_time = 0;
				ext.path_distance_use = use_hist && use_hist->access_count > 0
				    ? (double)(use_hist->access_count - 1) : 0.0;
				ext.path_distance_free = free_hist && free_hist->access_count > 0
				    ? (double)(free_hist->access_count - 1) : 0.0;
				ext.history.reserve(ext.use_thread_history_count + ext.free_thread_history_count);
				AppendHistory(use_hist, ext.use_thread_history_count, ext.history);
				AppendHistory(free_hist, ext.free_thread_history_count, ext.history);
				output_.extended_pairs.push_back(std::move(ext));
			}
		} else {
			output_.extended_pairs.clear();
		}

		output_.has_results = true;
		active_for_group_ = false;
	}

	// Get DDRD output to inject into master's ExecResult
	const DdrdOutputState& GetOutput() const { return output_; }

	bool HasResults() const { return output_.has_results; }

	void ResetAfterGroup()
	{
		ClearOutput();
		active_for_group_ = false;
		ukc_enter_monitor_mode();
	}

private:
	static constexpr size_t kDdrdMaxUafPairs = 0x200;

	void ClearOutput()
	{
		output_.basic_pairs.clear();
		output_.extended_pairs.clear();
		output_.has_results = false;
	}

	static uint32_t HistoryCopyCount(const ThreadAccessHistory* history)
	{
		if (!history)
			return 0;
		uint32_t available = history->buffer_full ? (uint32_t)SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM
		                                          : (uint32_t)history->access_count;
		if (available > MAX_ACCESS_HISTORY_RECORDS)
			available = MAX_ACCESS_HISTORY_RECORDS;
		return available;
	}

	static void AppendHistory(const ThreadAccessHistory* history, uint32_t limit,
	                          std::vector<DdrdSerializedAccessEntry>& out)
	{
		if (!history || limit == 0)
			return;
		uint32_t available = history->buffer_full ? (uint32_t)SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM
		                                          : (uint32_t)history->access_count;
		uint32_t to_copy = std::min(limit, available);
		out.reserve(out.size() + to_copy);
		int start = history->buffer_full ? history->access_index : 0;
		for (uint32_t i = 0; i < to_copy; i++) {
			int idx = (start + i) % SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM;
			const AccessRecord& rec = history->accesses[idx];
			DdrdSerializedAccessEntry entry;
			entry.var_name = rec.var_name;
			entry.call_stack_hash = rec.call_stack_hash;
			entry.access_time = rec.access_time;
			entry.sn = rec.sn >= 0 ? (uint32_t)rec.sn : 0;
			entry.access_type = (uint32_t)(uint8)(rec.access_type);
			out.push_back(entry);
		}
	}

	RaceDetector detector_;
	bool initialized_;
	bool available_;
	bool warned_unavailable_;
	bool extended_requested_;
	bool active_for_group_;
	DdrdOutputState output_;
};
#endif // GOOS_linux

class Runner
{
public:
	friend class Proc; // allow Proc to access Runner internals for barrier staging
	// Helper invoked by Proc to stage a completed barrier member.
	void StageBarrierResult(const StagedBarrierResult& staged)
	{
		auto it = active_barriers_.find(staged.group_id);
		if (it == active_barriers_.end()) {
			debug("runner: missing active barrier group=%lld for staging (proc slot=%d)\n",
			      (long long)staged.group_id, staged.proc ? staged.proc->Id() : -1);
			return;
		}
		ActiveBarrierExecution& active = it->second;
		if (active.pending_results.empty())
			active.pending_results.resize(active.group_size);
		if (staged.index >= 0 && staged.index < active.group_size) {
			active.pending_results[staged.index] = staged;
			active.completed++; // increment completion count here
			debug("runner: staged barrier member group=%lld index=%d (%d/%d)\n",
			      (long long)active.group_id, staged.index, active.completed, active.group_size);
		}
	}
	Runner(Connection& conn, int vm_index, const char* bin)
	    : conn_(conn),
	      vm_index_(vm_index)
	{
		int num_procs = Handshake();
		proc_id_pool_.emplace(num_procs);
		int max_signal_fd = max_signal_ ? max_signal_->FD() : -1;
		int cover_filter_fd = cover_filter_ ? cover_filter_->FD() : -1;
		for (int i = 0; i < num_procs; i++) {
			procs_.emplace_back(new Proc(conn, bin, this, *proc_id_pool_, i, num_procs, restarting_, corpus_triaged_,
				     max_signal_fd, cover_filter_fd, proc_opts_));
		}
		// Install staging callback for each proc now that Runner methods defined.
		for (auto& p : procs_) {
			p->SetStageBarrierCallback([this](const StagedBarrierResult& r){ StageBarrierResult(r); });
		}

		for (;;)
			Loop();
	}

private:
// Full definition now that Proc is defined.

	struct BarrierGroupState {
		uint64 participants_mask = 0;
		std::vector<int> proc_slots;
		std::vector<std::optional<rpc::ExecRequestRawT>> members;
		size_t ready = 0;
		bool queued = false;
		bool ddrd_active = false;
		// Legacy placeholder; staging now lives in ActiveBarrierExecution.
	};

	struct ActiveBarrierExecution {
		int64_t group_id = 0;
		int32_t group_size = 0;
		int32_t completed = 0; // number of members that have executed (staged)
		bool ddrd_active = false;
		std::vector<StagedBarrierResult> pending_results; // index -> staged result
	};

	Connection& conn_;
	const int vm_index_;
	std::optional<CoverFilter> max_signal_;
	std::optional<CoverFilter> cover_filter_;
	std::optional<ProcIDPool> proc_id_pool_;
	std::vector<std::unique_ptr<Proc>> procs_;
	std::deque<rpc::ExecRequestRawT> requests_;
	std::unordered_map<int64_t, BarrierGroupState> barrier_groups_;
	std::deque<int64_t> pending_barriers_;
	bool barrier_mode_enabled_ = false;
	std::unordered_map<int64_t, ActiveBarrierExecution> active_barriers_;
	std::vector<std::string> leak_frames_;
	int restarting_ = 0;
	bool corpus_triaged_ = false;
	ProcOpts proc_opts_{};
#if GOOS_linux
	RunnerDdrdController ddrd_controller_;
#endif

	friend std::ostream& operator<<(std::ostream& ss, const Runner& runner)
	{
		ss << "vm_index=" << runner.vm_index_
		   << " max_signal=" << !!runner.max_signal_
		   << " cover_filter=" << !!runner.cover_filter_
		   << " restarting=" << runner.restarting_
		   << " corpus_triaged=" << runner.corpus_triaged_
		   << " " << runner.proc_opts_
		   << "\n";
		ss << "procs:\n";
		for (const auto& proc : runner.procs_)
			ss << *proc;
		ss << "\nqueued requests (" << runner.requests_.size() << "):\n";
		for (const auto& req : runner.requests_)
			ss << req;
		return ss;
	}

	void Loop()
	{
		Select select;
		select.Arm(conn_.FD());
		for (auto& proc : procs_)
			proc->Arm(select);
		// Wait for ready host connection and subprocess pipes.
		// Timeout is for terminating hanged subprocesses.
		select.Wait(1000);
		uint64 now = current_time_ms();

		if (select.Ready(conn_.FD())) {
			rpc::HostMessageRawT raw;
			conn_.Recv(raw);
			if (auto* msg = raw.msg.AsExecRequest())
				Handle(*msg);
			else if (auto* msg = raw.msg.AsSignalUpdate())
				Handle(*msg);
			else if (auto* msg = raw.msg.AsCorpusTriaged())
				Handle(*msg);
			else if (auto* msg = raw.msg.AsStateRequest())
				Handle(*msg);
			else
				failmsg("unknown host message type", "type=%d", static_cast<int>(raw.msg.type));
		}
		uint64 reserved_mask = 0;
		if (barrier_mode_enabled_) {
			DispatchBarrierGroups();
			CheckBarrierCompletions();
			reserved_mask = PendingBarrierMask();
		}
		for (auto& proc : procs_) {
			proc->Ready(select, now, requests_.empty());
			if (!requests_.empty()) {
				if (reserved_mask & (1ull << proc->Id()))
					continue;
				if (proc->Execute(requests_.front()))
					requests_.pop_front();
			}
		}

		if (restarting_ < 0 || restarting_ > static_cast<int>(procs_.size()))
			failmsg("bad restarting", "restarting=%d", restarting_);
	}

	// Implementation must match that in pkg/rpcserver/rpcserver.go.
	uint64 HashAuthCookie(uint64 cookie)
	{
		const uint64_t prime1 = 73856093;
		const uint64_t prime2 = 83492791;

		return (cookie * prime1) ^ prime2;
	}

	int Handshake()
	{
		// Handshake stage 0: get a cookie from the manager.
		rpc::ConnectHelloRawT conn_hello;
		conn_.Recv(conn_hello);

		// Handshake stage 1: share basic information about the client.
		rpc::ConnectRequestRawT conn_req;
		conn_req.cookie = HashAuthCookie(conn_hello.cookie);
		conn_req.id = vm_index_;
		conn_req.arch = GOARCH;
		conn_req.git_revision = GIT_REVISION;
		conn_req.syz_revision = SYZ_REVISION;
		conn_.Send(conn_req);

		rpc::ConnectReplyRawT conn_reply;
		conn_.Recv(conn_reply);
		if (conn_reply.debug)
			flag_debug = true;
		debug("connected to manager: procs=%d cover_edges=%d kernel_64_bit=%d slowdown=%d syscall_timeout=%u"
		      " program_timeout=%u features=0x%llx\n",
		      conn_reply.procs, conn_reply.cover_edges, conn_reply.kernel_64_bit,
		      conn_reply.slowdown, conn_reply.syscall_timeout_ms,
		      conn_reply.program_timeout_ms, static_cast<uint64>(conn_reply.features));
		leak_frames_ = conn_reply.leak_frames;

		proc_opts_.use_cover_edges = conn_reply.cover_edges;
		proc_opts_.is_kernel_64_bit = is_kernel_64_bit = conn_reply.kernel_64_bit;
		proc_opts_.slowdown = conn_reply.slowdown;
		proc_opts_.syscall_timeout_ms = conn_reply.syscall_timeout_ms;
		proc_opts_.program_timeout_ms = conn_reply.program_timeout_ms;
		if (conn_reply.cover)
			max_signal_.emplace();

		// Handshake stage 2: share information requested by the manager.
		rpc::InfoRequestRawT info_req;
		info_req.files = ReadFiles(conn_reply.files);

		// This does any one-time setup for the requested features on the machine.
		// Note: this can be called multiple times and must be idempotent.
#if SYZ_HAVE_FEATURES
		setup_sysctl();
		setup_cgroups();
#endif
#if SYZ_HAVE_SETUP_EXT
		// This can be defined in common_ext.h.
		setup_ext();
#endif
		for (const auto& feat : features) {
			if (!(conn_reply.features & feat.id))
				continue;
			debug("setting up feature %s\n", rpc::EnumNameFeature(feat.id));
			const char* reason = feat.setup();
			conn_reply.features &= ~feat.id;
			std::unique_ptr<rpc::FeatureInfoRawT> res(new rpc::FeatureInfoRawT);
			res->id = feat.id;
			res->need_setup = true;
			if (reason) {
				debug("failed: %s\n", reason);
				res->reason = reason;
			}
			info_req.features.push_back(std::move(res));
		}
		for (auto id : rpc::EnumValuesFeature()) {
			if (!(conn_reply.features & id))
				continue;
			std::unique_ptr<rpc::FeatureInfoRawT> res(new rpc::FeatureInfoRawT);
			res->id = id;
			res->need_setup = false;
			info_req.features.push_back(std::move(res));
		}

#if SYZ_HAVE_KCSAN
		setup_kcsan_filter(conn_reply.race_frames);
#endif

		conn_.Send(info_req);

		rpc::InfoReplyRawT info_reply;
		conn_.Recv(info_reply);
		debug("received info reply: covfilter=%zu\n", info_reply.cover_filter.size());
		if (!info_reply.cover_filter.empty()) {
			cover_filter_.emplace();
			for (auto pc : info_reply.cover_filter)
				cover_filter_->Insert(pc);
		}

		Select::Prepare(conn_.FD());
		return conn_reply.procs;
	}

	void Handle(rpc::ExecRequestRawT& msg)
	{
		debug("recv exec request %llu: type=%llu flags=0x%llx env=0x%llx exec=0x%llx size=%zu\n",
		      static_cast<uint64>(msg.id),
		      static_cast<uint64>(msg.type),
		      static_cast<uint64>(msg.flags),
		      static_cast<uint64>(msg.exec_opts->env_flags()),
		      static_cast<uint64>(msg.exec_opts->exec_flags()),
		      msg.data.size());
		if (msg.exec_opts && IsSet(msg.exec_opts->exec_flags(), rpc::ExecFlag::Barrier) &&
		    msg.barrier_group_size > 1) {
			HandleBarrierRequest(msg);
			return;
		}
		if (msg.type == rpc::RequestType::Binary) {
			ExecuteBinary(msg);
			return;
		}
		for (auto& proc : procs_) {
			if (proc->Execute(msg))
				return;
		}
		requests_.push_back(std::move(msg));
	}

	void Handle(const rpc::SignalUpdateRawT& msg)
	{
		debug("recv signal update: new=%zu\n", msg.new_max.size());
		if (!max_signal_)
			fail("signal update when no signal filter installed");
		for (auto pc : msg.new_max)
			max_signal_->Insert(pc);
	}

	void Handle(const rpc::CorpusTriagedRawT& msg)
	{
		// TODO: repair leak checking (#4728).
		debug("recv corpus triaged\n");
		corpus_triaged_ = true;
	}

	void Handle(const rpc::StateRequestRawT& msg)
	{
		// Debug request about our internal state.
		std::ostringstream ss;
		ss << *this;
		const std::string& str = ss.str();
		rpc::StateResultRawT res;
		res.data.insert(res.data.begin(), str.data(), str.data() + str.size());
		rpc::ExecutorMessageRawT raw;
		raw.msg.Set(std::move(res));
		conn_.Send(raw);
	}

	void HandleBarrierRequest(rpc::ExecRequestRawT& msg)
	{
		barrier_mode_enabled_ = true;
		int64_t group_id = msg.barrier_group_id;
		auto& group = barrier_groups_[group_id];
		if (group.members.empty()) {
			group.participants_mask = msg.barrier_participants;
			group.proc_slots = EnumerateMask(group.participants_mask);
			size_t expected = static_cast<size_t>(msg.barrier_group_size);
			const size_t participants = group.proc_slots.size();
			if (participants != 0) {
				if (expected == 0 || expected != participants)
					expected = participants;
			} else if (expected == 0) {
				expected = 1;
			}
			group.members.resize(expected);
		}
		size_t idx = msg.barrier_index >= 0 ? static_cast<size_t>(msg.barrier_index) : 0;
		if (idx >= group.members.size())
			group.members.resize(idx + 1);
		if (group.members[idx].has_value())
			failmsg("duplicate barrier member", "group=%lld index=%zu", (long long)group_id, idx);
		// debug("runner: barrier member queued group=%lld index=%lld total=%zu mask=0x%llx\n",
		//       static_cast<long long>(group_id), static_cast<long long>(msg.barrier_index),
		//       group.members.size(), static_cast<unsigned long long>(group.participants_mask));
		group.members[idx].emplace(std::move(msg));
		group.ready++;
		// debug("runner: barrier group=%lld progress=%zu/%zu\n", static_cast<long long>(group_id),
		//       group.ready, group.members.size());
		if (!group.queued && group.ready == group.members.size()) {
			pending_barriers_.push_back(group_id);
			group.queued = true;
			debug("runner: barrier group=%lld ready for dispatch (%zu members)\n",
			      static_cast<long long>(group_id), group.members.size());
		}
	}

	void CheckBarrierCompletions()
	{
		// Iterate over active barriers and flush any fully staged groups.
		std::vector<int64_t> done_groups;
		for (auto& [group_id, active] : active_barriers_) {
			if (active.completed < active.group_size)
				continue; // not all members finished yet
			bool all_staged = true;
			if (active.pending_results.size() != (size_t)active.group_size)
				all_staged = false;
			else {
				for (int i = 0; i < active.group_size; i++) {
					if (!active.pending_results[i].proc) {
						all_staged = false;
						break;
					}
				}
			}
			if (!all_staged)
				continue;
			debug("runner: barrier group=%lld all %d members staged; flushing\n",
			      (long long)group_id, active.group_size);
#if GOOS_linux
			const DdrdOutputState* injected = nullptr;
			if (active.ddrd_active) {
				ddrd_controller_.CollectResults();
				if (ddrd_controller_.HasResults()) {
					debug("runner: DDRD collected for group=%lld (UAF pairs=%zu)\n",
					      (long long)group_id, ddrd_controller_.GetOutput().basic_pairs.size());
					injected = &ddrd_controller_.GetOutput();
				}
			}
#endif
			// Flush each staged member; inject DDRD only into master (index 0).
			for (int i = 0; i < active.group_size; i++) {
				StagedBarrierResult& staged = active.pending_results[i];
				if (!staged.proc)
					continue;
#if GOOS_linux
				const DdrdOutputState* use_injection = (i == 0) ? injected : nullptr;
#else
				const void* use_injection = nullptr;
#endif
				staged.proc->FlushPendingResult(staged, use_injection);
			}
#if GOOS_linux
			if (active.ddrd_active)
				ddrd_controller_.ResetAfterGroup();
#endif
			done_groups.push_back(group_id);
		}
		for (auto gid : done_groups) {
			active_barriers_.erase(gid);
			debug("runner: barrier group=%lld cleanup complete\n", (long long)gid);
		}
	}

	void DispatchBarrierGroups()
	{
		while (!pending_barriers_.empty()) {
			auto it = barrier_groups_.find(pending_barriers_.front());
			if (it == barrier_groups_.end()) {
				pending_barriers_.pop_front();
				continue;
			}
			// debug("runner: TryDispatchBarrier barrier group=%lld\n", static_cast<long long>(pending_barriers_.front()));
			if (!TryDispatchBarrier(pending_barriers_.front(), it->second))
				break;
			barrier_groups_.erase(it);
			pending_barriers_.pop_front();
		}
	}

	uint64 PendingBarrierMask()
	{
		while (!pending_barriers_.empty()) {
			auto it = barrier_groups_.find(pending_barriers_.front());
			if (it == barrier_groups_.end()) {
				pending_barriers_.pop_front();
				continue;
			}
			return it->second.participants_mask;
		}
		return 0;
	}

	bool TryDispatchBarrier(int64_t group_id, BarrierGroupState& group)
	{
		if (group.ready != group.members.size() || group.members.empty())
			return false;
		// debug("TryDispatchBarrier start\n");
		std::vector<Proc*> selected(group.members.size(), nullptr);
		if (!group.proc_slots.empty()) {
			if (group.proc_slots.size() != group.members.size()){
				// debug("barrier %lld mismatch: slots=%zu members=%zu mask=0x%llx\n",
              	// (long long)group_id, group.proc_slots.size(), group.members.size(),
              	// (unsigned long long)group.participants_mask);
			  	return false;
			}

			for (size_t i = 0; i < group.members.size(); i++) {
				if (!group.members[i].has_value())
					return false;
				Proc* proc = ProcBySlot(group.proc_slots[i]);
				if (!proc || !proc->CanRun(*group.members[i]))
					return false;
				selected[i] = proc;
			}
		} else {
			std::vector<Proc*> avail;
			for (auto& proc : procs_) {
				if (proc->IsAvailable())
					avail.push_back(proc.get());
			}
			if (avail.size() < group.members.size())
				return false;
			std::vector<bool> used(avail.size(), false);
			for (size_t i = 0; i < group.members.size(); i++) {
				if (!group.members[i].has_value())
					return false;
				bool assigned = false;
				for (size_t j = 0; j < avail.size(); j++) {
					if (used[j])
						continue;
					if (!avail[j]->CanRun(*group.members[i]))
						continue;
					selected[i] = avail[j];
					used[j] = true;
					assigned = true;
					break;
				}
				if (!assigned)
					return false;
			}
		}

#if GOOS_linux
		// Check if any member requests DDRD and prepare
		bool collect_uaf = false;
		bool collect_extended = false;
		for (const auto& member : group.members) {
			if (member.has_value() && member->exec_opts) {
				auto flags = member->exec_opts->exec_flags();
				if (IsSet(flags, rpc::ExecFlag::CollectDdrdUaf))
					collect_uaf = true;
				if (IsSet(flags, rpc::ExecFlag::CollectDdrdExtended))
					collect_extended = true;
			}
		}
		if (collect_uaf || collect_extended) {
			ddrd_controller_.PrepareForGroup(collect_uaf, collect_extended);
			group.ddrd_active = true;
		} else {
			group.ddrd_active = false;
		}
#endif

		// debug("runner: dispatching barrier group=%lld members=%zu reserved_mask=0x%llx\n",
		//       static_cast<long long>(group_id), group.members.size(),
		//       static_cast<unsigned long long>(group.participants_mask));

		// Record active barrier execution before dispatching
		ActiveBarrierExecution active;
		active.group_id = group_id;
		active.group_size = static_cast<int32_t>(selected.size());
		active.completed = 0;
		active.ddrd_active = group.ddrd_active;
		active_barriers_[group_id] = active;

		for (size_t i = 0; i < selected.size(); i++) {
			if (!selected[i])
				return false;
			// auto& member = *group.members[i];
			// debug("runner: barrier group=%lld member=%zu -> proc=%d index=%lld size=%lld\n",
			//       static_cast<long long>(group_id), i, selected[i]->Id(),
			//       static_cast<long long>(member.barrier_index),
			//       static_cast<long long>(member.barrier_group_size));
			if (!selected[i]->Execute(*group.members[i]))
				failmsg("failed to dispatch barrier member", "group=%lld index=%zu proc=%d",
				        (long long)group_id, i, selected[i]->Id());
			group.members[i].reset();
		}

		return true;
	}

	Proc* ProcBySlot(int slot)
	{
		for (auto& proc : procs_) {
			if (proc->Id() == slot)
				return proc.get();
		}
		return nullptr;
	}

	static std::vector<int> EnumerateMask(uint64 mask)
	{
		std::vector<int> ids;
		int bit = 0;
		while (mask) {
			if (mask & 1)
				ids.push_back(bit);
			mask >>= 1;
			bit++;
		}
		return ids;
	}

	void ExecuteBinary(rpc::ExecRequestRawT& msg)
	{
		rpc::ExecutingMessageRawT exec;
		exec.id = msg.id;
		rpc::ExecutorMessageRawT raw;
		raw.msg.Set(std::move(exec));
		conn_.Send(raw);

		char dir_template[] = "syz-bin-dirXXXXXX";
		char* dir = mkdtemp(dir_template);
		if (dir == nullptr)
			fail("mkdtemp failed");
		if (chmod(dir, 0777))
			fail("chmod failed");
		auto [err, output] = ExecuteBinaryImpl(msg, dir);
		if (!err.empty()) {
			char tmp[64];
			snprintf(tmp, sizeof(tmp), " (errno %d: %s)", errno, strerror(errno));
			err += tmp;
		}
		remove_dir(dir);
		rpc::ExecResultRawT res;
		res.id = msg.id;
		res.error = std::move(err);
		res.output = std::move(output);
		raw.msg.Set(std::move(res));
		conn_.Send(raw);
	}

	std::tuple<std::string, std::vector<uint8_t>> ExecuteBinaryImpl(rpc::ExecRequestRawT& msg, const char* dir)
	{
		// For simplicity we just wait for binary tests to complete blocking everything else.
		std::string file = std::string(dir) + "/syz-executor";
		int fd = open(file.c_str(), O_WRONLY | O_CLOEXEC | O_CREAT, 0755);
		if (fd == -1)
			return {"binary file creation failed", {}};
		ssize_t wrote = write(fd, msg.data.data(), msg.data.size());
		close(fd);
		if (wrote != static_cast<ssize_t>(msg.data.size()))
			return {"binary file write failed", {}};

		int stdin_pipe[2];
		if (pipe(stdin_pipe))
			fail("pipe failed");
		int stdout_pipe[2];
		if (pipe(stdout_pipe))
			fail("pipe failed");

		const char* argv[] = {file.c_str(), nullptr};
		std::vector<std::pair<int, int>> fds = {
		    {stdin_pipe[0], STDIN_FILENO},
		    {stdout_pipe[1], STDOUT_FILENO},
		    {stdout_pipe[1], STDERR_FILENO},
		};
		Subprocess process(argv, fds);

		close(stdin_pipe[0]);
		close(stdout_pipe[1]);

		int status = process.WaitAndKill(5 * proc_opts_.program_timeout_ms);

		std::vector<uint8_t> output;
		for (;;) {
			const size_t kChunk = 1024;
			output.resize(output.size() + kChunk);
			ssize_t n = read(stdout_pipe[0], output.data() + output.size() - kChunk, kChunk);
			output.resize(output.size() - kChunk + std::max<ssize_t>(n, 0));
			if (n <= 0)
				break;
		}
		close(stdin_pipe[1]);
		close(stdout_pipe[0]);

		return {status == kFailStatus ? "process failed" : "", std::move(output)};
	}
};

static void SigintHandler(int sig)
{
	// GCE VM preemption is signalled as SIGINT, notify syz-manager.
	exitf("SYZ-EXECUTOR: PREEMPTED");
}

static void SigchldHandler(int sig)
{
	// We need just blocking syscall preemption.
}

static void FatalHandler(int sig, siginfo_t* info, void* ucontext)
{
	// Print minimal debugging info we can extract reasonably easy.
	uintptr_t pc = 0xdeadbeef;
#if GOOS_linux
	auto& mctx = static_cast<ucontext_t*>(ucontext)->uc_mcontext;
	(void)mctx;
#if GOARCH_amd64
	pc = mctx.gregs[REG_RIP];
#elif GOARCH_arm64
	pc = mctx.pc;
#endif
#endif
	const char* name = "unknown signal";
	switch (sig) {
	case SIGSEGV:
		name = "SIGSEGV";
		break;
	case SIGBUS:
		name = "SIGBUS";
		break;
	case SIGILL:
		name = "SIGILL";
		break;
	case SIGFPE:
		name = "SIGFPE";
		break;
	}
	// Print the current function PC so that it's possible to map the failing PC
	// to a symbol in the binary offline (we usually compile as PIE).
	failmsg(name, "pc-offset:0x%zx pc:%p addr:%p code=%d",
		reinterpret_cast<uintptr_t>(reinterpret_cast<void*>(FatalHandler)) - pc,
		reinterpret_cast<void*>(pc), info->si_addr, info->si_code);
}

static void runner(char** argv, int argc)
{
	if (argc != 5)
		fail("usage: syz-executor runner <index> <manager-addr> <manager-port>");
	char* endptr = nullptr;
	int vm_index = strtol(argv[2], &endptr, 10);
	if (vm_index < 0 || *endptr != 0)
		failmsg("failed to parse VM index", "str='%s'", argv[2]);
	const char* const manager_addr = argv[3];
	const char* const manager_port = argv[4];

	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = kFdLimit;
	if (setrlimit(RLIMIT_NOFILE, &rlim))
		fail("setrlimit(RLIMIT_NOFILE) failed");

	// Ignore all signals we are not interested in.
	// In particular we want to ignore SIGPIPE, but also everything else since
	// test processes manage to send random signals using tracepoints with bpf programs.
	// This is not a bullet-proof protection, but it won't harm either.
	for (int sig = 0; sig <= 64; sig++)
		signal(sig, SIG_IGN);
	if (signal(SIGINT, SigintHandler) == SIG_ERR)
		fail("signal(SIGINT) failed");
	if (signal(SIGTERM, SigintHandler) == SIG_ERR)
		fail("signal(SIGTERM) failed");
	if (signal(SIGCHLD, SigchldHandler) == SIG_ERR)
		fail("signal(SIGCHLD) failed");
	struct sigaction act = {};
	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = FatalHandler;
	for (auto sig : {SIGSEGV, SIGBUS, SIGILL, SIGFPE}) {
		if (sigaction(sig, &act, nullptr))
			failmsg("sigaction failed", "sig=%d", sig);
	}

	Connection conn(manager_addr, manager_port);

	// This is required to make Subprocess fd remapping logic work.
	// kCoverFilterFd is the largest fd we set in the child processes.
	for (int fd = conn.FD(); fd < kCoverFilterFd;)
		fd = dup(fd);

	Runner(conn, vm_index, argv[0]);
}
