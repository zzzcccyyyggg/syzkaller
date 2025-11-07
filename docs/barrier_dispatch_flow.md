# Barrier Request Dispatch Flow in `executor_runner::Loop`

This note explains how the runner coordinates synchronous barrier executions inside the main `Runner::Loop()` in `executor/executor_runner.h`.

## 1. High-level loop stages

Each iteration of `Runner::Loop()` performs the following stages:

1. Create a `Select` object, arm the manager connection, and arm every subprocess pipe (`proc->Arm(select)`).
2. Wait up to 1 second for activity (`select.Wait(1000)`), primarily to detect hung subprocesses.
3. If the manager socket is ready, pull one host message and forward it to the appropriate handler. Barrier-aware requests call `HandleBarrierRequest()` and are **not** enqueued into `requests_` yet.
4. Call `DispatchBarrierGroups()` to attempt dispatching any barrier groups whose members have all arrived and whose target procs are available.
5. Query `PendingBarrierMask()` to learn which proc slots are reserved for barrier executions that are about to be dispatched.
6. Iterate over all procs: update their state (`proc->Ready(...)`), and if the normal request queue is not empty, attempt to start the front request on an idle proc whose slot is not reserved by an upcoming barrier member.

The remainder of this document focuses on stages 4–6, where barrier coordination happens.

## 2. Barrier state bookkeeping

Barrier requests are accumulated in `barrier_groups_`, an `unordered_map<int64_t, BarrierGroupState>`. Each `BarrierGroupState` tracks:

- `participants_mask`: bitmask of proc slots that should execute the group together (optional; 0 means "any idle proc").
- `proc_slots`: cached vector of slot ids extracted from the mask.
- `members`: vector of per-index `ExecRequestRawT` objects (optional entries until members arrive).
- `ready`: count of members already queued.
- `queued`: marks whether the group id was pushed into `pending_barriers_` (to avoid duplicates).

When `HandleBarrierRequest()` receives a new barrier member, it stores the request in `group.members[barrier_index]`, tracks progress, and once `ready == members.size()` the group id is appended to `pending_barriers_`.

## 3. Dispatching ready groups

`DispatchBarrierGroups()` walks `pending_barriers_` in FIFO order and tries to schedule the group at the front:

1. Lookup the `BarrierGroupState` by group id.
2. Call `TryDispatchBarrier()`. This checks that:
   - All expected members are present (`ready == members.size()` and no `nullopt` entries).
   - Either the participating proc slots were specified in the mask (and the corresponding procs are idle), or we can select a matching set of idle procs dynamically.
3. If the group cannot be dispatched yet (e.g. not all target procs are idle), the loop breaks to retry next iteration.
4. On success, each selected proc receives its `ExecRequestRawT` via `Proc::Execute()`, the stored entries are cleared, and the group state is removed from `barrier_groups_`.

Because dispatch is all-or-nothing, the barrier members start together after this function returns, ensuring synchronous execution semantics.

## 4. Reserving proc slots for imminent barriers

Immediately after `DispatchBarrierGroups()`, the runner calls `PendingBarrierMask()`. This function peeks at the next entry in `pending_barriers_` (without removing it) and returns the `participants_mask` for that group. The mask is a bitset over proc slots that are **required** by the upcoming barrier.

While the mask is non-zero, the subsequent loop that pulls from `requests_` will skip any proc whose slot bit is set:

```cpp
if (reserved_mask & (1ull << proc->Id()))
    continue;
```

This prevents ordinary requests from occupying slots that must remain free for the barrier group to dispatch in a later iteration. If the mask is zero (group has no affinity requirements), the loop proceeds normally; the barrier will only dispatch when enough idle procs are available, enforced by `TryDispatchBarrier()`.

## 5. Interaction with `requests_`

Barrier members never enter `requests_`. Only standard (non-barrier) requests fall through to the queue. When a barrier group is ready but cannot yet start because target procs are busy, the pending mask blocks new normal work on those procs, eventually freeing them and allowing `TryDispatchBarrier()` to succeed in a future iteration.

## 6. Summary of control flow

- Host messages arrive → `HandleBarrierRequest()` stores barrier members.
- Once a group is complete → group id enqueued to `pending_barriers_`.
- Each loop iteration → `DispatchBarrierGroups()` attempts to run the front group.
- Front group’s `participants_mask` → `PendingBarrierMask()` marks proc slots as reserved.
- Normal queue dispatch skips reserved procs, preserving capacity for the barrier group.

Together these steps guarantee that all members of a barrier group start together on the intended set of procs without starving ordinary work or deadlocking when procs are busy.

## 7. What happens after dispatch succeeds?

When `TryDispatchBarrier()` returns `true`, every member of the barrier group was handed off to a concrete `Proc` instance via `Proc::Execute()`:

1. **Per-proc scheduling** — Each selected `Proc` transitions to either `Handshake()` (if the helper executor just restarted) or `Execute()` (when already idle). This mirrors the normal request path; barrier members do not get special treatment beyond carrying barrier metadata.
2. **Manager notification** — Inside `Proc::Execute()` the runner sends an `ExecutingMessageRawT` back to the manager. This happens for every member, so the manager sees the whole group starting in rapid succession.
3. **Shared-memory payload** — The program bytes are copied into the proc’s request shared memory. The `execute_req` structure that is written down the request pipe includes the barrier identifiers: `barrier_group_id`, `barrier_index`, and `barrier_group_size`.
4. **Executor side barrier rendezvous** — The forked executor process reads `execute_req` in its main loop (`receive_execute` → `execute`) and stores the barrier fields in the per-run context. When the program reaches `syz_barrier_wait`, the executor uses that context to synchronise with peer executors. Only when all members reach the barrier does the syscall complete, enforcing the group rendezvous semantics.
5. **Completion handling** — After the program finishes, `Proc::HandleCompletion()` packages the results (including barrier metadata) and sends them to the manager. If a member crashed or hung, the usual restart/error paths trigger; the other members are unaffected except for whatever effect the barrier syscall itself imposes inside the executor runtime.

The key point is that once a barrier group is dispatched, each member travels through the standard executor pipeline. The barrier-specific fields survive end-to-end (request → executor → response) so that both the executor runtime and the manager can correlate the runs and enforce synchronous behaviour.
