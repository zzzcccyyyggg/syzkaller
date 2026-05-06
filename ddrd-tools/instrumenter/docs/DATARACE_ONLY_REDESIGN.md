# Instrumenter Datatrace-Only Redesign

## 1. Scope

This redesign only targets **data race detection**.

It explicitly does **not** optimize for:

- UAF-specific free tracking
- function enter/exit tracing
- basic block tracing
- generic "instrument everything that looks interesting"

The goal is narrower and stricter:

1. record real shared-memory accesses,
2. suppress definitely thread-local accesses,
3. preserve synchronization semantics needed by the runtime,
4. minimize algorithmic false positives and false negatives.

The current instrumenter does not meet that bar. The main issues are:

- the current taint gate is not a sound shared-access analysis,
- results depend too much on IR shape (`-O0` vs `-O1`),
- atomic and bulk-memory accesses are mostly invisible,
- stack spills and temporaries are frequently mistaken for shared accesses,
- synchronization modeling is incomplete,
- access identity is too weak for precise downstream reasoning.

## 2. Design Principles

### 2.1 Instrument actual memory events, not pointer ancestry guesses

The unit of observation must be a concrete memory access:

- `LoadInst`
- `StoreInst`
- `AtomicCmpXchgInst`
- `AtomicRMWInst`
- `memcpy/memmove/memset` style `MemIntrinsic`
- selected helper calls only when they are known to implement a memory access that is not visible in IR

The current "start from args/globals and taint forward" approach is not sufficient as the primary filter.

### 2.2 Filtering must be one-sided

Filtering is allowed to remove only accesses that are **definitely local**.

If an access is uncertain, keep it.

This is important because the current implementation drops many real shared accesses simply because the pointer came from a helper return, a PHI/select, or another non-seed source.

### 2.3 The access model must match the runtime conflict model

For each access we need enough metadata to answer:

- which address range was touched,
- whether it was a read, write, or atomic RMW,
- whether synchronization semantics apply,
- whether this is a bit-level sub-access with a known mask,
- which source site produced it.

If the runtime only knows `addr + site_hash + rw + size`, then many important distinctions are lost before validation even starts.

## 3. New Compiler-Side Algorithm

### 3.1 Replace taint-first filtering with access-first classification

For each memory event `M`:

1. decode the effective accessed pointer and access width,
2. recover the underlying object,
3. decide whether the access is definitely local,
4. if not definitely local, emit instrumentation.

Pseudo-code:

```text
for each function F:
  for each memory event M in F:
    D = decode_access(M)
    if !D.valid:
      continue

    Root = get_underlying_object(D.addr)
    Class = classify_root(Root, D.addr, M)

    if Class == DefinitelyLocal:
      continue

    Sync = classify_sync(M)
    Shape = classify_access_shape(M)
    Site = build_stable_site_id(M)

    emit_rec_mem_access(D.addr, Site, Shape, Sync, D.size)
```

### 3.2 Underlying object classification

Use LLVM object recovery helpers instead of the current custom taint walk.

Required analysis ingredients:

- `getUnderlyingObject` / `getUnderlyingObjects`
- `stripPointerCasts`
- `GEPOperator` handling
- PHI/select flattening
- `PointerMayBeCaptured`
- escape/capture tracking for `alloca`
- `TargetLibraryInfo` for `mem*`

Classification:

- `DefinitelyLocal`
  - non-escaping `alloca`
  - compiler spill slot
  - local aggregate field derived only from non-escaping allocas
  - stack-only temporary introduced by frontend/lowering
- `DefinitelyShared`
  - global variable
  - heap/allocator result
  - function argument pointer
  - pointer loaded from shared memory
  - pointer returned by call with unknown alias behavior
  - object reached through PHI/select merging shared candidates
- `UnknownButKeep`
  - anything not provably local

This immediately fixes the biggest current problem: stack slots like `%2 = alloca ptr` must not become race candidates simply because a later real shared pointer passed through them.

### 3.3 Supported access kinds

The new access decoder must support:

- plain load
- plain store
- atomic load
- atomic store
- atomic RMW
- compare-exchange
- memcpy read-side
- memcpy write-side
- memset write-side
- memmove read-side
- memmove write-side

For `memcpy/memmove` we should emit two logical accesses:

- source read range
- destination write range

This is much better than the current behavior, which only sees argument spills around the intrinsic call.

### 3.4 Stable site identity

The current `func_name + IR serial` hash is fragile and optimization-sensitive.

For datarace-only mode, `site_id` should be built from:

- canonical debug location
- inlining chain
- access opcode kind
- discriminator when available

Fallback only when debug info is missing:

- function name
- basic block index
- instruction order after pass insertion point

Important distinction:

- `site_id` identifies the **access site**
- `addr` identifies the **runtime memory object**

Downstream code should stop treating `var_name` as if it were a variable identity.

## 4. Bit, Flag, and Atomic Semantics

### 4.1 Same flag, different bit

This case needs careful handling.

Two accesses to different bits of the same word are **not automatically false positives**.

Examples:

- `flags |= BIT(0)` racing with `flags |= BIT(1)` is still a real unsynchronized read-modify-write conflict on the same word if these are plain non-atomic operations.
- C bitfields in the same storage unit are usually lowered to load-mask-store on the same byte/word, which also conflicts.

So the redesign must **not** blindly suppress same-word different-bit races.

### 4.2 What we should suppress

We may suppress only when we can prove both:

1. the accesses are disjoint at bit granularity,
2. the machine operation is also disjoint or synchronized.

That means:

- atomic kernel bitops that compile to atomic IR or known atomic helpers should be treated as atomic/synchronized, not as plain races,
- plain non-atomic bitfield updates should still be reported because they are true conflicting RMW accesses.

### 4.3 New access-shape metadata

Extend the instrumentation payload with optional bit-shape metadata:

```text
bit_offset   : starting bit within first byte
bit_width    : number of meaningful bits
shape_flags  : unknown/full-width/bitfield/atomic-rmw/memintrinsic
```

Extraction rules:

- for obvious bitfield lowering patterns (`load -> and/or/shl/lshr -> store same addr`), derive bit width and offset,
- for atomic bitops helper calls, annotate as atomic bit access,
- otherwise mark as `unknown/full-width`.

Runtime rule:

- only suppress overlap when both accesses have known, non-overlapping masks and at least one side is guaranteed not to issue a full-width conflicting RMW.

Default remains conservative: if unsure, report.

## 5. Synchronization Modeling

### 5.1 Lock instrumentation must be part of the datarace design

For datarace detection, memory accesses without synchronization context are not enough.

Required synchronization classes:

- mutex
- spinlock
- rwlock read
- rwlock write
- semaphore-like mutual exclusion if used by target subsystems
- completion/wait style one-way ordering only if runtime can consume it
- atomic access class

### 5.2 Fix current lock instrumentation limitations

Current problems:

- `trylock` config is parsed but unused,
- lock address is assumed to be operand 0,
- only exact function-pair matching is modeled.

Required redesign:

- keep a table of lock API descriptors:
  - function name
  - operation: acquire / release / try_acquire
  - lock mode: mutex / spin / read / write
  - lock pointer operand index
  - success condition for trylock
- emit lock events only on successful trylock paths,
- support common kernel lock helpers, not just direct primitive names.

### 5.3 Atomic accesses

Atomic accesses are not ordinary unsynchronized loads/stores.

Compiler side should mark:

- atomic load/store
- cmpxchg
- atomicrmw
- known atomic helper calls after intrinsic lowering

Runtime policy for datarace-only mode:

- atomic-vs-atomic does not create a data race report,
- atomic-vs-non-atomic conflicting access remains reportable,
- lock acquisition paths may still use atomics internally and should be filtered by sync-class rules.

## 6. Runtime Interface Redesign

Keep the old symbol available during migration, but define a new datarace-oriented entry point:

```c
void kccwf_rec_mem_access2(
    const volatile void *addr,
    u64 site_id,
    u8 access_kind,    // read/write/atomic_load/atomic_store/atomic_rmw/memcpy_read/...
    u8 sync_class,     // none/atomic/mutex/spin/rw_read/rw_write/...
    u16 bit_offset,    // 0xffff if unknown
    u16 bit_width,     // 0 if unknown/full-width
    u32 size_bytes,
    u32 debug_line_id  // stable compressed source id
);
```

Notes:

- `site_id` replaces the current over-loaded `var_name`.
- `addr + size_bytes + bit metadata` defines the conflict range.
- `access_kind` tells runtime whether this is plain or atomic.
- `sync_class` lets the runtime short-circuit obvious non-races.

Migration compatibility:

- old `kccwf_rec_mem_access()` can wrap into `kccwf_rec_mem_access2()` with conservative defaults.

## 7. What to Remove from Datatrace-Only Mode

For this mode, the following should be disabled by default:

- function enter/exit instrumentation
- basic block instrumentation
- free instrumentation

Reasons:

- they do not improve access precision,
- they complicate correctness,
- they add overhead and extra failure modes,
- downstream datarace logic already relies on stack trace collection in the kernel.

The CLI should expose an explicit datarace-focused mode:

```text
instrumenter input.ll --datarace-only --locks lockset.txt
```

Equivalent behavior:

- enable memory-access instrumentation,
- enable synchronization instrumentation,
- disable free/function/bb hooks.

## 8. Implementation Plan

### Phase 1: Correctness baseline

1. Remove current taint-based gating from the primary path.
2. Instrument all supported memory events.
3. Filter only definitely local allocas/spills.
4. Add atomic and memintrinsic support.
5. Disable function/bb/free hooks in datarace-only mode.

Expected outcome:

- far fewer false negatives,
- some temporary increase in candidate count,
- much more stable behavior across optimization levels.

### Phase 2: Precision recovery

1. Add underlying-object classification with capture/escape tracking.
2. Add lock API descriptor table and real trylock handling.
3. Add bit-shape extraction for bitfield and flag-update patterns.
4. Upgrade runtime API to `kccwf_rec_mem_access2`.

Expected outcome:

- lower false positive rate without reintroducing blind spots.

### Phase 3: Validation hardening

1. Replace textual sample tests with regression cases.
2. Add differential tests across `-O0`, `-O1`, `-O2`.
3. Add kernel-style helper cases:
   - accessor returns
   - `memcpy`
   - atomic bitops
   - trylock success/failure
   - stack spill non-race

## 9. Required Regression Matrix

At minimum, datarace-only mode must have tests for:

- global load/store
- argument-derived pointee load/store
- non-escaping `alloca` filtered out
- escaping `alloca` kept
- helper-returned shared pointer kept
- PHI/select merged shared pointer kept
- `memcpy` source and destination both instrumented
- atomic load/store recognized as atomic
- atomic RMW recognized as atomic
- bitfield same-byte accesses classified with bit metadata
- plain `flags |= BIT(x)` still reported as conflicting word access
- successful trylock acquires lock context
- failed trylock does not acquire lock context

## 10. Final Position

For datarace detection, the right redesign is:

- **access-first**
- **conservative local filtering**
- **explicit atomic and memintrinsic handling**
- **real synchronization modeling**
- **optional bit-shape precision, but never blanket suppression of different-bit accesses**

The current instrumenter should not be treated as a trustworthy datarace root until this redesign is implemented.
