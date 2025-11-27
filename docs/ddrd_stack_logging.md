# DDRD Stack Hash Logging Update

## Summary
- Extended the runner-side DDRD debug trace to include the raw call stack hashes gathered for each Use-After-Free pair.
- The log line emitted from `executor/executor_runner.h` now prints `free_stack` and `use_stack` fields alongside the existing access, signal, timing, and lock metadata.

## Impact
- Facilitates correlation of DDRD findings with stack-based diagnostics by exposing the 64-bit stack hash values directly in the debug output.
- No functional changes to DDRD analysis; the update only affects debugging visibility during barrier runs.

## Follow-up
- Rebuild the executor (`make executor`) to ensure the updated logging code is used at runtime.
