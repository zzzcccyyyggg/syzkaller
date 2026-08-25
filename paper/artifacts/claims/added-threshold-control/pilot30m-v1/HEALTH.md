# Pilot Health Record

- Observation date: 2026-08-21 (Pacific/Auckland).
- Valid run status: Dynamic, Fixed-500 retry1, Fixed-2500, and Fixed-10000 completed normally.
- Runner exit status: 0 for all four valid runs.
- Final QEMU state: no fuzz or validation QEMU PID remained in the final samples.
- Data integrity: threshold state remained valid JSON and retained both fuzzer and validator sections.
- Controller signal: validator timestamps remained fresh and Dynamic recorded three evidence-backed shrink decisions.
- LLM signal: every valid run initially loaded 12 Kimi groups and continued rate-limited polling.
- Progress signal: calls executed increased throughout all valid runs.
- Observed resource headroom: sampled available memory remained at or above approximately 33 GiB; sampled free disk remained above approximately 89 GiB.
- Expected validation activity: collection/verify batches and task-success records were present in every valid run.
- Confirmed race result: zero validated races in every variant during this short pilot.

## Incident

The original Fixed-500 run stalled at 63 calls for 240 seconds and was stopped automatically. Its evidence was retained, and a same-configuration retry completed successfully. The incident is treated as a transient run failure, not silently removed data.

## Reflection Gaps

- Single module and single valid repeat per policy.
- Offline Kimi replay rate greatly exceeded the historical producer rate.
- Validation stable-pair fanout made the 30-minute window too short for meaningful race-yield comparison.
- No randomized-threshold policy was tested.
- No Feishu notification contract was requested for this local pilot.
