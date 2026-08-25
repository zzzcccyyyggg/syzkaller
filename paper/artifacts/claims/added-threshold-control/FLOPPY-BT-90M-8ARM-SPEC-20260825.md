# Floppy and Bluetooth threshold pilot: eight arms for 90 minutes

Status: approved short pilot; results must not be presented as 12/24-hour data.

## Arms

Each module runs Dynamic `[50, 10000]us`, discrete-uniform Random over the same
range, Fixed-50, and Fixed-10000. All arms use the per-VM 120-second execution
watchdog and do not enable global calls-stall termination.

## Per-arm resources

```text
duration        = 5400s
fuzz            = 2 physical CPUs, 2 VMs x 2 vCPU, procs=2
validate        = 2 physical CPUs, 4 VMs x 2 vCPU
LLM             = 1 physical CPU, GPT-5.4 direct API, medium reasoning
entries/round   = 2
parallel calls  = 1
memory per VM   = 1GiB
VM lifetime     = 3600s
```

The remote 56-core host assigns CPUs 0-19 to Floppy and 20-39 to Bluetooth in
five-core blocks per arm. CPUs 40-55 remain unassigned for the host control
plane. HTTP base ports are 64000 through 64700 in increments of 100.

## Shared semantics

The arms share frozen initial corpus, kernel, executor, validation behavior,
delay multipliers/cap, stack cap 4, one concurrent task per canonical family,
collection backoff `free=1, weight=0.95, max_defer=0.9`, and threshold-aware
validation priority. Workdirs, queues, ports, LLM state, and VM images are
independent.

The launch implementation is
`run_floppy_bt_90m_8arm.py`. Configuration audit must complete for all eight
arms before launch. Startup health requires every arm to reach 2 fuzz and 4
validation QEMUs, increasing calls, and a live LLM producer; API success is
required once an eligible entry exists.
