# PTMX 24-hour four-arm launch record

## Launch

The local PTMX formal matrix started at approximately
`2026-08-26 02:14:45 +12:00`. Its expected cutoff is approximately
`2026-08-27 02:14:45 +12:00`.

```text
run prefix = 20260826-local-ptmx-formal24h-v2
sessions   = local24-ptmx-{dynamic,random,fixed50,fixed10000}
arms       = Dynamic, Random, Fixed-50, Fixed-10000
VMs        = 2 fuzz + 4 validation per arm; 24 total at full demand
```

The frozen manager SHA256 is
`272291cb71420673e0d3f0bd8d0ed50608fb4ceb59c90f7602b074fa5d257299` and
the executor SHA256 is
`1990510583668b46562f889396b05a2a2e10c34573f5b03193f6ff452d2edced`.
Both carry the syzkaller revision stamp from commit `c30d8ea60`.

## Startup health

At approximately four minutes after launch:

```text
arm          status    calls executed    MRP pairs    threshold
Dynamic      running              328          111        500us
Random       running              153          163       1582us
Fixed-50     running             1829           38         50us
Fixed-10000  running             1474         1876      10000us
```

- All four fuzz managers had two live QEMU instances and increasing calls.
- All four validation managers were consuming their independent queues.
- Validation demand reached the full 24-QEMU matrix capacity.
- Watcher records had `calls_stall_warning=false` for every arm.
- Dynamic completed two real GPT-5.4 API calls, accepted four generated
  programs, and its fuzzer logged `loaded=4 queued=4`. The completed round used
  16,608 input and 5,116 output tokens with no API or JSON failure.
- Host resources after all validation images were created were approximately
  62 GiB available memory and 58 GiB free disk. These remain above the formal
  abort boundaries of 20 GiB and 30 GiB.

The startup sample establishes operational health only; it is not an
experimental result.

## Rejected first launch

The `v1` attempt ran for about one minute and produced no usable experiment
data. The manager had been rebuilt while the executor still carried an older
syzkaller revision stamp, so all four fuzz managers correctly rejected the RPC
connection. The failed directories remain marked `failed` for auditability and
must not be included in result aggregation. The matching binary pair was built
and all formal arms were restarted from clean `v2` run IDs.
