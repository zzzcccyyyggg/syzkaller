# exp-unified Temporary Archive

Created on: 2026-04-19
Source: `/home/zzzccc/BASS/DDRD-syzkaller/exp-unified`

This archive was created because the main filesystem was full and could not
hold a persistent archive under the repository tree.

Current archive purpose:

- preserve the small result artifacts under `exp-unified/results/`
- preserve per-module experiment metadata needed to interpret those results

Included:

- `results/exp-unified/results/ptmx.log`
- `results/exp-unified/results/original/btrfs.log`
- `metadata/exp-unified/<module>/syscalls.txt`
- `metadata/exp-unified/<module>/overrides.json`
- `metadata/exp-unified/<module>/fuzz.cfg`
- `metadata/exp-unified/<module>/validate.cfg`
- `metadata/exp-unified/<module>/exp-fuzz.cfg`
- `metadata/exp-unified/<module>/exp-validate.cfg`

Not included:

- `exp-unified/<module>/workdir/`
- `exp-unified/<module>/logs/`
- any large runtime data

Important:

- This archive lives in `/dev/shm`, which is RAM-backed temporary storage.
- It will not survive a reboot.
- After deleting `exp-unified`, move this archive to a persistent location if you
  still want to keep it long-term.
