#!/usr/bin/env bash
cd /home/zzzccc/BASS/DDRD-syzkaller
mkdir -p exp/ocfs2/logs
exec bash scripts/run_ocfs2_3phase.sh
