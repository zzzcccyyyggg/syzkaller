#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
	echo "usage: $0 <delay> <log> <config> [<config>...]" >&2
	exit 2
fi

delay="$1"
log="$2"
shift 2
configs=("$@")

timestamp() {
	date '+%F %T %Z'
}

manager_pattern_for_config() {
	local cfg="$1"
	printf 'syz-manager -config %s' "$cfg"
}

kill_managers_for_config() {
	local cfg="$1"
	local sig="$2"
	local pattern
	pattern="$(manager_pattern_for_config "$cfg")"
	pgrep -f "$pattern" | xargs -r kill "-$sig"
}

kill_qemu_for_workdir() {
	local workdir="$1"
	local sig="$2"
	if [[ -z "$workdir" || "$workdir" == "null" ]]; then
		return
	fi
	ps -C qemu-system-x86_64 -o pid=,args= |
		grep -F "$workdir" |
		awk '{print $1}' |
		xargs -r kill "-$sig"
}

{
	echo "timer_started=$(timestamp)"
	echo "stop_after=$delay"
	for cfg in "${configs[@]}"; do
		echo "config=$cfg"
		if [[ -f "$cfg" ]]; then
			echo "workdir[$cfg]=$(jq -r '.workdir // empty' "$cfg")"
		fi
	done
} >>"$log" 2>&1

sleep "$delay"

{
	echo "timer_fired=$(timestamp)"
	echo "managers_before_stop:"
	for cfg in "${configs[@]}"; do
		pgrep -af "$(manager_pattern_for_config "$cfg")" || true
	done
} >>"$log" 2>&1

for cfg in "${configs[@]}"; do
	kill_managers_for_config "$cfg" TERM || true
done

sleep 30

for cfg in "${configs[@]}"; do
	kill_managers_for_config "$cfg" KILL || true
done

for cfg in "${configs[@]}"; do
	if [[ -f "$cfg" ]]; then
		workdir="$(jq -r '.workdir // empty' "$cfg")"
		kill_qemu_for_workdir "$workdir" TERM || true
	fi
done

sleep 5

for cfg in "${configs[@]}"; do
	if [[ -f "$cfg" ]]; then
		workdir="$(jq -r '.workdir // empty' "$cfg")"
		kill_qemu_for_workdir "$workdir" KILL || true
	fi
done

{
	echo "timer_done=$(timestamp)"
	echo "managers_after_stop:"
	for cfg in "${configs[@]}"; do
		pgrep -af "$(manager_pattern_for_config "$cfg")" || true
	done
	echo "qemu_after_stop:"
	for cfg in "${configs[@]}"; do
		if [[ -f "$cfg" ]]; then
			workdir="$(jq -r '.workdir // empty' "$cfg")"
			if [[ -n "$workdir" ]]; then
				ps -C qemu-system-x86_64 -o pid=,args= | grep -F "$workdir" || true
			fi
		fi
	done
} >>"$log" 2>&1
