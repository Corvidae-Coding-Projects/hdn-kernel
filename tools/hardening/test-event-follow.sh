#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu

tmp="$(mktemp -d)"
pid=
cleanup()
{
	if [ -n "$pid" ]; then
		kill -TERM "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

event_one='sequence=1 timestamp_ns=10 event_id=1 pid=1 uid=0 profile=1 authority=1 transition=1 action=1 reason=0 error=0 subject=1 object=0 flags=0'
event_two='sequence=2 timestamp_ns=20 event_id=2 pid=2 uid=0 profile=1 authority=2 transition=2 action=4 reason=1 error=-1 subject=2 object=0 flags=0'

printf '%s\n' "$event_one" > "$tmp/events"
./hdn-event-decode --follow --input "$tmp/events" > "$tmp/output" &
pid=$!
sleep 1
printf '%s\n' "$event_two" >> "$tmp/events"
sleep 1
kill -TERM "$pid"
wait "$pid"
pid=

[ "$(wc -l < "$tmp/output")" -eq 2 ]
[ "$(grep -c '^sequence=1 ' "$tmp/output")" -eq 1 ]
[ "$(grep -c '^sequence=2 ' "$tmp/output")" -eq 1 ]

if ./hdn-event-decode --follow --expect action=DENY \
	> "$tmp/invalid.out" 2>&1; then
	echo "test-event-follow: follow unexpectedly accepted --expect" >&2
	exit 1
fi

echo "test-event-follow: ring snapshots emit each sequence once"
