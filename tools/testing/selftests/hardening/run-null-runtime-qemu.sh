#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

set -eu

CC=${CC:-gcc}
QEMU=${QEMU:-qemu-system-x86_64}
KBUILD_OUTPUT=${KBUILD_OUTPUT:-}
WORK=${HDN_NULL_RUNTIME_WORK:-"${TMPDIR:-/tmp}/hdn-null-runtime.$$"}
LOG=${HDN_NULL_RUNTIME_LOG:-"$WORK/qemu.log"}
QEMU_MACHINE=${QEMU_MACHINE:-q35,accel=kvm}

if [ -z "$KBUILD_OUTPUT" ] || [ ! -r "$KBUILD_OUTPUT/arch/x86/boot/bzImage" ]; then
	echo "null-runtime: missing KBUILD_OUTPUT bzImage" >&2
	exit 2
fi
for command in "$CC" "$QEMU" cpio gzip timeout; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "null-runtime: missing command: $command" >&2
		exit 2
	fi
done

mkdir -p "$WORK/initramfs/dev" "$WORK/initramfs/proc" "$WORK/initramfs/sys"
"$CC" -static -O2 -Wall -Wextra -Werror \
	tools/testing/selftests/hardening/hdn_null_runtime_vm.c \
	-o "$WORK/initramfs/init"
(
	cd "$WORK/initramfs"
	find . -print0 | cpio --null -o --format=newc --owner=0:0 2>/dev/null | \
		gzip -9 > "$WORK/initramfs.cpio.gz"
)

set +e
timeout --signal=TERM --kill-after=10s 90s "$QEMU" \
	-machine "$QEMU_MACHINE" -cpu host -m 768 -smp 2 \
	-nodefaults -no-reboot -display none -monitor none -serial stdio \
	-kernel "$KBUILD_OUTPUT/arch/x86/boot/bzImage" \
	-initrd "$WORK/initramfs.cpio.gz" \
	-append "console=ttyS0 earlyprintk=serial nokaslr oops=panic panic=1" \
	>"$LOG" 2>&1
status=$?
set -e
cat "$LOG"

if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
	echo "null-runtime: guest timed out" >&2
	exit 1
fi
for marker in \
	HDN_NULL_RUNTIME_BOOTED \
	HDN_NULL_RUNTIME_MMAP_MIN \
	"HDN_NULL_RUNTIME_LOW_MAP_DENIED address=(nil)" \
	"HDN_NULL_RUNTIME_LOW_MAP_DENIED address=0x1000" \
	"HDN_NULL_RUNTIME_LKDTM_TRIGGER ACCESS_NULL"
do
	if ! grep -Fq "$marker" "$LOG"; then
		echo "null-runtime: missing marker: $marker" >&2
		exit 1
	fi
done
if grep -Eq 'HDN_NULL_RUNTIME_(FAIL|SURVIVED)|FAIL: survived bad (read|write)' "$LOG"; then
	echo "null-runtime: guest reported an unsafe result" >&2
	exit 1
fi
if ! grep -Eq 'BUG: (unable to handle page fault for address:|kernel NULL pointer dereference, address:) 0+|Unable to handle kernel NULL pointer dereference' "$LOG"; then
	echo "null-runtime: missing ordinary null-fault report" >&2
	exit 1
fi
if ! grep -Eq 'RIP: .*lkdtm_ACCESS_NULL|pc : lkdtm_ACCESS_NULL' "$LOG"; then
	echo "null-runtime: fault was not attributed to lkdtm_ACCESS_NULL" >&2
	exit 1
fi
if ! grep -Fq 'Kernel panic - not syncing:' "$LOG"; then
	echo "null-runtime: configured oops-to-panic path did not run" >&2
	exit 1
fi

echo "null-runtime: PASS (low mappings denied; ACCESS_NULL followed oops-to-panic path)"
