#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

set -eu

require_cmd()
{
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 4
	fi
}

abs_path()
{
	case "$1" in
	/*) printf '%s\n' "$1" ;;
	*) printf '%s\n' "$PWD/$1" ;;
	esac
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../../.." && pwd)

KBUILD_OUTPUT=${KBUILD_OUTPUT:-"$ROOT/../linux-7.0.12-build"}
KBUILD_OUTPUT=$(abs_path "$KBUILD_OUTPUT")
BZIMAGE=${BZIMAGE:-"$KBUILD_OUTPUT/arch/x86/boot/bzImage"}
CC=${CC:-gcc}
QEMU=${QEMU:-qemu-system-x86_64}
QEMU_TIMEOUT=${QEMU_TIMEOUT:-180}
QEMU_MEMORY=${QEMU_MEMORY:-1024M}
QEMU_SMP=${QEMU_SMP:-2}
QEMU_MACHINE=${QEMU_MACHINE:-q35,accel=tcg}
HDN_SMOKE_EXPECTED_PASS=${HDN_SMOKE_EXPECTED_PASS:-1116}
WORK=${HDN_QEMU_WORK:-"${TMPDIR:-/tmp}/hdn-qemu-smoke.$$"}
LOG=${HDN_QEMU_LOG:-"$WORK/qemu.log"}
QMP=${HDN_QEMU_QMP:-"$WORK/qmp.sock"}
HDN_USB_HOTPLUG_TIMEOUT=${HDN_USB_HOTPLUG_TIMEOUT:-60}
SIGN_FILE=${SIGN_FILE:-"$KBUILD_OUTPUT/scripts/sign-file"}
HDN_SIGNING_KEY=${HDN_SIGNING_KEY:-"$KBUILD_OUTPUT/certs/signing_key.pem"}
HDN_SIGNING_CERT=${HDN_SIGNING_CERT:-"$KBUILD_OUTPUT/certs/signing_key.x509"}
HDN_SYMBOL_TEST_MODULE=${HDN_SYMBOL_TEST_MODULE:-"$KBUILD_OUTPUT/fs/efivarfs/efivarfs.ko"}

cleanup()
{
	if [ "${KEEP_HDN_QEMU_WORK:-0}" != "1" ]; then
		rm -rf "$WORK"
	fi
}

trap cleanup EXIT INT TERM

require_cmd "$CC"
require_cmd "$QEMU"
require_cmd cpio
require_cmd gzip
require_cmd find
require_cmd grep
require_cmd mkfifo
require_cmd nc
require_cmd timeout

if [ ! -r "$BZIMAGE" ]; then
	echo "missing kernel image: $BZIMAGE" >&2
	echo "build one first, for example: make O=$KBUILD_OUTPUT -j\$(nproc) bzImage" >&2
	exit 4
fi
if ! grep -q '^CONFIG_TEST_FIRMWARE=y$' "$KBUILD_OUTPUT/.config"; then
	echo "HDN QEMU smoke requires CONFIG_TEST_FIRMWARE=y for firmware policy proof" >&2
	echo "enable it in the kernel build config and rebuild bzImage" >&2
	exit 4
fi
if ! grep -q '^CONFIG_FUSE_FS=y$' "$KBUILD_OUTPUT/.config"; then
	echo "HDN QEMU smoke requires CONFIG_FUSE_FS=y for FUSE policy proof" >&2
	echo "enable it in the kernel build config and rebuild bzImage" >&2
	exit 4
fi
if ! grep -q '^CONFIG_TUN=y$' "$KBUILD_OUTPUT/.config"; then
	echo "HDN QEMU smoke requires CONFIG_TUN=y for non-loopback blackhole proof" >&2
	echo "enable it in the kernel build config and rebuild bzImage" >&2
	exit 4
fi
if ! grep -q '^CONFIG_FANOTIFY=y$' "$KBUILD_OUTPUT/.config"; then
	echo "HDN QEMU smoke requires CONFIG_FANOTIFY=y for fanotify watch policy proof" >&2
	echo "enable it in the kernel build config and rebuild bzImage" >&2
	exit 4
fi
if [ ! -x "$SIGN_FILE" ]; then
	echo "missing sign-file helper: $SIGN_FILE" >&2
	echo "build scripts first, for example: make O=$KBUILD_OUTPUT scripts" >&2
	exit 4
fi
if [ ! -r "$HDN_SIGNING_KEY" ] || [ ! -r "$HDN_SIGNING_CERT" ]; then
	echo "missing kernel signing key/cert under $KBUILD_OUTPUT/certs" >&2
	exit 4
fi
if ! grep -q '^CONFIG_EFIVAR_FS=m$' "$KBUILD_OUTPUT/.config"; then
	echo "HDN QEMU smoke requires CONFIG_EFIVAR_FS=m for module symbol-disclosure proof" >&2
	echo "enable it in the kernel build config and rebuild modules" >&2
	exit 4
fi
if [ ! -r "$HDN_SYMBOL_TEST_MODULE" ]; then
	echo "missing signed test module: $HDN_SYMBOL_TEST_MODULE" >&2
	echo "build modules first, for example: make O=$KBUILD_OUTPUT -j\$(nproc) modules" >&2
	exit 4
fi

rm -rf "$WORK"
mkdir -p "$WORK/initramfs"
mkdir -p "$WORK/initramfs/sbin"

"$CC" -static -D__EXPORTED_HEADERS__ -I"$ROOT/include/uapi" -O2 -Wall -Wextra \
	-o "$WORK/hdn-policy" "$ROOT/tools/hardening/hdn-policy.c"
"$WORK/hdn-policy" "$ROOT/tools/hardening/default.policy" \
	"$WORK/default.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/default.hdn.unsigned" "$WORK/default.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/restricted.policy" \
	"$WORK/restricted.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/restricted.hdn.unsigned" "$WORK/restricted.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/proc-disclose.policy" \
	"$WORK/proc-disclose.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/proc-disclose.hdn.unsigned" "$WORK/proc-disclose.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/trace-symbol.policy" \
	"$WORK/trace-symbol.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/trace-symbol.hdn.unsigned" "$WORK/trace-symbol.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/chroot-mount.policy" \
	"$WORK/chroot-mount.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/chroot-mount.hdn.unsigned" "$WORK/chroot-mount.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/jit.policy" \
	"$WORK/jit.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/jit.hdn.unsigned" "$WORK/jit.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/execstack.policy" \
	"$WORK/execstack.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/execstack.hdn.unsigned" "$WORK/execstack.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/textrel.policy" \
	"$WORK/textrel.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/textrel.hdn.unsigned" "$WORK/textrel.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/relro.policy" \
	"$WORK/relro.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/relro.hdn.unsigned" "$WORK/relro.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/kill.policy" \
	"$WORK/kill.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/kill.hdn.unsigned" "$WORK/kill.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/cred-deny.policy" \
	"$WORK/cred-deny.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/cred-deny.hdn.unsigned" "$WORK/cred-deny.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/privexec-deny.policy" \
	"$WORK/privexec-deny.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/privexec-deny.hdn.unsigned" "$WORK/privexec-deny.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/identity.policy" \
	"$WORK/identity.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/identity.hdn.unsigned" "$WORK/identity.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/module-path.policy" \
	"$WORK/module-path.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/module-path.hdn.unsigned" "$WORK/module-path.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/firmware.policy" \
	"$WORK/firmware.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/firmware.hdn.unsigned" "$WORK/firmware.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/mount-policy.policy" \
	"$WORK/mount-policy.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/mount-policy.hdn.unsigned" "$WORK/mount-policy.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/mount-ro-policy.policy" \
	"$WORK/mount-ro-policy.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/mount-ro-policy.hdn.unsigned" "$WORK/mount-ro-policy.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/proc-task.policy" \
	"$WORK/proc-task.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/proc-task.hdn.unsigned" "$WORK/proc-task.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/namespace-only.policy" \
	"$WORK/namespace-only.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/namespace-only.hdn.unsigned" "$WORK/namespace-only.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/namespace-proc-task.policy" \
	"$WORK/namespace-proc-task.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/namespace-proc-task.hdn.unsigned" "$WORK/namespace-proc-task.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/subject.policy" \
	"$WORK/subject.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/subject.hdn.unsigned" "$WORK/subject.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/userns-depth.policy" \
	"$WORK/userns-depth.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/userns-depth.hdn.unsigned" "$WORK/userns-depth.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/role.policy" \
	"$WORK/role.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/role.hdn.unsigned" "$WORK/role.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/capability.policy" \
	"$WORK/capability.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/capability.hdn.unsigned" "$WORK/capability.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/object-audit.policy" \
	"$WORK/object-audit.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/object-audit.hdn.unsigned" "$WORK/object-audit.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/process-account.policy" \
	"$WORK/process-account.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/process-account.hdn.unsigned" "$WORK/process-account.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/object-write.policy" \
	"$WORK/object-write.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/object-write.hdn.unsigned" "$WORK/object-write.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/socket-policy.policy" \
	"$WORK/socket-policy.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/socket-policy.hdn.unsigned" "$WORK/socket-policy.hdn"
"$WORK/hdn-policy" "$SCRIPT_DIR/block-admin.policy" \
	"$WORK/block-admin.hdn.unsigned"
"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
	"$WORK/block-admin.hdn.unsigned" "$WORK/block-admin.hdn"

"$CC" -static -O2 -Wall -Wextra \
	-I"$ROOT/tools/testing/selftests" \
	-isystem "$ROOT/usr/include" \
	-o "$WORK/hdn_smoke" "$SCRIPT_DIR/hdn_smoke.c"

"$CC" -static -O2 -Wall -Wextra -D__EXPORTED_HEADERS__ \
	-I"$ROOT/include/uapi" \
	-isystem "$ROOT/usr/include" \
	-o "$WORK/hdn-elfnote-jit" "$SCRIPT_DIR/hdn_elfnote_jit.c"

"$CC" -static -O2 -Wall -Wextra \
	-o "$WORK/hdn-refresh-target" "$SCRIPT_DIR/hdn_refresh_target.c"

"$CC" -static -O2 -Wall -Wextra \
	-isystem "$ROOT/usr/include" \
	-o "$WORK/hdn-rofs-apply" "$ROOT/tools/hardening/hdn-rofs-apply.c"

"$CC" -static -O2 -Wall -Wextra \
	-isystem "$ROOT/usr/include" \
	-o "$WORK/hdn-rofs-transaction" \
	"$ROOT/tools/hardening/hdn-rofs-transaction.c"

"$CC" -static -O2 -Wall -Wextra -D__EXPORTED_HEADERS__ \
	-DHDN_ROFS_APPLY_PATH='"/hdn-rofs-apply"' \
	-DHDN_ROFS_TRANSACTION_PATH='"/hdn-rofs-transaction"' \
	-DHDN_ADMIN_BROKER_CONFIG='"/hdn-admin-broker.conf"' \
	-I"$ROOT/include/uapi" \
	-isystem "$ROOT/usr/include" \
	-o "$WORK/hdn-admin-broker" \
	"$ROOT/tools/hardening/hdn-admin-broker.c"

"$CC" -static -O2 -Wall -Wextra -D__EXPORTED_HEADERS__ \
	-DHDN_ROFS_APPLY_PATH='"/hdn-rofs-apply"' \
	-DHDN_ROFS_TRANSACTION_PATH='"/hdn-rofs-transaction"' \
	-DHDN_ADMIN_BROKER_CONFIG='"/hdn-admin-broker-missing.conf"' \
	-I"$ROOT/include/uapi" \
	-isystem "$ROOT/usr/include" \
	-o "$WORK/hdn-admin-broker-missing" \
	"$ROOT/tools/hardening/hdn-admin-broker.c"

"$CC" -static -O2 -Wall -Wextra -D__EXPORTED_HEADERS__ \
	-DHDN_ROFS_APPLY_PATH='"/hdn-rofs-apply"' \
	-DHDN_ROFS_TRANSACTION_PATH='"/hdn-rofs-transaction"' \
	-DHDN_ADMIN_BROKER_CONFIG='"/hdn-admin-broker-unsafe.conf"' \
	-I"$ROOT/include/uapi" \
	-isystem "$ROOT/usr/include" \
	-o "$WORK/hdn-admin-broker-unsafe" \
	"$ROOT/tools/hardening/hdn-admin-broker.c"

"$CC" -static -O2 -Wall -Wextra -D__EXPORTED_HEADERS__ \
	-DHDN_ROFS_APPLY_PATH='"/hdn-rofs-apply"' \
	-DHDN_ROFS_TRANSACTION_PATH='"/hdn-rofs-transaction"' \
	-DHDN_ADMIN_BROKER_CONFIG='"/hdn-admin-broker-token.conf"' \
	-I"$ROOT/include/uapi" \
	-isystem "$ROOT/usr/include" \
	-o "$WORK/hdn-admin-broker-token" \
	"$ROOT/tools/hardening/hdn-admin-broker.c"

"$CC" -static -O2 -Wall -Wextra \
	-o "$WORK/hdn-approval-token" \
	"$ROOT/tools/hardening/hdn-approval-token.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_ADMIN_BROKER_PATH='"/hdn-admin-broker"' \
	-DHDN_SYSTEM_TRANSACTION_CONFIG='"/hdn-system-transactions.conf"' \
	-o "$WORK/hdn-system-transaction" \
	"$ROOT/tools/hardening/hdn-system-transaction.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_ADMIN_BROKER_PATH='"/hdn-admin-broker"' \
	-DHDN_SYSTEM_TRANSACTION_PATH='"/hdn-system-transaction"' \
	-DHDN_RECOVERY_ACTION_CONFIG='"/hdn-recovery-actions.conf"' \
	-o "$WORK/hdn-recovery-action" \
	"$ROOT/tools/hardening/hdn-recovery-action.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_RECOVERY_METADATA_CONFIG='"/hdn-recovery-metadata.conf"' \
	-o "$WORK/hdn-recovery-describe" \
	"$ROOT/tools/hardening/hdn-recovery-describe.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_RECOVERY_SESSION_CONFIG='"/hdn-recovery-session.conf"' \
	-DHDN_RECOVERY_DESCRIBE_PATH='"/hdn-recovery-describe"' \
	-DHDN_RECOVERY_ACTION_PATH='"/hdn-recovery-action"' \
	-DHDN_RECOVERY_CONFIRM_PATH='"/hdn-recovery-prompt"' \
	-o "$WORK/hdn-recovery-session" \
	"$ROOT/tools/hardening/hdn-recovery-session.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_RECOVERY_PORTAL_CONFIG='"/hdn-recovery-portal.conf"' \
	-DHDN_RECOVERY_SESSION_PATH='"/hdn-recovery-session"' \
	-o "$WORK/hdn-recovery-portal" \
	"$ROOT/tools/hardening/hdn-recovery-portal.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_RECOVERY_PANEL_CONFIG='"/hdn-recovery-panel.conf"' \
	-DHDN_RECOVERY_DESCRIBE_PATH='"/hdn-recovery-describe"' \
	-DHDN_RECOVERY_PORTAL_PATH='"/hdn-recovery-portal"' \
	-o "$WORK/hdn-recovery-panel" \
	"$ROOT/tools/hardening/hdn-recovery-panel.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_RECOVERY_UI_CONFIG='"/hdn-recovery-ui.conf"' \
	-DHDN_RECOVERY_PANEL_PATH='"/hdn-recovery-panel"' \
	-o "$WORK/hdn-recovery-ui" \
	"$ROOT/tools/hardening/hdn-recovery-ui.c"

"$CC" -static -O2 -Wall -Wextra \
	-o "$WORK/hdn-recovery-prompt" \
	"$ROOT/tools/hardening/hdn-recovery-prompt.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_ADMIN_BROKER_PATH='"/hdn-admin-broker-token"' \
	-DHDN_APPROVAL_TOKEN_PATH='"/hdn-approval-token"' \
	-DHDN_APPROVAL_TOKEN_DIR='"/hdn-approvals"' \
	-DHDN_PROMPT_DISPATCH_CONFIG='"/hdn-prompt-actions.conf"' \
	-o "$WORK/hdn-prompt-dispatch" \
	"$ROOT/tools/hardening/hdn-prompt-dispatch.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_PROMPT_METADATA_CONFIG='"/hdn-prompt-metadata.conf"' \
	-o "$WORK/hdn-prompt-describe" \
	"$ROOT/tools/hardening/hdn-prompt-describe.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_PROMPT_SESSION_CONFIG='"/hdn-prompt-session.conf"' \
	-DHDN_PROMPT_DESCRIBE_PATH='"/hdn-prompt-describe"' \
	-DHDN_PROMPT_DISPATCH_PATH='"/hdn-prompt-dispatch"' \
	-DHDN_PROMPT_AUTH_PATH='"/hdn-auth-prompt"' \
	-o "$WORK/hdn-prompt-session" \
	"$ROOT/tools/hardening/hdn-prompt-session.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_PROMPT_PORTAL_CONFIG='"/hdn-prompt-portal.conf"' \
	-DHDN_PROMPT_SESSION_PATH='"/hdn-prompt-session"' \
	-o "$WORK/hdn-prompt-portal" \
	"$ROOT/tools/hardening/hdn-prompt-portal.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_DESKTOP_ACTION_CONFIG='"/hdn-desktop-actions.conf"' \
	-DHDN_PROMPT_PORTAL_PATH='"/hdn-prompt-portal"' \
	-o "$WORK/hdn-desktop-action" \
	"$ROOT/tools/hardening/hdn-desktop-action.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_DESKTOP_DAEMON_CONFIG='"/hdn-desktop-daemon.conf"' \
	-DHDN_DESKTOP_ACTION_PATH='"/hdn-desktop-action"' \
	-o "$WORK/hdn-desktop-daemon" \
	"$ROOT/tools/hardening/hdn-desktop-daemon.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_STATUS_HELPER_PATH='"/hdn-status"' \
	-DHDN_DESKTOP_DAEMON_PATH='"/hdn-desktop-daemon"' \
	-DHDN_POLICY_DAEMON_PATH='"/hdn-policy-daemon"' \
	-o "$WORK/hdn-control-center" \
	"$ROOT/tools/hardening/hdn-control-center.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_SETTINGS_PANEL_CONFIG='"/hdn-settings-panel.conf"' \
	-DHDN_CONTROL_CENTER_PATH='"/hdn-control-center"' \
	-o "$WORK/hdn-settings-panel" \
	"$ROOT/tools/hardening/hdn-settings-panel.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_SETTINGS_UI_CONFIG='"/hdn-settings-ui.conf"' \
	-DHDN_SETTINGS_PANEL_PATH='"/hdn-settings-panel"' \
	-o "$WORK/hdn-settings-ui" \
	"$ROOT/tools/hardening/hdn-settings-ui.c"

"$CC" -static -O2 -Wall -Wextra \
	-o "$WORK/hdn-auth-prompt" \
	"$ROOT/tools/hardening/hdn-auth-prompt.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_ADMIN_BROKER_PATH='"/hdn-admin-broker"' \
	-DHDN_IMAGE_SEAL_CONFIG='"/hdn-image-seals.conf"' \
	-o "$WORK/hdn-image-seal" \
	"$ROOT/tools/hardening/hdn-image-seal.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_PACKAGE_HOOK_CONFIG='"/hdn-package-hooks.conf"' \
	-DHDN_SYSTEM_TRANSACTION_PATH='"/hdn-system-transaction"' \
	-DHDN_IMAGE_SEAL_PATH='"/hdn-image-seal"' \
	-o "$WORK/hdn-package-hook" \
	"$ROOT/tools/hardening/hdn-package-hook.c"

"$CC" -static -O2 -Wall -Wextra -D__EXPORTED_HEADERS__ \
	-I"$ROOT/include/uapi" \
	-isystem "$ROOT/usr/include" \
	-o "$WORK/hdn-event-decode" \
	"$ROOT/tools/hardening/hdn-event-decode.c"

"$CC" -static -O2 -Wall -Wextra -D__EXPORTED_HEADERS__ \
	-I"$ROOT/include/uapi" \
	-isystem "$ROOT/usr/include" \
	-o "$WORK/hdn-status" \
	"$ROOT/tools/hardening/hdn-status.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_SUPPORT_BUNDLE_CONFIG='"/hdn-support-bundle.conf"' \
	-DHDN_STATUS_HELPER_PATH='"/hdn-status"' \
	-DHDN_EVENT_DECODE_PATH='"/hdn-event-decode"' \
	-DHDN_EVENTS_PATH='"/hdn-support-bundle.events"' \
	-o "$WORK/hdn-support-bundle" \
	"$ROOT/tools/hardening/hdn-support-bundle.c"

"$CC" -static -O2 -Wall -Wextra -D__EXPORTED_HEADERS__ \
	-I"$ROOT/include/uapi" \
	-isystem "$ROOT/usr/include" \
	-o "$WORK/hdn-policy-learn" \
	"$ROOT/tools/hardening/hdn-policy-learn.c"

"$CC" -static -O2 -Wall -Wextra -D__EXPORTED_HEADERS__ \
	-I"$ROOT/include/uapi" \
	-isystem "$ROOT/usr/include" \
	-o "$WORK/hdn-policy-merge" \
	"$ROOT/tools/hardening/hdn-policy-merge.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_POLICY_WORKFLOW_CONFIG='"/hdn-policy-workflows.conf"' \
	-DHDN_POLICY_LEARN_PATH='"/hdn-policy-learn"' \
	-DHDN_POLICY_MERGE_PATH='"/hdn-policy-merge"' \
	-DHDN_POLICY_COMPILER_PATH='"/hdn-policy"' \
	-DHDN_ADMIN_BROKER_PATH='"/hdn-admin-broker"' \
	-o "$WORK/hdn-policy-workflow" \
	"$ROOT/tools/hardening/hdn-policy-workflow.c"

"$CC" -static -O2 -Wall -Wextra \
	-DHDN_POLICY_DAEMON_CONFIG='"/hdn-policy-daemon.conf"' \
	-DHDN_POLICY_WORKFLOW_PATH='"/hdn-policy-workflow"' \
	-o "$WORK/hdn-policy-daemon" \
	"$ROOT/tools/hardening/hdn-policy-daemon.c"

"$CC" -static -O2 -Wall -Wextra \
	-o "$WORK/init" "$SCRIPT_DIR/vm_init.c"

cp "$WORK/hdn_smoke" "$WORK/initramfs/hdn_smoke"
cp "$WORK/hdn-refresh-target" "$WORK/initramfs/hdn-refresh-target"
cp "$WORK/capability.hdn" "$WORK/initramfs/capability.hdn"
cp "$WORK/object-audit.hdn" "$WORK/initramfs/object-audit.hdn"
cp "$WORK/hdn_smoke" "$WORK/initramfs/sbin/modprobe"
chmod 0755 "$WORK/initramfs/sbin/modprobe"
cp "$WORK/hdn_smoke" "$WORK/initramfs/hdn-identity-trusted"
cp "$WORK/hdn_smoke" "$WORK/initramfs/hdn-identity-copy"
cp "$WORK/hdn_smoke" "$WORK/initramfs/hdn-identity-inherit"
cp "$WORK/hdn_smoke" "$WORK/initramfs/hdn-identity-parent-inherit"
cp "$WORK/hdn_smoke" "$WORK/initramfs/hdn-object-exec-protected"
cp "$WORK/hdn_smoke" "$WORK/initramfs/hdn-object-exec-unprotected"
cp "$WORK/hdn_smoke" "$WORK/initramfs/hdn-ptrace-object-target"
cp "$WORK/hdn_smoke" "$WORK/initramfs/hdn-proc-reader"
chmod 0755 "$WORK/initramfs/hdn-object-exec-protected"
chmod 0755 "$WORK/initramfs/hdn-object-exec-unprotected"
chmod 0755 "$WORK/initramfs/hdn-ptrace-object-target"
cp "$WORK/hdn_smoke" "$WORK/initramfs/hdn-rofs-updater"
cp "$WORK/hdn-elfnote-jit" "$WORK/initramfs/hdn-elfnote-jit"
cp "$WORK/hdn-rofs-apply" "$WORK/initramfs/hdn-rofs-apply"
cp "$WORK/hdn-rofs-apply" "$WORK/initramfs/hdn-rofs-bind-apply"
cp "$WORK/hdn-rofs-transaction" "$WORK/initramfs/hdn-rofs-transaction"
cp "$WORK/hdn-admin-broker" "$WORK/initramfs/hdn-admin-broker"
cp "$WORK/hdn-admin-broker-missing" "$WORK/initramfs/hdn-admin-broker-missing"
cp "$WORK/hdn-admin-broker-unsafe" "$WORK/initramfs/hdn-admin-broker-unsafe"
cp "$WORK/hdn-admin-broker-token" "$WORK/initramfs/hdn-admin-broker-token"
cp "$WORK/hdn-approval-token" "$WORK/initramfs/hdn-approval-token"
cp "$WORK/hdn-system-transaction" "$WORK/initramfs/hdn-system-transaction"
cp "$WORK/hdn-recovery-action" "$WORK/initramfs/hdn-recovery-action"
cp "$WORK/hdn-recovery-describe" "$WORK/initramfs/hdn-recovery-describe"
cp "$WORK/hdn-recovery-session" "$WORK/initramfs/hdn-recovery-session"
cp "$WORK/hdn-recovery-portal" "$WORK/initramfs/hdn-recovery-portal"
cp "$WORK/hdn-recovery-panel" "$WORK/initramfs/hdn-recovery-panel"
cp "$WORK/hdn-recovery-ui" "$WORK/initramfs/hdn-recovery-ui"
cp "$WORK/hdn-recovery-prompt" "$WORK/initramfs/hdn-recovery-prompt"
cp "$WORK/hdn-prompt-dispatch" "$WORK/initramfs/hdn-prompt-dispatch"
cp "$WORK/hdn-prompt-describe" "$WORK/initramfs/hdn-prompt-describe"
cp "$WORK/hdn-prompt-session" "$WORK/initramfs/hdn-prompt-session"
cp "$WORK/hdn-prompt-portal" "$WORK/initramfs/hdn-prompt-portal"
cp "$WORK/hdn-desktop-action" "$WORK/initramfs/hdn-desktop-action"
cp "$WORK/hdn-desktop-daemon" "$WORK/initramfs/hdn-desktop-daemon"
cp "$WORK/hdn-control-center" "$WORK/initramfs/hdn-control-center"
cp "$WORK/hdn-settings-panel" "$WORK/initramfs/hdn-settings-panel"
cp "$WORK/hdn-settings-ui" "$WORK/initramfs/hdn-settings-ui"
cp "$WORK/hdn-auth-prompt" "$WORK/initramfs/hdn-auth-prompt"
cp "$WORK/hdn-image-seal" "$WORK/initramfs/hdn-image-seal"
cp "$WORK/hdn-package-hook" "$WORK/initramfs/hdn-package-hook"
cp "$WORK/hdn-event-decode" "$WORK/initramfs/hdn-event-decode"
cp "$WORK/hdn-status" "$WORK/initramfs/hdn-status"
cp "$WORK/hdn-support-bundle" "$WORK/initramfs/hdn-support-bundle"
cp "$WORK/hdn-policy" "$WORK/initramfs/hdn-policy"
cp "$WORK/hdn-policy-learn" "$WORK/initramfs/hdn-policy-learn"
cp "$WORK/hdn-policy-merge" "$WORK/initramfs/hdn-policy-merge"
cp "$WORK/hdn-policy-workflow" "$WORK/initramfs/hdn-policy-workflow"
cp "$WORK/hdn-policy-daemon" "$WORK/initramfs/hdn-policy-daemon"
mkdir -p "$WORK/initramfs/hdn-package-manager-hooks"
cp "$ROOT/tools/hardening/package-manager-hooks/apt/99-hdn-package-update" \
	"$WORK/initramfs/hdn-package-manager-hooks/apt.conf"
cp "$ROOT/tools/hardening/package-manager-hooks/pacman/99-hdn-package-update.hook" \
	"$WORK/initramfs/hdn-package-manager-hooks/pacman.hook"
cp "$ROOT/tools/hardening/package-manager-hooks/dnf/99-hdn-package-update.action" \
	"$WORK/initramfs/hdn-package-manager-hooks/dnf.action"
cp "$ROOT/tools/hardening/package-manager-hooks/dnf5/99-hdn-package-update.actions" \
	"$WORK/initramfs/hdn-package-manager-hooks/dnf5.actions"
cp "$ROOT/tools/hardening/package-manager-hooks/systemd/hdn-image-seal.service" \
	"$WORK/initramfs/hdn-package-manager-hooks/hdn-image-seal.service"
cat > "$WORK/initramfs/hdn-admin-broker.conf" <<'EOF'
# Product-approved privileged intents for the QEMU hardening smoke test.
rofs-mount /hdn-product-rofs
rofs-worker /hdn_smoke
rofs-apply-list /hdn-rofs-apply-list.conf
rofs-apply-list /hdn-rofs-apply-unsafe-list.conf
rofs-apply-list /hdn-image-seal-list.conf
policy-dir /hdn-policies
allow-policy-rollback
EOF
chmod 0644 "$WORK/initramfs/hdn-admin-broker.conf"
printf '%s\n' '/hdn-product-rofs-broker' \
	> "$WORK/initramfs/hdn-rofs-apply-list.conf"
chmod 0644 "$WORK/initramfs/hdn-rofs-apply-list.conf"
printf '%s\n' '/hdn-product-rofs-broker' \
	> "$WORK/initramfs/hdn-rofs-apply-unsafe-list.conf"
chmod 0666 "$WORK/initramfs/hdn-rofs-apply-unsafe-list.conf"
printf '%s\n' '/hdn-product-rofs-broker' \
	> "$WORK/initramfs/hdn-rofs-apply-denied.conf"
chmod 0644 "$WORK/initramfs/hdn-rofs-apply-denied.conf"
printf '%s\n' '/hdn-image-seal-rofs' \
	> "$WORK/initramfs/hdn-image-seal-list.conf"
chmod 0644 "$WORK/initramfs/hdn-image-seal-list.conf"
cat > "$WORK/initramfs/hdn-admin-broker-unsafe.conf" <<'EOF'
# Deliberately unsafe allowlist used to prove the broker fails closed.
rofs-mount /hdn-product-rofs
rofs-worker /hdn_smoke
EOF
chmod 0666 "$WORK/initramfs/hdn-admin-broker-unsafe.conf"
mkdir -p "$WORK/initramfs/hdn-approvals"
chmod 0700 "$WORK/initramfs/hdn-approvals"
cat > "$WORK/initramfs/hdn-admin-broker-token.conf" <<'EOF'
# Product-approved prompt handoff config for broker approval token tests.
rofs-mount /hdn-product-rofs
rofs-worker /hdn_smoke
approval-token-dir /hdn-approvals
require-approval-token
EOF
chmod 0644 "$WORK/initramfs/hdn-admin-broker-token.conf"
cat > "$WORK/initramfs/hdn-system-transactions.conf" <<'EOF'
# Product package/image updater transactions for the QEMU hardening smoke test.
transaction package-update /hdn-product-rofs /hdn_smoke --product-rofs-write-sentinel
transaction package-repair /hdn-product-rofs /hdn_smoke --product-rofs-write-sentinel
EOF
chmod 0644 "$WORK/initramfs/hdn-system-transactions.conf"
cat > "$WORK/initramfs/hdn-system-transactions-unsafe.conf" <<'EOF'
# Deliberately unsafe transaction config used to prove fail-closed behavior.
transaction package-update /hdn-product-rofs /hdn_smoke --product-rofs-write-sentinel
EOF
chmod 0666 "$WORK/initramfs/hdn-system-transactions-unsafe.conf"
cat > "$WORK/initramfs/hdn-package-hooks.conf" <<'EOF'
# Product package-manager hooks for the QEMU hardening smoke test.
hook package-update system-transaction package-update
hook image-seal-default image-seal default
EOF
chmod 0644 "$WORK/initramfs/hdn-package-hooks.conf"
cat > "$WORK/initramfs/hdn-package-hooks-unsafe.conf" <<'EOF'
# Deliberately unsafe package hook config used to prove fail-closed behavior.
hook package-update system-transaction package-update
EOF
chmod 0666 "$WORK/initramfs/hdn-package-hooks-unsafe.conf"
cat > "$WORK/initramfs/hdn-recovery-actions.conf" <<'EOF'
# Product-approved recovery actions for the QEMU hardening smoke test.
action policy-rollback policy-rollback
action package-repair system-transaction package-repair
EOF
chmod 0644 "$WORK/initramfs/hdn-recovery-actions.conf"
cat > "$WORK/initramfs/hdn-recovery-actions-unsafe.conf" <<'EOF'
# Deliberately unsafe recovery config used to prove fail-closed behavior.
action policy-rollback policy-rollback
EOF
chmod 0666 "$WORK/initramfs/hdn-recovery-actions-unsafe.conf"
cat > "$WORK/initramfs/hdn-recovery-metadata.conf" <<'EOF'
# Product-approved recovery metadata for the QEMU hardening smoke test.
recovery policy-rollback title Roll back security policy
recovery policy-rollback message Restore the previous signed hardening policy.
recovery policy-rollback consequence The current policy generation is replaced by the rollback slot.
recovery policy-rollback risk recovery
recovery package-repair title Repair protected system files
recovery package-repair message Run the product package repair transaction.
recovery package-repair consequence The protected system mount is temporarily writable and then resealed.
recovery package-repair risk repair
EOF
chmod 0644 "$WORK/initramfs/hdn-recovery-metadata.conf"
cat > "$WORK/initramfs/hdn-recovery-metadata-unsafe.conf" <<'EOF'
# Deliberately unsafe recovery metadata config used to prove fail-closed behavior.
recovery policy-rollback title Roll back security policy
recovery policy-rollback message Restore the previous signed hardening policy.
recovery policy-rollback consequence The current policy generation is replaced by the rollback slot.
recovery policy-rollback risk recovery
EOF
chmod 0666 "$WORK/initramfs/hdn-recovery-metadata-unsafe.conf"
cat > "$WORK/initramfs/hdn-recovery-session.conf" <<'EOF'
# Product-approved recovery session backend for the QEMU hardening smoke test.
describe-helper /hdn-recovery-describe
confirm-helper /hdn-recovery-prompt --test-approve
action-helper /hdn-recovery-action
EOF
chmod 0644 "$WORK/initramfs/hdn-recovery-session.conf"
cat > "$WORK/initramfs/hdn-recovery-session-deny.conf" <<'EOF'
# Recovery session config with a confirmation denial.
describe-helper /hdn-recovery-describe
confirm-helper /hdn-recovery-prompt --test-deny
action-helper /hdn-recovery-action
EOF
chmod 0644 "$WORK/initramfs/hdn-recovery-session-deny.conf"
cat > "$WORK/initramfs/hdn-recovery-session-nodisplay.conf" <<'EOF'
# Recovery session config using the real recovery prompt in a no-display VM.
describe-helper /hdn-recovery-describe
confirm-helper /hdn-recovery-prompt
action-helper /hdn-recovery-action
EOF
chmod 0644 "$WORK/initramfs/hdn-recovery-session-nodisplay.conf"
cat > "$WORK/initramfs/hdn-recovery-session-unsafe.conf" <<'EOF'
# Deliberately unsafe recovery session config used to prove fail-closed behavior.
describe-helper /hdn-recovery-describe
confirm-helper /hdn-recovery-prompt --test-approve
action-helper /hdn-recovery-action
EOF
chmod 0666 "$WORK/initramfs/hdn-recovery-session-unsafe.conf"
cat > "$WORK/initramfs/hdn-recovery-portal.conf" <<'EOF'
# Product-approved recovery UI portal for the QEMU hardening smoke test.
session-helper /hdn-recovery-session
action rollback-policy policy-rollback
action repair-system package-repair
EOF
chmod 0644 "$WORK/initramfs/hdn-recovery-portal.conf"
cat > "$WORK/initramfs/hdn-recovery-portal-unsafe.conf" <<'EOF'
# Deliberately unsafe recovery portal config used to prove fail-closed behavior.
session-helper /hdn-recovery-session
action rollback-policy policy-rollback
action repair-system package-repair
EOF
chmod 0666 "$WORK/initramfs/hdn-recovery-portal-unsafe.conf"
cat > "$WORK/initramfs/hdn-recovery-panel.conf" <<'EOF'
# Product-approved recovery panel action map for the QEMU hardening smoke test.
describe-helper /hdn-recovery-describe
portal-helper /hdn-recovery-portal
action rollback-policy policy-rollback rollback-policy
action repair-system package-repair repair-system
EOF
chmod 0644 "$WORK/initramfs/hdn-recovery-panel.conf"
cat > "$WORK/initramfs/hdn-recovery-panel-unsafe.conf" <<'EOF'
# Deliberately unsafe recovery panel config used to prove fail-closed behavior.
describe-helper /hdn-recovery-describe
portal-helper /hdn-recovery-portal
action rollback-policy policy-rollback rollback-policy
action repair-system package-repair repair-system
EOF
chmod 0666 "$WORK/initramfs/hdn-recovery-panel-unsafe.conf"
cat > "$WORK/initramfs/hdn-recovery-ui.conf" <<'EOF'
# Product-approved recovery UI manifest for the QEMU hardening smoke test.
panel-helper /hdn-recovery-panel
title System Recovery
message Choose a recovery action.
action repair-system
action rollback-policy
EOF
chmod 0644 "$WORK/initramfs/hdn-recovery-ui.conf"
cat > "$WORK/initramfs/hdn-recovery-ui-unsafe.conf" <<'EOF'
# Deliberately unsafe recovery UI config used to prove fail-closed behavior.
panel-helper /hdn-recovery-panel
title System Recovery
message Choose a recovery action.
action repair-system
action rollback-policy
EOF
chmod 0666 "$WORK/initramfs/hdn-recovery-ui-unsafe.conf"
cat > "$WORK/initramfs/hdn-prompt-actions.conf" <<'EOF'
# Product-approved post-auth prompt actions for the QEMU hardening smoke test.
action package-update rofs-transaction /hdn-product-rofs -- /hdn_smoke --product-rofs-write-sentinel
EOF
chmod 0644 "$WORK/initramfs/hdn-prompt-actions.conf"
cat > "$WORK/initramfs/hdn-prompt-actions-unsafe.conf" <<'EOF'
# Deliberately unsafe prompt action config used to prove fail-closed behavior.
action package-update rofs-transaction /hdn-product-rofs -- /hdn_smoke --product-rofs-write-sentinel
EOF
chmod 0666 "$WORK/initramfs/hdn-prompt-actions-unsafe.conf"
cat > "$WORK/initramfs/hdn-prompt-metadata.conf" <<'EOF'
# Product-approved prompt metadata for the QEMU hardening smoke test.
prompt package-update title Install system updates
prompt package-update message The operating system will update protected system files.
prompt package-update consequence The system image is temporarily writable and then resealed.
prompt package-update risk system
EOF
chmod 0644 "$WORK/initramfs/hdn-prompt-metadata.conf"
cat > "$WORK/initramfs/hdn-prompt-metadata-unsafe.conf" <<'EOF'
# Deliberately unsafe prompt metadata config used to prove fail-closed behavior.
prompt package-update title Install system updates
prompt package-update message The operating system will update protected system files.
prompt package-update consequence The system image is temporarily writable and then resealed.
prompt package-update risk system
EOF
chmod 0666 "$WORK/initramfs/hdn-prompt-metadata-unsafe.conf"
cat > "$WORK/initramfs/hdn-prompt-session.conf" <<'EOF'
# Product-approved prompt session backend for the QEMU hardening smoke test.
describe-helper /hdn-prompt-describe
auth-helper /hdn-auth-prompt --test-approve
dispatch-helper /hdn-prompt-dispatch
EOF
chmod 0644 "$WORK/initramfs/hdn-prompt-session.conf"
cat > "$WORK/initramfs/hdn-prompt-session-deny.conf" <<'EOF'
# Prompt session config with an authenticator denial.
describe-helper /hdn-prompt-describe
auth-helper /hdn-auth-prompt --test-deny
dispatch-helper /hdn-prompt-dispatch
EOF
chmod 0644 "$WORK/initramfs/hdn-prompt-session-deny.conf"
cat > "$WORK/initramfs/hdn-prompt-session-nodisplay.conf" <<'EOF'
# Prompt session config using the real GUI helper in a no-display VM.
describe-helper /hdn-prompt-describe
auth-helper /hdn-auth-prompt
dispatch-helper /hdn-prompt-dispatch
EOF
chmod 0644 "$WORK/initramfs/hdn-prompt-session-nodisplay.conf"
cat > "$WORK/initramfs/hdn-prompt-session-unsafe.conf" <<'EOF'
# Deliberately unsafe prompt session config used to prove fail-closed behavior.
describe-helper /hdn-prompt-describe
auth-helper /hdn-auth-prompt --test-approve
dispatch-helper /hdn-prompt-dispatch
EOF
chmod 0666 "$WORK/initramfs/hdn-prompt-session-unsafe.conf"
cat > "$WORK/initramfs/hdn-prompt-portal.conf" <<'EOF'
# Product-approved desktop prompt portal for the QEMU hardening smoke test.
session-helper /hdn-prompt-session
action desktop-package-update package-update
EOF
chmod 0644 "$WORK/initramfs/hdn-prompt-portal.conf"
cat > "$WORK/initramfs/hdn-prompt-portal-unsafe.conf" <<'EOF'
# Deliberately unsafe prompt portal config used to prove fail-closed behavior.
session-helper /hdn-prompt-session
action desktop-package-update package-update
EOF
chmod 0666 "$WORK/initramfs/hdn-prompt-portal-unsafe.conf"
cat > "$WORK/initramfs/hdn-desktop-actions.conf" <<'EOF'
# Product-approved desktop action map for the QEMU hardening smoke test.
portal-helper /hdn-prompt-portal
action updates.install desktop-package-update
EOF
chmod 0644 "$WORK/initramfs/hdn-desktop-actions.conf"
cat > "$WORK/initramfs/hdn-desktop-actions-unsafe.conf" <<'EOF'
# Deliberately unsafe desktop action config used to prove fail-closed behavior.
portal-helper /hdn-prompt-portal
action updates.install desktop-package-update
EOF
chmod 0666 "$WORK/initramfs/hdn-desktop-actions-unsafe.conf"
cat > "$WORK/initramfs/hdn-desktop-daemon.conf" <<'EOF'
# Product-approved desktop daemon backend for the QEMU hardening smoke test.
desktop-action-helper /hdn-desktop-action
allow-action updates.install
EOF
chmod 0644 "$WORK/initramfs/hdn-desktop-daemon.conf"
cat > "$WORK/initramfs/hdn-desktop-daemon-unsafe.conf" <<'EOF'
# Deliberately unsafe desktop daemon config used to prove fail-closed behavior.
desktop-action-helper /hdn-desktop-action
allow-action updates.install
EOF
chmod 0666 "$WORK/initramfs/hdn-desktop-daemon-unsafe.conf"
cat > "$WORK/initramfs/hdn-settings-panel.conf" <<'EOF'
# Product-approved settings-panel action map for the QEMU hardening smoke test.
control-center-helper /hdn-control-center
action updates.install updates.install
EOF
chmod 0644 "$WORK/initramfs/hdn-settings-panel.conf"
cat > "$WORK/initramfs/hdn-settings-panel-unsafe.conf" <<'EOF'
# Deliberately unsafe settings-panel config used to prove fail-closed behavior.
control-center-helper /hdn-control-center
action updates.install updates.install
EOF
chmod 0666 "$WORK/initramfs/hdn-settings-panel-unsafe.conf"
cat > "$WORK/initramfs/hdn-settings-ui.conf" <<'EOF'
# Product-approved settings UI manifest for the QEMU hardening smoke test.
settings-panel-helper /hdn-settings-panel
title System Settings
message Choose an approved system action.
action updates.install Install system updates
EOF
chmod 0644 "$WORK/initramfs/hdn-settings-ui.conf"
cat > "$WORK/initramfs/hdn-settings-ui-unsafe.conf" <<'EOF'
# Deliberately unsafe settings UI config used to prove fail-closed behavior.
settings-panel-helper /hdn-settings-panel
title System Settings
message Choose an approved system action.
action updates.install Install system updates
EOF
chmod 0666 "$WORK/initramfs/hdn-settings-ui-unsafe.conf"
cat > "$WORK/initramfs/hdn-support-bundle.conf" <<'EOF'
# Product-approved support bundle config for the QEMU hardening smoke test.
status-helper /hdn-status
event-decode-helper /hdn-event-decode
event-input /hdn-support-bundle.events
include-compat 1
include-events 1
max-section-bytes 65536
EOF
chmod 0644 "$WORK/initramfs/hdn-support-bundle.conf"
cat > "$WORK/initramfs/hdn-support-bundle-unsafe.conf" <<'EOF'
# Deliberately unsafe support bundle config used to prove fail-closed behavior.
status-helper /hdn-status
event-decode-helper /hdn-event-decode
event-input /hdn-support-bundle.events
include-compat 1
include-events 1
max-section-bytes 65536
EOF
chmod 0666 "$WORK/initramfs/hdn-support-bundle-unsafe.conf"
cat > "$WORK/initramfs/hdn-image-seals.conf" <<'EOF'
# Product-approved image sealing sequence for the QEMU hardening smoke test.
seal default rofs-apply /hdn-image-seal-list.conf
EOF
chmod 0644 "$WORK/initramfs/hdn-image-seals.conf"
cat > "$WORK/initramfs/hdn-image-seals-unsafe.conf" <<'EOF'
# Deliberately unsafe image seal config used to prove fail-closed behavior.
seal default rofs-apply /hdn-image-seal-list.conf
EOF
chmod 0666 "$WORK/initramfs/hdn-image-seals-unsafe.conf"
cat > "$WORK/initramfs/hdn-policy-workflows.conf" <<'EOF'
# Product-approved policy review workflow for the QEMU hardening smoke test.
workflow default /hdn-policy-workflow-base.policy /hdn-policy-workflow-events /hdn-policy-workflow-learn.frag /hdn-policy-workflow-output.policy /hdn-policy-workflow-output.unsigned.hdn /hdn-policies/default.hdn
EOF
chmod 0644 "$WORK/initramfs/hdn-policy-workflows.conf"
cat > "$WORK/initramfs/hdn-policy-workflows-unsafe.conf" <<'EOF'
# Deliberately unsafe policy workflow config used to prove fail-closed behavior.
workflow default /hdn-policy-workflow-base.policy /hdn-policy-workflow-events /hdn-policy-workflow-learn.frag /hdn-policy-workflow-output.policy /hdn-policy-workflow-output.unsigned.hdn /hdn-policies/default.hdn
EOF
chmod 0666 "$WORK/initramfs/hdn-policy-workflows-unsafe.conf"
cat > "$WORK/initramfs/hdn-policy-workflows-nosigned.conf" <<'EOF'
# Legacy policy workflow config without a signed commit input.
workflow default /hdn-policy-workflow-base.policy /hdn-policy-workflow-events /hdn-policy-workflow-learn.frag /hdn-policy-workflow-output.policy /hdn-policy-workflow-output.unsigned.hdn
EOF
chmod 0644 "$WORK/initramfs/hdn-policy-workflows-nosigned.conf"
cat > "$WORK/initramfs/hdn-policy-daemon.conf" <<'EOF'
# Product-approved policy daemon backend for the QEMU hardening smoke test.
workflow-helper /hdn-policy-workflow
allow-workflow default
EOF
chmod 0644 "$WORK/initramfs/hdn-policy-daemon.conf"
cat > "$WORK/initramfs/hdn-policy-daemon-unsafe.conf" <<'EOF'
# Deliberately unsafe policy daemon config used to prove fail-closed behavior.
workflow-helper /hdn-policy-workflow
allow-workflow default
EOF
chmod 0666 "$WORK/initramfs/hdn-policy-daemon-unsafe.conf"
printf '%s\n' '#!/hdn_smoke --identity-script-sentinel' \
	> "$WORK/initramfs/hdn-identity-script"
chmod 0755 "$WORK/initramfs/hdn-identity-script"
printf '%s\n' 'not a loadable module' > "$WORK/initramfs/hdn-known-module"
chmod 0644 "$WORK/initramfs/hdn-known-module"
mkdir -p "$WORK/initramfs/lib/firmware"
printf '%s\n' 'trusted firmware payload' \
	> "$WORK/initramfs/lib/firmware/hdn-allowed-fw.bin"
printf '%s\n' 'denied firmware payload' \
	> "$WORK/initramfs/lib/firmware/hdn-denied-fw.bin"
printf '%s\n' 'protected object policy target' \
	> "$WORK/initramfs/hdn-object-write-protected"
chmod 0644 "$WORK/initramfs/hdn-object-write-protected"
printf '%s\n' 'unprotected object policy target' \
	> "$WORK/initramfs/hdn-object-write-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-write-unprotected"
mkfifo "$WORK/initramfs/hdn-object-write-fifo-protected"
chmod 0644 "$WORK/initramfs/hdn-object-write-fifo-protected"
mkfifo "$WORK/initramfs/hdn-object-write-fifo-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-write-fifo-unprotected"
printf '%s\n' 'protected object read policy target' \
	> "$WORK/initramfs/hdn-object-read-protected"
chmod 0644 "$WORK/initramfs/hdn-object-read-protected"
printf '%s\n' 'unprotected object read policy target' \
	> "$WORK/initramfs/hdn-object-read-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-read-unprotected"
mkfifo "$WORK/initramfs/hdn-object-read-fifo-protected"
chmod 0644 "$WORK/initramfs/hdn-object-read-fifo-protected"
mkfifo "$WORK/initramfs/hdn-object-read-fifo-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-read-fifo-unprotected"
ln -s /hdn-object-read-unprotected \
	"$WORK/initramfs/hdn-object-readlink-protected"
ln -s /hdn-object-read-unprotected \
	"$WORK/initramfs/hdn-object-readlink-unprotected"
printf '%s\n' 'protected object delete policy target' \
	> "$WORK/initramfs/hdn-object-delete-protected"
chmod 0644 "$WORK/initramfs/hdn-object-delete-protected"
printf '%s\n' 'unprotected object delete policy target' \
	> "$WORK/initramfs/hdn-object-delete-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-delete-unprotected"
printf '%s\n' 'object delete replace source' \
	> "$WORK/initramfs/hdn-object-delete-replace-source"
chmod 0644 "$WORK/initramfs/hdn-object-delete-replace-source"
mkdir -p "$WORK/initramfs/hdn-object-delete-protected-dir"
chmod 0755 "$WORK/initramfs/hdn-object-delete-protected-dir"
mkdir -p "$WORK/initramfs/hdn-object-delete-unprotected-dir"
chmod 0755 "$WORK/initramfs/hdn-object-delete-unprotected-dir"
printf '%s\n' 'append-only object policy target' \
	> "$WORK/initramfs/hdn-object-append-protected"
chmod 0644 "$WORK/initramfs/hdn-object-append-protected"
printf '%s\n' 'truncate-only object policy target' \
	> "$WORK/initramfs/hdn-object-truncate-protected"
chmod 0644 "$WORK/initramfs/hdn-object-truncate-protected"
printf '%s\n' 'unprotected truncate object policy target' \
	> "$WORK/initramfs/hdn-object-truncate-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-truncate-unprotected"
printf '%s\n' 'protected rename object policy target' \
	> "$WORK/initramfs/hdn-object-rename-protected"
chmod 0644 "$WORK/initramfs/hdn-object-rename-protected"
printf '%s\n' 'unprotected rename object policy target' \
	> "$WORK/initramfs/hdn-object-rename-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-rename-unprotected"
printf '%s\n' 'protected object hardlink source' \
	> "$WORK/initramfs/hdn-object-link-protected"
chmod 0644 "$WORK/initramfs/hdn-object-link-protected"
printf '%s\n' 'unprotected object hardlink source' \
	> "$WORK/initramfs/hdn-object-link-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-link-unprotected"
printf '%s\n' 'protected object attr target' \
	> "$WORK/initramfs/hdn-object-attr-protected"
chmod 0644 "$WORK/initramfs/hdn-object-attr-protected"
printf '%s\n' 'unprotected object attr target' \
	> "$WORK/initramfs/hdn-object-attr-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-attr-unprotected"
printf '%s\n' 'protected object chmod target' \
	> "$WORK/initramfs/hdn-object-chmod-protected"
chmod 0644 "$WORK/initramfs/hdn-object-chmod-protected"
printf '%s\n' 'protected object setid target' \
	> "$WORK/initramfs/hdn-object-setid-protected"
chmod 0644 "$WORK/initramfs/hdn-object-setid-protected"
printf '%s\n' 'unprotected object setid target' \
	> "$WORK/initramfs/hdn-object-setid-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-setid-unprotected"
mkdir -p "$WORK/initramfs/hdn-object-setid-create-protected"
chmod 0755 "$WORK/initramfs/hdn-object-setid-create-protected"
mkdir -p "$WORK/initramfs/hdn-object-setid-create-unprotected"
chmod 0755 "$WORK/initramfs/hdn-object-setid-create-unprotected"
printf '%s\n' 'protected object chown target' \
	> "$WORK/initramfs/hdn-object-chown-protected"
chmod 0644 "$WORK/initramfs/hdn-object-chown-protected"
printf '%s\n' 'protected object utime target' \
	> "$WORK/initramfs/hdn-object-utime-protected"
chmod 0644 "$WORK/initramfs/hdn-object-utime-protected"
printf '%s\n' 'protected object setxattr target' \
	> "$WORK/initramfs/hdn-object-setxattr-protected"
chmod 0644 "$WORK/initramfs/hdn-object-setxattr-protected"
printf '%s\n' 'protected object removexattr target' \
	> "$WORK/initramfs/hdn-object-removexattr-protected"
chmod 0644 "$WORK/initramfs/hdn-object-removexattr-protected"
printf '%s\n' 'unprotected object split metadata target' \
	> "$WORK/initramfs/hdn-object-split-attr-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-split-attr-unprotected"
printf '%s\n' 'protected object xattr target' \
	> "$WORK/initramfs/hdn-object-xattr-protected"
chmod 0644 "$WORK/initramfs/hdn-object-xattr-protected"
printf '%s\n' 'unprotected object xattr target' \
	> "$WORK/initramfs/hdn-object-xattr-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-xattr-unprotected"
printf '%s\n' 'protected object access target' \
	> "$WORK/initramfs/hdn-object-access-protected"
chmod 0644 "$WORK/initramfs/hdn-object-access-protected"
printf '%s\n' 'unprotected object access target' \
	> "$WORK/initramfs/hdn-object-access-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-access-unprotected"
printf '%s\n' 'protected object stat target' \
	> "$WORK/initramfs/hdn-object-stat-protected"
chmod 0644 "$WORK/initramfs/hdn-object-stat-protected"
printf '%s\n' 'unprotected object stat target' \
	> "$WORK/initramfs/hdn-object-stat-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-stat-unprotected"
mkdir -p "$WORK/initramfs/hdn-object-list-protected"
chmod 0755 "$WORK/initramfs/hdn-object-list-protected"
printf '%s\n' 'protected object list target' \
	> "$WORK/initramfs/hdn-object-list-protected/entry"
chmod 0644 "$WORK/initramfs/hdn-object-list-protected/entry"
mkdir -p "$WORK/initramfs/hdn-object-list-unprotected"
chmod 0755 "$WORK/initramfs/hdn-object-list-unprotected"
printf '%s\n' 'unprotected object list target' \
	> "$WORK/initramfs/hdn-object-list-unprotected/entry"
chmod 0644 "$WORK/initramfs/hdn-object-list-unprotected/entry"
printf '%s\n' 'protected object find target' \
	> "$WORK/initramfs/hdn-object-find-protected"
chmod 0644 "$WORK/initramfs/hdn-object-find-protected"
printf '%s\n' 'unprotected object find target' \
	> "$WORK/initramfs/hdn-object-find-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-find-unprotected"
printf '%s\n' 'protected object ioctl target' \
	> "$WORK/initramfs/hdn-object-ioctl-protected"
chmod 0644 "$WORK/initramfs/hdn-object-ioctl-protected"
printf '%s\n' 'unprotected object ioctl target' \
	> "$WORK/initramfs/hdn-object-ioctl-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-ioctl-unprotected"
printf '%s\n' 'protected object lock target' \
	> "$WORK/initramfs/hdn-object-lock-protected"
chmod 0644 "$WORK/initramfs/hdn-object-lock-protected"
printf '%s\n' 'unprotected object lock target' \
	> "$WORK/initramfs/hdn-object-lock-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-lock-unprotected"
printf '%s\n' 'protected object watch target' \
	> "$WORK/initramfs/hdn-object-watch-protected"
chmod 0644 "$WORK/initramfs/hdn-object-watch-protected"
printf '%s\n' 'unprotected object watch target' \
	> "$WORK/initramfs/hdn-object-watch-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-watch-unprotected"
mkdir -p "$WORK/initramfs/hdn-object-watch-dir-protected"
chmod 0755 "$WORK/initramfs/hdn-object-watch-dir-protected"
mkdir -p "$WORK/initramfs/hdn-object-watch-dir-unprotected"
chmod 0755 "$WORK/initramfs/hdn-object-watch-dir-unprotected"
printf '%s\n' 'protected object receive target' \
	> "$WORK/initramfs/hdn-object-receive-protected"
chmod 0644 "$WORK/initramfs/hdn-object-receive-protected"
printf '%s\n' 'unprotected object receive target' \
	> "$WORK/initramfs/hdn-object-receive-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-receive-unprotected"
	> "$WORK/initramfs/hdn-object-fcntl-protected"
chmod 0644 "$WORK/initramfs/hdn-object-fcntl-protected"
	> "$WORK/initramfs/hdn-object-fcntl-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-fcntl-unprotected"
mkdir -p "$WORK/initramfs/hdn-object-chdir-protected"
chmod 0755 "$WORK/initramfs/hdn-object-chdir-protected"
mkdir -p "$WORK/initramfs/hdn-object-chdir-unprotected"
chmod 0755 "$WORK/initramfs/hdn-object-chdir-unprotected"
mkdir -p "$WORK/initramfs/hdn-object-mount-protected"
chmod 0755 "$WORK/initramfs/hdn-object-mount-protected"
mkdir -p "$WORK/initramfs/hdn-object-mount-unprotected"
chmod 0755 "$WORK/initramfs/hdn-object-mount-unprotected"
mkdir -p "$WORK/initramfs/hdn-object-umount-protected"
chmod 0755 "$WORK/initramfs/hdn-object-umount-protected"
mkdir -p "$WORK/initramfs/hdn-object-umount-unprotected"
chmod 0755 "$WORK/initramfs/hdn-object-umount-unprotected"
mkdir -p "$WORK/initramfs/hdn-object-move-mount-source-denied"
chmod 0755 "$WORK/initramfs/hdn-object-move-mount-source-denied"
mkdir -p "$WORK/initramfs/hdn-object-move-mount-source-allowed"
chmod 0755 "$WORK/initramfs/hdn-object-move-mount-source-allowed"
mkdir -p "$WORK/initramfs/hdn-object-mount-source-protected"
chmod 0755 "$WORK/initramfs/hdn-object-mount-source-protected"
mkdir -p "$WORK/initramfs/hdn-object-mount-source-unprotected"
chmod 0755 "$WORK/initramfs/hdn-object-mount-source-unprotected"
mkdir -p "$WORK/initramfs/hdn-object-move-mount-source-target-denied"
chmod 0755 "$WORK/initramfs/hdn-object-move-mount-source-target-denied"
mkdir -p "$WORK/initramfs/hdn-object-move-mount-source-target-allowed"
chmod 0755 "$WORK/initramfs/hdn-object-move-mount-source-target-allowed"
mkdir -p "$WORK/initramfs/hdn-object-unix-bind-protected"
chmod 0777 "$WORK/initramfs/hdn-object-unix-bind-protected"
mkdir -p "$WORK/initramfs/hdn-object-unix-bind-unprotected"
chmod 0777 "$WORK/initramfs/hdn-object-unix-bind-unprotected"
mkdir -p "$WORK/initramfs/hdn-object-find-dir"
chmod 0755 "$WORK/initramfs/hdn-object-find-dir"
printf '%s\n' 'hidden object find target' \
	> "$WORK/initramfs/hdn-object-find-dir/hidden"
chmod 0644 "$WORK/initramfs/hdn-object-find-dir/hidden"
printf '%s\n' 'visible object find target' \
	> "$WORK/initramfs/hdn-object-find-dir/visible"
chmod 0644 "$WORK/initramfs/hdn-object-find-dir/visible"
mkdir -p "$WORK/initramfs/hdn-object-find-tree"
chmod 0755 "$WORK/initramfs/hdn-object-find-tree"
printf '%s\n' 'tree-hidden object find target' \
	> "$WORK/initramfs/hdn-object-find-tree/child"
chmod 0644 "$WORK/initramfs/hdn-object-find-tree/child"
mkdir -p "$WORK/initramfs/hdn-object-tree-protected/nested"
chmod 0777 "$WORK/initramfs/hdn-object-tree-protected"
chmod 0777 "$WORK/initramfs/hdn-object-tree-protected/nested"
printf '%s\n' 'protected object tree read target' \
	> "$WORK/initramfs/hdn-object-tree-protected/nested/read-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-protected/nested/read-target"
printf '%s\n' 'protected object tree write target' \
	> "$WORK/initramfs/hdn-object-tree-protected/nested/write-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-protected/nested/write-target"
printf '%s\n' 'protected object tree delete target' \
	> "$WORK/initramfs/hdn-object-tree-protected/nested/delete-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-protected/nested/delete-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-protected/nested/delete-dir"
chmod 0755 "$WORK/initramfs/hdn-object-tree-protected/nested/delete-dir"
printf '%s\n' 'protected object tree attr target' \
	> "$WORK/initramfs/hdn-object-tree-protected/nested/attr-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-protected/nested/attr-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-protected/nested/list-target"
chmod 0755 "$WORK/initramfs/hdn-object-tree-protected/nested/list-target"
printf '%s\n' 'protected object tree list target' \
	> "$WORK/initramfs/hdn-object-tree-protected/nested/list-target/entry"
chmod 0644 "$WORK/initramfs/hdn-object-tree-protected/nested/list-target/entry"
printf '%s\n' 'protected object tree find target' \
	> "$WORK/initramfs/hdn-object-tree-protected/nested/find-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-protected/nested/find-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-ops/nested"
chmod 0777 "$WORK/initramfs/hdn-object-tree-ops"
chmod 0777 "$WORK/initramfs/hdn-object-tree-ops/nested"
cp "$WORK/hdn_smoke" \
	"$WORK/initramfs/hdn-object-tree-ops/nested/exec-target"
chmod 0755 "$WORK/initramfs/hdn-object-tree-ops/nested/exec-target"
printf '%s\n' 'protected object tree link source' \
	> "$WORK/initramfs/hdn-object-tree-ops/nested/link-source"
chmod 0644 "$WORK/initramfs/hdn-object-tree-ops/nested/link-source"
printf '%s\n' 'protected object tree ioctl target' \
	> "$WORK/initramfs/hdn-object-tree-ops/nested/ioctl-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-ops/nested/ioctl-target"
printf '%s\n' 'protected object tree lock target' \
	> "$WORK/initramfs/hdn-object-tree-ops/nested/lock-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-ops/nested/lock-target"
printf '%s\n' 'protected object tree watch target' \
	> "$WORK/initramfs/hdn-object-tree-ops/nested/watch-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-ops/nested/watch-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-ops/nested/watch-dir"
chmod 0755 "$WORK/initramfs/hdn-object-tree-ops/nested/watch-dir"
printf '%s\n' 'protected object tree fcntl target' \
	> "$WORK/initramfs/hdn-object-tree-ops/nested/fcntl-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-ops/nested/fcntl-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-ops/nested/chdir-target"
chmod 0755 "$WORK/initramfs/hdn-object-tree-ops/nested/chdir-target"
printf '%s\n' 'protected object tree truncate target' \
	> "$WORK/initramfs/hdn-object-tree-ops/nested/truncate-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-ops/nested/truncate-target"
printf '%s\n' 'protected object tree rename target' \
	> "$WORK/initramfs/hdn-object-tree-ops/nested/rename-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-ops/nested/rename-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-receive/nested"
chmod 0777 "$WORK/initramfs/hdn-object-tree-receive"
chmod 0777 "$WORK/initramfs/hdn-object-tree-receive/nested"
printf '%s\n' 'protected object tree receive target' \
	> "$WORK/initramfs/hdn-object-tree-receive/nested/receive-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-receive/nested/receive-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-mount/nested/mount-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-mount/nested/move-target"
chmod 0777 "$WORK/initramfs/hdn-object-tree-mount"
chmod 0777 "$WORK/initramfs/hdn-object-tree-mount/nested"
chmod 0755 "$WORK/initramfs/hdn-object-tree-mount/nested/mount-target"
chmod 0755 "$WORK/initramfs/hdn-object-tree-mount/nested/move-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-move-mount-source"
chmod 0755 "$WORK/initramfs/hdn-object-tree-move-mount-source"
mkdir -p "$WORK/initramfs/hdn-object-tree-umount/nested/umount-target"
chmod 0777 "$WORK/initramfs/hdn-object-tree-umount"
chmod 0777 "$WORK/initramfs/hdn-object-tree-umount/nested"
chmod 0755 "$WORK/initramfs/hdn-object-tree-umount/nested/umount-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-meta/nested"
chmod 0777 "$WORK/initramfs/hdn-object-tree-meta"
chmod 0777 "$WORK/initramfs/hdn-object-tree-meta/nested"
printf '%s\n' 'protected object tree chmod target' \
	> "$WORK/initramfs/hdn-object-tree-meta/nested/chmod-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-meta/nested/chmod-target"
printf '%s\n' 'protected object tree chown target' \
	> "$WORK/initramfs/hdn-object-tree-meta/nested/chown-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-meta/nested/chown-target"
printf '%s\n' 'protected object tree utime target' \
	> "$WORK/initramfs/hdn-object-tree-meta/nested/utime-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-meta/nested/utime-target"
printf '%s\n' 'protected object tree setxattr target' \
	> "$WORK/initramfs/hdn-object-tree-meta/nested/setxattr-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-meta/nested/setxattr-target"
printf '%s\n' 'protected object tree removexattr target' \
	> "$WORK/initramfs/hdn-object-tree-meta/nested/removexattr-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-meta/nested/removexattr-target"
printf '%s\n' 'protected object tree xattr target' \
	> "$WORK/initramfs/hdn-object-tree-meta/nested/xattr-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-meta/nested/xattr-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-ipc-bind/nested/bind-dir"
chmod 0777 "$WORK/initramfs/hdn-object-tree-ipc-bind"
chmod 0777 "$WORK/initramfs/hdn-object-tree-ipc-bind/nested"
chmod 0777 "$WORK/initramfs/hdn-object-tree-ipc-bind/nested/bind-dir"
mkdir -p "$WORK/initramfs/hdn-object-tree-ipc-listen/nested"
chmod 0777 "$WORK/initramfs/hdn-object-tree-ipc-listen"
chmod 0777 "$WORK/initramfs/hdn-object-tree-ipc-listen/nested"
mkdir -p "$WORK/initramfs/hdn-object-tree-ipc-accept/nested"
chmod 0777 "$WORK/initramfs/hdn-object-tree-ipc-accept"
chmod 0777 "$WORK/initramfs/hdn-object-tree-ipc-accept/nested"
mkdir -p "$WORK/initramfs/hdn-object-tree-ipc-send/nested"
chmod 0777 "$WORK/initramfs/hdn-object-tree-ipc-send"
chmod 0777 "$WORK/initramfs/hdn-object-tree-ipc-send/nested"
mkdir -p "$WORK/initramfs/hdn-object-tree-ipc-recv/nested"
chmod 0777 "$WORK/initramfs/hdn-object-tree-ipc-recv"
chmod 0777 "$WORK/initramfs/hdn-object-tree-ipc-recv/nested"
mkdir -p "$WORK/initramfs/hdn-object-tree-unprotected/nested"
chmod 0777 "$WORK/initramfs/hdn-object-tree-unprotected"
chmod 0777 "$WORK/initramfs/hdn-object-tree-unprotected/nested"
printf '%s\n' 'unprotected object tree write target' \
	> "$WORK/initramfs/hdn-object-tree-unprotected/nested/write-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-unprotected/nested/write-target"
cp "$WORK/hdn_smoke" \
	"$WORK/initramfs/hdn-object-tree-unprotected/nested/exec-target"
chmod 0755 "$WORK/initramfs/hdn-object-tree-unprotected/nested/exec-target"
printf '%s\n' 'unprotected object tree link source' \
	> "$WORK/initramfs/hdn-object-tree-unprotected/nested/link-source"
chmod 0644 "$WORK/initramfs/hdn-object-tree-unprotected/nested/link-source"
printf '%s\n' 'unprotected object tree ioctl target' \
	> "$WORK/initramfs/hdn-object-tree-unprotected/nested/ioctl-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-unprotected/nested/ioctl-target"
printf '%s\n' 'unprotected object tree lock target' \
	> "$WORK/initramfs/hdn-object-tree-unprotected/nested/lock-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-unprotected/nested/lock-target"
printf '%s\n' 'unprotected object tree watch target' \
	> "$WORK/initramfs/hdn-object-tree-unprotected/nested/watch-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-unprotected/nested/watch-target"
printf '%s\n' 'unprotected object tree fcntl target' \
	> "$WORK/initramfs/hdn-object-tree-unprotected/nested/fcntl-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-unprotected/nested/fcntl-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-unprotected/nested/chdir-target"
chmod 0755 "$WORK/initramfs/hdn-object-tree-unprotected/nested/chdir-target"
printf '%s\n' 'unprotected object tree truncate target' \
	> "$WORK/initramfs/hdn-object-tree-unprotected/nested/truncate-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-unprotected/nested/truncate-target"
printf '%s\n' 'unprotected object tree rename target' \
	> "$WORK/initramfs/hdn-object-tree-unprotected/nested/rename-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-unprotected/nested/rename-target"
printf '%s\n' 'unprotected object tree receive target' \
	> "$WORK/initramfs/hdn-object-tree-unprotected/nested/receive-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-unprotected/nested/receive-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-unprotected/nested/mount-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-unprotected/nested/move-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-unprotected/nested/umount-target"
chmod 0755 "$WORK/initramfs/hdn-object-tree-unprotected/nested/mount-target"
chmod 0755 "$WORK/initramfs/hdn-object-tree-unprotected/nested/move-target"
chmod 0755 "$WORK/initramfs/hdn-object-tree-unprotected/nested/umount-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-move-mount-source-unmatched"
chmod 0755 "$WORK/initramfs/hdn-object-tree-move-mount-source-unmatched"
mkdir -p "$WORK/initramfs/hdn-object-tree-split/nested"
chmod 0777 "$WORK/initramfs/hdn-object-tree-split"
chmod 0777 "$WORK/initramfs/hdn-object-tree-split/nested"
printf '%s\n' 'protected split tree unlink target' \
	> "$WORK/initramfs/hdn-object-tree-split/nested/unlink-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-split/nested/unlink-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-split/nested/rmdir-target"
chmod 0755 "$WORK/initramfs/hdn-object-tree-split/nested/rmdir-target"
mkdir -p "$WORK/initramfs/hdn-object-tree-append/nested"
chmod 0777 "$WORK/initramfs/hdn-object-tree-append"
chmod 0777 "$WORK/initramfs/hdn-object-tree-append/nested"
printf '%s\n' 'protected append tree target' \
	> "$WORK/initramfs/hdn-object-tree-append/nested/append-target"
chmod 0644 "$WORK/initramfs/hdn-object-tree-append/nested/append-target"
mkdir -p "$WORK/initramfs/hdn-object-create-protected"
chmod 0777 "$WORK/initramfs/hdn-object-create-protected"
mkdir -p "$WORK/initramfs/hdn-object-create-unprotected"
chmod 0777 "$WORK/initramfs/hdn-object-create-unprotected"
mkdir -p "$WORK/initramfs/hdn-object-rename-target-protected"
chmod 0777 "$WORK/initramfs/hdn-object-rename-target-protected"
mkdir -p "$WORK/initramfs/hdn-object-link-target-protected"
chmod 0777 "$WORK/initramfs/hdn-object-link-target-protected"
mkdir -p "$WORK/initramfs/hdn-object-creat-protected"
chmod 0777 "$WORK/initramfs/hdn-object-creat-protected"
mkdir -p "$WORK/initramfs/hdn-object-mkdir-protected"
chmod 0777 "$WORK/initramfs/hdn-object-mkdir-protected"
mkdir -p "$WORK/initramfs/hdn-object-mknod-protected"
chmod 0777 "$WORK/initramfs/hdn-object-mknod-protected"
mkdir -p "$WORK/initramfs/hdn-object-symlink-protected"
chmod 0777 "$WORK/initramfs/hdn-object-symlink-protected"
printf '%s\n' 'protected object unlink target' \
	> "$WORK/initramfs/hdn-object-unlink-protected"
chmod 0644 "$WORK/initramfs/hdn-object-unlink-protected"
mkdir -p "$WORK/initramfs/hdn-object-rmdir-protected"
chmod 0755 "$WORK/initramfs/hdn-object-rmdir-protected"
mkdir -p "$WORK/initramfs/hdn-object-split-create-unprotected"
chmod 0777 "$WORK/initramfs/hdn-object-split-create-unprotected"
printf '%s\n' 'unprotected object split unlink target' \
	> "$WORK/initramfs/hdn-object-split-unlink-unprotected"
chmod 0644 "$WORK/initramfs/hdn-object-split-unlink-unprotected"
mkdir -p "$WORK/initramfs/hdn-object-split-rmdir-unprotected"
chmod 0755 "$WORK/initramfs/hdn-object-split-rmdir-unprotected"
cp "$WORK/init" "$WORK/initramfs/init"
cp "$WORK/default.hdn" "$WORK/initramfs/default.hdn"
cp "$WORK/default.hdn.unsigned" "$WORK/initramfs/default.hdn.unsigned"
cp "$WORK/restricted.hdn" "$WORK/initramfs/restricted.hdn"
cp "$WORK/proc-disclose.hdn" "$WORK/initramfs/proc-disclose.hdn"
cp "$WORK/trace-symbol.hdn" "$WORK/initramfs/trace-symbol.hdn"
cp "$WORK/chroot-mount.hdn" "$WORK/initramfs/chroot-mount.hdn"
cp "$WORK/jit.hdn" "$WORK/initramfs/jit.hdn"
cp "$WORK/execstack.hdn" "$WORK/initramfs/execstack.hdn"
cp "$WORK/textrel.hdn" "$WORK/initramfs/textrel.hdn"
cp "$WORK/relro.hdn" "$WORK/initramfs/relro.hdn"
cp "$WORK/kill.hdn" "$WORK/initramfs/kill.hdn"
cp "$WORK/cred-deny.hdn" "$WORK/initramfs/cred-deny.hdn"
cp "$WORK/privexec-deny.hdn" "$WORK/initramfs/privexec-deny.hdn"
cp "$WORK/identity.hdn" "$WORK/initramfs/identity.hdn"
cp "$WORK/module-path.hdn" "$WORK/initramfs/module-path.hdn"
cp "$WORK/firmware.hdn" "$WORK/initramfs/firmware.hdn"
cp "$WORK/mount-policy.hdn" "$WORK/initramfs/mount-policy.hdn"
cp "$WORK/mount-ro-policy.hdn" "$WORK/initramfs/mount-ro-policy.hdn"
cp "$WORK/proc-task.hdn" "$WORK/initramfs/proc-task.hdn"
cp "$WORK/namespace-only.hdn" "$WORK/initramfs/namespace-only.hdn"
cp "$WORK/namespace-proc-task.hdn" "$WORK/initramfs/namespace-proc-task.hdn"
cp "$WORK/subject.hdn" "$WORK/initramfs/subject.hdn"
cp "$WORK/userns-depth.hdn" "$WORK/initramfs/userns-depth.hdn"
cp "$WORK/role.hdn" "$WORK/initramfs/role.hdn"
cp "$WORK/process-account.hdn" "$WORK/initramfs/process-account.hdn"
cp "$WORK/object-write.hdn" "$WORK/initramfs/object-write.hdn"
cp "$WORK/socket-policy.hdn" "$WORK/initramfs/socket-policy.hdn"
cp "$WORK/block-admin.hdn" "$WORK/initramfs/block-admin.hdn"
cp "$HDN_SYMBOL_TEST_MODULE" "$WORK/initramfs/hdn-symbol-test-module.ko"
if ! tail -c 28 "$WORK/initramfs/hdn-symbol-test-module.ko" |
	grep -q 'Module signature appended'; then
	"$SIGN_FILE" sha512 "$HDN_SIGNING_KEY" "$HDN_SIGNING_CERT" \
		"$WORK/initramfs/hdn-symbol-test-module.ko"
fi
mkdir -p "$WORK/initramfs/hdn-policies"
cp "$WORK/default.hdn" "$WORK/initramfs/hdn-policies/default.hdn"
printf '%s\n' 'qmp usb hotplug enabled' \
	> "$WORK/initramfs/hdn-usb-hotplug-test"

(
	cd "$WORK/initramfs"
	find . -print0 | cpio --null -o --format=newc --owner=0:0
) | gzip -9 > "$WORK/initramfs.cpio.gz"

send_usb_hotplug()
{
	waited=0

	while [ ! -S "$QMP" ] && [ "$waited" -lt "$HDN_USB_HOTPLUG_TIMEOUT" ]; do
		sleep 1
		waited=$((waited + 1))
	done

	waited=0
	while ! grep -q "HDN_USB_HOTPLUG_READY" "$LOG" 2>/dev/null; do
		if grep -q "HDN_SMOKE_EXIT=" "$LOG" 2>/dev/null; then
			return 0
		fi
		if [ "$waited" -ge "$HDN_USB_HOTPLUG_TIMEOUT" ]; then
			printf '%s\n' "HDN_QMP_USB_HOTPLUG_TIMEOUT" >> "$LOG"
			return 0
		fi
		sleep 1
		waited=$((waited + 1))
	done

		{
			printf '%s\r\n' '{"execute":"qmp_capabilities"}'
			sleep 1
			printf '%s' '{"execute":"device_add","arguments":{'
			printf '%s' '"driver":"usb-kbd",'
			printf '%s' '"id":"hdn-usb-hotplug",'
			printf '%s\r\n' '"bus":"hdn-xhci.0"}}'
			sleep 1
		} | timeout 5 nc -U "$QMP" > "$WORK/qmp-hotplug.log" 2>&1 || true
	if grep -q '"error"' "$WORK/qmp-hotplug.log" 2>/dev/null; then
		cat "$WORK/qmp-hotplug.log" >> "$LOG"
	fi
}

send_usb_hotplug &
usb_hotplug_pid=$!

set +e
timeout "$QEMU_TIMEOUT" "$QEMU" \
	-M "$QEMU_MACHINE" -cpu max -smp "$QEMU_SMP" -m "$QEMU_MEMORY" \
	-device qemu-xhci,id=hdn-xhci \
	-qmp unix:"$QMP",server=on,wait=off \
	-kernel "$BZIMAGE" \
	-initrd "$WORK/initramfs.cpio.gz" \
	-append "console=ttyS0 rdinit=/init panic=1 oops=panic spectre_v2_user=prctl spec_store_bypass_disable=prctl hdn.proc_task_gid=65533" \
	-nographic -no-reboot >"$LOG" 2>&1
qemu_status=$?
set -e

if kill -0 "$usb_hotplug_pid" 2>/dev/null; then
	kill "$usb_hotplug_pid" 2>/dev/null || true
fi
wait "$usb_hotplug_pid" 2>/dev/null || true

cat "$LOG"

if [ "$qemu_status" -eq 124 ]; then
	echo "qemu timed out" >&2
	exit "$qemu_status"
fi

if grep -Eq "Kernel panic|BUG:|Oops|WARNING:" "$LOG"; then
	echo "kernel reported a fatal diagnostic" >&2
	exit 1
fi

grep -q "HDN_INIT booted" "$LOG"
grep -q "HDN_SMOKE_EXIT=0" "$LOG"
grep -q "# Totals: pass:$HDN_SMOKE_EXPECTED_PASS fail:0 xfail:0 xpass:0 skip:0 error:0" "$LOG"

if [ "$qemu_status" -ne 0 ] && ! grep -q "reboot: Power down" "$LOG"; then
	echo "qemu exited with status $qemu_status" >&2
	exit "$qemu_status"
fi

echo "HDN_QEMU_SMOKE_PASS log=$LOG"
