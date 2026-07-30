#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only

set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "test-admin-ux: run as root" >&2
	exit 2
fi

base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d /tmp/hdn-admin-ux.XXXXXX)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
chmod 0755 "$tmp"
install -m 0755 "$base/hdn-prompt-session" "$tmp/hdn-prompt-session"
install -m 0755 "$base/hdn-prompt-portal" "$tmp/hdn-prompt-portal"
install -m 0755 "$base/hdn-recovery-session" "$tmp/hdn-recovery-session"
install -m 0755 "$base/hdn-recovery-portal" "$tmp/hdn-recovery-portal"
install -m 0755 "$base/hdn-recovery-panel" "$tmp/hdn-recovery-panel"
install -m 0755 "$base/hdn-recovery-ui" "$tmp/hdn-recovery-ui"
install -m 0755 "$base/hdn-settings-panel" "$tmp/hdn-settings-panel"
install -m 0755 "$base/hdn-settings-ui" "$tmp/hdn-settings-ui"
session="$tmp/hdn-prompt-session"
portal="$tmp/hdn-prompt-portal"
recovery_session="$tmp/hdn-recovery-session"
recovery_portal="$tmp/hdn-recovery-portal"
recovery_panel="$tmp/hdn-recovery-panel"
recovery_ui="$tmp/hdn-recovery-ui"
settings_panel="$tmp/hdn-settings-panel"
settings_ui="$tmp/hdn-settings-ui"

cat >"$tmp/fake-pkexec" <<EOF
#!/bin/sh
set -eu
[ "\$#" -eq 3 ]
[ "\$1" = "$session" ]
[ "\$2" = "--authorized" ]
[ "\$3" = "package-update" ]
EOF
chmod 0755 "$tmp/fake-pkexec"

cat >"$tmp/prompt-portal.conf" <<EOF
session-helper $session
elevation-helper $tmp/fake-pkexec
action desktop-package-update package-update
EOF
chmod 0644 "$tmp/prompt-portal.conf"

if runuser -u nobody -- "$session" --authorized package-update; then
	echo "test-admin-ux: unprivileged --authorized call succeeded" >&2
	exit 1
fi

runuser -u nobody -- "$portal" --config "$tmp/prompt-portal.conf" \
	desktop-package-update

cat >"$tmp/fake-prompt-describe" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' HDN_PROMPT_METADATA_V1 "action=$1" \
	'title=Install system updates' 'message=Apply approved updates.' \
	'consequence=Protected files may change.' 'risk=update'
EOF
cat >"$tmp/fake-prompt-auth" <<EOF
#!/bin/sh
set -eu
touch "$tmp/auth-called"
exit 1
EOF
cat >"$tmp/fake-prompt-dispatch" <<EOF
#!/bin/sh
set -eu
printf '%s\n' "\$*" >> "$tmp/prompt-dispatches"
if [ "\${1:-}" = "--dry-run" ] && [ -e "$tmp/fail-prompt-preflight" ]; then
	exit 42
fi
EOF
chmod 0755 "$tmp/fake-prompt-describe" "$tmp/fake-prompt-auth" \
	"$tmp/fake-prompt-dispatch"
cat >"$tmp/prompt-session.conf" <<EOF
describe-helper $tmp/fake-prompt-describe
auth-helper $tmp/fake-prompt-auth
dispatch-helper $tmp/fake-prompt-dispatch
EOF
chmod 0644 "$tmp/prompt-session.conf"
"$session" --authorized --config "$tmp/prompt-session.conf" package-update
[ "$(sed -n '1p' "$tmp/prompt-dispatches")" = "--dry-run package-update" ]
[ "$(sed -n '2p' "$tmp/prompt-dispatches")" = "package-update" ]
[ ! -e "$tmp/auth-called" ]
"$session" --authorized --dry-run --config "$tmp/prompt-session.conf" \
	package-update
[ "$(sed -n '3p' "$tmp/prompt-dispatches")" = "--dry-run package-update" ]
touch "$tmp/fail-prompt-preflight"
if "$session" --authorized --config "$tmp/prompt-session.conf" \
	package-update; then
	echo "test-admin-ux: prompt action ignored preflight failure" >&2
	exit 1
fi
rm "$tmp/fail-prompt-preflight"
[ "$(wc -l < "$tmp/prompt-dispatches")" -eq 4 ]
if "$session" --config "$tmp/prompt-session.conf" package-update; then
	echo "test-admin-ux: denied fallback authentication succeeded" >&2
	exit 1
fi
[ "$(wc -l < "$tmp/prompt-dispatches")" -eq 4 ]
[ -e "$tmp/auth-called" ]

cat >"$tmp/fake-control-center" <<EOF
#!/bin/sh
set -eu
printf '%s\n' "\$*" >> "$tmp/control-center-calls"
EOF
chmod 0755 "$tmp/fake-control-center"
cat >"$tmp/settings-panel.conf" <<EOF
control-center-helper $tmp/fake-control-center
action updates.install updates.install
EOF
chmod 0644 "$tmp/settings-panel.conf"
"$settings_panel" --config "$tmp/settings-panel.conf" action updates.install
"$settings_panel" --config "$tmp/settings-panel.conf" --dry-run \
	action updates.install
[ "$(sed -n '1p' "$tmp/control-center-calls")" = "action updates.install" ]
[ "$(sed -n '2p' "$tmp/control-center-calls")" = \
	"--dry-run action updates.install" ]
[ "$(wc -l < "$tmp/control-center-calls")" -eq 2 ]

cat >"$tmp/fake-settings-panel" <<EOF
#!/bin/sh
set -eu
if [ "\${1:-}" = "status" ]; then
	printf '%s\n' 'HDN_SETTINGS_PANEL_STATUS available=1'
	exit 0
fi
printf '%s\n' "\$*" >> "$tmp/settings-ui-calls"
EOF
chmod 0755 "$tmp/fake-settings-panel"
cat >"$tmp/settings-ui.conf" <<EOF
settings-panel-helper $tmp/fake-settings-panel
title System Settings
message Choose an approved system action.
action updates.install Install system updates
EOF
chmod 0644 "$tmp/settings-ui.conf"
"$settings_ui" --config "$tmp/settings-ui.conf" --test-choice updates.install
"$settings_ui" --config "$tmp/settings-ui.conf" --dry-run \
	--test-choice updates.install
[ "$(sed -n '1p' "$tmp/settings-ui-calls")" = "action updates.install" ]
[ "$(sed -n '2p' "$tmp/settings-ui-calls")" = \
	"--dry-run action updates.install" ]
[ "$(wc -l < "$tmp/settings-ui-calls")" -eq 2 ]

cat >"$tmp/fake-dnf5" <<EOF
#!/bin/sh
set -eu
[ "\$#" -eq 3 ]
case "\$1" in
	upgrade|distro-sync) ;;
	*) exit 1 ;;
esac
[ "\$2" = "--refresh" ]
[ "\$3" = "--assumeyes" ]
[ "\${HDN_PACKAGE_TRANSACTION:-}" = "1" ]
[ "\${HOME:-}" = "/root" ]
[ ! -e "$tmp/fail-dnf" ] || exit 42
printf '%s\n' "\$1" >> "$tmp/dnf-operations"
printf '%s\n' "dnf:\$1" >> "$tmp/transaction-order"
EOF
chmod 0755 "$tmp/fake-dnf5"
cat >"$tmp/fake-policy-load" <<EOF
#!/bin/sh
set -eu
[ "\$#" -eq 1 ]
[ "\$1" = "--refresh" ]
[ "\${HDN_PACKAGE_TRANSACTION:-}" = "1" ]
printf '%s\n' refresh >> "$tmp/policy-refreshes"
printf '%s\n' refresh >> "$tmp/transaction-order"
[ ! -e "$tmp/fail-refresh" ] || exit 43
EOF
chmod 0755 "$tmp/fake-policy-load"
cat >"$tmp/fake-systemctl" <<EOF
#!/bin/sh
set -eu
[ "\$#" -eq 3 ]
[ "\$1" = "stop" ]
[ "\$2" = "packagekit.service" ]
[ "\$3" = "dnf5daemon-server.service" ]
printf '%s\n' "\$*" >> "$tmp/systemctl-calls"
EOF
chmod 0755 "$tmp/fake-systemctl"
cat >"$tmp/fake-rofs-transaction" <<EOF
#!/bin/sh
set -eu
[ "\$#" -ge 4 ]
printf '%s\n' "\$1" >> "$tmp/opened-mounts"
[ "\$2" = "--" ]
shift 2
exec "\$@"
EOF
chmod 0755 "$tmp/fake-rofs-transaction"
cat >"$tmp/mountinfo" <<'EOF'
100 1 8:1 / /boot ro,relatime - ext4 /dev/vda1 ro
101 100 8:2 / /boot/efi ro,relatime - vfat /dev/vda2 ro
EOF
cc -O2 -Wall -Wextra \
	-DHDN_DNF5_PATH="\"$tmp/fake-dnf5\"" \
	-DHDN_ROFS_TRANSACTION_PATH="\"$tmp/fake-rofs-transaction\"" \
	-DHDN_PACKAGE_WORKER_PATH="\"$tmp/hdn-package-worker\"" \
	-DHDN_MOUNTINFO_PATH="\"$tmp/mountinfo\"" \
	-DHDN_POLICY_LOAD_PATH="\"$tmp/fake-policy-load\"" \
	-DHDN_SYSTEMCTL_PATH="\"$tmp/fake-systemctl\"" \
	-o "$tmp/hdn-package-worker" "$base/hdn-package-worker.c"
"$tmp/hdn-package-worker"
"$tmp/hdn-package-worker" update
"$tmp/hdn-package-worker" repair
[ "$(sed -n '1p' "$tmp/dnf-operations")" = "upgrade" ]
[ "$(sed -n '2p' "$tmp/dnf-operations")" = "upgrade" ]
[ "$(sed -n '3p' "$tmp/dnf-operations")" = "distro-sync" ]
[ "$(wc -l < "$tmp/policy-refreshes")" -eq 3 ]
[ "$(sed -n '1,6p' "$tmp/transaction-order")" = "$(printf '%s\n' \
	'dnf:upgrade' refresh 'dnf:upgrade' refresh 'dnf:distro-sync' refresh)" ]
[ "$(sed -n '1p' "$tmp/opened-mounts")" = "/boot" ]
[ "$(sed -n '2p' "$tmp/opened-mounts")" = "/boot/efi" ]
[ "$(sed -n '5p' "$tmp/opened-mounts")" = "/boot" ]
[ "$(sed -n '6p' "$tmp/opened-mounts")" = "/boot/efi" ]
[ "$(wc -l < "$tmp/opened-mounts")" -eq 6 ]
[ "$(wc -l < "$tmp/systemctl-calls")" -eq 6 ]
touch "$tmp/fail-dnf"
if "$tmp/hdn-package-worker" update; then
	echo "test-admin-ux: updater ignored DNF failure" >&2
	exit 1
fi
rm "$tmp/fail-dnf"
[ "$(wc -l < "$tmp/policy-refreshes")" -eq 3 ]
[ "$(wc -l < "$tmp/systemctl-calls")" -eq 8 ]
touch "$tmp/fail-refresh"
if "$tmp/hdn-package-worker" update; then
	echo "test-admin-ux: updater ignored policy refresh failure" >&2
	exit 1
fi
rm "$tmp/fail-refresh"
[ "$(wc -l < "$tmp/policy-refreshes")" -eq 4 ]
[ "$(wc -l < "$tmp/systemctl-calls")" -eq 10 ]
if "$tmp/hdn-package-worker" arbitrary; then
	echo "test-admin-ux: updater accepted an arbitrary operation" >&2
	exit 1
fi

cat >"$tmp/fake-recovery-portal" <<EOF
#!/bin/sh
set -eu
printf '%s\n' "\$*" >> "$tmp/panel-calls"
EOF
chmod 0755 "$tmp/fake-recovery-portal"
cat >"$tmp/recovery-panel.conf" <<EOF
describe-helper /bin/true
portal-helper $tmp/fake-recovery-portal
action repair-system package-repair repair-system
EOF
chmod 0644 "$tmp/recovery-panel.conf"
if runuser -u nobody -- "$recovery_panel" --authorized \
	--config "$tmp/recovery-panel.conf" action repair-system; then
	echo "test-admin-ux: unprivileged recovery panel authorization succeeded" >&2
	exit 1
fi
"$recovery_panel" --authorized --config "$tmp/recovery-panel.conf" \
	action repair-system
[ "$(sed -n '1p' "$tmp/panel-calls")" = \
	"--authorized repair-system" ]
"$recovery_panel" --authorized --dry-run \
	--config "$tmp/recovery-panel.conf" action repair-system
[ "$(sed -n '2p' "$tmp/panel-calls")" = \
	"--dry-run --authorized repair-system" ]
[ "$(wc -l < "$tmp/panel-calls")" -eq 2 ]

cat >"$tmp/fake-recovery-panel-ui" <<EOF
#!/bin/sh
set -eu
if [ "\${1:-}" = "describe" ]; then
	printf '%s\n' HDN_RECOVERY_METADATA_V1 "action=\$2" \
		'title=Repair protected system files' \
		'message=Repair package state.' \
		'consequence=Protected files may change.' 'risk=repair'
	exit 0
fi
printf '%s\n' "\$*" >> "$tmp/recovery-ui-calls"
EOF
chmod 0755 "$tmp/fake-recovery-panel-ui"
cat >"$tmp/recovery-ui.conf" <<EOF
panel-helper $tmp/fake-recovery-panel-ui
title System Recovery
message Choose a repair action.
action repair-system
EOF
chmod 0644 "$tmp/recovery-ui.conf"
"$recovery_ui" --config "$tmp/recovery-ui.conf" \
	--test-choice repair-system
"$recovery_ui" --config "$tmp/recovery-ui.conf" --dry-run \
	--test-choice repair-system
[ "$(sed -n '1p' "$tmp/recovery-ui-calls")" = "action repair-system" ]
[ "$(sed -n '2p' "$tmp/recovery-ui-calls")" = \
	"--dry-run action repair-system" ]
[ "$(wc -l < "$tmp/recovery-ui-calls")" -eq 2 ]

cat >"$tmp/fake-recovery-session" <<EOF
#!/bin/sh
set -eu
printf '%s\n' "\$*" >> "$tmp/portal-calls"
EOF
chmod 0755 "$tmp/fake-recovery-session"
cat >"$tmp/recovery-portal.conf" <<EOF
session-helper $tmp/fake-recovery-session
action repair-system package-repair
EOF
chmod 0644 "$tmp/recovery-portal.conf"
if runuser -u nobody -- "$recovery_portal" --authorized \
	--config "$tmp/recovery-portal.conf" repair-system; then
	echo "test-admin-ux: unprivileged recovery portal authorization succeeded" >&2
	exit 1
fi
"$recovery_portal" --authorized --config "$tmp/recovery-portal.conf" \
	repair-system
[ "$(cat "$tmp/portal-calls")" = "--authorized package-repair" ]

cat >"$tmp/fake-recovery-describe" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' HDN_RECOVERY_METADATA_V1 "action=$1" \
	'title=Repair protected system files' 'message=Repair package state.' \
	'consequence=Protected files may change.' 'risk=repair'
EOF
cat >"$tmp/fake-recovery-confirm" <<EOF
#!/bin/sh
set -eu
touch "$tmp/confirm-called"
exit 1
EOF
cat >"$tmp/fake-recovery-action" <<EOF
#!/bin/sh
set -eu
printf '%s\n' "\$*" >> "$tmp/recovery-actions"
EOF
chmod 0755 "$tmp/fake-recovery-describe" "$tmp/fake-recovery-confirm" \
	"$tmp/fake-recovery-action"
cat >"$tmp/recovery-session.conf" <<EOF
describe-helper $tmp/fake-recovery-describe
confirm-helper $tmp/fake-recovery-confirm
action-helper $tmp/fake-recovery-action
EOF
chmod 0644 "$tmp/recovery-session.conf"
if runuser -u nobody -- "$recovery_session" --authorized \
	--config "$tmp/recovery-session.conf" package-repair; then
	echo "test-admin-ux: unprivileged recovery session authorization succeeded" >&2
	exit 1
fi
"$recovery_session" --authorized --config "$tmp/recovery-session.conf" \
	package-repair
[ "$(sed -n '1p' "$tmp/recovery-actions")" = \
	"--dry-run package-repair" ]
[ "$(sed -n '2p' "$tmp/recovery-actions")" = "package-repair" ]
[ ! -e "$tmp/confirm-called" ]
if "$recovery_session" --config "$tmp/recovery-session.conf" \
	package-repair; then
	echo "test-admin-ux: denied recovery confirmation unexpectedly succeeded" >&2
	exit 1
fi
[ "$(wc -l < "$tmp/recovery-actions")" -eq 2 ]
[ -e "$tmp/confirm-called" ]

HDN_PACKAGE_TRANSACTION=1 "$base/hdn-package-hook" image-seal-default

grep -qx 'approval-token-dir /run/hdn/approvals' \
	"$base/admin-broker.conf"
grep -qx 'require-approval-token' "$base/admin-broker.conf"

for hook in \
	"$base/package-manager-hooks/apt/99-hdn-package-update" \
	"$base/package-manager-hooks/pacman/99-hdn-package-update.hook" \
	"$base/package-manager-hooks/dnf/99-hdn-package-update.action" \
	"$base/package-manager-hooks/dnf5/99-hdn-package-update.actions"; do
	grep -q 'hdn-package-hook image-seal-default' "$hook"
	if grep -q 'hdn-package-hook package-update' "$hook"; then
		echo "test-admin-ux: recursive package update hook in $hook" >&2
		exit 1
	fi
done

echo "test-admin-ux: authorization, update/repair, recovery, and reseal hooks passed"
