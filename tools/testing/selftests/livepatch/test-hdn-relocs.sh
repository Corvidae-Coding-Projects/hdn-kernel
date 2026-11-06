#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Run explicitly in a disposable guest after rewriting and signing the fixture.
set -euo pipefail
patch=${1:?pass the rewritten, signed good patch module}
target=${2:?pass the signed target module}
[[ $EUID == 0 ]] || exit 4
[[ -d /sys/kernel/livepatch ]] || exit 4
[[ ! -d /sys/module/test_hdn_klp_patch && ! -d /sys/module/test_hdn_klp_target ]] || exit 4
cleanup() {
    if [[ -e /sys/kernel/livepatch/test_hdn_klp_patch/enabled ]]; then
        echo 0 > /sys/kernel/livepatch/test_hdn_klp_patch/enabled
        for ((i=0; i<100; i++)); do
            [[ $(cat /sys/kernel/livepatch/test_hdn_klp_patch/transition) == 0 ]] && break
            sleep .1
        done
    fi
    rmmod test_hdn_klp_target 2>/dev/null || true
    rmmod test_hdn_klp_patch 2>/dev/null || true
}
trap cleanup EXIT
insmod "$patch" fail_after_binding=1
# The callback must see both correct pointers before rejecting publication.
if insmod "$target"; then
    echo 'FAIL: callback rejection admitted target' >&2
    exit 1
fi
[[ ! -d /sys/module/test_hdn_klp_target ]]
[[ $(cat /sys/module/test_hdn_klp_patch/parameters/binding_count) == 1 ]]
echo 0 > /sys/module/test_hdn_klp_patch/parameters/fail_after_binding
# Failed application must have withdrawn both relocations, permitting reload.
insmod "$target"
[[ $(cat /sys/module/test_hdn_klp_patch/parameters/binding_count) == 2 ]]
rmmod test_hdn_klp_target
insmod "$target"
[[ $(cat /sys/module/test_hdn_klp_patch/parameters/binding_count) == 3 ]]
echo 'PASS: read-only/cross-page binding, failed publication, unload, reload'
