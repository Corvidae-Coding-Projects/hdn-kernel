#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../../.." && pwd)
KBUILD_OUTPUT=${KBUILD_OUTPUT:-"$ROOT/../linux-7.0.12-build"}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/hdn-kallsyms-api.XXXXXX")

cleanup()
{
	rm -rf "$TMP"
}

trap cleanup EXIT INT TERM

if [ ! -r "$KBUILD_OUTPUT/.config" ]; then
	echo "missing configured kernel build: $KBUILD_OUTPUT" >&2
	exit 4
fi

cat >"$TMP/Makefile" <<'EOF'
obj-m += hdn_ksym_api_positive.o
obj-m += hdn_ksym_api_negative.o
EOF

cat >"$TMP/hdn_ksym_api_positive.c" <<'EOF'
#include <linux/kallsyms-lookup.h>

unsigned long hdn_ksym_api_positive(void);

unsigned long hdn_ksym_api_positive(void)
{
	return kallsyms_lookup_name("_stext");
}
EOF

cat >"$TMP/hdn_ksym_api_negative.c" <<'EOF'
#include <linux/kallsyms.h>

unsigned long hdn_ksym_api_negative(void);

unsigned long hdn_ksym_api_negative(void)
{
	return kallsyms_lookup_name("_stext");
}
EOF

echo "TAP version 13"
echo "1..3"

if make -s -C "$ROOT" O="$KBUILD_OUTPUT" M="$TMP" \
	hdn_ksym_api_positive.o >"$TMP/positive.log" 2>&1; then
	echo "ok 1 raw lookup is declared through kallsyms-lookup.h"
else
	echo "not ok 1 raw lookup is declared through kallsyms-lookup.h"
	cat "$TMP/positive.log"
	exit 1
fi

if make -s -C "$ROOT" O="$KBUILD_OUTPUT" M="$TMP" \
	hdn_ksym_api_negative.o >"$TMP/negative.log" 2>&1; then
	echo "not ok 2 kallsyms.h withholds raw lookup declarations"
	exit 1
fi

if grep -q 'kallsyms_lookup_name' "$TMP/negative.log" &&
	grep -Eq 'implicit declaration|undeclared function' "$TMP/negative.log"; then
	echo "ok 2 kallsyms.h withholds raw lookup declarations"
else
	echo "not ok 2 kallsyms.h withholds raw lookup declarations"
	cat "$TMP/negative.log"
	exit 1
fi

grep -RIlE --include='*.c' --include='*.h' --exclude-dir=tools \
	'(^|[^[:alnum:]_])(kallsyms_sym_address|kallsyms_on_each_symbol|kallsyms_on_each_match_symbol|kallsyms_lookup_name|kallsyms_lookup_size_offset|kallsyms_lookup|lookup_symbol_name)[[:space:]]*\(' \
	"$ROOT" |
while IFS= read -r source; do
	if [ "$source" = "$ROOT/include/linux/kallsyms-lookup.h" ]; then
		continue
	fi
	if ! grep -Fq '#include <linux/kallsyms-lookup.h>' "$source"; then
		printf '%s\n' "$source"
	fi
done >"$TMP/missing-internal-include"

if [ -s "$TMP/missing-internal-include" ]; then
	echo "not ok 3 raw kallsyms consumers opt into the internal header"
	cat "$TMP/missing-internal-include"
	exit 1
fi

echo "ok 3 raw kallsyms consumers opt into the internal header"
