// SPDX-License-Identifier: GPL-2.0-only
// Reject unchecked conditional ownership acquisition, including HDN wrappers.
// Options: --include-headers --very-quiet
virtual report

@unchecked@
identifier op =~ "^(refcount_(inc|add)_not_zero(_acquire)?|req_ref_inc_not_zero|atomic(_long|64)?_inc_not_zero)$";
position p;
@@
op@p(...);

@script:python depends on report@
op << unchecked.op;
p << unchecked.p;
@@
coccilib.report.print_report(p[0], "ERROR: ignored checked reference acquisition from " + str(op))
