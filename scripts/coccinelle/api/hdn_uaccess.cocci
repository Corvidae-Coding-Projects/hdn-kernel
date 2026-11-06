// SPDX-License-Identifier: GPL-2.0-only
// Report source-level address-space removal; each use needs semantic review.
virtual report

@cast@
type T, U;
T __user *p;
position loc;
@@
(U *)p@loc

@script:python depends on report@
loc << cast.loc;
@@
coccilib.report.print_report(loc[0], "HDN_UDEREF: cast removes __user; review access-window and address validation")

@direct@
type T;
T __user *p;
position loc;
@@
*p@loc

@script:python depends on report@
loc << direct.loc;
@@
coccilib.report.print_report(loc[0], "HDN_UDEREF: user dereference candidate; require an approved uaccess primitive")

@array@
type T;
T __user *p;
expression index;
position loc;
@@
p@loc[index]

@script:python depends on report@
loc << array.loc;
@@
coccilib.report.print_report(loc[0], "HDN_UDEREF: user array dereference candidate; require an approved uaccess primitive")

@member@
type T;
T __user *p;
identifier field;
position loc;
@@
p@loc->field

@script:python depends on report@
loc << member.loc;
@@
coccilib.report.print_report(loc[0], "HDN_UDEREF: user member dereference candidate; require an approved uaccess primitive")
