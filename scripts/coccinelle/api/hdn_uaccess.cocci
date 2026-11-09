// SPDX-License-Identifier: GPL-2.0-only
// Report source-level address-space removal; each use needs semantic review.
virtual report
virtual fixture
virtual hdn_uderef_analysis

@cast depends on fixture ||
	(!(file in "tools/testing/selftests/hardening/hdn_uaccess_bad_source.c") &&
	 (hdn_uderef_analysis || !(file in "security/hardening/uderef_test.c"))) expression@
attribute name __user;
type T =~ "__user", U !~ "__user";
idexpression T p;
position loc;
@@
 (U@loc *)p

@script:python depends on report@
loc << cast.loc;
@@
coccilib.report.print_report(loc[0], "HDN_UDEREF: cast removes __user; review access-window and address validation")

@direct depends on fixture ||
	(!(file in "tools/testing/selftests/hardening/hdn_uaccess_bad_source.c") &&
	 (hdn_uderef_analysis || !(file in "security/hardening/uderef_test.c"))) expression@
attribute name __user;
type T =~ "__user";
idexpression T p;
position loc;
@@
 *p@loc

@script:python depends on report@
loc << direct.loc;
@@
coccilib.report.print_report(loc[0], "HDN_UDEREF: user dereference candidate; require an approved uaccess primitive")

@array depends on fixture ||
	(!(file in "tools/testing/selftests/hardening/hdn_uaccess_bad_source.c") &&
	 (hdn_uderef_analysis || !(file in "security/hardening/uderef_test.c"))) expression@
attribute name __user;
type T =~ "__user";
idexpression T p;
expression index;
position loc;
@@
p@loc[index]

@script:python depends on report@
loc << array.loc;
@@
coccilib.report.print_report(loc[0], "HDN_UDEREF: user array dereference candidate; require an approved uaccess primitive")

@member depends on fixture ||
	(!(file in "tools/testing/selftests/hardening/hdn_uaccess_bad_source.c") &&
	 (hdn_uderef_analysis || !(file in "security/hardening/uderef_test.c"))) expression@
attribute name __user;
type T =~ "__user";
idexpression T p;
identifier member_name;
position loc;
@@
p@loc->member_name

@script:python depends on report@
loc << member.loc;
@@
coccilib.report.print_report(loc[0], "HDN_UDEREF: user member dereference candidate; require an approved uaccess primitive")
