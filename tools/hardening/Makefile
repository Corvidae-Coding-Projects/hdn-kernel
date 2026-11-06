CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
CPPFLAGS += -D__EXPORTED_HEADERS__ -I../../include/uapi

PREFIX ?= /usr
exec_prefix ?= $(PREFIX)
libexecdir ?= $(exec_prefix)/libexec
sysconfdir ?= /etc
systemdunitdir ?= $(PREFIX)/lib/systemd/system
aptconfdir ?= $(sysconfdir)/apt/apt.conf.d
libalpmhookdir ?= $(PREFIX)/share/libalpm/hooks
dnfposttransdir ?= $(sysconfdir)/dnf/plugins/post-transaction-actions.d
dnf5actionsdir ?= $(sysconfdir)/dnf/libdnf5-plugins/actions.d
polkitactionsdir ?= $(PREFIX)/share/polkit-1/actions
applicationsdir ?= $(PREFIX)/share/applications
tmpfilesdir ?= $(PREFIX)/lib/tmpfiles.d

HDN_PROGRAMS := \
	hdn-compat-abi \
	hdn-hardware-facts \
	hdn-policy \
	hdn-rofs-apply \
	hdn-rofs-transaction \
	hdn-admin-broker \
	hdn-approval-token \
	hdn-system-transaction \
	hdn-recovery-action \
	hdn-recovery-describe \
	hdn-recovery-session \
	hdn-recovery-portal \
	hdn-recovery-panel \
	hdn-recovery-ui \
	hdn-recovery-prompt \
	hdn-prompt-dispatch \
	hdn-prompt-describe \
	hdn-prompt-session \
	hdn-prompt-portal \
	hdn-desktop-action \
	hdn-desktop-daemon \
	hdn-control-center \
	hdn-settings-panel \
	hdn-settings-ui \
	hdn-auth-prompt \
	hdn-image-seal \
	hdn-package-worker \
	hdn-package-hook \
	hdn-support-bundle \
	hdn-event-decode \
	hdn-status \
	hdn-policy-learn \
	hdn-policy-merge \
	hdn-policy-workflow \
	hdn-policy-daemon

HDN_CONFIGS := \
	admin-broker.conf \
	readonly-mounts.conf \
	image-seals.conf \
	system-transactions.conf \
	package-hooks.conf \
	recovery-actions.conf \
	recovery-metadata.conf \
	recovery-session.conf \
	recovery-portal.conf \
	recovery-panel.conf \
	recovery-ui.conf \
	prompt-actions.conf \
	prompt-metadata.conf \
	prompt-session.conf \
	prompt-portal.conf \
	desktop-actions.conf \
	desktop-daemon.conf \
	settings-panel.conf \
	settings-ui.conf \
	support-bundle.conf \
	policy-workflows.conf \
	policy-daemon.conf

all: $(HDN_PROGRAMS)

hdn-compat-abi: hdn-compat-abi.c ../../include/uapi/linux/hardening.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-hardware-facts: hdn-hardware-facts.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-policy: hdn-policy.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-rofs-apply: hdn-rofs-apply.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-rofs-transaction: hdn-rofs-transaction.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-admin-broker: hdn-admin-broker.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-approval-token: hdn-approval-token.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-system-transaction: hdn-system-transaction.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-recovery-action: hdn-recovery-action.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-recovery-describe: hdn-recovery-describe.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-recovery-session: hdn-recovery-session.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-recovery-portal: hdn-recovery-portal.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-recovery-panel: hdn-recovery-panel.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-recovery-ui: hdn-recovery-ui.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-recovery-prompt: hdn-recovery-prompt.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-prompt-dispatch: hdn-prompt-dispatch.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-prompt-describe: hdn-prompt-describe.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-prompt-session: hdn-prompt-session.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-prompt-portal: hdn-prompt-portal.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-desktop-action: hdn-desktop-action.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-desktop-daemon: hdn-desktop-daemon.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-control-center: hdn-control-center.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-settings-panel: hdn-settings-panel.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-settings-ui: hdn-settings-ui.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-auth-prompt: hdn-auth-prompt.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-image-seal: hdn-image-seal.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-package-worker: hdn-package-worker.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-package-hook: hdn-package-hook.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-support-bundle: hdn-support-bundle.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-event-decode: hdn-event-decode.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-status: hdn-status.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-policy-learn: hdn-policy-learn.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-policy-merge: hdn-policy-merge.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-policy-workflow: hdn-policy-workflow.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

hdn-policy-daemon: hdn-policy-daemon.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

clean:
	$(RM) $(HDN_PROGRAMS)

install: all
	install -d -m 0755 $(DESTDIR)$(libexecdir)
	install -m 0755 $(HDN_PROGRAMS) $(DESTDIR)$(libexecdir)
	install -m 0755 hdn-compat hdn-stack-vmcore $(DESTDIR)$(libexecdir)
	install -d -m 0755 $(DESTDIR)$(sysconfdir)/hdn
	install -m 0644 $(HDN_CONFIGS) $(DESTDIR)$(sysconfdir)/hdn
	install -D -m 0644 package-manager-hooks/apt/99-hdn-package-update \
		$(DESTDIR)$(aptconfdir)/99-hdn-package-update
	install -D -m 0644 package-manager-hooks/pacman/99-hdn-package-update.hook \
		$(DESTDIR)$(libalpmhookdir)/99-hdn-package-update.hook
	install -D -m 0644 package-manager-hooks/dnf/99-hdn-package-update.action \
		$(DESTDIR)$(dnfposttransdir)/99-hdn-package-update.action
	install -D -m 0644 package-manager-hooks/dnf5/99-hdn-package-update.actions \
		$(DESTDIR)$(dnf5actionsdir)/99-hdn-package-update.actions
	install -D -m 0644 package-manager-hooks/systemd/hdn-image-seal.service \
		$(DESTDIR)$(systemdunitdir)/hdn-image-seal.service
	install -D -m 0644 hdn-audit.service \
		$(DESTDIR)$(systemdunitdir)/hdn-audit.service
	install -D -m 0644 org.hdn.system.policy \
		$(DESTDIR)$(polkitactionsdir)/org.hdn.system.policy
	install -D -m 0644 org.hdn.Settings.desktop \
		$(DESTDIR)$(applicationsdir)/org.hdn.Settings.desktop
	install -D -m 0644 hdn-approvals.tmpfiles \
		$(DESTDIR)$(tmpfilesdir)/hdn-approvals.conf

check-admin-ux: all
	sh ./test-admin-ux.sh

check-event-follow: hdn-event-decode
	sh ./test-event-follow.sh

check: check-admin-ux check-event-follow

.PHONY: all clean install check check-admin-ux check-event-follow
