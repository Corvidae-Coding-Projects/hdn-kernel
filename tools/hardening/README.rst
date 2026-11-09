.. SPDX-License-Identifier: GPL-2.0-only

Linux Hardening Policy Tools
============================

``hdn-policy`` compiles a small text policy into the binary profile table
staged through ``securityfs/hardening/policy`` and published by
``securityfs/hardening/commit``.

``hdn-rofs-apply`` is the product image helper for making already-mounted
system paths read-only after policy commit. It accepts mountpoint arguments or
``-f readonly-mounts.conf``. For individual mountpoints it uses a read-only
remount; with ``--recursive`` it uses ``mount_setattr(MOUNT_ATTR_RDONLY)``.
List files passed through ``-f`` must be regular, root-owned, not group/world
writable, and not symlinks. List entries can be bare absolute paths for the
legacy required behavior, ``required PATH`` for a must-seal mount, or
``optional PATH`` for a mount that is sealed only when it is present as a
mounted filesystem. ``bind PATH`` creates a self-bind mount when the path is
not already a mountpoint and then requires the resulting mount to seal. This
supports conventional unified-root installations without accidentally
remounting the whole root filesystem. Optional entries let one product config
cover boot, EFI, and app-store mounts without failing images that do not split
those paths out.

``hdn-rofs-transaction`` is the package/update helper for temporarily relaxing
a product read-only mount, running one worker command, and resealing the mount
read-only before returning. Read-only resealing retries bounded transient
``EBUSY`` failures after syncing, while still returning failure if a writer
does not release the protected filesystem. The helper blocks ordinary
termination signals while the writable window is open, stops and reaps the
complete worker process group on cancellation or direct-worker completion,
acts as a child subreaper so orphaned group members remain under guardian
control even across HDN profile transitions, and restores signal delivery
only after the mount has been resealed. If a
superblock-level read-only state requires the legacy remount fallback, the
helper preserves the mount's existing ``nosuid``, ``nodev``, ``noexec``, and
other observable VFS restrictions and verifies the requested final state.

``hdn-package-worker`` composes that primitive across the fixed boot paths used
by system updates. After the broker opens ``/usr``, the worker inspects
``/proc/self/mountinfo`` and opens read-only ``/boot`` and ``/boot/efi`` mounts
in order before starting DNF5. Nested transaction parents reseal EFI, boot, and
then ``/usr`` in reverse order on either success or worker failure. Paths and
operations remain compiled or root-configured product choices rather than
caller-provided arguments. The DNF worker stops PackageKit and the DNF daemon
before and after its transaction so background metadata writers cannot retain
the RPM database across the reseal boundary.

The shipped broker config requires intent-bound approval tokens under
``/run/hdn/approvals``. This matches the default prompt dispatcher and keeps
the graphical authorization path usable without permitting tokenless direct
broker calls.

``hdn-image-seal`` is the named image/first-boot sealing facade. Installers,
first-boot services, and image updaters call a product operation name such as
``default`` instead of constructing raw broker command lines. The helper reads
root-owned ``/etc/hdn/image-seals.conf`` entries of the form
``seal NAME policy-commit SIGNED_POLICY`` or
``seal NAME rofs-apply READONLY_LIST`` and runs matching steps through
``hdn-admin-broker`` in file order. The config must be a regular root-owned
file that is not group/world writable. ``--dry-run`` preflights the same
approved broker steps without committing policy or changing mount state.
The shipped ``default`` operation only reseals protected mounts and is safe to
use at every boot and after package transactions. The ``provision`` operation
commits the signed default policy before sealing mounts for installers or image
builders that own initial policy activation.

``hdn-system-transaction`` is the named package/image updater facade. Package
tools call a product operation name such as ``package-update`` or
``package-repair`` instead of
supplying raw mountpoints or worker paths. The helper reads root-owned
``/etc/hdn/system-transactions.conf`` entries of the form
``transaction NAME MOUNTPOINT WORKER [ARG...]`` and execs
``hdn-admin-broker rofs-transaction`` for the matching approved operation.
``--dry-run`` follows the same approved broker route without running the
worker or changing the protected mount. The config must be a regular
root-owned file that is not group/world writable.

``hdn-package-hook`` is the package-manager hook facade above named system
transactions and image seals. Package managers and image builders call stable
hook names such as ``package-update`` or ``image-seal-default`` instead of
knowing which backend helper implements the operation. The helper reads
root-owned ``/etc/hdn/package-hooks.conf`` entries of the form
``hook NAME system-transaction TRANSACTION`` or ``hook NAME image-seal SEAL``
and dispatches the matching backend without invoking a shell. The config must
be a regular root-owned file that is not group/world writable. Example product
hook snippets for APT/dpkg, pacman/libalpm, DNF 4, DNF5/libdnf5, and systemd
image sealing live under ``tools/hardening/package-manager-hooks/``.
``--dry-run`` is passed to the approved backend so package-manager and
image-updater integration can preflight the route without applying a
transaction or image seal.

``hdn-recovery-action`` is the named recovery facade for repair and rollback
UI. Recovery flows call a product-approved action name such as
``policy-rollback`` instead of writing ``securityfs`` directly or exposing raw
broker commands. The helper reads root-owned ``/etc/hdn/recovery-actions.conf``
entries of the form ``action NAME policy-rollback`` or
``action NAME system-transaction TRANSACTION`` and dispatches the matching
backend. The config must be a regular root-owned file that is not group/world
writable. ``--dry-run`` preflights the approved rollback or repair backend
without rolling policy back or changing protected mounts.

``hdn-recovery-describe`` is the read-only recovery metadata facade for
recovery UI. It maps product recovery actions such as ``policy-rollback`` or
``package-repair`` to stable ``key=value`` metadata: title, message,
consequence, and optional risk. The helper reads root-owned
``/etc/hdn/recovery-metadata.conf`` entries of the form
``recovery NAME FIELD VALUE`` and rejects unknown actions, incomplete metadata,
or unsafe configs. It does not run recovery actions; execution remains behind
``hdn-recovery-action``.

``hdn-recovery-session`` is the root-side recovery session facade for recovery
UI. It reads recovery metadata through ``hdn-recovery-describe``, passes that
metadata to a product confirmation/authentication helper over stdin, and calls
``hdn-recovery-action`` only if confirmation succeeds. Its root-owned
``/etc/hdn/recovery-session.conf`` selects the describe helper, confirmation
helper, and action helper with absolute paths. The helper never invokes a shell
and rejects unsafe configs, failed confirmation, or unknown actions before
repair work can run. After confirmation, the session first preflights the
approved action and then executes it inside the same authorized root process,
so a real recovery request has one authorization boundary. ``--dry-run``
validates metadata and runs only that preflight, skipping confirmation and
protected-state mutation.
The root-only ``--authorized`` mode also skips the fallback confirmation after
an exact-executable PolicyKit authentication; unprivileged callers cannot claim
that path directly.

``hdn-recovery-portal`` is the product recovery UI entrypoint above
``hdn-recovery-session``. Recovery panels and rescue shells call a branded
action such as ``rollback-policy`` or ``repair-system`` from root-owned
``/etc/hdn/recovery-portal.conf`` instead of knowing the recovery-session
helper path or backend action names. The config maps ``action
RECOVERY_UI_ACTION RECOVERY_SESSION_ACTION`` and may set
``session-helper PATH``. Unknown recovery UI actions, unsafe configs, and
shell-style command construction fail closed. ``--dry-run`` follows the same
branded action mapping without showing confirmation UI or changing protected
state. ``--authorized`` is accepted only as root and propagates the completed
PolicyKit authorization to the recovery session.

``hdn-recovery-panel`` is the graphical-recovery-facing command above
``hdn-recovery-describe`` and ``hdn-recovery-portal``. Product UI calls
``describe RECOVERY_ACTION`` for recovery text, ``action RECOVERY_ACTION`` for
a root-owned recovery action, or the shortcuts ``repair`` and ``rollback`` for
normal repair and rollback operations. Its root-owned
``/etc/hdn/recovery-panel.conf`` maps ``action RECOVERY_ACTION
DESCRIBE_ACTION PORTAL_ACTION`` entries and may set ``describe-helper PATH``
and ``portal-helper PATH``. Unknown panel actions, unsafe configs, unsafe
action names, and shell-style command construction fail closed. ``--dry-run``
validates the same recovery portal route without confirmation UI or
protected-state mutation. Real actions are forwarded once; the recovery
session performs preflight and execution behind the same authorization. The
packaged PolicyKit recovery action authenticates this exact panel executable
once; root-only ``--authorized`` propagation prevents a second confirmation
dialog.

``hdn-recovery-ui`` is the dependency-light graphical recovery frontend above
``hdn-recovery-panel``. Product recovery shells can run one command that reads
root-owned ``/etc/hdn/recovery-ui.conf``, obtains metadata for each approved
action through ``hdn-recovery-panel describe``, displays a repair/rollback
selection through ``zenity`` or ``kdialog`` when a desktop session is
available, and dispatches only the selected approved action back through
``hdn-recovery-panel``. The config maps allowed ``action RECOVERY_ACTION``
entries and may set ``panel-helper PATH``, ``title TEXT``, and ``message
TEXT``. Unknown actions, unsafe configs, unsafe helper paths, missing display
sessions, invalid metadata, and shell-style command construction fail closed.
``--dry-run`` validates the selected panel route without confirmation UI or
protected-state mutation. Harnesses and product tests can use
``--test-choice RECOVERY_ACTION`` or ``--test-cancel`` for deterministic
selection without a graphical session.

``hdn-recovery-prompt`` is the dependency-light recovery confirmation frontend
for that session contract. It reads ``HDN_RECOVERY_METADATA_V1`` from stdin,
verifies that the metadata action matches the requested action, and shows a
graphical confirmation dialog through ``zenity``, ``kdialog``, or
``xmessage`` when a desktop session is available. It exits nonzero if no
graphical session is available, if metadata is malformed, or if the user
cancels, so recovery and repair work remains fail-closed. The
``--test-approve`` and ``--test-deny`` modes are intended for root-owned
harness or product configs that need deterministic session tests.

``hdn-approval-token`` is the root-side token issuer for product prompt
daemons. After the GUI/authentication side approves a typed operation, this
helper creates a root-owned 0600 token under a root-only approval directory,
adds a short ``CLOCK_MONOTONIC`` expiry, and prints the token path for the
broker call. It accepts only the broker's known typed intents.

``hdn-prompt-dispatch`` is the root-side post-auth dispatch facade for product
prompt daemons. After the GUI/authentication side approves a named action such
as ``package-update``, this helper reads root-owned
``/etc/hdn/prompt-actions.conf`` entries of the form
``action NAME INTENT [ARG...]``, creates a short-lived approval token, and
execs ``hdn-admin-broker --approval-token`` with the matching typed intent.
``--dry-run`` creates and then removes a short-lived approval token while
asking the broker to validate the same typed route without running it. The
config must be a regular root-owned file that is not group/world writable. The
broker allowlist used with this helper must approve the token directory with
``approval-token-dir``; product builds should also enable
``require-approval-token`` for prompt-mediated admin actions. The broker's
``seal-readonly`` intent is intentionally token-exempt: it accepts the same
root-owned mount allowlists as ``rofs-apply`` but can only reduce mount
permissions, allowing early boot to close the protected image before an
interactive authorization service exists.

``hdn-prompt-describe`` is the read-only prompt metadata facade for desktop
authentication UI. Before showing a UAC-style approval prompt, the desktop
daemon asks for a product action such as ``package-update`` and receives stable
``key=value`` metadata: title, message, consequence, and optional risk. The
helper reads root-owned ``/etc/hdn/prompt-metadata.conf`` entries of the form
``prompt NAME FIELD VALUE`` and refuses unknown actions, incomplete metadata,
or unsafe configs. It does not issue approval tokens or dispatch privileged
operations; approval still flows through ``hdn-prompt-dispatch``.

``hdn-prompt-session`` is the root-side prompt session facade for a desktop
authenticator. It reads prompt metadata through ``hdn-prompt-describe``, passes
that metadata to a product authenticator over stdin, and calls
``hdn-prompt-dispatch`` only if authentication succeeds. Its root-owned
``/etc/hdn/prompt-session.conf`` selects the describe helper, authenticator,
and dispatch helper with absolute paths. The helper never invokes a shell and
rejects unsafe configs, failed authentication, or unknown actions before
privileged dispatch can run. ``--dry-run`` still validates metadata and the
dispatch route, but skips authentication and privileged mutation. After a
successful authentication, a real request runs the dispatch preflight and the
real dispatch inside the same authorized root process. This preserves broker
validation while requiring only one PolicyKit prompt.

``hdn-prompt-portal`` is the product desktop entrypoint above
``hdn-prompt-session``. Desktop shells, settings panels, and update notifiers
call a branded action such as ``package-update`` from root-owned
``/etc/hdn/prompt-portal.conf`` instead of knowing the prompt-session helper
path or backend action names. The config maps ``action DESKTOP_ACTION
PROMPT_SESSION_ACTION`` and may set ``session-helper PATH`` and
``elevation-helper PATH``. A normal desktop caller crosses the configured
PolicyKit boundary before prompt-session receives root-only ``--authorized``;
direct unprivileged attempts to use that mode fail closed. Root callers keep
the explicit authenticator path for recovery and supervised service use.
``--dry-run`` follows the same mapping without changing protected state.

``hdn-desktop-action`` is the stable UI-facing command above
``hdn-prompt-portal``. Product UI code calls namespaced verbs such as
``updates.install`` from root-owned ``/etc/hdn/desktop-actions.conf``. The
config maps ``action DESKTOP_ACTION PROMPT_PORTAL_ACTION`` and may set
``portal-helper PATH``. This keeps desktop shells and settings panels from
depending on prompt portal action names or lower-level helper paths.
``--dry-run`` preflights the same mapped verb without prompting or changing
protected state.

``hdn-desktop-daemon`` is the root-side desktop action service above
``hdn-desktop-action``. It can run a single approved verb or stay attached to a
supervised frontend through ``--stdio``. Its root-owned
``/etc/hdn/desktop-daemon.conf`` allowlists ``allow-action DESKTOP_ACTION``
entries and may set ``desktop-action-helper PATH``. Unknown verbs, unsafe
configs, unsafe action names, and shell-style command construction fail closed.
One-shot ``--dry-run ACTION`` and stdio ``dry-run ACTION`` preflight an
approved verb without prompting or changing protected state.

``hdn-control-center`` is the stable product-facing command for settings panels
and desktop shells. It provides a single branded entry point for product status
and UI actions: ``status`` execs ``hdn-status`` with caller-supplied status
arguments, ``action DESKTOP_ACTION`` execs ``hdn-desktop-daemon`` for a
root-owned allowlisted verb, and ``policy COMMAND WORKFLOW`` execs
``hdn-policy-daemon`` for named policy learning, candidate generation, and
policy compilation or signed-policy commit. ``--dry-run`` is accepted for
``action DESKTOP_ACTION`` and ``policy commit WORKFLOW`` so settings panels can
preflight the approved action or commit path without showing auth UI, changing
protected mounts, or installing a new policy. ``--stdio`` keeps the
product-facing frontend attached to a supervised backend; accepted requests are
``status``, ``action DESKTOP_ACTION``, ``dry-run action DESKTOP_ACTION``,
``policy COMMAND WORKFLOW``, and ``dry-run policy commit WORKFLOW``. Unknown
stdio actions fail through the same allowlisted desktop-daemon path as
one-shot actions.
Configured helper paths must be absolute and cannot contain ``.`` or ``..``
path components, and action/workflow names use the same safe verb syntax as the
backend daemons.

``hdn-settings-panel`` is the graphical-settings-facing command above
``hdn-control-center``. Product UI calls ``status`` for product health,
``action SETTINGS_ACTION`` for a root-owned settings action, or the shortcut
``update`` for the normal package/update operation. Its root-owned
``/etc/hdn/settings-panel.conf`` maps ``action SETTINGS_ACTION
CONTROL_CENTER_ACTION`` entries and may set ``control-center-helper PATH``.
Unknown settings actions, unsafe configs, unsafe action names, and shell-style
command construction fail closed. ``--dry-run`` validates the same
control-center action route without auth UI or protected-state mutation. Real
actions are forwarded once through the desktop stack; the root prompt session
owns the preflight and execution after authorization.

``hdn-settings-ui`` is the dependency-light graphical settings frontend above
``hdn-settings-panel``. Product config owns the window title, message,
settings-panel helper path, and allowed ``action SETTINGS_ACTION LABEL``
manifest. The UI selects through ``zenity`` or ``kdialog`` when a graphical
session exists, rejects unapproved selections, and fails closed without a
display. Deterministic ``--test-choice`` and ``--test-cancel`` modes let
product harnesses prove the same route without a desktop session. Real actions
are dispatched once to the settings panel, avoiding duplicate authentication;
explicit ``--dry-run`` requests still validate the complete approved route.

``hdn-auth-prompt`` is the dependency-light desktop authenticator for that
session contract. It reads ``HDN_PROMPT_METADATA_V1`` from stdin, verifies that
the metadata action matches the requested action, and shows a graphical
approval dialog through ``zenity``, ``kdialog``, or ``xmessage`` when a desktop
session is available. It exits nonzero if no graphical session is available, if
metadata is malformed, or if the user cancels, so privileged work remains
fail-closed. The ``--test-approve`` and ``--test-deny`` modes are intended for
root-owned harness or product configs that need deterministic session tests.
The installed ``org.hdn.system.modify`` PolicyKit action is the normal GNOME
authentication surface; ``hdn-auth-prompt`` remains the dependency-light
fallback for an already-privileged recovery or product daemon.

``hdn-event-decode`` turns ``securityfs/hardening/events`` records into stable
UAPI names for product UI, logging, and harness consumers. It can also assert
decoded expectations such as ``--expect reason=USER_WX_MAPPING`` and
``--expect action=DENY_AUDIT`` without depending on raw numeric IDs in
scripts. Common packed ``object`` payloads are also decoded for UI/log
consumers, including exec argument counts, severe-signal and coredump signal
numbers, resource IDs and resource-pressure values, time-change operations, USB
bus/port context, and socket family/type/protocol or endpoint context.
With ``--follow`` it polls the bounded securityfs ring, tracks the greatest
sequence already emitted, and prints each new event once. The shipped
``hdn-audit.service`` runs that mode as a tightly sandboxed root reader and
sends the decoded records to the system journal under ``hdn-audit``, closing
the persistence gap between the finite kernel ring and normal log retention.

``hdn-status`` turns ``securityfs/hardening/status`` into a stable
product-facing ``key=value`` contract for settings panels, desktop daemons,
support bundles, and recovery UI. It summarizes policy readiness, phase,
profile/rule counts, mitigation counts, and audit-flood state without requiring
UI code to parse raw kernel status labels directly. It also decodes
``audit_flood_last_action``, ``audit_flood_last_authority``,
``audit_flood_last_transition``, and ``audit_flood_last_reason`` to UAPI names
and supports ``--expect KEY=VALUE`` for harnesses. The optional ``--compat``
view adds ``compat_*`` feature-family keys derived from sealed HDN status bits
so installers, support tools, and settings panels can test familiar hardening
families without depending on raw kernel status labels or lower-level policy
internals. Those families include coarse memory-initialization, allocator,
compiler, stack, and kernel W^X/page-table hardening checks in addition to the
policy-controlled proc, symbol, BPF, module, audit, and device surfaces.

``hdn-support-bundle`` is the read-only product support facade above
``hdn-status`` and ``hdn-event-decode``. It reads a root-owned
``support-bundle.conf``, refuses writable configs, validates absolute helper and
event paths, and prints bounded ``status``, ``compat``, and optional decoded
event sections without invoking a shell or exposing raw securityfs paths to
normal support UI.

``hdn-policy-learn`` consumes the same event records and emits a reviewable
policy fragment for settings UI, support tools, and developer-mode workflows.
Denied profile-authority events become de-duplicated ``allow PROFILE
AUTHORITY...`` suggestions, selected compatibility memory denials become
``mem PROFILE FLAG...`` suggestions, and high-risk identity or invariant
failures such as simultaneous W+X, untrusted executable paths, module identity,
firmware identity, policy administration, credential widening, and broad TPE
bypass become ``# review`` comments instead of automatic broad grants.

``hdn-policy-merge`` turns reviewed learner output into a candidate text
policy. It copies a base ``.policy`` file, consumes only ``allow`` and ``mem``
lines from the reviewed fragment, refuses suggestions for profiles that are not
defined in the base policy, de-duplicates grants that already exist, and
appends a clearly marked ``HDN_POLICY_MERGE_V1`` block. It does not compile,
sign, or commit the result; those remain separate review and policy-transaction
steps.

``hdn-policy-workflow`` is the named admin facade above learner, merge,
compiler, and broker helpers. Settings panels, support tools, and
developer-mode policy UI call a workflow name such as ``default`` instead of
supplying raw event-log, base policy, fragment, candidate, binary output, or
signed policy paths. The helper reads root-owned
``/etc/hdn/policy-workflows.conf`` entries of the form ``workflow NAME
BASE_POLICY EVENT_LOG SUGGESTIONS CANDIDATE_POLICY [BINARY_POLICY
[SIGNED_POLICY]]`` and runs ``learn NAME``, ``candidate NAME``, ``compile
NAME``, or ``commit NAME`` through the configured helper paths. ``compile``
writes an unsigned candidate payload; signing remains an external product
policy step; ``commit`` delegates the configured signed policy path to
``hdn-admin-broker policy-commit``. The config must be a regular root-owned
file that is not group/world writable, all paths must be absolute without
``.`` or ``..`` components, and input/output path reuse is rejected.

``hdn-policy-daemon`` is the root-side policy workflow service above
``hdn-policy-workflow``. Product UI and support tools submit only ``learn``,
``candidate``, ``compile``, or ``commit`` plus a workflow name; the daemon
allowlists workflow names through root-owned ``/etc/hdn/policy-daemon.conf``
and then delegates to the workflow helper. One-shot ``--dry-run commit
WORKFLOW`` reaches the workflow helper's broker preflight path without
installing the signed policy. The daemon also supports a simple ``--stdio``
mode for frontends that keep a privileged backend process open; stdio requests
are ``COMMAND WORKFLOW`` or ``dry-run commit WORKFLOW``.

``hdn-admin-broker`` is the privileged backend facade for product UI prompts.
It accepts typed intents instead of raw shell commands: ``rofs-apply``,
``rofs-transaction``, ``policy-commit``, and ``policy-rollback``. The ROFS
intents exec the narrow helpers directly, require absolute mount and worker
paths, and can be compiled with product-specific helper paths. The broker also
loads ``/etc/hdn/admin-broker.conf`` by default and fails closed unless the
requested mountpoint, worker, read-only mount list, policy path, or rollback
intent is product-approved there. The allowlist must be a regular root-owned
file that is not group/world writable. Product builds can also require a
desktop prompt handoff token: ``require-approval-token`` makes the broker
refuse every typed intent unless the caller supplies ``--approval-token PATH``
under an approved ``approval-token-dir``. Tokens must be root-owned regular
files, not group/world accessible, not symlinks, one-link, and must contain
``HDN_APPROVAL_V1``, ``intent=<typed-intent>``, and
``expires-monotonic-ms=<deadline>``. Non-dry-run use consumes the token before
dispatching the privileged helper.

The helper ``Makefile`` has an ``install`` target for distro packaging. It
installs the helper binaries under ``/usr/libexec``, root-owned config
templates under ``/etc/hdn``, and the shipped APT/dpkg, pacman/libalpm,
DNF 4, DNF5/libdnf5, and systemd hook snippets under their native integration
directories. Packagers can stage the layout with ``DESTDIR=`` and can override
``libexecdir``, ``sysconfdir``, ``systemdunitdir``, and the package-manager
hook directory variables. The same target installs the PolicyKit action, HDN
settings desktop entry, and systemd-tmpfiles rule for the root-only approval
directory.

Example::

  make -C tools/hardening
  sudo make -C tools/hardening check
  tools/hardening/hdn-policy tools/hardening/default.policy default.hdn.unsigned
  scripts/sign-file sha512 certs/signing_key.pem certs/signing_key.x509 \
    default.hdn.unsigned default.hdn
  sudo cp default.hdn /sys/kernel/security/hardening/policy
  echo 1 | sudo tee /sys/kernel/security/hardening/commit
  sudo make -C tools/hardening install
  sudo tools/hardening/hdn-rofs-apply -f /etc/hdn/readonly-mounts.conf
  sudo tools/hardening/hdn-admin-broker rofs-apply -f /etc/hdn/readonly-mounts.conf
  sudo tools/hardening/hdn-image-seal --dry-run default
  sudo tools/hardening/hdn-image-seal default
  sudo tools/hardening/hdn-rofs-transaction /usr -- /usr/libexec/hdn-package-worker
  sudo tools/hardening/hdn-admin-broker rofs-transaction /usr -- /usr/libexec/hdn-package-worker
  sudo tools/hardening/hdn-system-transaction --dry-run package-update
  sudo tools/hardening/hdn-system-transaction package-update
  sudo tools/hardening/hdn-package-hook --dry-run package-update
  sudo tools/hardening/hdn-package-hook package-update
  sudo tools/hardening/hdn-recovery-describe policy-rollback
  sudo tools/hardening/hdn-recovery-action --dry-run package-repair
  sudo tools/hardening/hdn-recovery-action policy-rollback
  sudo tools/hardening/hdn-recovery-action package-repair
  sudo tools/hardening/hdn-recovery-session --dry-run package-repair
  sudo tools/hardening/hdn-recovery-session package-repair
  sudo tools/hardening/hdn-recovery-portal --dry-run repair-system
  sudo tools/hardening/hdn-recovery-portal repair-system
  sudo tools/hardening/hdn-recovery-portal rollback-policy
  sudo tools/hardening/hdn-recovery-panel describe repair-system
  sudo tools/hardening/hdn-recovery-panel --dry-run rollback
  sudo tools/hardening/hdn-recovery-panel rollback
  sudo tools/hardening/hdn-recovery-ui
  sudo tools/hardening/hdn-recovery-ui --dry-run --test-choice rollback-policy
  sudo install -d -o root -g root -m 0700 /run/hdn/approvals
  sudo tools/hardening/hdn-prompt-describe package-update
  sudo tools/hardening/hdn-prompt-session package-update
  sudo tools/hardening/hdn-prompt-portal package-update
  sudo tools/hardening/hdn-desktop-action updates.install
  sudo tools/hardening/hdn-desktop-daemon updates.install
  sudo tools/hardening/hdn-control-center action updates.install
  sudo tools/hardening/hdn-prompt-dispatch package-update
  TOKEN=$(sudo tools/hardening/hdn-approval-token --intent rofs-transaction)
  sudo tools/hardening/hdn-admin-broker --approval-token "$TOKEN" rofs-transaction /usr -- /usr/libexec/hdn-package-worker
  sudo tools/hardening/hdn-event-decode --quiet --expect reason=USER_WX_MAPPING --expect action=DENY_AUDIT
  sudo tools/hardening/hdn-status --expect available=1 --expect mitigations_sealed=1
  sudo tools/hardening/hdn-support-bundle --dry-run
  sudo tools/hardening/hdn-support-bundle --no-events
  sudo tools/hardening/hdn-control-center status --expect available=1
  sudo tools/hardening/hdn-policy-learn --input /sys/kernel/security/hardening/events
  sudo tools/hardening/hdn-policy-merge base.policy reviewed-learn.frag candidate.policy
  sudo tools/hardening/hdn-policy-workflow learn default
  sudo tools/hardening/hdn-policy-workflow candidate default
  sudo tools/hardening/hdn-policy-workflow compile default
  sudo tools/hardening/hdn-policy-workflow commit default
  sudo tools/hardening/hdn-policy-daemon learn default
  sudo tools/hardening/hdn-policy-daemon compile default
  sudo tools/hardening/hdn-policy-daemon --dry-run commit default
  sudo tools/hardening/hdn-policy-daemon commit default
  sudo tools/hardening/hdn-control-center policy compile default
  sudo tools/hardening/hdn-control-center --dry-run policy commit default
  sudo tools/hardening/hdn-control-center policy commit default
  sudo tools/hardening/hdn-control-center --dry-run action updates.install
  printf 'action updates.install\n' | sudo tools/hardening/hdn-control-center --stdio
  printf 'dry-run action updates.install\n' | sudo tools/hardening/hdn-control-center --stdio
  printf 'dry-run policy commit default\n' | sudo tools/hardening/hdn-control-center --stdio
  sudo tools/hardening/hdn-settings-panel status --expect available=1
  sudo tools/hardening/hdn-settings-panel --dry-run action updates.install
  sudo tools/hardening/hdn-settings-panel action updates.install
  sudo tools/hardening/hdn-settings-ui --dry-run --test-choice updates.install
  sudo tools/hardening/hdn-settings-ui --test-choice updates.install

An approval-token flow is intentionally generated by a product prompt daemon,
not by the user at a shell. The preferred product integration is for the desktop
frontend to call ``hdn-settings-ui`` for direct graphical settings selection,
``hdn-settings-panel`` for settings-panel-owned actions, and
``hdn-control-center`` for lower-level supervised backends. For policy
workflows, ``hdn-control-center`` submits the requested
``learn``, ``candidate``, ``compile``, or ``commit`` operation to
``hdn-policy-daemon``; commit preflights use ``--dry-run`` through the same
control-center and daemon route, including the control-center stdio backend for
supervised settings panels. For graphical settings actions, ``hdn-settings-ui``
selects an approved product verb and calls ``hdn-settings-panel``; the panel
maps that verb to a control-center action and asks ``hdn-control-center`` to
submit the stable verb to ``hdn-desktop-daemon``. The daemon allowlists the verb
and calls ``hdn-desktop-action``, the desktop action helper maps that verb to
``hdn-prompt-portal``, and the portal maps it to the root-side prompt session.
The session performs preflight and execution behind that single authorization
boundary.
Lower-level frontends can still call ``hdn-desktop-daemon`` or
``hdn-desktop-action`` directly, and lower-level daemons can still authenticate
the user and call ``hdn-prompt-dispatch`` with a named product action when they
own the session flow themselves. Recovery frontends should call
``hdn-recovery-ui`` when they want a complete graphical repair/rollback
selection flow, or ``hdn-recovery-panel`` when the product frontend owns its
own layout. The UI obtains text through the panel, and the panel maps normal
``repair`` and ``rollback`` commands to root-owned recovery metadata and portal
routes before the lower session/action/broker layers run.
``hdn-approval-token`` remains the narrow root-side issuer for daemon
integrations that need to create and pass broker tokens themselves. The token
format is simple for daemon integration::

  HDN_APPROVAL_V1
  intent=rofs-transaction
  expires-monotonic-ms=123456789

The deadline is a ``CLOCK_MONOTONIC`` millisecond value. Prompt daemons should
issue short-lived tokens only after user authentication, either indirectly
through ``hdn-prompt-dispatch`` or directly by calling ``hdn-approval-token``
or by generating the same format with equivalent safe file handling.
Prompt daemons should use ``hdn-prompt-describe`` before authentication so the
UI text comes from a root-owned product manifest rather than from raw broker
arguments. A daemon that wants the root-side backend to enforce the complete
describe/authenticate/dispatch order can call ``hdn-prompt-session`` instead
of separately invoking the describe and dispatch helpers. ``hdn-auth-prompt``
is the starter authenticator for that flow: it gives product builds a normal
desktop approval dialog while keeping tokens, broker arguments, and policy
writes behind root-owned helpers.

Testing
-------

The hardening selftest can be built with::

  make -C tools/testing/selftests/hardening

For a boot-level smoke test, build a kernel image and run the QEMU harness::

  scripts/config --file ../linux-7.0.12-build/.config -e TEST_FIRMWARE
  make O=../linux-7.0.12-build olddefconfig
  make O=../linux-7.0.12-build -j$(nproc) bzImage
  sh tools/testing/selftests/hardening/run-qemu-smoke.sh

The runner builds static ``hdn_smoke`` and ``vm_init`` binaries, packs a tiny
initramfs, boots the configured ``bzImage``, and fails unless the in-VM TAP run
reports all hardening smoke tests passing. Use ``KBUILD_OUTPUT`` or ``BZIMAGE``
to point it at a non-default kernel build directory. The QEMU firmware policy
proof uses the upstream ``test_firmware`` driver, so the smoke kernel must be
built with ``CONFIG_TEST_FIRMWARE=y``. The current development harness expects
1092 passing hardening checks, including support-bundle fail-closed collection
proofs, object-scoped ptrace denial, protected shared-memory attach policy,
signed per-profile capability ceilings and allow-audit masks, bounded nested
user namespaces, monotonic read-only boot sealing, and abstract AF_UNIX object
policy plus proc-sensitive syscall, metadata, and scheduler-state disclosure
checks.

The kernel loader requires the compiled payload to carry an appended PKCS#7
signature using the standard kernel module-signature trailer. Unsigned policy
payloads are rejected before structural parsing. Policy mutation requires
``CAP_MAC_ADMIN`` or ``CAP_SYS_ADMIN`` and the current hardening profile's
``POLICY_ADMIN`` authority. A valid write to ``policy`` only stages the
transaction; ``commit`` atomically publishes the staged policy as the active
policy and moves the old active policy into the rollback slot. Valid policy
tables are vmalloc-backed and sealed read-only before they become staged or
active; replacement and rollback paths temporarily unseal only to free retired
tables. ``rollback`` discards any staged policy and swaps the active and
previous policies. Policies may include ``base <generation>`` to require that
the active policy generation still matches the signed expected base when the
policy is staged and again when it is committed. If ``base`` is omitted, the
compiler uses ``HDN_POLICY_EXPECT_ANY`` for bring-up and intentionally
unconditional updates.

Text policy syntax
------------------

Blank lines and ``#`` comments are ignored. ``generation`` names the new policy
generation. ``base`` is optional and names the active generation this policy
expects to replace; use ``base 0`` for the first policy load.

::

  generation 1
  base 0
  default 1
  privileged 2

  profile 1 default
  profile 2 privileged
  profile 3 system-app

  allow 1 CRED_CHANGE
  allow 1 SOCKET_CREATE SOCKET_CONNECT SOCKET_SERVER

  allow 2 BPF_LOAD PERF_OPEN USERNS_CREATE MODULE_LOAD MODULE_AUTOLOAD
  allow 2 PTRACE PROC_DISCLOSE PROC_TASK_VIEW DEBUGFS SYSFS_MUTATE SYSFS_READ
  allow 2 KEXEC_LOAD FIRMWARE_LOAD IO_URING_RESTRICTED_OP
  allow 2 KERNEL_LOG_READ KERNEL_LOG_WRITE RAW_IO MOUNT_ADMIN POLICY_ADMIN
  allow 2 NAMESPACE_ADMIN CRED_CHANGE CHROOT_ADMIN TRUSTED_EXEC_BYPASS
  allow 2 IPC_ADMIN TTY_INJECT TTY_ACCESS FUSE_MOUNT ROFS_RELAX USB_ATTACH USB_MONITOR
  allow 2 SOCKET_CREATE SOCKET_CONNECT SOCKET_SERVER TIME_ADMIN RESOURCE_ADMIN
  allow 2 BLOCK_DEVICE_ACCESS BLOCK_DEVICE_ADMIN SIGNAL PROCESS_MEMORY MEMORY_MIGRATE PROCESS_FD
  audit 2 MODULE_LOAD KEXEC_LOAD

  capability-deny 3 CAP_SYS_ADMIN CAP_SYS_MODULE CAP_SYS_RAWIO
  capability-audit 2 CAP_FOWNER

  mem 2 ALLOW_WX ALLOW_EXEC_AFTER_WRITE ALLOW_FIXED_ANON_EXEC
  mem 2 ALLOW_READ_IMPLIES_EXEC
  mem 3 ALLOW_JIT_EXEC_AFTER_WRITE

  response 3 KILL_MEMORY KILL_KERNEL_SURFACE
  feature 1 DENY_UNTRUSTED_USER_EXEC
  feature 2 DENY_UNPRIVILEGED_PRIVEXEC
  feature 3 ENFORCE_TRUSTED_EXEC CHROOT_CONTAINED AUDIT_PROCESS_ACCOUNT PROTECT_SHM

  role desktop-admin allow POLICY_ADMIN CRED_CHANGE
  role desktop-admin audit POLICY_ADMIN
  role service-ceiling capability-deny CAP_SYS_ADMIN CAP_SYS_MODULE
  role service-observer capability-audit CAP_FOWNER
  role jit-runtime mem ALLOW_JIT_EXEC_AFTER_WRITE
  role workstation-admin include desktop-admin jit-runtime
  use-role 2 desktop-admin
  use-role 3 workstation-admin

  subject uid 1000 3
  subject gid 100 3
  umask 7 077
  userns-max 3 2
  resource 2 NOFILE 64 128

  object 2 deny-write path /etc/hdn/protected.conf
  object 2 deny-read path /etc/hdn/secret.conf
  object 2 deny-delete path /etc/hdn/important.db
  object 2 deny-create path /etc/hdn/protected-dir
  object 2 deny-creat path /etc/hdn/no-new-files
  object 2 deny-mkdir path /etc/hdn/no-new-dirs
  object 2 deny-mknod path /etc/hdn/no-new-nodes
  object 2 deny-symlink path /etc/hdn/no-new-symlinks
  object 2 deny-unlink path /etc/hdn/no-unlink.conf
  object 2 deny-rmdir path /etc/hdn/no-rmdir
  object 2 deny-exec path /usr/bin/blocked-tool
  object 2 audit-read path /etc/hdn/watched.conf
  object 2 audit-append path /var/log/hdn/audit.log
  object 2 audit-write tree /var/lib/hdn/managed
  object 2 audit-exec inode 8 1 23456
  object 2 append-only path /var/log/hdn/audit.log
  object 2 deny-link path /etc/hdn/link-sensitive.conf
  object 2 deny-link-target path /etc/hdn/no-link-in
  object 2 deny-attr path /etc/hdn/locked-metadata.conf
  object 2 deny-chmod path /etc/hdn/mode-locked.conf
  object 2 deny-chown path /etc/hdn/owner-locked.conf
  object 2 deny-utime path /etc/hdn/timestamps-locked.conf
  object 2 deny-setid path /etc/hdn/no-setid
  object 2 deny-ptrace path /usr/bin/nondebuggable
  object 2 deny-xattr path /etc/hdn/hidden-xattrs.conf
  object 2 deny-setxattr path /etc/hdn/xattr-write-locked.conf
  object 2 deny-removexattr path /etc/hdn/xattr-remove-locked.conf
  object 2 deny-access path /etc/hdn/hidden-probe.conf
  object 2 deny-stat path /etc/hdn/metadata-hidden.conf
  object 2 deny-list path /etc/hdn/name-hidden-dir
  object 2 deny-find path /etc/hdn/lookup-hidden.conf
  object 2 deny-ioctl path /etc/hdn/device-control
  object 2 deny-lock path /etc/hdn/coordination.lock
  object 2 deny-watch path /etc/hdn/changes-hidden.conf
  object 2 deny-receive path /etc/hdn/fd-passing-hidden.conf
  object 2 deny-fcntl path /etc/hdn/descriptor-control-hidden.conf
  object 2 deny-chdir path /etc/hdn/no-cwd
  object 2 deny-mount path /etc/hdn/no-cover
  object 2 deny-mount-source path /etc/hdn/no-move-source
  object 2 deny-umount path /etc/hdn/no-detach
  object 2 deny-truncate path /etc/hdn/no-size-change
  object 2 deny-rename path /etc/hdn/no-move
  object 2 deny-rename-target path /etc/hdn/no-rename-in
  object 2 deny-unix-connect path /run/hdn/private.sock
  object 2 deny-unix-bind path /run/hdn/private-sockets
  object 2 deny-unix-listen path /run/hdn/listener.sock
  object 2 deny-unix-accept path /run/hdn/listener.sock
  object 2 deny-unix-send path /run/hdn/datagram.sock
  object 2 deny-unix-recv path /run/hdn/datagram.sock
  object 2 deny-unix-connect abstract hdn-private-service
  object 2 deny-unix-bind abstract hdn-private-service
  object 2 deny-read tree /etc/hdn/secrets
  object 2 deny-write inode 8 1 12345

  exec 3 path /usr/bin/example
  exec 3 verity sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  exec 3 interpreter-path /usr/bin/python3 original-path /opt/app/main.py
  exec inherit path /usr/libexec/profile-helper parent 3 audit-inherit

  module 2 path /lib/modules/example.ko
  module 2 verity sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  firmware 2 name iwlwifi/example.ucode

Authority names may be written as ``BPF_LOAD``, ``AUTH_BPF_LOAD``,
``HDN_AUTH_BPF_LOAD``, or with dashes instead of underscores.
``audit`` marks allowed authority use for ``ALLOW_AUDIT`` events without
granting the authority by itself.

``role`` defines reusable compiler-side templates for authority, audit, memory,
capability-deny, capability-audit, response, and feature policy. ``role <child>
include <parent>...`` expands
parent role grants into the child role, with cycle and missing-parent rejection.
``use-role <profile> <role>`` expands the final role grants into the named
profile before the policy is written and signed; the kernel still consumes
compact sealed profile records and never interprets role names at runtime. Role
uses are order-independent, and unknown roles or profiles fail policy
compilation. The QEMU smoke suite stages a policy whose privileged profile gets
``POLICY_ADMIN`` only through an included parent role and proves that the
nested role-expanded authority permits rollback.

``capability-deny <profile> <capability>...`` is a signed ceiling over Linux's
ordinary effective and user-namespace capability result. A listed capability is
denied after the normal capability check succeeds, so UID 0, file capabilities,
and ownership of a child user namespace cannot widen that profile past policy.
``capability-audit`` records successful listed capability uses without denying
them. Capability names use the Linux ``CAP_*`` spelling or a numeric ID, and the
compiler rejects IDs above ``CAP_LAST_CAP``. The same operations are available
inside reusable roles as ``role <name> capability-deny ...`` and ``role <name>
capability-audit ...``. No-audit kernel probes remain enforced but do not emit
events; normal denials use ``HDN_TRANS_CAPABILITY`` with
``HDN_REASON_CAPABILITY_PROFILE`` and carry the capability number as the event
object. The event decoder presents the matching ``CAP_*`` name. The shipped
daily-driver profiles do not set a capability deny mask, while confined service
profiles can remove individual powers without relying on a UID change. QEMU
proves role expansion, ``CAP_CHOWN`` denial, successful ``CAP_FOWNER`` audit,
named telemetry, and rollback restoration.

Memory grants are explicit compatibility exceptions. By default, writable and
executable mappings, exec-after-write transitions, fixed anonymous executable
mappings, and executable-stack ELF file mappings are denied for profiles
without the corresponding ``mem`` flag. The legacy ``READ_IMPLIES_EXEC``
personality behavior is also narrowed by removing execute permission unless the
profile grants ``ALLOW_READ_IMPLIES_EXEC``. ``ALLOW_JIT_EXEC_AFTER_WRITE`` is
the narrow JIT grant: it allows a profile to convert private anonymous writable
mappings to executable mappings with ``mprotect()``, but it does not allow
simultaneous W+X, file-backed exec-after-write, shared mappings, fixed
executable mappings, or executable-stack ELF mappings.
``ALLOW_EXEC_AFTER_WRITE`` remains the broader compatibility exception for
profiles that cannot use the JIT-specific discipline.
``ALLOW_EXEC_STACK_ELF`` is the separate legacy-binary compatibility exception
for executable ``PT_GNU_STACK`` files. ``ALLOW_TEXTREL_MPROTECT`` is the
separate legacy-binary compatibility exception for text relocation style
``mprotect()`` transitions on ELF files marked with ``DT_TEXTREL`` or
``DF_TEXTREL``. When a private ELF mapping that exactly matches a
``PT_GNU_RELRO`` segment becomes read-only, HDN also clears its future write
eligibility so it cannot be made writable again. ``ALLOW_RELRO_WRITE`` is the
separate signed compatibility exception for software that must reopen such a
range. The QEMU smoke suite carries dedicated signed JIT, executable-stack,
textrel, and RELRO policies to prove these grants allow only their intended
compatibility paths without becoming broader memory-execution bypasses.

When ``SECURITY_HARDENING_MEMFD_NOEXEC`` is enabled, HDN also treats
executable memfds as a build-time memory-execution invariant instead of a
promptable authority. ``vm.memfd_noexec`` starts and stays at the enforced
no-exec level, unflagged ``memfd_create()`` calls receive upstream
``MFD_NOEXEC_SEAL`` behavior, and explicit ``MFD_EXEC`` requests are rejected.
Legitimate JIT and legacy executable-memory cases should use the profile and
trusted-ELF compatibility paths above. The QEMU smoke suite proves the sealed
status bit, the locked sysctl value, downgrade rejection, and explicit
executable memfd denial.

Response flags are explicit profile-level exploit responses. ``KILL_DENY``
sends ``SIGKILL`` to a userspace task after any hardening denial. ``KILL_MEMORY``
does the same only for memory-execution denials such as W^X,
exec-after-write, fixed anonymous executable mappings, and
``READ_IMPLIES_EXEC`` rewrites that become denials. ``KILL_KERNEL_SURFACE``
kills after denied access to gated kernel attack surfaces such as BPF, perf,
module loading, ptrace, ptrace execute-only reads, proc disclosure, debugfs,
owner-only sysfs reads, sysfs mutation, kexec, firmware loading, kernel log
reads and writes,
raw I/O, mount administration, namespace administration, chroot administration,
USB attachment, USB monitor capture, and non-local socket
creation/client/server operations.
Denials still return the original error and emit events; kill responses add
``HDN_EVENT_RESPONSE_KILL_TASK`` to the event ``flags`` field. The QEMU smoke
suite also stages a signed
``KILL_MEMORY`` policy and verifies a denied W+X mapping terminates the task
and records the kill-response event flag. Successful exec audit events from
tasks that are currently chrooted add ``HDN_EVENT_CHROOTED`` to the same
``flags`` field.

``subject`` rules are signed profile-selection rules for account identity.
``subject uid <id> <profile>`` selects a profile when any of the task's real,
effective, saved, or filesystem UIDs match ``id``. ``subject gid <id>
<profile>`` selects a profile when any of the task's real, effective, saved,
filesystem, or supplementary groups match ``id``. Subject rules are evaluated
before the default profile for non-privileged exec and credential transitions;
privileged exec still enters the policy's privileged profile. QEMU stages a
dedicated subject policy and proves both UID and GID profile selection.

``umask <profile> <mask>`` sets a profile-level umask floor. The kernel ORs the
profile mask with the process umask in the normal VFS creation path, so policy
can make file and directory creation stricter without loosening a process-chosen
mask. The QEMU subject policy gives profile 7 ``077`` and proves a task that
sets its own umask to ``000`` still creates regular files as ``0600`` and
directories as ``0700``.

``userns-max <profile> <level>`` limits the highest user-namespace level a
profile may create. Level ``0`` leaves the profile unlimited, while levels
``1`` through ``32`` are absolute levels below the initial user namespace.
The profile must also hold ``USERNS_CREATE`` authority. A request beyond the
limit fails with ``EPERM`` and records ``HDN_REASON_USERNS_DEPTH``; the event
object reports the requested level. This permits sandbox launchers to build a
small, signed namespace hierarchy without granting arbitrary nesting.

``feature <profile> INHERIT_UNMATCHED_EXEC`` keeps an otherwise unmatched,
non-privileged child executable in its caller's profile. Explicit exec rules
still take precedence, and any privilege-gaining executable still enters the
privileged profile. This is intended for signed sandbox and container launchers
whose payload inode identities only exist inside a mount namespace created at
runtime. It lets the payload retain the launcher's bounded namespace and memory
policy without granting the same compatibility flags to ordinary host
applications.

``resource <profile> <rlimit> <soft> <hard>`` sets a profile-level resource
ceiling for future ``setrlimit(2)`` and ``prlimit64(2)`` writes. ``rlimit`` may
be a numeric Linux resource id or a name such as ``NOFILE``, ``NPROC``, ``CORE``,
``AS``, or ``RTTIME``; ``soft`` and ``hard`` are unsigned integers or
``infinity``/``unlimited``. The ceiling follows the target task's hardening
profile, so a helper cannot raise a restricted profile beyond its signed cap
through ``prlimit64(2)``. QEMU gives the restricted profile a ``NOFILE`` ceiling
and proves both soft-limit and hard-limit raises above that ceiling are denied
with ``HDN_REASON_RESOURCE_PROFILE_LIMIT``.

``object`` rules are signed object constraints under a profile. The implemented
operations are ``object <profile> deny-write path <absolute-path>``,
``object <profile> deny-read path <absolute-path>``,
``object <profile> deny-delete path <absolute-path>``,
``object <profile> deny-create path <absolute-path>``,
``object <profile> deny-creat path <absolute-path>``,
``object <profile> deny-mkdir path <absolute-path>``,
``object <profile> deny-mknod path <absolute-path>``,
``object <profile> deny-symlink path <absolute-path>``,
``object <profile> deny-unlink path <absolute-path>``,
``object <profile> deny-rmdir path <absolute-path>``,
``object <profile> deny-exec path <absolute-path>``,
``object <profile> append-only path <absolute-path>``,
``object <profile> deny-link path <absolute-path>``,
``object <profile> deny-link-target path <absolute-path>``,
``object <profile> deny-attr path <absolute-path>``,
``object <profile> deny-chmod path <absolute-path>``,
``object <profile> deny-chown path <absolute-path>``,
``object <profile> deny-utime path <absolute-path>``,
``object <profile> deny-setid path <absolute-path>``,
``object <profile> deny-ptrace path <absolute-path>``,
``object <profile> deny-xattr path <absolute-path>``,
``object <profile> deny-setxattr path <absolute-path>``,
``object <profile> deny-removexattr path <absolute-path>``,
``object <profile> deny-access path <absolute-path>``,
``object <profile> deny-stat path <absolute-path>``,
``object <profile> deny-list path <absolute-path>``,
``object <profile> deny-find path <absolute-path>``,
``object <profile> deny-ioctl path <absolute-path>``,
``object <profile> deny-lock path <absolute-path>``,
``object <profile> deny-watch path <absolute-path>``,
``object <profile> deny-receive path <absolute-path>``,
``object <profile> deny-fcntl path <absolute-path>``,
``object <profile> deny-chdir path <absolute-path>``,
``object <profile> deny-mount path <absolute-path>``,
``object <profile> deny-mount-source path <absolute-path>``,
``object <profile> deny-umount path <absolute-path>``,
``object <profile> deny-truncate path <absolute-path>``,
``object <profile> deny-rename path <absolute-path>``,
``object <profile> deny-rename-target path <absolute-path>``,
``object <profile> deny-unix-connect path <absolute-path>``,
``object <profile> deny-unix-bind path <absolute-path>``,
``object <profile> deny-unix-listen path <absolute-path>``,
``object <profile> deny-unix-accept path <absolute-path>``,
``object <profile> deny-unix-send path <absolute-path>``,
``object <profile> deny-unix-recv path <absolute-path>``, the abstract
AF_UNIX name forms below, and the allowed-operation audit forms
``audit-read``, ``audit-append``, ``audit-write``, ``audit-exec``, ``audit-find``,
``audit-create``, ``audit-delete``, ``audit-link``, and ``audit-setid`` with
``path``, ``nofollow-path``, ``tree``, or ``inode`` identity. The
audit forms do not grant access. When the rest of the kernel and HDN policy
permit a matching operation, HDN emits an ``ALLOW_AUDIT`` object event with
the operation-specific transition and object identity. Audit and denial masks
are independent; if both match, denial wins and HDN emits only the denial.
The QEMU smoke suite proves all nine object-operation audit transitions,
symbolic decoder
output, deny precedence, rollback, and absence of further audit events after
rollback. The abstract
AF_UNIX name forms ``object <profile> deny-unix-connect abstract <name>``,
``object <profile> deny-unix-bind abstract <name>``,
``object <profile> deny-unix-listen abstract <name>``,
``object <profile> deny-unix-accept abstract <name>``,
``object <profile> deny-unix-send abstract <name>``, and
``object <profile> deny-unix-recv abstract <name>``, the literal
final-component ``object <profile> <operation> nofollow-path <absolute-path>``
form, the
recursive ``object <profile> <operation> tree <absolute-directory>`` form, and
the equivalent ``inode <major> <minor> <ino>`` forms. ``deny-create``,
``deny-creat``, ``deny-mkdir``, ``deny-mknod``, ``deny-symlink``, and
``deny-unix-bind`` match the parent directory identity. ``deny-setid`` matches
the target object for mode changes and the parent directory for creation,
tmpfile, and mknod requests that ask for setuid or executable-setgid mode bits.
``deny-ptrace`` matches the target task's executable object before the broader
profile-level ptrace gate.
``deny-unix-listen`` and ``deny-unix-accept`` match the bound filesystem
socket identity. ``deny-unix-send`` matches the destination filesystem socket
identity for pathname and connected datagram sends. ``deny-unix-recv`` matches
the bound filesystem socket identity for datagram receives. The ``abstract``
forms match exact printable AF_UNIX abstract names without the leading NUL and
cover named connect, bind, listen, accept, datagram send, connected datagram
send, and datagram receive operations without exposing raw socket names in
events. ``deny-delete``,
``deny-unlink``, and ``deny-rmdir`` match the object being removed, while
``deny-link`` matches the hardlink source file identity. ``tree`` inputs must
resolve to directories and match that
directory plus descendants by dentry ancestry and compiled device/inode
identity. ``path``
inputs follow a final symlink and resolve to the target identity;
``nofollow-path`` resolves the final component literally so policies can name a
symlink inode or other terminal object without following it. Inputs are resolved
to device/inode identity when the policy is staged; hot paths use the compiled
identity, not a string lookup. The kernel enforces
	deny-write for regular-file, FIFO, character-device, and block-device write opens,
	``write(2)``, ``writev(2)``, pipe-to-file ``splice(2)``,
	``copy_file_range(2)`` destination writes, ``sendfile(2)``
	destination writes, legacy AIO and io_uring writes, reflink/remap
	destination writes, shared writable ``mmap(2)``,
	shared writable ``mprotect(2)`` upgrades,
truncate/ftruncate, and fallocate,
including writable data paths and mapping attempts through descriptors opened
before policy commit. It enforces
append-only by allowing ``O_APPEND``/``RWF_APPEND`` writes while denying
non-append writes through already-open descriptors, pipe-to-file ``splice(2)``,
``copy_file_range(2)`` destination writes, ``sendfile(2)`` destination
writes, reflink/remap destination writes, shared writable ``mmap(2)``,
shared writable ``mprotect(2)`` upgrades, exported iterator writes, legacy AIO
and io_uring writes that do not carry append intent, truncate/ftruncate, and
fallocate. It enforces
deny-read for regular-file, FIFO, character-device, and block-device read opens, read paths
		that pass through ``rw_verify_area()``, ``copy_file_range(2)``
		source reads, file-to-pipe ``splice(2)`` source reads,
		``sendfile(2)`` source reads, legacy AIO and io_uring read
		operations, reflink/remap source range checks,
	readable file ``mmap(2)`` attempts, and readable
	``mprotect(2)`` upgrades, including already-open
	descriptors after policy commit, and for
	symlink target disclosure through
``readlink(2)``/``readlinkat(2)`` when the symlink inode is selected with
``nofollow-path`` or ``inode``. It enforces deny-delete for file unlink,
directory ``rmdir(2)``, rename away, and replacement of a protected target,
including recursive ``tree`` matches. The split ``deny-unlink`` and
``deny-rmdir`` operations gate only their named removal operations before
falling back to aggregate ``deny-delete``. It enforces deny-create for
regular-file create, ``mkdir(2)``, FIFO, character-device, and block-device
creation through ``mknod(2)``, ``symlink(2)``, ``link(2)``, tmpfile creation,
and rename into a protected directory. The split ``deny-creat``,
``deny-mkdir``, ``deny-mknod``, and ``deny-symlink`` operations gate only their
named creation operations before falling back to aggregate ``deny-create``. It
enforces deny-exec for
``execve(2)`` and file-backed executable ``mmap(2)``/``mprotect(2)``
transitions. It enforces deny-link for hardlink attempts whose source is a
protected regular file, and deny-link-target for incoming hardlinks by target
directory identity without blocking ordinary creates in that directory. It
enforces deny-attr as an aggregate metadata gate for
mode, ownership, size, explicit timestamp changes through the common setattr
path, VFS file-attribute changes such as ``FS_IOC_SETFLAGS`` through the common
fileattr path, and extended attribute or POSIX ACL set/remove operations
through the common VFS xattr/ACL paths. The split ``deny-chmod``, ``deny-chown``,
``deny-utime``, ``deny-setxattr``, and ``deny-removexattr`` operations provide
exact gates for those metadata and xattr mutations when a policy does not want
the aggregate behavior. ``deny-setid`` is a narrower setid-bit gate for
``chmod(2)``/``fchmodat(2)`` changes that would result in setuid or
executable-setgid bits, plus ``O_CREAT``/tmpfile/``mknod(2)`` requests that ask
for those bits, without blocking ordinary mode changes or ordinary creates. It
enforces deny-ptrace for ptrace-style access to a target task whose executable
matches the protected object, before profile-level ptrace policy. It
enforces deny-xattr for extended attribute
name/value discovery through ``getxattr(2)`` and ``listxattr(2)``, POSIX ACL
xattr reads through the common ACL helper, and aggregate xattr mutation control
through the common xattr/ACL paths. It enforces
deny-access for explicit ``access(2)``/``faccessat(2)`` probes and makes
``R_OK``/``W_OK``/``X_OK`` probes respect existing deny-read, deny-write, and
deny-exec regular-file rules. It enforces deny-stat for metadata discovery
through ``stat(2)``, ``lstat(2)``, ``fstat(2)``, ``fstatat(2)``, and
``statx(2)`` paths that use the common VFS getattr path, and for VFS
file-attribute reads such as ``FS_IOC_GETFLAGS`` through the common fileattr
path. It enforces deny-list
for directory name discovery through the common VFS ``iterate_dir()`` path used
by ``readdir(3)`` and ``getdents64(2)``, including already-open directory file
descriptors after policy commit. It enforces deny-find for regular non-directory
``open(2)``, ``open(2)`` with ``O_PATH``, and ``name_to_handle_at(2)``,
returning ``ENOENT`` while recording a dedicated object-policy denial event.
Regular open checks run after more specific read/write denials, so a combined
tree rule still reports its specific data-access denial. Directory enumeration
uses deny-find per entry, hiding matching protected entries from
``readdir(3)``/``getdents64(2)`` without denying the whole containing directory.
It enforces deny-ioctl for native and compat
``ioctl(2)`` requests through the common file ioctl security path, including
device/control files where ioctl is the mutation surface. It enforces
deny-lock for advisory lock and lease acquisition through the common file lock
security path, covering BSD ``flock(2)``, POSIX/OFD ``fcntl(2)`` locks, and
file leases while allowing unlock operations. It enforces deny-watch for
filesystem notification mark creation through the common fsnotify security
path, including ``inotify_add_watch(2)``, directory ``F_NOTIFY`` dnotify
marks, and ``fanotify_mark(2)`` when fanotify is configured. It enforces
deny-receive for open
file descriptors received through the common ``security_file_receive()`` path
used by Unix-domain socket descriptor passing. It enforces deny-fcntl for
descriptor and file-control operations through the common ``fcntl(2)`` security
path, including fd duplication, flag/owner/signal changes, leases, seals,
pipe sizing, delegation updates, write-hint updates, lock acquisition, and
``ioctl(2)`` aliases for close-on-exec, nonblocking, and async flag changes,
while leaving read-only fcntl queries usable. It enforces deny-chdir for
current-working-directory changes through ``chdir(2)`` and ``fchdir(2)``,
including directory descriptors opened before policy commit. It enforces
deny-mount for mount-tree attachment through ``mount(2)`` and the
``move_mount(2)`` destination path, preventing protected objects from being
covered by a new mount. It enforces deny-mount-source for ``move_mount(2)``
and legacy ``mount(2)`` ``MS_MOVE`` source paths, preventing protected mounted
trees from being moved elsewhere. It enforces deny-umount for ``umount(2)`` and
``umount2(2)`` after normal VFS/capability validation and before the mounted
tree is detached. It enforces deny-truncate for path truncation, descriptor
truncation, ``O_TRUNC`` opens, and ``fallocate(2)`` extent mutation while
leaving ordinary writes governed by deny-write or append-only policy. It
enforces deny-rename for source-object rename attempts, applies the same
source-object check to both objects in ``RENAME_EXCHANGE`` operations, and
enforces deny-rename-target for incoming rename attempts by destination
directory identity without blocking ordinary creates in that directory. It
enforces deny-unix-connect for filesystem-backed AF_UNIX socket pathname
connect attempts before the peer socket is selected. It enforces
deny-unix-bind for filesystem-backed AF_UNIX socket bind attempts by parent
directory identity before the socket node is created. It enforces
deny-unix-listen and deny-unix-accept for filesystem-backed AF_UNIX listening
sockets by bound socket identity. It enforces deny-unix-send for
filesystem-backed AF_UNIX pathname and connected datagram sends by destination
socket identity, and deny-unix-recv for filesystem-backed AF_UNIX datagram
receives by bound socket identity. The same deny-unix operation family can
match exact abstract AF_UNIX names for named connect/send, bind, listen,
accept, connected datagram send, and datagram receive.
QEMU stages a
dedicated object policy and proves protected
read/write/delete/create/creat/mkdir/mknod/symlink/unlink/rmdir/exec/link/link-target/attr/chmod/chown/utime/setid/xattr/setxattr/removexattr/access/stat/list/find/ioctl/lock/watch/receive/fcntl/chdir/mount/mount-source/umount/truncate/rename/rename-target/unix-connect/unix-bind/unix-listen/unix-accept/unix-send/unix-recv targets, protected
	file-capability xattr get/list/set/remove attempts, protected POSIX ACL xattr reads, preopened descriptor reads, readable mmap, and readable mprotect,
	unmatched readable mmap and mprotect,
		protected FIFO, character-device, and block-device read/write open denial,
			protected truncate plus preopened ftruncate/fallocate denial,
				setuid chmod/create and executable-setgid mknod denial,
				ordinary chmod/create/mknod allowance, truncate-only ordinary write allowance, path truncate
			denial, unmatched truncate allowance, and preopened
			ftruncate and fallocate denial,
			protected rename denial and unmatched rename allowance,
			protected Unix socket connect denial and unmatched
			socket connect allowance,
			unmatched truncate/ftruncate allowance,
			preopened descriptor splice, copy-file-range, sendfile, clone,
			clone-range, io_uring, and legacy AIO write denial,
			unmatched sendfile, io_uring, and legacy AIO write allowance,
			preopened copy-file-range, splice, sendfile, io_uring, legacy
			AIO, clone, and clone-range source read denial, unmatched
			copy-file-range, splice, sendfile, io_uring, and legacy AIO
			source read allowance, preopened append-only
			descriptor io_uring and legacy AIO rewrite denial, io_uring
			and legacy AIO append allowance, and splice, copy-file-range,
			sendfile, clone, clone-range, truncate, preopened ftruncate,
			and fallocate write denial,
	preopened descriptor shared writable mapping denial, protected FIFO, character-device, and block-device creation
denial, protected tmpfile creation denial, preopened descriptor stat and list
denial, protected regular-open and file-handle export denial, protected
directory delete and rename denial, direct and recursive deny-find
directory-entry hiding, recursive tree children including
nested attr, xattr, access-probe, stat, list, find, incoming rename target,
and incoming hardlink target changes, and append-only rewrite and shared
writable mapping paths are denied while unmatched files,
unmatched directories, unmatched link sources, unmatched attrs, unmatched
xattr reads and mutations, unmatched access probes, unmatched stat probes, unmatched list probes,
	unmatched find probes, unmatched executable paths, unmatched ioctl targets,
	unmatched advisory lock targets, unmatched FIFO, character-device, and block-device read/write opens, unmatched inotify/dnotify/fanotify watch targets, unmatched fd receive, fcntl
	duplicate targets, chdir targets and preopened chdir descriptors, truncate
	targets and preopened truncate descriptors, rename sources, rename targets,
	hardlink target directories, filesystem
socket connect targets, mount targets, move-mount targets, move-mount source
roots, umount targets, unmatched trees, and append writes
	remain usable.

The exploit-mitigation baseline also forces upstream strict kernel RWX and
strict module RWX when the architecture supports them. Module text is made
executable read-only after relocation, module rodata is made read-only, and
module data is made non-executable through the normal module loader path. The
QEMU smoke suite asserts both strict kernel RWX and strict module RWX in the
sealed mitigation status.

On architectures that support it, the same baseline enables and enforces
upstream page-table checking. This catches invalid user page-table sharing and
double-mapping states synchronously when mappings are installed or removed. The
sealed mitigation status reports ``mitigation_page_table_check: 1`` when the
enforced check is present, and the QEMU smoke suite asserts that status.

The baseline also locks ``/proc/sys/vm/mmap_min_addr`` at or above ``64 KiB``.
Higher product or LSM floors remain valid, but a later privileged sysctl write
cannot drop the low-address mapping barrier to ``0``. The sealed mitigation
status reports ``mitigation_mmap_min_addr: 1``, and the QEMU smoke suite proves
the locked sysctl plus unprivileged fixed ``mmap(2)`` denial below the floor.

The same baseline selects upstream vmapped kernel stacks, default kernel stack
offset randomization, stack zeroing, kernel stack erasure, zeroing of used
call-clobbered registers on return, randstruct, and strong stack protector
where supported. The sealed mitigation status reports
``mitigation_vmap_stack: 1``, ``mitigation_thread_info_in_task: 1``,
``mitigation_randomize_kstack: 1``, ``mitigation_init_stack_zero: 1``,
``mitigation_kstack_erase: 1``, ``mitigation_zero_call_used_regs: 1``,
``mitigation_randstruct: 1``, and ``mitigation_stackprotector_strong: 1`` when
those upstream protections are present; the QEMU smoke suite asserts those
status bits.

``CONFIG_SECURITY_HARDENING_RAND_THREADSTACK`` adds randomized unmapped gaps
to private anonymous no-hint ``MAP_STACK`` and stack-like ``MAP_GROWSDOWN``
placement when process ASLR is enabled. The generic VM and x86 unmapped-area
paths are wired, and the QEMU smoke suite asserts both
``mitigation_rand_threadstack: 1`` and varied page-aligned inter-stack gaps for
anonymous ``MAP_STACK`` and ``MAP_GROWSDOWN`` mappings.

HDN's own mitigation and policy tables are vmalloc-backed and sealed read-only
after validation/publication. On x86, supervisor write-protection faults
against those sealed HDN pages are recorded before exception-table fixup as
``HDN_TRANS_SEALED_DATA`` with ``HDN_REASON_SEALED_DATA_WRITE``. The
policy-admin-only ``securityfs/hardening/sealed_write_probe`` endpoint
deliberately attempts a nofault write to the sealed mitigation page so tests
can prove the reporter without corrupting state.

``feature`` uses the same profile flag field as ``response`` but is preferred
for non-kill profile behavior. ``ENFORCE_TRUSTED_EXEC`` denies execution from a
path whose dentry and mountpoint ancestors are not root-owned or are
group/world writable, unless the profile has ``TRUSTED_EXEC_BYPASS`` authority.
``DENY_UNTRUSTED_USER_EXEC`` is the profile-scoped non-root TPE mode: non-root
tasks in the profile cannot execute, executable-map, or executable-mprotect
files from non-root-owned executable directories, world-writable directories,
group-writable non-root directories, or world-writable files unless the profile
has ``TRUSTED_EXEC_BYPASS``. Profile
assignment replaces group/invert switches: put untrusted users in a profile
with the flag and trusted users in a profile without it, or grant the bypass
authority to a narrow compatibility profile. ``CHROOT_CONTAINED`` treats
chroot as a containment boundary: after a successful
``chroot()``, the current working directory is moved to the new root, repeated
``chroot()`` is denied, and ``chdir()``/``fchdir()`` targets outside the current
root are denied unless the profile has ``CHROOT_ADMIN`` authority. Contained
chroots also deny ``chmod()``, character/block-device ``mknod()``, bad
mount operations even when the profile otherwise has ``MOUNT_ADMIN``,
directory renames out of the current root, abstract AF_UNIX socket connections
to sockets bound outside the current root, ``shmat()``, priority increases
through nice/setpriority, dangerous capability use, and findtask-style task
discovery outside the current root by default. Outside-root tasks are hidden
from PID lookup/procfs views and explicit signal/file-owner targeting is
denied. The reduced capability set covers module loading, raw I/O, broad system
administration, reboot/time changes, raw networking, tty configuration, IPC
ownership override, file capability writes, kernel log control, MAC
administration, immutable-file changes, process accounting, and network
administration. Trusted compatibility services can use ``CHROOT_ADMIN`` as the
narrow bypass. Successful exec audit events from contained tasks carry
``HDN_EVENT_CHROOTED`` so log consumers can separate chrooted execs without
forking the policy model. Contained-chroot denials carry operation-specific
reason codes for chmod, mknod, mount, shmat, priority increases, bad directory
renames, abstract UNIX sockets, capability use, and outside-task targeting.
``DENY_UNPRIVILEGED_PRIVEXEC`` denies unprivileged
callers that attempt to execute privileged helpers, including setuid, setgid,
secureexec, and file-capability transitions, even when the target exec profile
otherwise has ``CRED_CHANGE``. Root and callers with set-ID/capability
administration capability can still launch those helpers for service-management
and recovery flows. The QEMU smoke suite proves the flag with both setuid-root
and file-capability helpers. ``ENFORCE_READONLY_MOUNTS`` rejects new writable
mounts and writable bind/open-tree clones unless the profile has
``ROFS_RELAX`` authority. Read-only mount creation remains available so product
profiles can keep normal discovery and sandbox setup while preventing new
writable filesystem attachments. The QEMU smoke suite proves the product
shape by transitioning from the mount-capable root profile into a trusted
updater profile that has ``ROFS_RELAX`` and can create the writable mount.
``AUDIT_PROCESS_ACCOUNT`` records a ``PROCESS_ACCOUNT`` allow-audit event for
process-level exits in that profile. The event ``object`` carries the raw exit
status passed through the kernel exit path, matching the process-accounting
audit use case without enabling global exit logging.

Namespace administration is separate from mount administration. Profiles
without ``NAMESPACE_ADMIN`` cannot create non-user namespaces, create detached
mount namespace files through ``open_tree(OPEN_TREE_NAMESPACE)``, or join a
namespace owned by a different hardening profile. Mount namespaces inherit the
creator's hardening profile, and procfs, owner-only sysfs, and debugfs/tracefs
disclosure or mutation gates require authority from both the current task
profile and the current mount namespace profile. When ``setns(2)`` uses a
pidfd received through inheritance or IPC, or pidfd namespace ioctls open
namespace file descriptors from a pidfd target, HDN first checks the target
task against the same ``PROC_TASK_VIEW`` rule used for pidfd metadata before
harvesting namespaces from that task.

``SYSFS_MUTATE`` authority covers sysfs writes. ``SYSFS_READ`` authority covers
owner-only sysfs attributes plus sensitive world-readable kernel metadata such
as ``/sys/kernel/vmcoreinfo`` and ``/sys/kernel/notes``. Profiles without it
cannot read those attributes, and covered entries are hidden from sysfs
directory enumeration. Ordinary group- and world-readable sysfs entries remain
visible so normal desktop device discovery and service management keep working.

``USB_ATTACH`` authority covers new USB device attachment after boot policy is
active. The gate runs in the USB hub attach path before enumeration and driver
binding, so profiles without the authority cannot introduce a newly connected
USB device into the kernel driver surface. Root hubs and devices already
discovered before policy commit remain governed by normal USB core state.
``USB_MONITOR`` authority separately covers usbmon text and binary capture
interfaces, so a profile can be allowed to approve devices without being able
to sniff USB control, HID, or bulk traffic. The QEMU smoke suite uses runtime
USB hotplug through QMP ``device_add`` to prove a restricted profile denies new
attachment and records the ``USB_ATTACH`` event, and opens ``/dev/usbmon0`` to
prove the same restricted profile denies monitor capture and records the
``USB_MONITOR`` event.

``SOCKET_CREATE``, ``SOCKET_CONNECT``, and ``SOCKET_SERVER`` authority cover
non-local socket creation, outbound connection attempts, and server-side
``bind()``, ``listen()``, and ``accept()`` operations. AF_UNIX/AF_LOCAL sockets
remain available without these authorities so normal desktop IPC does not
depend on network access policy. The shipped daily-driver default policy grants
all three socket authorities to profile 1 so normal application networking
works without prompts; confined profiles can still drop one or more grants. The
QEMU smoke suite proves a restricted profile denies AF_INET socket creation
while still allowing AF_UNIX creation, and proves a socket-capable profile
without client/server grants cannot connect or bind stream and datagram sockets
over IPv4 or IPv6. The same suite checks the encoded endpoint object for IPv4
address/port denials and IPv6 address-hash/port denials across both socket
types.

Network blackhole and TCP simultaneous-connect hardening are build-time
baseline mitigations rather than profile authorities. When enabled, HDN
suppresses remote closed-port TCP resets, UDP ICMP port-unreachable replies,
and IPv4 protocol-unreachable replies, keeps loopback closed-port diagnostics
working, bounds ``LAST_ACK`` retries, and removes TCP crossed-SYN simultaneous
open. The QEMU smoke suite proves the status bits and loopback TCP/UDP
exemption. It also creates a TUN-backed non-loopback interface and injects
closed-port TCP and UDP packets to prove remote reset and ICMP suppression.

``TIME_ADMIN`` authority covers system time mutation after ordinary
``CAP_SYS_TIME`` and LSM checks have succeeded. Profiles without it are denied
wall-clock changes, kernel timezone changes, and mutable ``adjtimex()``
operations, while clock reads and read-only time queries remain available. The
QEMU smoke suite proves a restricted root profile cannot change realtime and
records the ``TIME_ADMIN`` event.

``RESOURCE_ADMIN`` authority covers privileged hard resource-limit raises after
ordinary ``CAP_SYS_RESOURCE`` and LSM checks have succeeded. Profiles without
it may still lower limits and adjust soft limits within the current hard limit,
but cannot raise hard limits through ``setrlimit()`` or ``prlimit()``. The QEMU
smoke suite proves a restricted root profile cannot raise its ``RLIMIT_NOFILE``
hard limit after lowering it and records the ``RESOURCE_ADMIN`` event.
Successful resource-limit write audit records the resource number, including
limits such as ``RLIMIT_RSS`` that Linux exposes but does not otherwise enforce.
Resource audit also records actual pressure at selected enforcement sites:
``RLIMIT_NOFILE`` fd exhaustion and explicit fd-number violations, plus
``RLIMIT_FSIZE`` write/truncate denials, ``RLIMIT_CORE`` coredump suppression,
``RLIMIT_NPROC`` fork denials, ``RLIMIT_AS`` and ``RLIMIT_DATA`` VM expansion
denials, ``RLIMIT_STACK`` stack growth denials, ``RLIMIT_MEMLOCK`` lock
denials, ``RLIMIT_MSGQUEUE`` POSIX mqueue accounting denials,
``RLIMIT_SIGPENDING`` queued-signal denials, and ``RLIMIT_CPU`` CPU-time
pressure, ``RLIMIT_RTTIME`` realtime-runtime pressure, plus ``RLIMIT_NICE``
and ``RLIMIT_RTPRIO`` scheduler-priority denials, and ``RLIMIT_LOCKS``
file-lock conflict pressure for BSD ``flock()`` and POSIX/OFD lock acquisition
failures. The smoke suite proves the deterministic ``NOFILE``, ``FSIZE``,
``CORE``, ``AS``, ``DATA``, ``STACK``, ``NPROC``, ``MEMLOCK``, ``MSGQUEUE``,
``SIGPENDING``, ``CPU``, ``RTTIME``, ``NICE``, ``RTPRIO``, and ``LOCKS``
pressure paths.

``PTRACE`` authority covers direct native and compat ``ptrace()`` operations
and access checks made with ``PTRACE_MODE_ATTACH``. Read-only process metadata
checks made through ``ptrace_may_access(..., PTRACE_MODE_READ)`` use
``PROC_DISCLOSE`` instead, so a desktop broker can identify a caller without
receiving debugger authority. ``PTRACE`` remains a compatibility superset for
profiles that already combine inspection and debugging, and same-profile
inspection remains allowed.
``PTRACE_ATTACH`` and ``PTRACE_SEIZE`` attempts that pass the direct ptrace gate
emit HDN-native ``PTRACE`` audit events, preserving later upstream kernel
denials as deny-audit records and successful attaches as allow-audit records.
The exploit-mitigation baseline also builds Yama and locks
``kernel.yama.ptrace_scope`` at the relational level, so same-UID sibling
ptrace cannot be globally re-enabled by lowering the upstream sysctl.
``PTRACE_EXEC_READ`` is deliberately separate: profiles without it cannot use
ptrace-like forced reads, including active ``/proc/<pid>/mem`` reads, to read a
target VMA that is executable but not readable. The starter policy does not
grant this authority by default; a debugger broker can grant it to a narrower
developer profile when that compatibility is intentional.

``SIGNAL`` authority covers user-originated signal sends across HDN profile
boundaries after ordinary Unix signal permission checks. Self, same-thread
group, same-profile, and direct-child signals remain available for normal job
control; sibling or unrelated cross-profile targets require ``SIGNAL``.

``PROCESS_MEMORY`` authority covers explicit remote process address-space
operations across HDN profile boundaries after ordinary ptrace/capability
checks. Profiles without it cannot use ``process_vm_readv(2)``,
``process_vm_writev(2)``, ``process_madvise(2)``, or ``process_mrelease(2)``
against another profile; same-profile cooperating processes remain usable.

``MEMORY_MIGRATE`` authority covers explicit remote page-placement and
migration operations across HDN profile boundaries after ordinary
ptrace/capability checks. Profiles without it cannot use ``move_pages(2)`` or
``migrate_pages(2)`` against another profile; same-profile page-location
queries remain usable.

``PROCESS_FD`` authority covers explicit remote file-descriptor extraction
across HDN profile boundaries after ordinary ptrace checks. Profiles without
it cannot use ``pidfd_getfd(2)`` against another profile; same-profile helper
processes can still share descriptors through pidfds.

``PROC_DISCLOSE`` authority covers procfs interfaces that disclose kernel
addresses, symbol names, stack state, raw kernel memory, or sensitive
cross-process address-space metadata. Profiles without that authority are
denied privileged interfaces such as ``/proc/kcore`` and kernel config reads,
see an empty ``/proc/kallsyms`` stream instead of symbol names with redacted
addresses, see null/zero base addresses for loaded modules in
``/proc/modules``, and cannot read another mm's ``/proc/<pid>/cmdline``,
``/proc/<pid>/environ``, ``/proc/<pid>/auxv``, or
``/proc/<pid>/syscall``, nor another task's ``/proc/<pid>/io`` accounting,
``/proc/<pid>/personality`` flags, or ``/proc/<pid>/coredump_filter`` state.
It also satisfies read-only ``ptrace_may_access()`` checks used by procfs links
such as ``/proc/<pid>/root`` while leaving direct ptrace operations gated by
``PTRACE``.
The same authority covers cross-task ``/proc/<pid>/coredump_filter`` writes, so
restricted profiles cannot alter another process' future core-dump selection.
Cross-task ``/proc/<pid>/limits`` reads also require ``PROC_DISCLOSE`` so
restricted peers cannot inventory another process' resource ceilings.
Cross-task ``/proc/<pid>/statm`` reads require ``PROC_DISCLOSE`` so restricted
peers cannot sample another process' memory accounting.
Cross-task ``/proc/<pid>/sched`` and ``/proc/<pid>/schedstat`` reads require
the same authority so restricted peers cannot sample another process'
scheduler timing and accounting state.

Kernel symbol APIs are split by disclosure risk. ``linux/kallsyms.h`` exposes
only policy-redacting formatters and common symbol metadata; raw name/address
lookup and iteration require the explicit internal
``linux/kallsyms-lookup.h`` include. Every in-tree raw consumer is classified
through that header, and every user-reachable trace, probe, BPF, procfs, or
debugfs frontend still authorizes ``PROC_DISCLOSE`` before using it. The
``kallsyms-api.sh`` Kbuild selftest proves the internal include compiles while
the ordinary include leaves ``kallsyms_lookup_name()`` undeclared.

``PROC_TASK_VIEW`` authority is the narrow bypass for HDN's hidepid-like
task-directory visibility rule. Profiles without it can see their own UID's
tasks but cannot enumerate or open other users' ``/proc/<pid>`` directories
or mint sibling/unrelated ``pidfd_open(2)`` task handles for those tasks.
If a pidfd arrives through inheritance or IPC, ``PIDFD_GET_INFO`` metadata
reads are checked against the same task-visibility rule before disclosing
credentials, cgroup IDs, PID ancestry, or coredump state, and
``/proc/self/fdinfo/<pidfd>`` redacts the target PID fields when the target is
not visible.
``PROC_DISCLOSE`` also bypasses task hiding as a compatibility superset, but
profiles that only need process-manager visibility should grant
``PROC_TASK_VIEW`` instead. Procfs instances mounted with upstream
``hidepid=1`` or ``hidepid=2`` and ``gid=<gid>`` let members of that proc mount
group see other users' task directories on that mount without granting either
proc authority. Product images can also set ``SECURITY_HARDENING_PROC_TASK_GID``
or boot with ``hdn.proc_task_gid=<gid>`` to give one global group the same
task-view visibility without broader proc disclosure.
``SECURITY_HARDENING_PROC_TASK_MODES`` also makes public proc task directories
owner-and-task-view-group traversable instead of world-traversable whenever
that group is configured. The QEMU smoke suite commits a restricted root
profile and verifies hidden other-user PIDs, verifies grouped
``hidepid=2,gid=0`` proc mount visibility, verifies a configured task-view
group can see other-user PIDs and open pidfds without ``PROC_TASK_VIEW``,
verifies proc task directories carry the configured group and restricted modes,
then commits a proc-task profile that can see other-user PIDs, open pidfds for
other-user tasks, and inspect received pidfd metadata and fdinfo while kernel
symbols remain hidden.

``CONFIG_SECURITY_HARDENING_PROC_IPADDR`` adds owner-readable
``/proc/<pid>/ipaddr`` attribution for accepted IPv4 TCP peers. The accepting
process records the peer address on its shared signal state; on the next fork,
the address is handed to the child and cleared from the parent. If that process
opens a local TCP connection, HDN records the established connection tuple long
enough for the local acceptor to consume it and keep attributing work to the
original peer. AF_UNIX stream listeners get the same carried attribution
through the accepted server-side socket. The QEMU smoke suite proves
accepted-loopback attribution, the one-time child handoff, local TCP carry, and
AF_UNIX stream carry to backend listeners.

``CONFIG_SECURITY_HARDENING_PATH_DEFAULTS`` defaults and locks upstream
``fs.protected_symlinks``, ``fs.protected_hardlinks``,
``fs.protected_fifos``, and ``fs.protected_regular`` at hardened values. This
keeps sticky-directory link and replacement protections from being downgraded
after boot. The QEMU smoke suite proves the hardened values and rejection of
lower sysctl writes for all four controls.

``CONFIG_SECURITY_HARDENING_EXPLOIT_MITIGATIONS`` locks
``/proc/sys/kernel/dmesg_restrict`` at level ``1``. Kernel log reads remain
restricted after boot even if a later admin path attempts to lower the sysctl.
HDN still keeps direct kernel log reads behind the ``KERNEL_LOG_READ`` profile
authority and ``/dev/kmsg`` writes behind ``KERNEL_LOG_WRITE`` so log injection
does not require log-read disclosure. QEMU proves the locked sysctl value,
failed lowering attempts, unprivileged kernel log denial, restricted-profile
kernel log write denial and event decoding, and sealed status reporting.

``CONFIG_SECURITY_HARDENING_UNPRIV_BPF`` locks
``/proc/sys/kernel/unprivileged_bpf_disabled`` to ``1``. That is the upstream
irreversible disabled state, so unprivileged BPF cannot be re-enabled by a later
sysctl write. HDN also keeps BPF program loads behind the ``BPF_LOAD`` profile
authority for privileged service policy. On eBPF-JIT-capable architectures, the
same option selects ``BPF_JIT`` and ``BPF_JIT_ALWAYS_ON`` to remove the BPF
interpreter, defaults and locks ``/proc/sys/net/core/bpf_jit_harden`` to ``2``
for constant blinding, and defaults and locks
``/proc/sys/net/core/bpf_jit_kallsyms`` to ``0``. QEMU proves the locked
unprivileged-BPF sysctl state, failed re-enable attempts, sealed JIT hardening
status, locked JIT hardening, hidden JIT kallsyms, and unprivileged load denial.

``CONFIG_SECURITY_HARDENING_UNPRIV_PERF_KERNEL`` locks
``/proc/sys/kernel/perf_event_paranoid`` at level ``3``. That is the upstream
state that disables all unprivileged ``perf_event_open()`` use. HDN still keeps
kernel and namespace perf visibility behind the ``PERF_OPEN`` profile authority
for privileged service policy. QEMU proves the locked sysctl value, failed
lowering attempts, unprivileged kernel perf denial, and sealed status reporting.

``CONFIG_SECURITY_HARDENING_USERFAULTFD_RESTRICT`` locks
``/proc/sys/vm/unprivileged_userfaultfd`` at ``0`` whenever the selected kernel
build enables ``CONFIG_USERFAULTFD``. This leaves unprivileged
``UFFD_USER_MODE_ONLY`` syscall users usable while preventing unprivileged
handlers for kernel-mode faults; if the syscall is not built at all, HDN reports
the same mitigation as unavailable-by-construction. ``/dev/userfaultfd`` remains
governed by ordinary device permissions for trusted virtualization and
checkpoint/restore services. QEMU proves the sealed status bit, the locked or
unavailable sysctl state, failed enable attempts, unprivileged kernel-fault UFFD
denial, and user-mode-only UFFD allowance or syscall absence.

HDN keeps selected io_uring attack-surface expansion paths behind the
``IO_URING_RESTRICTED_OP`` profile authority while leaving ordinary rings
available. The gate covers SQPOLL ring setup, which creates kernel-side
submission polling work, and selected privileged registration operations such
as worker affinity/limits, NAPI, zero-copy receive, user memory regions, and
BPF filters. QEMU proves unprivileged SQPOLL setup denial, denial event
emission, and denial of a restricted registration operation.

``CONFIG_SECURITY_HARDENING_EXPLOIT_MITIGATIONS`` locks
``/proc/sys/kernel/kptr_restrict`` at level ``2``. Kernel pointers printed
through ``%pK`` remain zeroed regardless of caller privilege, and the global
sysctl cannot be lowered by later admin writes. QEMU proves the locked sysctl
value, failed lowering attempts, and sealed status reporting.

``RAW_IO`` authority covers both raw port permission syscalls such as
``ioperm()``/``iopl()`` and character-device raw hardware access through
``/dev/mem``, ``/dev/port``, ``/dev/cpu/*/msr``, and
``/dev/cpu/*/cpuid``. Device files still retain the normal upstream capability
and lockdown checks; HDN adds the profile-level authority check.

``BLOCK_DEVICE_ACCESS`` authority covers direct userspace opens of block special
files. HDN checks this after normal VFS/block permission checks and before the
block driver open path, so raw device reads and writes require explicit service
authority while mounted filesystems and other in-kernel block users are not
gated by this policy. The QEMU smoke suite proves a restricted root profile
cannot open a raw block device and records the ``BLOCK_DEVICE_ACCESS`` event.

``BLOCK_DEVICE_ADMIN`` is separate: it gates block-device administration and
mutation commands after a process is allowed to open the device, including
partition table changes, discard/zeroout, zone management, block trace control,
block crypto key control, persistent reservation writes, driver-specific
fallback ioctls, and block io_uring discard. QEMU proves a profile with
``BLOCK_DEVICE_ACCESS`` but without ``BLOCK_DEVICE_ADMIN`` can query a raw
block device but cannot run an admin ioctl, and records the
``BLOCK_DEVICE_ADMIN`` denial event.

``IPC_ADMIN`` authority is a compatibility bypass for HDN's IPC
over-permission hardening. Without that authority, System V message queues,
semaphores, shared memory objects, and POSIX message queue files with broad
world or mismatched group access are denied to cross-uid or cross-gid callers
before the ordinary IPC owner capability fallback. The QEMU smoke suite proves
all three System V IPC object types and POSIX mqueue send/receive access by
creating root-owned mode ``0666`` objects and verifying that an unprivileged
uid cannot use them.

``PROTECT_SHM`` is a profile feature for System V shared memory. HDN stamps the
creator profile onto each shared-memory segment and denies ``shmat()`` from a
different profile when the creator profile enabled the feature, even if normal
SysV permissions would otherwise allow the attach. Same-profile attaches remain
allowed. The check uses the stable profile identifier recorded at creation time
rather than chasing the creator pid at attach time, so pid reuse and task exit do
not change the protected object boundary.

``TTY_INJECT`` authority gates terminal command-injection ioctls. Profiles
without that authority are denied ``TIOCSTI`` and VT ``TIOCLINUX`` before input
is injected or copied through the terminal path. When TTY injection hardening is
enabled, HDN also forces ``dev.tty.legacy_tiocsti`` and
``dev.tty.ldisc_autoload`` off and rejects later attempts to enable either
runtime knob. The QEMU smoke suite verifies the locked sysctl values, failed
enable attempts, both ioctl denials, and the corresponding event records.

``TTY_ACCESS`` authority gates inherited or preopened terminal descriptors.
Profiles without that authority may still use their controlling terminal, and
PTY masters remain available for terminal emulators and trusted brokers, but
reads, writes, and generic ioctls against another terminal are denied before the
line discipline or tty driver runs. A PTY's controlling-session leader and its
direct parent are also accepted as the native session endpoint and broker. This
lets an SSH or login broker perform terminal setup and cleanup without granting
generic terminal authority to the user profile. Establishing a controlling
terminal with ``TIOCSCTTY`` remains governed by the kernel's native
session-leader, ownership, and capability checks. The QEMU smoke suite verifies
denied unrelated-terminal read, write, and ioctl attempts, permitted
controlling-PTY acquisition and broker ioctl access, and the corresponding
event records.

``FUSE_MOUNT`` authority gates userspace-backed FUSE filesystems separately
from broad ``MOUNT_ADMIN`` authority. Profiles without it are denied FUSE and
FUSE block-device mount creation through both legacy and fd-based mount paths.
The QEMU smoke suite proves this with a root profile that can administer mounts
but cannot open a FUSE mount context.

``ROFS_RELAX`` authority gates attempts to make read-only mounts or read-only
superblocks writable again. Profiles without it can still make mounts
read-only, but cannot clear that invariant through legacy remount,
bind-remount, ``mount_setattr()``, or superblock reconfiguration paths. The QEMU
smoke suite proves both legacy remount and ``mount_setattr()`` denials. Profiles
with ``ENFORCE_READONLY_MOUNTS`` also deny new writable mounts through legacy
mount creation, fd-based mount creation, and writable mount-tree clones unless
they have ``ROFS_RELAX``. The QEMU smoke suite proves writable ``tmpfs`` denial
and read-only ``tmpfs`` allowance under that feature, plus a parent-scoped
updater exec path that enters a ``ROFS_RELAX`` profile and can create the
writable ``tmpfs`` mount. It also proves the product image path: a writable
mount exists before the enforcing policy is committed, ``hdn-rofs-apply`` runs
under a narrow ``MOUNT_ADMIN`` profile without ``ROFS_RELAX``, makes that mount
read-only, and a subsequent write-open fails with ``EROFS``. It also proves
``hdn-rofs-apply -f`` skips absent and non-mounted ``optional`` entries while
sealing a ``required`` mounted path from the same root-owned list. The brokered
image path is proved separately: ``hdn-admin-broker rofs-apply -f`` denies an
unapproved read-only mount list, refuses an approved-but-writable list in the
apply helper, accepts a safe product-approved list, transitions into the
narrow apply helper, and leaves the listed mount read-only with ``EROFS`` on
later write-open. It then proves the package/update path:
``hdn-rofs-transaction`` runs under a
``MOUNT_ADMIN`` + ``ROFS_RELAX`` profile, temporarily remounts the product path
writable, runs the worker command, reseals the mount read-only, and leaves a
post-transaction write-open failing with ``EROFS``. Cancellation is checked by
terminating the guardian while its worker is live and requiring the worker to
stop before the mount becomes read-only again. Normal completion is also
checked with a worker that tries to leave a background descendant behind; the
guardian adopts, stops, and reaps that process group before resealing. A
restricted read-only mount forces the legacy remount path and verifies that
``nosuid``, ``nodev``,
and ``noexec`` survive both the writable window and reseal. It also proves the brokered
path: ``hdn-admin-broker`` enters a product admin profile, accepts the typed
``rofs-transaction`` intent only when the mountpoint and worker are listed in
the broker allowlist, execs the transaction helper, and leaves the same
post-transaction ``EROFS`` invariant. The suite also proves an unapproved
worker is denied before it can update the sealed product mount, and that a
missing or writable broker allowlist fails closed before the same privileged
transaction can run. The broker's policy path is also smoke-tested: a signed
policy under the product-approved policy directory is committed through
``hdn-admin-broker policy-commit`` and rolled back through
``hdn-admin-broker policy-rollback``, while an otherwise valid signed policy
outside the approved policy directory is denied without staging or changing the
active generation. The prompt-handoff path is also smoke-tested with a separate
strict broker config: missing approval tokens, unsafe tokens, and tokens for
the wrong typed intent or an expired monotonic deadline are denied, while a
valid root-owned token for ``rofs-transaction`` allows the dry-run dispatch
path. The root-side issuer is also tested: unknown intents are rejected and a
valid issued token is accepted by the broker. In a real brokered ROFS
transaction, the token is consumed before dispatch so replay fails without
changing the sealed mount. The named image sealing facade is tested too:
unknown image seal names and unsafe image seal configs are denied without
sealing the test mount, while an approved image seal dry-run leaves the test
mount writable before the real image seal applies a broker-approved read-only
mount list and leaves writes failing with ``EROFS``. The named
prompt metadata facade is tested too: unknown prompt actions and unsafe prompt
metadata configs are denied, while an approved ``package-update`` action emits
stable title/message/consequence/risk metadata for a desktop prompt. The named
prompt session facade is tested too: unknown prompt actions, unsafe prompt
session configs, and failed authentication are denied before dispatch, while an
approved session authenticates, reaches the strict token-required broker,
updates the product mount, and reseals it read-only. Dry-run action preflight
through the prompt session skips authentication, validates the broker route,
cleans up the temporary approval token, and leaves the sealed mount unchanged.
The named prompt portal facade is tested too: unknown desktop actions and
unsafe portal configs are denied before session dispatch, while an approved
desktop action maps to ``package-update``, reaches prompt-session, updates the
product mount, and reseals it read-only. The stable desktop action facade is
tested too: unknown UI verbs and unsafe desktop action configs are denied
before prompt portal dispatch, while an approved ``updates.install`` verb maps
to the portal, authenticates, updates the product mount, and reseals it
read-only. The desktop daemon facade is tested too: unknown UI verbs and
unsafe daemon configs are denied before desktop-action dispatch, while an
approved stdio ``updates.install`` verb dry-runs without prompt or mount change
before the real request reaches desktop-action, authenticates, updates the
product mount, and reseals it read-only. The control-center facade is tested
too: product status is routed through ``hdn-status``, unknown UI verbs are
denied before daemon dispatch, and approved one-shot and stdio
``updates.install`` dry-runs leave the sealed mount unchanged before the real
action reaches the desktop daemon, authenticates, updates the product mount,
and reseals it read-only. The settings-panel facade is tested too: unknown
settings actions and unsafe settings configs are denied, while approved
``updates.install`` dry-run leaves the sealed mount unchanged before the real
action reaches control-center and reseals the mount. The settings UI facade is
tested too: unknown choices, unsafe UI configs, canceled selection, and
no-display sessions are denied, while approved ``updates.install`` dry-run
leaves the sealed mount unchanged before the real UI route reaches
settings-panel and reseals the mount. The named
post-auth prompt dispatch facade is tested too: unknown prompt actions and
unsafe prompt configs are denied, while an approved ``package-update`` action
creates a fresh approval token, reaches the strict token-required broker,
updates the product mount, and reseals it read-only. The named package/update
facade is tested too: unknown transaction
names and unsafe transaction configs are denied, while an approved
``package-update`` dry-run preflights the broker route without changing the
sealed mount before the real entry updates the product mount through the broker
and reseals it read-only. The package-manager hook facade is tested too:
unknown hook names and unsafe hook configs are denied, while an approved
``package-update`` hook dry-run reaches the named transaction backend without
changing the sealed mount before the real hook preserves the same read-only
reseal invariant. The shipped package-manager hook snippets are
tested too: the APT/dpkg hook, pacman/libalpm hook, DNF 4 action, DNF5/libdnf5
action, and image-seal systemd unit all point at stable ``hdn-package-hook``
actions. The package-manager snippets invoke ``image-seal-default`` after a
transaction instead of recursively starting another package transaction.
``hdn-package-worker`` is the fixed-operation DNF5 worker used inside the
approved writable-mount window. Its default/``update`` mode runs a refreshed
upgrade; ``repair`` runs a refreshed ``distro-sync``. It rejects other modes,
sanitizes its environment, and marks the nested DNF transaction so its post
hook leaves resealing to the outer broker transaction. If ``/boot`` or
``/boot/efi`` is a separate read-only mount, the worker opens each through a
nested fixed-path transaction before DNF and reseals them in reverse order.
PackageKit and the DNF daemon are quiesced on both sides of DNF and policy
refresh; host tests verify those exact fixed service names without touching
host services. The host authorization test exercises this complete nesting
for update and repair operations. Contained chroot file-handle
open is denied, and contained chroot mount denial is tested with a profile that
can mount outside the chroot but is denied after ``chroot()``. The event
decoder names both the ``CHROOT_FILE_HANDLE`` and ``CHROOT_MOUNT`` reasons.
The recovery facade is smoke-tested as well: unknown
actions and unsafe recovery configs are denied, an approved
``policy-rollback`` dry-run leaves the active generation unchanged before the
real action rolls the policy back through the broker, and an approved
``package-repair`` dry-run preflights the named transaction backend without
changing the sealed mount before the real action runs the named package
transaction and reseals the product mount read-only. The recovery metadata
facade is tested too: unknown recovery actions and unsafe metadata configs are
denied, while an approved ``policy-rollback`` action emits stable
title/message/consequence/risk metadata for recovery UI. The recovery session
facade is tested too: unknown actions, unsafe session configs, and failed
confirmation are denied before repair work, while approved ``policy-rollback``
and ``package-repair`` sessions dry-run without confirmation or protected-state
mutation before the real sessions describe the action, confirm it, run the
named recovery action, and preserve the rollback or read-only reseal invariant.
Host authorization tests also prove unprivileged ``--authorized`` calls fail at
the panel, portal, and session layers while the root path skips the fallback
confirmation and reaches only the mapped action.
The recovery portal facade is tested too: unknown recovery UI actions and
unsafe portal configs are denied before session dispatch, while approved
``repair-system`` and ``rollback-policy`` actions map to recovery-session,
preserve rollback behavior, and dry-run without confirmation or protected-state
mutation before real repair reseals the product mount read-only. The recovery
panel facade is tested too: unknown panel actions and unsafe panel configs are
denied before metadata or portal dispatch, while approved ``repair-system`` and
``rollback-policy`` actions expose stable metadata, preflight portal routes,
and preserve rollback behavior before real actions run. The recovery UI facade
is tested too: unknown UI choices and unsafe UI configs are denied, no-display
sessions and canceled selections fail closed before mutation, and approved
``rollback-policy`` dry-run plus real selection reaches recovery-panel while
preserving rollback behavior. The shipped
``readonly-mounts.conf`` is a product baseline: ``/usr`` uses an explicit
self-bind when it is not already a mountpoint, while
``/boot``, ``/boot/efi``, ``/opt``, ``/usr/local``,
``/var/lib/flatpak``, and ``/var/lib/snapd`` are optional mounted
filesystems. Real distro images can tailor it further, but should leave
mutable state such as ``/var``, ``/home``, ``/run``, and ``/tmp`` out unless
they provide an overlay or updater/recovery profile.

Credential changes are mediated before commit. A non-exec credential change
that widens privilege, such as gaining root IDs, joining a different user
namespace, or gaining permitted, effective, inheritable, bounding, or ambient
capabilities, requires the current profile's ``CRED_CHANGE`` authority.
Privileged exec transitions are checked against the target exec profile before
the new executable commits credentials, so setuid, setgid, and file-capability
helpers need an explicit target profile that carries ``CRED_CHANGE``. The QEMU
smoke suite verifies both sides of this contract with setuid-root and
file-capability helpers: valid transitions land in the privileged profile,
while otherwise identical transitions are denied when the target profile lacks
``CRED_CHANGE``. Profiles can also set ``DENY_UNPRIVILEGED_PRIVEXEC`` to block
ordinary users from executing privileged helpers at all; the dedicated QEMU
policy grants ``CRED_CHANGE`` and still proves setuid-root and file-capability
exec denial with ``HDN_REASON_UNPRIVILEGED_PRIVEXEC``.
The shipped daily-driver default policy grants ``CRED_CHANGE`` to profile 1 so
privilege-dropping service managers and daemons keep working out of the box;
confined product profiles can remove that grant when they need a tighter
subject.

When ``CONFIG_SECURITY_HARDENING_SUID_SPECTRE`` is enabled, privileged helpers
launched by non-root callers also force upstream user-controllable speculation
controls to their permanent disabled state. This covers the prctl-managed
Speculative Store Bypass and indirect-branch controls used by upstream x86
Spectre mitigations; CPUs that report a control as not affected remain treated
as already safe. The QEMU smoke suite boots with ``spectre_v2_user=prctl`` and
``spec_store_bypass_disable=prctl``, tries to re-enable both controls before a
setuid-root exec, and verifies every prctl-managed control exposed by the CPU is
force-disabled. Controls reported as not affected, unsupported, or not
prctl-managed are treated as not applicable to that CPU model.

When ``CONFIG_SECURITY_HARDENING_SETXID`` is enabled, a multithreaded process
that drops from root real uid to a non-root real uid queues the committed
credential for sibling threads through fixed per-task work. Sibling threads
only apply the pending credential while they are still on the original root
credential state, so the propagation preserves ordinary kernel credential
ordering while preventing one thread from retaining root after another thread
has performed the process-level drop. The QEMU smoke suite proves a
root-to-nobody uid/gid drop in one thread becomes visible in its sibling thread.

Repeated crash signals from privileged exec transitions are throttled by file
identity, target profile, and uid. After a short burst of crashes from the same
setuid or file-capability helper, later attempts to execute that helper are
temporarily denied before credentials commit and emit
``HDN_REASON_BRUTE_THROTTLED``. This is intended to make brute-force probing of
privileged helpers noisy and self-limiting without involving a userspace
prompt. The QEMU smoke suite proves this by crashing a setuid-root helper three
times as an unprivileged uid and verifying the next exec is denied.

Privileged exec lineage is tracked across later execs in the process mm. When
``fs.suid_dumpable`` is disabled, a descendant of a privileged helper that
becomes dumpable again is still denied ``SIGXCPU``/``SIGXFSZ`` coredumps before
core-file creation. The exploit-mitigation baseline keeps
``fs.suid_dumpable`` locked at ``0`` so setuid-core modes cannot be enabled
globally after boot. The denial emits a ``COREDUMP`` event with
``HDN_REASON_PRIVILEGED_DESCENDANT_COREDUMP`` and the signal number in
``object``. The QEMU smoke suite proves this by entering a setuid-root helper,
dropping back to an unprivileged uid, execing a normal binary, forcing
dumpability, verifying the ``SIGXFSZ`` core is blocked, and proving the
``fs.suid_dumpable`` sysctl value cannot be raised.

``securityfs/hardening/events`` exposes one text record per hardening event.
Each record includes ``event_id``, ``authority``, ``transition``, ``action``,
``reason``, ``subject``, ``object``, and ``flags``. ``event_id`` is the stable
broker/logging identifier for the gate class and mirrors the public
``HDN_EVENT_ID_*`` UAPI values. ``subject`` is the current task ID. ``object``
is gate-specific low-cost identity: target PID for ptrace, inode for
file-backed module or memory events, generation for policy transactions,
target profile for namespace/profile crossings, address for anonymous memory
and sealed-data write faults,
USB bus/port for device attachment, socket family/type/protocol for socket
creation gates, socket family/type/port/IPv4 address for IPv4 client/server
endpoint gates, socket family/type/port/address-hash for IPv6 client/server
endpoint gates, POSIX mqueue inode for mqueue hardening, severe signal number
and fault address for signal audit events, or the operation-specific numeric
value for BPF, perf, namespace creation, time mutation, and resource limit
changes. Failed fork attempts use ``HDN_REASON_FORK_FAILED`` and carry the
specific rejection errno in the event ``error`` field. Protected symlink,
hardlink, FIFO, and regular-file sticky-directory denials use the
``FS_PROTECTION`` transition with dedicated ``HDN_REASON_PROTECTED_*`` reason
names and the protected inode number in ``object``. Resource pressure events
pack the resource number into the high 8 bits
of ``object`` and a capped requested value into the low 56 bits.
``PROCESS_ACCOUNT`` events carry the raw kernel exit status in ``object``.
``COREDUMP`` denials for privileged descendants carry the fatal signal number
in ``object``.
``flags`` carries explicit event modifiers such as
``HDN_EVENT_RESPONSE_KILL_TASK`` for kill-response denials and
``HDN_EVENT_CHROOTED`` for exec audit events emitted by chrooted tasks. Chroot
containment denials use dedicated ``HDN_REASON_CHROOT_*`` values for
operation-level log routing without cloning grsecurity sysctl names, including
``HDN_REASON_CHROOT_MOUNT`` for mount attempts from contained chroots and
``HDN_REASON_CHROOT_FILE_HANDLE`` for file-handle based opens from contained
chroots, and ``HDN_REASON_CHROOT_SYSCTL`` for proc-sysctl writes from contained
chroots. Failed fork attempts use ``HDN_REASON_FORK_FAILED``.
``hdn-event-decode`` maps the numeric ``event_id``, ``authority``,
``transition``, ``action``, ``reason``, and flag fields to UAPI names for
desktop notification and log-export consumers. It also maps common packed
``object`` payloads to named details for exec arguments, severe signals,
coredumps, resources, time changes, USB devices, and socket operations. The
``--follow`` mode de-duplicates repeated ring snapshots by monotonic sequence;
``hdn-audit.service`` enables it after the signed policy loader and persists
the decoded stream through journald. The
QEMU smoke suite proves the decoder can identify a W+X denial by decoded
``USER_WX_MAPPING`` reason and ``DENY_AUDIT`` action, a severe signal audit
event by decoded ``SIGNAL`` transition, packed event object details from a
synthetic fixture, a remote process-memory denial by decoded
``PROCESS_MEMORY`` authority, a remote page-migration denial by decoded
``MEMORY_MIGRATE`` authority, a remote file-descriptor extraction denial by
decoded ``PROCESS_FD`` authority, a failed fork audit event by decoded
``FORK_FAILED`` reason, a process-accounting audit event by decoded
``PROCESS_ACCOUNT`` transition, plus
filesystem protection audit by decoded ``FS_PROTECTION`` transition and
``PROTECTED_SYMLINK`` reason, plus contained chroot mount and file-handle
denials by their decoded reason names, and contained chroot sysctl denial by
decoded ``CHROOT_SYSCTL`` reason.

``hdn-status`` maps raw status lines to product-facing state for UI and support
tooling: ``state``, ``attention``, ``attention_reason``, policy phase, rule
count, mitigation totals, and audit-flood suppression state. It also decodes
the most recent flood-suppressed action, authority, transition, and reason to
the same UAPI names used by the event decoder. The QEMU smoke suite proves live
status reporting and a synthetic audit-flood fixture with decoded
``DENY_AUDIT``, ``USB_MONITOR``, and ``RESOURCE_PROFILE_LIMIT`` names. The
``hdn-control-center status`` facade is covered as the intended desktop entry
point above ``hdn-status``.

Repeated identical event keys are flood-controlled before they can churn the
fixed securityfs ring or kernel diagnostics. The first events in a burst remain
visible; later repetitions within the window are suppressed and counted in
``securityfs/hardening/status`` under ``audit_flood_suppressed_total`` and the
``audit_flood_last_*`` fields. The QEMU smoke suite proves this by triggering a
W+X denial burst and checking that the suppressed counter increases.

Exec rules attach profiles from file identities. The policy compiler accepts
path syntax for product policy inputs and raw inode syntax for deterministic
package-manager output::

  exec 3 path /usr/bin/example
  exec 3 path /usr/bin/example verity sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  exec 3 inode 8 1 123456
  exec 3 verity FS_VERITY_HASH_ALG_SHA256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  exec 3 interpreter-path /usr/bin/python3 original-path /opt/app/main.py
  exec 3 interpreter 8 1 111 original 8 1 222 verity sha512 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f parent 1
  exec inherit path /usr/bin/helper parent 3 audit-inherit

Exec path rules are kept in the signed policy payload and resolved inside the
target kernel when the policy is loaded. The staged policy is then sealed with
the resolved superblock device major/minor and inode number, so a policy can be
built away from the target root filesystem while runtime enforcement still uses
exact file identity. Raw ``inode`` rules bypass path resolution and use the
provided identity directly. Interpreter rules require both the final
interpreter identity and the original script/app identity so executing the
interpreter directly does not inherit the script profile. Verity rules match
the final executable file's fs-verity digest as reported by the kernel. The
algorithm accepts ``sha256``, ``sha512``, the ``FS_VERITY_HASH_ALG_*`` names,
or the numeric UAPI value. ``exec inherit`` rules match executable identity like
normal exec rules but leave the caller in its current profile; the optional
``parent PROFILE`` clause scopes that inheritance to a caller profile. The QEMU
``audit-inherit`` option records a stable ``EXEC_INHERIT`` allow-audit event
only after a matching inherited exec commits; it is rejected on non-inherit
rules. The QEMU smoke suite carries policies proving direct binary matches,
unmatched copies, interpreter/script matches, exec-profile inheritance,
parent-scoped inheritance, signed profile-wide inheritance for runtime-mounted
sandbox payloads, unmatched parent-scoped defaults, and replacement of a
trusted path after policy load, plus inherited-exec audit decoding and
post-rollback silence.

Module rules are a separate trust table for ``finit_module()``. A caller needs
``MODULE_LOAD`` authority and the module file must match a rule for the
caller's current profile once an active hardening policy is loaded. This means
signed but unknown modules are denied until the policy manager installs a trust
record. Implicit kernel autoload requests use the separate
``MODULE_AUTOLOAD`` authority before modprobe is invoked, so product policy can
distinguish explicit package-manager module installation from request_module()
alias expansion. One-argument ``request_module(name)`` calls are routed as
exact aliases instead of treating ``name`` as a printf format string; formatted
requests must pass explicit arguments. Authorized modprobe helpers also receive
bounded HDN context in their environment: ``HDN_MODULE_REQUEST`` carries the
resolved alias, ``HDN_MODULE_UID`` and ``HDN_MODULE_EUID`` carry the requesting
credentials in the initial user namespace, and ``HDN_MODULE_PROFILE`` carries
the current HDN profile id. Supported syntax is::

  module 2 path /lib/modules/example.ko
  module 2 path /lib/modules/example.ko verity sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  module 2 inode 8 1 123456
  module 2 verity FS_VERITY_HASH_ALG_SHA256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  module 2 signed
  module 2 path /lib/modules/example.ko signed

Module path rules follow the same load-time resolution model as exec path
rules: the signed path is resolved inside the target kernel and the sealed
policy enforces the resulting superblock device major/minor plus inode
identity. Raw ``inode`` module rules use the provided identity directly. Verity
module rules match the module file digest as reported by fs-verity. A
``signed`` rule delegates module identity to the kernel's enforced module
signature keyring; HDN permits the request only when signature enforcement is
active, and the normal module loader then performs the cryptographic check.
It can be combined with path or verity matching when both constraints are
required. This lets a product admit all modules signed by its kernel build key
without thousands of inode rules while unsigned or untrusted-key modules still
fail in the ordinary module loader. The QEMU
smoke suite proves both sides of module path identity by allowing one named
invalid module file to reach the upstream module parser, then replacing that
path after policy load and verifying the new inode is denied by HDN.

Firmware rules are a separate trust table for firmware requested by drivers. A
caller needs ``FIRMWARE_LOAD`` authority and the requested firmware name must
match a rule for the caller's current profile once an active hardening policy is
loaded. The match is the exact firmware request name before filesystem fallback
paths or compression suffixes are searched::

  firmware 2 name iwlwifi/example.ucode
  firmware 2 any

``firmware PROFILE any`` is an explicit signed-policy delegation for product
profiles whose firmware search tree is controlled by the immutable system
image. Confined profiles can continue to use exact-name records.

The QEMU smoke suite uses the upstream ``test_firmware`` driver to trigger real
``request_firmware()`` calls. It proves a trusted firmware name reaches the
filesystem loader and an otherwise present but untrusted firmware name is denied
by HDN with the untrusted-firmware reason.

After loading a policy, the policy manager should seal normal runtime mutation
with::

  echo runtime | sudo tee /sys/kernel/security/hardening/phase

Phase changes use the same capability plus ``POLICY_ADMIN`` authority check as
policy load, commit, and rollback. Runtime can move to ``recovery`` for
controlled repair or rollback, but it cannot move back to the normal
policy-load phase. The QEMU smoke suite commits a canary policy before sealing
runtime, verifies normal mutation is rejected, enters recovery, rolls back to
the previous active generation, confirms earlier events remain available, and
reseals runtime.
