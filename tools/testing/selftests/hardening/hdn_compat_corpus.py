#!/usr/bin/python3 -I
# SPDX-License-Identifier: GPL-2.0-only
"""Disposable guest integration driver; requires an empty fs-verity work directory.

The running test kernel must trust the supplied test-only signing certificate.
Never run on a host: this replaces the guest policy and does not restore it.
"""
import argparse
import concurrent.futures
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess

ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}
FS = Path("/sys/kernel/security/hardening")


def run(*args, ok=True):
    result = subprocess.run([str(a) for a in args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=45, env=ENV)
    if ok and result.returncode:
        raise RuntimeError(f"command failed: {args[0]}: {result.stderr.decode(errors='replace')[:2048]}")
    return result


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    try:
        if os.write(fd, data) != len(data):
            raise RuntimeError("short securityfs write")
    finally:
        os.close(fd)


class Target:
    def __init__(self, path):
        self.process = subprocess.Popen([str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, env=ENV, bufsize=0)
        assert self.line() == b"READY\n"

    def line(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            if not selector.select(10):
                raise RuntimeError("target response timeout")
            result = self.process.stdout.readline(128)
            if not result:
                raise RuntimeError("target exited before response")
            return result

    def check(self, command, allowed):
        self.process.stdin.write(command.encode())
        response = self.line().decode().split()
        assert response[0] == command
        value = int(response[1])
        assert value == 0 if allowed else value in (errno.EPERM, errno.EACCES), response

    def close(self):
        self.process.stdin.write(b"q")
        self.process.wait(timeout=10)
        assert self.process.returncode == 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("work", "tools", "target", "sign-file", "kernel-key", "kernel-cert",
                 "source-gate", "build-gate"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    assert os.environ.get("HDN_DISPOSABLE_VM") == "COMPATIBILITY" and os.geteuid() == 0
    assert "hdn.compat_fixture=1" in Path("/proc/cmdline").read_text().split()
    assert a.work.is_absolute() and a.work.is_dir() and not list(a.work.iterdir())
    source_gate = json.loads(a.source_gate.read_text())
    build_gate = json.loads(a.build_gate.read_text())
    assert source_gate["schema_version"] == 1 and build_gate["schema_version"] == 1
    status = dict(line.split(": ", 1) for line in (FS / "status").read_text().splitlines() if ": " in line)
    assert status["phase"] == "policy_load" and status["policy_loaded"] == "0"
    assert status["compatibility_intent_version"] == "1"
    assert status["compatibility_binding_version"] == "1"
    assert status["application_compatibility"] == "approval-required"
    assert status["application_remediation"] == "restart-then-update-application"
    w = a.work
    target = w / "application"
    shutil.copyfile(a.target, target)
    target.chmod(0o755)
    measured = run(a.target, "--enable-verity", target).stdout.decode().strip()
    abi = json.loads(run(a.tools / "hdn-compat-abi").stdout)
    for name in ("publisher", "authority", "wrong"):
        run("/usr/bin/openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=HDN disposable compatibility fixture",
            "-keyout", w / (name + ".key"), "-out", w / (name + ".pem"))
    publisher_der = run("/usr/bin/openssl", "x509", "-in", w / "publisher.pem", "-outform", "DER").stdout
    policy_text = """generation 1
base 0
default 1
privileged 2
profile 1 default
profile 2 fixture-controller
profile 100 approved-application
profile 101 approved-fixed-application
profile 102 approved-combined-application
allow 1 CRED_CHANGE
allow 2 POLICY_ADMIN CRED_CHANGE MOUNT_ADMIN NAMESPACE_ADMIN USERNS_CREATE SIGNAL
allow 2 RESOURCE_ADMIN PROCESS_FD PROC_TASK_VIEW PROC_DISCLOSE
allow 100 CRED_CHANGE
allow 101 CRED_CHANGE
allow 102 CRED_CHANGE
mem 100 ALLOW_JIT_EXEC_AFTER_WRITE
mem 101 ALLOW_FIXED_ANON_EXEC
mem 102 ALLOW_FIXED_ANON_EXEC ALLOW_JIT_EXEC_AFTER_WRITE
"""
    (w / "base.policy").write_text(policy_text)
    run(a.tools / "hdn-policy", w / "base.policy", w / "base.hdn")
    base = (w / "base.hdn").read_bytes()
    size = abi["records"]["profile"]["size"]
    profiles = {profile_id: base[abi["header"]["size"] + index * size:
                                 abi["header"]["size"] + (index + 1) * size]
                for index, profile_id in enumerate((1, 2, 100, 101, 102))}
    manifest = {"schema": 1, "kind": "hdn.compat.package", "package": {"name": "fixture", "version": "1", "release": "1"},
                "policy_generation": 1, "executables": [{"path": str(target), "sha256": sha(target.read_bytes()),
                "verity": {"algorithm": "sha256", "digest": measured}, "intents": ["jit-private"]}]}
    approvals = {"schema": 1, "kind": "hdn.compat.approvals", "package": manifest["package"], "policy_generation": 1,
                 "publisher_sha256": sha(publisher_der), "base_policy_sha256": sha(base), "bindings": [
                     {"path": str(target), "profile_id": 100, "parent_profile_id": 2,
                      "profile_sha256": sha(profiles[100]), "intents": ["jit-private"]}]}
    results = []

    def sign_document(data, name, key, digest="sha256"):
        document, signature = w / (name + ".json"), w / (name + ".cms")
        document.write_bytes(data)
        run("/usr/bin/openssl", "cms", "-sign", "-binary", "-md", digest, "-in", document,
            "-signer", w / (key + ".pem"), "-inkey", w / (key + ".key"), "-outform", "DER", "-out", signature)
        return document, signature

    approved_file, approved_sig = sign_document(json.dumps(approvals).encode(), "approvals", "authority")

    def compile_case(name, content, success, key="publisher", approval=approved_file, signature=approved_sig,
                     digest="sha256", publisher_cert="publisher", authority_cert="authority"):
        raw = content if isinstance(content, bytes) else json.dumps(content).encode()
        document, signed = sign_document(raw, name, key, digest)
        output = w / (name + ".hdn")
        result = run(a.tools / "hdn-compat", "compile", "--manifest", document, "--manifest-signature", signed,
                     "--publisher-cert", w / (publisher_cert + ".pem"), "--approvals", approval,
                     "--approvals-signature", signature, "--authority-cert", w / (authority_cert + ".pem"),
                     "--base-policy", w / "base.hdn", "--image-root", "/", "--output", output, ok=False)
        (w / (name + ".log")).write_bytes(result.stdout + result.stderr)
        assert (result.returncode == 0) == success, (name, result.stderr)
        assert output.exists() == success
        results.append({"case": name, "pass": True})
        return output

    def signed_approval(name, value, key="authority"):
        return sign_document(json.dumps(value).encode(), name + "-approval", key)

    unsigned = compile_case("valid", manifest, True)
    compile_case("wrong-signer", manifest, False, key="wrong")
    compile_case("weak-content-digest", manifest, False, digest="sha1")
    publisher_approval, publisher_approval_sig = signed_approval(
        "same-identity", approvals, "publisher")
    compile_case("same-publisher-and-authority", manifest, False,
                 approval=publisher_approval, signature=publisher_approval_sig,
                 authority_cert="publisher")

    for name, intent_set, profile_id in (
        ("supported-fixed-private", ["fixed-private-code"], 101),
        ("supported-combined-private", ["fixed-private-code", "jit-private"], 102),
    ):
        supported_manifest = copy.deepcopy(manifest)
        supported_manifest["executables"][0]["intents"] = intent_set
        supported_approvals = copy.deepcopy(approvals)
        supported_approvals["bindings"][0].update(
            profile_id=profile_id, profile_sha256=sha(profiles[profile_id]),
            intents=intent_set)
        approval_file, approval_sig = signed_approval(name, supported_approvals)
        compile_case(name, supported_manifest, True, approval=approval_file,
                     signature=approval_sig)
    for name, modify in (
        ("unknown-version", lambda m: m.update(schema=2)),
        ("unknown-field", lambda m: m.update(disable_kernexec=True)),
        ("old-package", lambda m: m["package"].update(version="0")),
        ("old-generation", lambda m: m.update(policy_generation=2)),
        ("wrong-content", lambda m: m["executables"][0].update(sha256="0" * 64)),
        ("wrong-verity", lambda m: m["executables"][0]["verity"].update(digest="0" * 64)),
        ("wx", lambda m: m["executables"][0].update(intents=["writable-executable"])),
        ("ambient-group", lambda m: m.update(group=0)),
        ("emulate-trampoline", lambda m: m["executables"][0].update(intents=["emulate-trampoline"])),
        ("emulate-signal-restorer", lambda m: m["executables"][0].update(intents=["emulate-signal-restorer"])),
        ("emulate-plt", lambda m: m["executables"][0].update(intents=["emulate-plt"])),
        ("emulate-resolver", lambda m: m["executables"][0].update(intents=["emulate-resolver"])),
    ):
        changed = copy.deepcopy(manifest)
        modify(changed)
        compile_case(name, changed, False)
    compile_case("duplicate-field", json.dumps(manifest).replace('"schema": 1', '"schema": 1, "schema": 1').encode(), False)

    for name, modify in (
        ("approval-unknown-version", lambda value: value.update(schema=2)),
        ("approval-unknown-field", lambda value: value.update(global_disable=True)),
        ("approval-old-package", lambda value: value["package"].update(release="0")),
        ("approval-old-generation", lambda value: value.update(policy_generation=2)),
        ("approval-wrong-publisher", lambda value: value.update(publisher_sha256="0" * 64)),
        ("approval-wrong-base", lambda value: value.update(base_policy_sha256="0" * 64)),
        ("approval-wrong-path", lambda value: value["bindings"][0].update(path=str(w / "other"))),
        ("approval-wrong-profile", lambda value: value["bindings"][0].update(profile_sha256="0" * 64)),
        ("approval-broader-intent", lambda value: value["bindings"][0].update(intents=["fixed-private-code"])),
        ("approval-duplicate-binding", lambda value: value["bindings"].append(copy.deepcopy(value["bindings"][0]))),
        ("approval-missing-binding", lambda value: value.update(bindings=[])),
    ):
        changed = copy.deepcopy(approvals)
        modify(changed)
        approval_file, approval_sig = signed_approval(name, changed)
        compile_case(name, manifest, False, approval=approval_file, signature=approval_sig)
    duplicate_approval = json.dumps(approvals).replace(
        '"schema": 1', '"schema": 1, "schema": 1').encode()
    duplicate_approval_file, duplicate_approval_sig = sign_document(
        duplicate_approval, "approval-duplicate-field-approval", "authority")
    compile_case("approval-duplicate-field", manifest, False,
                 approval=duplicate_approval_file, signature=duplicate_approval_sig)
    wrong_approval_file, wrong_approval_sig = signed_approval(
        "approval-wrong-signer", approvals, "wrong")
    compile_case("approval-wrong-signer", manifest, False,
                 approval=wrong_approval_file, signature=wrong_approval_sig)
    weak_approval_file, weak_approval_sig = sign_document(
        json.dumps(approvals).encode(), "approval-weak-digest-approval",
        "authority", "sha1")
    compile_case("approval-weak-digest", manifest, False,
                 approval=weak_approval_file, signature=weak_approval_sig)
    renamed = w / "renamed"
    target.rename(renamed)
    compile_case("renamed", manifest, False)
    target.symlink_to(renamed)
    compile_case("symlink", manifest, False)
    target.unlink()
    renamed.rename(target)
    try:
        with target.open("r+b") as stream:
            stream.write(b"x")
    except OSError as error:
        assert error.errno in (errno.EPERM, errno.EACCES, errno.ETXTBSY)
    else:
        raise RuntimeError("fs-verity image was writable")

    signed_policy = w / "valid.signed"
    run(a.sign_file, "sha256", a.kernel_key, a.kernel_cert, unsigned, signed_policy)
    write(FS / "policy", signed_policy.read_bytes())
    write(FS / "commit", b"1\n")
    unchanged_namespace = run("/usr/bin/unshare", "--mount", "--fork",
                              target, "--transition", ok=False)
    assert unchanged_namespace.returncode == 0, unchanged_namespace.stderr
    container_alias = w / "flatpak-boundary" / "application"
    container_alias.parent.mkdir()
    container_alias.touch(mode=0o755)
    remounted = run(
        "/usr/bin/unshare", "--mount", "--fork", "/bin/sh", "-eu", "-c",
        'mount --bind "$1" "$2"; exec "$2" --transition',
        "hdn-compat-boundary", target, container_alias, ok=False)
    assert remounted.returncode in (errno.EPERM, errno.EACCES) and not remounted.stderr, remounted.stderr
    results.append({"case": "container-and-Flatpak-path-boundary", "pass": True})
    running = Target(target)
    running.check("a", True)
    running.check("f", True)
    running.check("w", False)
    target.rename(renamed)
    running.check("a", False)
    renamed.rename(target)
    running.check("a", False)
    running.close()
    results.append({"case": "package-install-execution-fork-wx-rename-latched", "pass": True})
    running = Target(target)
    running.check("a", True)
    replacement = w / "replacement"
    shutil.copyfile(target, replacement)
    replacement.chmod(0o755)
    run(a.target, "--enable-verity", replacement)
    replacement.replace(target)
    running.check("a", False)
    running.close()
    running = Target(target)
    running.check("a", False)
    running.close()
    write(FS / "phase", b"runtime\n")
    write(FS / "refresh", signed_policy.read_bytes())
    running = Target(target)
    running.check("a", True)
    write(FS / "refresh", signed_policy.read_bytes())
    running.check("a", False)
    running.close()
    results.append({"case": "package-upgrade-replacement-rebind-publication-expiry", "pass": True})
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        for _ in range(16):
            future = pool.submit(Target, target)
            write(FS / "refresh", signed_policy.read_bytes())
            running = future.result(timeout=15)
            write(FS / "refresh", signed_policy.read_bytes())
            running.check("a", False)
            running.close()
    results.append({"case": "concurrent-launch-refresh-expiry", "pass": True})
    write(FS / "phase", b"recovery\n")
    write(FS / "rollback", b"1\n")
    write(FS / "policy", signed_policy.read_bytes())
    write(FS / "commit", b"1\n")
    running = Target(target)
    running.check("a", False)
    running.close()
    results.append({"case": "package-rollback-no-old-grant", "pass": True})
    report = {"schema": 1, "passed": results, "policy_sha256": sha(unsigned.read_bytes()),
              "target_sha256": sha(target.read_bytes()), "kernel_release": os.uname().release,
              "architecture": os.uname().machine,
              "source_gate_sha256": sha(a.source_gate.read_bytes()),
              "build_gate_sha256": sha(a.build_gate.read_bytes()),
              "remaining_qualification": ["cross-architecture", "package-manager-transaction", "desktop-rendering", "performance"]}
    (w / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
