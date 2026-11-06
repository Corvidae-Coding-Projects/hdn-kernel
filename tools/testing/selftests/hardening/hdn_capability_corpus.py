#!/usr/bin/python3 -I
# SPDX-License-Identifier: GPL-2.0-only
"""Disposable signed-policy corpus for architecture capability requirements."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess

ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
FS = Path("/sys/kernel/security/hardening")
SATISFIES = {"enforced", "not-applicable"}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args, ok=True):
    result = subprocess.run([str(arg) for arg in args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, timeout=30)
    if ok and result.returncode:
        raise RuntimeError(f"command failed: {args[0]}: {result.stderr.decode(errors='replace')[:2048]}")
    return result


def status():
    return dict(line.split(": ", 1) for line in (FS / "status").read_text().splitlines()
                if ": " in line)


def write(path, data, accepted):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
        try:
            count = os.write(fd, data)
            if count != len(data):
                raise RuntimeError("short securityfs write")
        finally:
            os.close(fd)
    except OSError as error:
        if accepted or error.errno not in (errno.EINVAL, errno.EOPNOTSUPP, errno.EPERM):
            raise
        return error.errno
    if not accepted:
        raise RuntimeError("capability requirement unexpectedly accepted")
    return 0


def policy_text(generation, base, requirements=()):
    required = "".join(f"require-capability {name}\n" for name in requirements)
    return f"""generation {generation}
base {base}
{required}default 1
privileged 2
profile 1 default
profile 2 fixture-controller
allow 1 CRED_CHANGE
allow 2 POLICY_ADMIN CRED_CHANGE
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("work", "tools", "sign-file", "kernel-key", "kernel-cert",
                 "source-gate", "build-gate"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("HDN_DISPOSABLE_VM") == "ARCH-CAPABILITY"
    assert os.geteuid() == 0 and "hdn.arch_capability_fixture=1" in Path("/proc/cmdline").read_text().split()
    assert args.work.is_absolute() and args.work.is_dir() and not list(args.work.iterdir())
    source_gate = json.loads(args.source_gate.read_text())
    build_gate = json.loads(args.build_gate.read_text())
    assert source_gate["schema_version"] == 1 and build_gate["version"] == 1
    initial = status()
    assert initial["phase"] == "policy_load" and initial["policy_loaded"] == "0"
    assert initial["capability_version"] == "1"
    capabilities = {
        key.removeprefix("capability."): value.split(",", 1)[0]
        for key, value in initial.items() if key.startswith("capability.")
    }
    assert capabilities and all(state in {
        "undeclared", "unsupported", "disabled", "initializing", "degraded",
        "enforced", "not-applicable"} for state in capabilities.values())
    results = []

    def compile_policy(name, text, accepted=True):
        source = args.work / (name + ".policy")
        unsigned = args.work / (name + ".hdn")
        signed = args.work / (name + ".signed")
        source.write_text(text)
        result = run(args.tools / "hdn-policy", source, unsigned, ok=False)
        if (result.returncode == 0) != accepted or unsigned.exists() != accepted:
            raise RuntimeError(name + " compiler disposition mismatch")
        if not accepted:
            results.append({"case": name, "pass": True})
            return None, None
        run(args.sign_file, "sha256", args.kernel_key, args.kernel_cert, unsigned, signed)
        return unsigned, signed

    for name, state in capabilities.items():
        _, signed = compile_policy("require-" + name, policy_text(1, 0, (name,)))
        accepted = state in SATISFIES
        error = write(FS / "policy", signed.read_bytes(), accepted)
        results.append({"case": "require-" + name, "state": state,
                        "accepted": accepted, "errno": error, "pass": True})

    first = next(iter(capabilities))
    compile_policy("duplicate-requirement",
                   policy_text(1, 0, (first, first)), accepted=False)
    compile_policy("unknown-requirement",
                   policy_text(1, 0) + "require-capability unknown-invariant\n",
                   accepted=False)

    zero_unsigned, zero_signed = compile_policy("unconstrained-generation-1",
                                                policy_text(1, 0))
    abi = json.loads(run(args.tools / "hdn-compat-abi").stdout)
    flags_offset, flags_size = abi["header"]["fields"]["flags"]
    malformed = bytearray(zero_unsigned.read_bytes())
    flags = int.from_bytes(malformed[flags_offset:flags_offset + flags_size], abi["byteorder"])
    malformed[flags_offset:flags_offset + flags_size] = (flags | (1 << 31)).to_bytes(
        flags_size, abi["byteorder"])
    unknown_unsigned = args.work / "unknown-mask.hdn"
    unknown_signed = args.work / "unknown-mask.signed"
    unknown_unsigned.write_bytes(malformed)
    run(args.sign_file, "sha256", args.kernel_key, args.kernel_cert,
        unknown_unsigned, unknown_signed)
    write(FS / "policy", unknown_signed.read_bytes(), False)
    results.append({"case": "unknown-capability-mask", "pass": True})

    write(FS / "policy", zero_signed.read_bytes(), True)
    write(FS / "commit", b"1\n", True)
    strict_names = tuple(name for name, state in capabilities.items() if state in SATISFIES)
    _, strict_signed = compile_policy("strict-generation-2",
                                      policy_text(2, 1, strict_names))
    write(FS / "policy", strict_signed.read_bytes(), True)
    write(FS / "commit", b"1\n", True)
    committed = status()
    assert committed["capability_requirements"] == "satisfied"
    expected_mask = sum(1 << index for index, name in enumerate(capabilities)
                        if name in strict_names)
    assert int(committed["capability_required_mask"], 0) == expected_mask
    results.append({"case": "strict-commit", "pass": True})

    write(FS / "phase", b"runtime\n", True)
    write(FS / "refresh", strict_signed.read_bytes(), True)
    assert status()["capability_requirements"] == "satisfied"
    results.append({"case": "strict-refresh", "pass": True})
    write(FS / "phase", b"recovery\n", True)
    write(FS / "rollback", b"1\n", True)
    rolled_back = status()
    assert rolled_back["capability_requirements"] == "unconstrained"
    assert int(rolled_back["capability_required_mask"], 0) == 0
    results.append({"case": "capability-rollback", "pass": True})

    report = {
        "schema_version": 1,
        "architecture": initial["capability_architecture"],
        "source_gate_sha256": sha(args.source_gate),
        "build_gate_sha256": sha(args.build_gate),
        "capabilities": capabilities,
        "passed": results,
        "hardware_qualified": False,
    }
    (args.work / "capability-result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
