#!/usr/bin/python3 -I
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise mandatory-capability summary handling through the real status CLI."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hdn-status", type=Path, required=True)
    args = parser.parse_args()
    cases = {
        "satisfied": ("0x1", "satisfied", "enforced,hardware",
                      ("active", "0", "none")),
        "not-applicable": ("0x1", "satisfied", "not-applicable,none",
                           ("active", "0", "none")),
        "unconstrained": ("0x0", "unconstrained", None,
                          ("active", "0", "none")),
        "unsatisfied": ("0x1", "unsatisfied", "degraded,software",
                        ("degraded", "1", "capability_requirements_unsatisfied")),
        "missing-summary": ("0x1", None, "enforced,hardware",
                            ("degraded", "1", "capability_requirements_unsatisfied")),
        "missing-record": ("0x1", "satisfied", None,
                           ("degraded", "1", "capability_requirements_unsatisfied")),
        "malformed-summary": ("0x1", "unknown", "enforced,hardware",
                              ("degraded", "1", "capability_requirements_unsatisfied")),
        "unknown-mask": ("0x80000000", "satisfied", "enforced,hardware",
                         ("degraded", "1", "capability_requirements_unsatisfied")),
        "zero-satisfied": ("0x0", "satisfied", None,
                           ("degraded", "1", "capability_requirements_unsatisfied")),
    }
    with tempfile.TemporaryDirectory(prefix="hdn-status-capability-") as directory:
        root = Path(directory)
        for name, (mask, summary, record, expected) in cases.items():
            status = root / (name + ".status")
            lines = [
                "mitigations_sealed: 1", "policy_loaded: 1", "policy_sealed: 1",
                "phase: runtime", "capability_version: 1",
                "capability_architecture: fixture",
                "capability_required_mask: " + mask,
            ]
            if summary is not None:
                lines.append("capability_requirements: " + summary)
            if record is not None:
                lines.append("capability.kernel_wx: " + record)
            status.write_text("\n".join(lines) + "\n")
            result = subprocess.run(
                [str(args.hdn_status), "--status-path", str(status)],
                check=True, capture_output=True, text=True, timeout=10,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            values = dict(line.split("=", 1) for line in result.stdout.splitlines()
                          if "=" in line)
            actual = (values.get("state"), values.get("attention"),
                      values.get("attention_reason"))
            if actual != expected:
                raise RuntimeError(f"{name}: expected {expected}, got {actual}")


if __name__ == "__main__":
    main()
