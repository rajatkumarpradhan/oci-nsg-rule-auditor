from __future__ import annotations

import argparse
import json
import sys

from . import analysis, model, sarif

DISCLAIMER = ("Review priorities from a simplified model of security lists and NSGs. "
              "Not tested against a live tenancy; calls no OCI API.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="nsg-audit", description="Offline audit of security lists and NSGs (synthetic/exported data).")
    ap.add_argument("inventory")
    ap.add_argument("--output")
    ap.add_argument("--format", choices=["json", "sarif"], default="json", help="format of the --output file (default json)")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"])
    a = ap.parse_args(argv)
    if a.format == "sarif" and not a.output:
        print("error: --format sarif needs --output", file=sys.stderr)
        return 1
    try:
        inv = model.load_file(a.inventory)
    except (OSError, json.JSONDecodeError, model.ModelError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    fs = analysis.analyze(inv)
    for f in fs:
        print(f"[{f.severity.upper():6}] {f.rule} {f.subject}: {f.message}")
    print(f"{len(fs)} finding(s) across {len(inv.groups)} rule group(s), {len(inv.subnets)} subnet(s), {len(inv.vnics)} VNIC(s).")
    if a.output:
        doc = sarif.to_sarif(fs, a.inventory.replace("\\", "/")) if a.format == "sarif" else \
            {"disclaimer": DISCLAIMER, "findings": [f.to_dict() for f in fs]}
        with open(a.output, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
    if a.fail_on and any(analysis.SEV[f.severity] <= analysis.SEV[a.fail_on] for f in fs):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
