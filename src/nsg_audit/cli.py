from __future__ import annotations

import argparse
import json
import sys

from . import analysis, model, reach, sarif

DISCLAIMER = ("Review priorities from a simplified model of security lists and NSGs. "
              "Not tested against a live tenancy; calls no OCI API.")


def main(argv=None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    if args and args[0] == "reach":
        return _reach(args[1:])
    ap = argparse.ArgumentParser(prog="nsg-audit", description="Offline audit of security lists and NSGs (synthetic/exported data).")
    ap.add_argument("inventory")
    ap.add_argument("--output")
    ap.add_argument("--format", choices=["json", "sarif"], default="json", help="format of the --output file (default json)")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"])
    a = ap.parse_args(args)
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


def _reach(argv) -> int:
    ap = argparse.ArgumentParser(prog="nsg-audit reach",
                                 description="Can source A reach target VNIC B on protocol/port P? Exit 0 reachable, 3 not, 1 bad input.")
    ap.add_argument("inventory")
    ap.add_argument("--source", required=True, help="CIDR or VNIC name")
    ap.add_argument("--target", required=True, help="VNIC name")
    ap.add_argument("--protocol", default="tcp", choices=["tcp", "udp", "icmp", "all"])
    ap.add_argument("--port", type=int)
    a = ap.parse_args(argv)
    try:
        inv = model.load_file(a.inventory)
        res = reach.reach(inv, a.source, a.target, a.protocol, a.port)
    except (OSError, json.JSONDecodeError, model.ModelError, reach.ReachError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    port_text = f"{a.protocol}/{a.port}" if a.port is not None else a.protocol
    if res.reachable:
        print(f"REACHABLE {a.source} -> {a.target} {port_text}")
        for al in res.allows:
            print(f"  allowed by {al.subject} ({al.detail})")
        for n in res.notes:
            print(f"  note: {n}")
        return 0
    print(f"NOT REACHABLE {a.source} -> {a.target} {port_text}")
    for n in res.notes:
        print(f"  {n}")
    return 3


if __name__ == "__main__":
    sys.exit(main())
