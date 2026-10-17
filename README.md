# oci-nsg-rule-auditor

Offline audit of OCI security lists and network security groups (NSGs). It reads a JSON inventory, applies 16 rules and prints findings ordered by severity. It can also write JSON or SARIF 2.1.0.

This is a portfolio project. The inventory format is a simplified schema I made up for this tool. It is not the OCI API or Terraform shape. The data in `examples/` is synthetic. Nothing here has been run against a real tenancy, and the tool calls no OCI API. The rule list is my own checklist, not an official OCI or CIS benchmark.

## Run

```
python -m pip install -e .
nsg-audit examples/risky.json
nsg-audit examples/risky.json --output report.sarif --format sarif --fail-on high
```

Exit codes: 0 ok, 1 bad input, 2 a finding at or above `--fail-on`.

## Reachability query

```
nsg-audit reach examples/good.json --source lb-1 --target app-vm-1 --port 8080
nsg-audit reach examples/good.json --source 10.0.1.0/24 --target app-vm-1 --protocol tcp --port 443
```

Answers "can source A reach target VNIC B on protocol/port P?" from the inventory. The source is a CIDR or a VNIC name; the target is a VNIC. The tool checks the source's effective egress (for a VNIC source) and the target's effective ingress (its subnet's security lists plus its NSGs), prints the rule(s) that allow the traffic or why nothing does, and exits 0 when reachable, 3 when not, 1 on bad input. The exit code makes it usable as a CI assertion.

Simplifications, on top of the audit ones below:

- VNICs have no IP addresses in the inventory, so a CIDR rule can only be evaluated against a CIDR source, and an egress rule "to anywhere" (prefix length 0) is assumed to cover a VNIC target.
- Stateful rules track replies. A stateless allow counts only when the target's effective set also has a stateless egress rule covering the source (the return check matches protocol and peer, not ports).
- No routing tables, gateways or live tenancy data.

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| NS001 | high | SSH or RDP open to 0.0.0.0/0 or ::/0 |
| NS002 | high | all protocols from anywhere |
| NS003 | high | common database port open to anywhere (1433, 1521, 3306, 5432, 6379, 27017) |
| NS004 | medium | one rule opens more than 100 ports to anywhere (not reported when NS001-NS003 already hit) |
| NS005 | medium | source broader than /16 (IPv6: /32) reaching an admin or database port |
| NS006 | medium | stateless ingress with no stateless egress rule |
| NS007 | low | NSG not attached to any VNIC |
| NS008 | low | security list not attached to any subnet |
| NS009 | low | duplicate rule |
| NS010 | medium | rule refers to an NSG that does not exist |
| NS011 | low | all ICMP from anywhere |
| NS012 | low | rule already covered by a broader rule in the same list |
| NS013 | low | egress all protocols to anywhere |
| NS014 | medium | subnet or VNIC refers to a security list, NSG or subnet that does not exist |
| NS015 | low | the same rule appears in two groups that govern the same VNIC |
| NS016 | low | a rule is covered by a broader rule in another group on the same VNIC |

## Effective rules per VNIC

A VNIC is governed by its subnet's security lists and its own NSGs together. Give a VNIC a `"subnet"` name in the inventory and the tool checks the combined set: NS015 and NS016 report duplicates and shadowing that only show up across the groups (per-group duplicates and shadowing are NS009 and NS012). IPv6 and NSG-to-NSG peer rules are handled the same way as IPv4 in the combined set.

## Limits

- The stateless check (NS006) only looks for any matching-direction stateless rule in the same list, not exact return ports, and the combined-set checks do not change it.
- Combined-set checks (NS015, NS016) cover duplicates and shadowing across a VNIC's groups; they do not model routing tables or gateways.
- Shadowing (NS012) compares protocol, ports, source and statefulness only.
- Ports are a single number or a `[low, high]` range per rule.

## Tests

```
python -m unittest discover -s tests -v
```

The tests cover the boundaries (100 vs 101 ports, /16 vs /15), IPv6, shadowing, duplicates, validation errors, CLI exit codes and SARIF output. `examples/good.json` must produce zero findings and `examples/risky.json` must trigger all 16 rules. The reach tests cover allow, deny, NSG peer rules, stateless return paths, port boundaries and the CLI exit codes.
