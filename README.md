# oci-nsg-rule-auditor

Offline audit of OCI security lists and network security groups (NSGs). It reads a JSON inventory, applies 14 rules and prints findings ordered by severity. It can also write JSON or SARIF 2.1.0.

This is a portfolio project. The inventory format is a simplified schema I made up for this tool. It is not the OCI API or Terraform shape. The data in `examples/` is synthetic. Nothing here has been run against a real tenancy, and the tool calls no OCI API. The rule list is my own checklist, not an official OCI or CIS benchmark.

## Run

```
python -m pip install -e .
nsg-audit examples/risky.json
nsg-audit examples/risky.json --output report.sarif --format sarif --fail-on high
```

Exit codes: 0 ok, 1 bad input, 2 a finding at or above `--fail-on`.

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
| NS014 | medium | subnet or VNIC refers to a security list or NSG that does not exist |

## Limits

- Rules are checked per list. It does not compute the effective rule set for a VNIC by combining security lists and NSGs.
- The stateless check (NS006) only looks for any matching-direction stateless rule in the same list, not exact return ports.
- Shadowing (NS012) compares protocol, ports, source and statefulness only.
- Ports are a single number or a `[low, high]` range per rule.

## Tests

```
python -m unittest discover -s tests -v
```

The tests cover the boundaries (100 vs 101 ports, /16 vs /15), IPv6, shadowing, duplicates, validation errors, CLI exit codes and SARIF output. `examples/good.json` must produce zero findings and `examples/risky.json` must trigger all 14 rules.
