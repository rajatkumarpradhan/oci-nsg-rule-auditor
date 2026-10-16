"""SARIF 2.1.0 output. Hand-built minimal subset; the input has no line numbers, so results point
at the input file and name the rule group and rule in a logical location. Not validated against
the official schema or a viewer."""
from __future__ import annotations

from .analysis import Finding

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"high": "error", "medium": "warning", "low": "note"}
RULES = {
    "NS001": "SSH or RDP open to the internet",
    "NS002": "All protocols and ports open to the internet",
    "NS003": "Database port open to the internet",
    "NS004": "Very wide TCP/UDP port range open to the internet",
    "NS005": "Very large source range reaches an admin or database port",
    "NS006": "Stateless ingress without a stateless egress rule",
    "NS007": "NSG not attached to any VNIC",
    "NS008": "Security list not attached to any subnet",
    "NS009": "Duplicate rule",
    "NS010": "Rule refers to an NSG that is not in the inventory",
    "NS011": "All ICMP types open to the internet",
    "NS012": "Rule is already covered by a broader rule",
    "NS013": "Egress allows everything to anywhere",
    "NS014": "Subnet or VNIC refers to a group that is not in the inventory",
    "NS015": "Same rule appears in two groups that govern the same VNIC",
    "NS016": "Rule is covered by a broader rule in another group on the same VNIC",
}


def to_sarif(findings: list[Finding], artifact_uri: str, version: str = "0.1.0") -> dict:
    rules = [{"id": r, "shortDescription": {"text": t}} for r, t in sorted(RULES.items())]
    index = {r["id"]: i for i, r in enumerate(rules)}
    results = []
    for f in findings:
        res = {"ruleId": f.rule, "level": LEVEL[f.severity], "message": {"text": f.message},
               "locations": [{"physicalLocation": {"artifactLocation": {"uri": artifact_uri}},
                              "logicalLocations": [{"name": f.subject}]}]}
        if f.rule in index:
            res["ruleIndex"] = index[f.rule]
        if f.evidence:
            res["properties"] = {"evidence": f.evidence}
        results.append(res)
    return {"$schema": SCHEMA, "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "oci-nsg-rule-auditor", "version": version, "rules": rules}}, "results": results}]}
