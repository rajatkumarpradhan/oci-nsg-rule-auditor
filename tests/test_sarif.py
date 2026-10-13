import json
import os
import tempfile
import unittest

from nsg_audit import analysis, model
from nsg_audit.cli import main
from nsg_audit.sarif import LEVEL, RULES, to_sarif

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def findings(name="risky.json"):
    return analysis.analyze(model.load_file(os.path.join(EX, name)))


class SarifTests(unittest.TestCase):
    def test_shape(self):
        doc = to_sarif(findings(), "examples/risky.json")
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["$schema"].endswith("sarif-2.1.0.json"))
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"], "oci-nsg-rule-auditor")

    def test_results_match_findings_and_levels(self):
        fs = findings()
        res = to_sarif(fs, "x.json")["runs"][0]["results"]
        self.assertEqual([r["ruleId"] for r in res], [f.rule for f in fs])
        self.assertEqual(LEVEL, {"high": "error", "medium": "warning", "low": "note"})
        for f, r in zip(fs, res):
            self.assertEqual(r["level"], LEVEL[f.severity])

    def test_rules_cover_every_audit_rule_and_indexes_match(self):
        run = to_sarif(findings(), "x.json")["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        self.assertEqual([r["id"] for r in rules], sorted(RULES))
        self.assertEqual({f.rule for f in findings()}, set(RULES))
        for r in run["results"]:
            self.assertEqual(rules[r["ruleIndex"]]["id"], r["ruleId"])

    def test_location_and_empty_case(self):
        res = to_sarif(findings(), "dir/inv.json")["runs"][0]["results"][0]
        self.assertEqual(res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "dir/inv.json")
        self.assertTrue(res["locations"][0]["logicalLocations"][0]["name"])
        self.assertEqual(to_sarif(findings("good.json"), "g.json")["runs"][0]["results"], [])

    def test_cli(self):
        with tempfile.TemporaryDirectory() as t:
            s = os.path.join(t, "r.sarif")
            self.assertEqual(main([os.path.join(EX, "risky.json"), "--output", s, "--format", "sarif", "--fail-on", "high"]), 2)
            self.assertEqual(len(json.load(open(s, encoding="utf-8"))["runs"][0]["results"]), len(findings()))
            self.assertEqual(main([os.path.join(EX, "good.json"), "--format", "sarif"]), 1)


if __name__ == "__main__":
    unittest.main()
