"""Effective rule set per VNIC: a subnet's security lists plus the VNIC's NSGs, combined."""
import copy
import json
import os
import unittest

from nsg_audit import analysis, model

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def run(d):
    return analysis.analyze(model.load(d))


def rules(d):
    return {f.rule for f in run(d)}


def fixture():
    """One VNIC governed by security list 'sl' (via subnet 's') and NSG 'n'."""
    return {
        "security_lists": [
            {"name": "sl",
             "ingress": [{"protocol": "tcp", "source": "10.0.0.0/16", "ports": [1, 65535]}],
             "egress": [{"protocol": "tcp", "destination": "10.0.0.0/8", "ports": 443}]},
        ],
        "nsgs": [
            {"name": "n",
             "ingress": [{"protocol": "tcp", "source": "10.0.1.0/24", "ports": 443}],
             "egress": [{"protocol": "tcp", "destination": "10.0.2.0/24", "ports": 5432}]},
        ],
        "subnets": [{"name": "s", "security_lists": ["sl"]}],
        "vnics": [{"name": "v", "subnet": "s", "nsgs": ["n"]}],
    }


class EffectiveSetTests(unittest.TestCase):
    def test_shadow_across_groups(self):
        # clean per group; the NSG rule adds nothing once combined with the security list
        f = [x for x in run(fixture()) if x.rule == "NS016"]
        self.assertEqual([x.subject for x in f], ["vnic:v nsg:n/ingress[0]"])

    def test_duplicate_across_groups(self):
        d = fixture()
        d["nsgs"][0]["ingress"][0] = {"protocol": "tcp", "source": "10.0.0.0/16", "ports": [1, 65535]}
        f = [x for x in run(d) if x.rule == "NS015"]
        self.assertEqual([x.subject for x in f], ["vnic:v security_list:sl/ingress[0]"])
        self.assertNotIn("NS016", rules(d))

    def test_clean_combination_has_no_findings(self):
        d = fixture()
        d["security_lists"][0]["ingress"] = [{"protocol": "tcp", "source": "10.0.0.0/24", "ports": 443}]
        self.assertEqual(run(d), [])

    def test_vnic_without_subnet_still_combines_its_nsgs(self):
        d = fixture()
        d["nsgs"].append({"name": "n2",
                          "ingress": [{"protocol": "tcp", "source": "10.0.1.0/24", "ports": 443}],
                          "egress": []})
        d["vnics"] = [{"name": "v", "nsgs": ["n", "n2"]}]
        f = [x for x in run(d) if x.rule in ("NS015", "NS016")]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].rule, "NS015")

    def test_ipv6_shadow_across_groups(self):
        d = fixture()
        d["security_lists"][0]["ingress"] = [{"protocol": "tcp", "source": "2001:db8::/32", "ports": [1, 65535]}]
        d["nsgs"][0]["ingress"] = [{"protocol": "tcp", "source": "2001:db8::/64", "ports": 443}]
        f = [x for x in run(d) if x.rule == "NS016"]
        self.assertEqual([x.subject for x in f], ["vnic:v nsg:n/ingress[0]"])

    def test_mixed_ip_versions_never_shadow_across_groups(self):
        d = fixture()
        d["security_lists"][0]["ingress"] = [{"protocol": "tcp", "source": "0.0.0.0/0", "ports": [1, 65535]}]
        d["nsgs"][0]["ingress"] = [{"protocol": "tcp", "source": "::/0", "ports": 443}]
        # the v6 rule is not covered by the v4 rule (and both are exposure findings, not NS016)
        self.assertNotIn("NS016", rules(d))

    def test_nsg_peer_rule_duplicate_across_groups(self):
        d = fixture()
        peer = {"protocol": "tcp", "source": "nsg:web", "ports": 8080}
        d["nsgs"].append({"name": "web", "ingress": [], "egress": []})
        d["security_lists"][0]["ingress"] = [copy.deepcopy(peer)]
        d["nsgs"][0]["ingress"] = [copy.deepcopy(peer)]
        d["vnics"][0]["nsgs"].append("web")
        f = [x for x in run(d) if x.rule == "NS015"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].subject, "vnic:v security_list:sl/ingress[0]")

    def test_stateless_difference_is_not_a_cross_duplicate(self):
        d = fixture()
        d["nsgs"][0]["ingress"][0] = {"protocol": "tcp", "source": "10.0.0.0/16", "ports": [1, 65535], "stateless": True}
        self.assertNotIn("NS015", rules(d))

    def test_two_vnics_report_per_vnic(self):
        d = fixture()
        d["vnics"].append({"name": "v2", "subnet": "s", "nsgs": ["n"]})
        f = [x for x in run(d) if x.rule == "NS016"]
        self.assertEqual({x.subject.split()[0] for x in f}, {"vnic:v", "vnic:v2"})

    def test_missing_subnet_reference(self):
        d = fixture()
        d["vnics"][0]["subnet"] = "ghost"
        f = [x for x in run(d) if x.rule == "NS014"]
        self.assertEqual([x.subject for x in f], ["vnic:v"])
        self.assertEqual(f[0].severity, "medium")

    def test_subnet_field_is_validated(self):
        d = fixture()
        d["vnics"][0]["subnet"] = 7
        with self.assertRaises(model.ModelError):
            model.load(d)
        d["vnics"][0]["subnet"] = "  "
        with self.assertRaises(model.ModelError):
            model.load(d)

    def test_per_group_checks_unchanged_without_vnics(self):
        d = fixture()
        d["vnics"] = []
        # only the pre-existing per-group hygiene finding remains (unattached NSG)
        self.assertEqual([f.rule for f in run(d)], ["NS007"])


class ExampleTests(unittest.TestCase):
    def test_risky_example_triggers_effective_rules(self):
        with open(os.path.join(EX, "risky.json"), encoding="utf-8") as f:
            r = rules(json.load(f))
        self.assertIn("NS015", r)
        self.assertIn("NS016", r)


if __name__ == "__main__":
    unittest.main()
