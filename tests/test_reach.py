"""Reachability query: nsg-audit reach, over the effective rule sets."""
import copy
import json
import os
import tempfile
import unittest

from nsg_audit import model, reach
from nsg_audit.cli import main

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def inv():
    return {
        "security_lists": [
            {"name": "app-sl",
             "ingress": [{"protocol": "tcp", "source": "10.0.1.0/24", "ports": 8080}],
             "egress": [{"protocol": "all", "destination": "0.0.0.0/0"}]},
            {"name": "db-sl",
             "ingress": [{"protocol": "tcp", "source": "10.0.1.0/24", "ports": 5432}],
             "egress": [{"protocol": "tcp", "destination": "10.0.1.0/24"}]},
        ],
        "nsgs": [
            {"name": "app-nsg", "ingress": [],
             "egress": [{"protocol": "tcp", "destination": "nsg:db-nsg", "ports": 5432}]},
            {"name": "db-nsg",
             "ingress": [{"protocol": "tcp", "source": "nsg:app-nsg", "ports": 5432}],
             "egress": []},
        ],
        "subnets": [
            {"name": "app-subnet", "security_lists": ["app-sl"]},
            {"name": "db-subnet", "security_lists": ["db-sl"]},
        ],
        "vnics": [
            {"name": "app-1", "subnet": "app-subnet", "nsgs": ["app-nsg"]},
            {"name": "db-1", "subnet": "db-subnet", "nsgs": ["db-nsg"]},
        ],
    }


def load(d):
    return model.load(copy.deepcopy(d))


def reach_of(d, source, target, protocol="tcp", port=5432):
    return reach.reach(load(d), source, target, protocol, port)


class ReachTests(unittest.TestCase):
    def test_nsg_peer_allow_vnic_to_vnic(self):
        r = reach_of(inv(), "app-1", "db-1")
        self.assertTrue(r.reachable)
        self.assertEqual([a.subject for a in r.allows], ["nsg:db-nsg/ingress[0]"])

    def test_wrong_port_is_not_reachable(self):
        self.assertFalse(reach_of(inv(), "app-1", "db-1", port=5433).reachable)

    def test_port_boundaries_are_inclusive(self):
        d = inv()
        d["nsgs"][1]["ingress"][0]["ports"] = [100, 200]
        self.assertTrue(reach_of(d, "app-1", "db-1", port=100).reachable)
        self.assertTrue(reach_of(d, "app-1", "db-1", port=200).reachable)
        self.assertFalse(reach_of(d, "app-1", "db-1", port=201).reachable)
        self.assertFalse(reach_of(d, "app-1", "db-1", port=99).reachable)

    def test_cidr_source_covered_by_security_list(self):
        r = reach_of(inv(), "10.0.1.0/25", "db-1")
        self.assertTrue(r.reachable)
        self.assertEqual([a.subject for a in r.allows], ["security_list:db-sl/ingress[0]"])

    def test_cidr_source_outside_the_rule_is_denied(self):
        self.assertFalse(reach_of(inv(), "10.0.2.0/24", "db-1").reachable)

    def test_cidr_source_broader_than_the_rule_is_denied(self):
        # the whole source range must fit inside the rule's source
        self.assertFalse(reach_of(inv(), "10.0.0.0/16", "db-1").reachable)

    def test_single_address_source(self):
        self.assertTrue(reach_of(inv(), "10.0.1.7", "db-1").reachable)

    def test_protocol_mismatch(self):
        self.assertFalse(reach_of(inv(), "app-1", "db-1", protocol="udp", port=5432).reachable)

    def test_all_protocols_rule_allows_any_protocol(self):
        d = inv()
        d["nsgs"][1]["ingress"] = [{"protocol": "all", "source": "nsg:app-nsg"}]
        self.assertTrue(reach_of(d, "app-1", "db-1", protocol="udp", port=53).reachable)

    def test_icmp_needs_no_port(self):
        d = inv()
        d["nsgs"][1]["ingress"] = [{"protocol": "icmp", "source": "nsg:app-nsg", "icmp_type": 8}]
        self.assertTrue(reach_of(d, "app-1", "db-1", protocol="icmp").reachable)

    def test_stateless_allow_without_return_rule_is_not_reachable(self):
        d = inv()
        d["nsgs"][1]["ingress"][0]["stateless"] = True
        r = reach_of(d, "app-1", "db-1")
        self.assertFalse(r.reachable)
        self.assertIn("stateless", r.notes[0])

    def test_stateless_allow_with_return_rule_is_reachable(self):
        d = inv()
        d["nsgs"][1]["ingress"][0]["stateless"] = True
        d["nsgs"][1]["egress"] = [{"protocol": "tcp", "destination": "nsg:app-nsg", "stateless": True}]
        self.assertTrue(reach_of(d, "app-1", "db-1").reachable)

    def test_source_egress_is_checked(self):
        d = inv()
        d["nsgs"].append({"name": "iso-nsg", "ingress": [], "egress": []})
        d["nsgs"][1]["ingress"].append({"protocol": "tcp", "source": "nsg:iso-nsg", "ports": 5432})
        d["vnics"].append({"name": "iso-1", "nsgs": ["iso-nsg"]})
        r = reach_of(d, "iso-1", "db-1")
        self.assertFalse(r.reachable)
        self.assertIn("egress", r.notes[0])

    def test_vnic_without_subnet_uses_its_nsgs(self):
        # app-1's NSG alone (egress nsg:db-nsg:5432) plus db-1's NSG peer rule suffice
        d = inv()
        for v in d["vnics"]:
            v.pop("subnet", None)
        self.assertTrue(reach_of(d, "app-1", "db-1").reachable)

    def test_subnet_security_lists_count_too(self):
        # with no NSGs anywhere, db-sl's CIDR ingress still answers a CIDR source
        d = inv()
        d["nsgs"] = []
        for v in d["vnics"]:
            v["nsgs"] = []
        self.assertTrue(reach_of(d, "10.0.1.0/25", "db-1").reachable)

    def test_unknown_endpoints_and_bad_input(self):
        with self.assertRaises(reach.ReachError):
            reach_of(inv(), "ghost", "db-1")
        with self.assertRaises(reach.ReachError):
            reach_of(inv(), "app-1", "10.0.1.0/24")          # target must be a VNIC
        with self.assertRaises(reach.ReachError):
            reach_of(inv(), "app-1", "db-1", port=None)      # tcp needs a port
        with self.assertRaises(reach.ReachError):
            reach_of(inv(), "app-1", "db-1", port=70000)


class ReachCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "inv.json")
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(inv(), f)

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *extra):
        return main(["reach", self.path, *extra])

    def test_exit_codes(self):
        self.assertEqual(self.cli("--source", "app-1", "--target", "db-1", "--port", "5432"), 0)
        self.assertEqual(self.cli("--source", "app-1", "--target", "db-1", "--port", "5433"), 3)
        self.assertEqual(self.cli("--source", "ghost", "--target", "db-1", "--port", "5432"), 1)
        self.assertEqual(self.cli("--source", "app-1", "--target", "db-1"), 1)   # tcp without port
        self.assertEqual(main(["reach", os.path.join(self.tmp.name, "none.json"),
                               "--source", "app-1", "--target", "db-1", "--port", "5432"]), 1)

    def test_good_example_lb_can_reach_app(self):
        p = os.path.join(EX, "good.json")
        self.assertEqual(main(["reach", p, "--source", "lb-1", "--target", "app-vm-1", "--port", "8080"]), 0)
        self.assertEqual(main(["reach", p, "--source", "lb-1", "--target", "app-vm-1", "--port", "8081"]), 3)


if __name__ == "__main__":
    unittest.main()
