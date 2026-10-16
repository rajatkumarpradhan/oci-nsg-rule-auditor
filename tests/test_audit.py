import copy
import json
import os
import tempfile
import unittest

from nsg_audit import analysis, model
from nsg_audit.cli import main

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def ex(name):
    with open(os.path.join(EX, name), encoding="utf-8") as f:
        return json.load(f)


GOOD = ex("good.json")


def run(d):
    return analysis.analyze(model.load(d))


def rules(d):
    return {f.rule for f in run(d)}


def inv(ingress=None, egress=None, extra=None):
    """One security list attached to one subnet; add rules to test a single behaviour."""
    d = {"security_lists": [{"name": "t", "ingress": ingress or [], "egress": egress or [{"protocol": "tcp", "destination": "10.0.0.0/8", "ports": 443}]}],
         "subnets": [{"name": "s", "security_lists": ["t"]}]}
    d.update(extra or {})
    return d


def ing(**kw):
    r = {"protocol": "tcp", "source": "0.0.0.0/0", "ports": 443}
    r.update(kw)
    return r


class ExampleTests(unittest.TestCase):
    def test_good_example_is_clean(self):
        self.assertEqual(run(copy.deepcopy(GOOD)), [])

    def test_risky_example_triggers_every_rule(self):
        self.assertEqual(rules(ex("risky.json")), {f"NS{n:03d}" for n in range(1, 17)})

    def test_order_is_by_severity(self):
        sev = [analysis.SEV[f.severity] for f in run(ex("risky.json"))]
        self.assertEqual(sev, sorted(sev))

    def test_empty_inventory(self):
        self.assertEqual(run({}), [])


class ExposureTests(unittest.TestCase):
    def test_ssh_and_rdp_from_anywhere(self):
        for port, rule in ((22, "NS001"), (3389, "NS001")):
            with self.subTest(port=port):
                self.assertIn(rule, rules(inv([ing(ports=port)])))

    def test_ipv6_anywhere_counts(self):
        self.assertIn("NS001", rules(inv([ing(source="::/0", ports=22)])))

    def test_range_covering_ssh(self):
        self.assertIn("NS001", rules(inv([ing(ports=[20, 25])])))
        self.assertNotIn("NS001", rules(inv([ing(ports=[23, 30])])))

    def test_all_ports_tcp_covers_admin_and_db(self):
        r = rules(inv([ing(ports=None)]))
        self.assertTrue({"NS001", "NS003"} <= r)

    def test_udp_does_not_count_as_ssh(self):
        self.assertNotIn("NS001", rules(inv([ing(protocol="udp", ports=22)])))

    def test_all_protocols_from_anywhere(self):
        r = rules(inv([{"protocol": "all", "source": "0.0.0.0/0"}]))
        self.assertIn("NS002", r)
        self.assertNotIn("NS001", r)          # NS002 already says everything

    def test_numeric_protocol_names(self):
        self.assertIn("NS002", rules(inv([{"protocol": "-1", "source": "0.0.0.0/0"}])))
        self.assertIn("NS001", rules(inv([{"protocol": 6, "source": "0.0.0.0/0", "ports": 22}])))

    def test_db_ports(self):
        for port in (1433, 1521, 3306, 5432, 6379, 27017):
            with self.subTest(port=port):
                self.assertIn("NS003", rules(inv([ing(ports=port)])))
        self.assertNotIn("NS003", rules(inv([ing(ports=5433)])))

    def test_https_from_anywhere_is_fine(self):
        self.assertEqual(rules(inv([ing(ports=443)])), set())

    def test_wide_range_boundary(self):
        self.assertNotIn("NS004", rules(inv([ing(ports=[1000, 1099])])))     # 100 ports
        self.assertIn("NS004", rules(inv([ing(ports=[1000, 1100])])))        # 101 ports

    def test_wide_range_not_reported_twice_when_ssh_hit(self):
        r = rules(inv([ing(ports=[1, 1000])]))
        self.assertIn("NS001", r)
        self.assertNotIn("NS004", r)

    def test_broad_private_range_on_admin_port(self):
        self.assertIn("NS005", rules(inv([ing(source="10.0.0.0/8", ports=22)])))
        self.assertNotIn("NS005", rules(inv([ing(source="10.0.0.0/16", ports=22)])))   # /16 is not broad
        self.assertIn("NS005", rules(inv([ing(source="10.0.0.0/15", ports=22)])))
        self.assertNotIn("NS005", rules(inv([ing(source="10.0.0.0/8", ports=443)])))   # not an admin or DB port

    def test_ipv6_broad_boundary(self):
        self.assertIn("NS005", rules(inv([ing(source="2001::/31", ports=22)])))
        self.assertNotIn("NS005", rules(inv([ing(source="2001:db8::/32", ports=22)])))

    def test_narrow_source_on_ssh_is_fine(self):
        self.assertEqual(rules(inv([ing(source="10.0.0.0/24", ports=22)])), set())

    def test_icmp(self):
        self.assertIn("NS011", rules(inv([{"protocol": "icmp", "source": "0.0.0.0/0"}])))
        self.assertNotIn("NS011", rules(inv([{"protocol": "icmp", "source": "0.0.0.0/0", "icmp_type": 3}])))
        self.assertNotIn("NS011", rules(inv([{"protocol": "icmp", "source": "10.0.0.0/8"}])))

    def test_egress_anywhere_all(self):
        d = inv([], [{"protocol": "all", "destination": "0.0.0.0/0"}])
        self.assertEqual(rules(d), {"NS013"})
        self.assertEqual(rules(inv([], [{"protocol": "tcp", "destination": "0.0.0.0/0", "ports": 443}])), set())


class HygieneTests(unittest.TestCase):
    def test_duplicate_rule(self):
        f = [x for x in run(inv([ing(), ing()])) if x.rule == "NS009"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].evidence, {"duplicate_of": 0})

    def test_same_rule_with_different_statefulness_is_not_duplicate(self):
        self.assertNotIn("NS009", rules(inv([ing(), ing(stateless=True)])))

    def test_shadowed_rule(self):
        d = inv([ing(source="10.0.0.0/16", ports=[400, 500]), ing(source="10.0.5.0/24", ports=450)])
        f = [x for x in run(d) if x.rule == "NS012"]
        self.assertEqual([x.subject for x in f], ["security_list:t/ingress[1]"])

    def test_not_shadowed_when_port_or_network_escapes(self):
        base = ing(source="10.0.0.0/16", ports=[400, 500])
        self.assertNotIn("NS012", rules(inv([base, ing(source="10.0.5.0/24", ports=[450, 501])])))
        self.assertNotIn("NS012", rules(inv([base, ing(source="10.1.0.0/16", ports=450)])))
        self.assertNotIn("NS012", rules(inv([base, ing(source="10.0.0.0/8", ports=450)])))   # broader, not covered

    def test_shadow_needs_same_statefulness_and_protocol(self):
        base = ing(source="10.0.0.0/16", ports=[400, 500])
        self.assertNotIn("NS012", rules(inv([base, ing(source="10.0.5.0/24", ports=450, stateless=True)])))
        self.assertNotIn("NS012", rules(inv([base, ing(source="10.0.5.0/24", ports=450, protocol="udp")])))

    def test_shadow_by_all_protocols_and_icmp_types(self):
        self.assertIn("NS012", rules(inv([{"protocol": "all", "source": "10.0.0.0/16"}, ing(source="10.0.1.0/24", ports=22)])))
        self.assertIn("NS012", rules(inv([{"protocol": "icmp", "source": "10.0.0.0/16"}, {"protocol": "icmp", "source": "10.0.1.0/24", "icmp_type": 3}])))
        self.assertNotIn("NS012", rules(inv([{"protocol": "icmp", "source": "10.0.0.0/16", "icmp_type": 8}, {"protocol": "icmp", "source": "10.0.1.0/24", "icmp_type": 3}])))

    def test_mixed_ip_versions_never_shadow(self):
        self.assertNotIn("NS012", rules(inv([ing(source="0.0.0.0/0", ports=443), ing(source="::1/128", ports=443)])))

    def test_stateless_without_return_rule(self):
        d = inv([ing(source="10.0.0.0/24", ports=8080, stateless=True)])
        self.assertIn("NS006", rules(d))
        d["security_lists"][0]["egress"].append({"protocol": "tcp", "destination": "10.0.0.0/24", "stateless": True})
        self.assertNotIn("NS006", rules(d))

    def test_stateful_rules_need_no_return_rule(self):
        self.assertNotIn("NS006", rules(inv([ing(source="10.0.0.0/24", ports=8080)])))

    def test_attachment_checks(self):
        d = inv()
        d["security_lists"].append({"name": "loose"})
        d["nsgs"] = [{"name": "n1"}]
        d["vnics"] = [{"name": "v", "nsgs": []}]
        f = {(x.rule, x.subject) for x in run(d)}
        self.assertIn(("NS008", "security_list:loose"), f)
        self.assertIn(("NS007", "nsg:n1"), f)
        d["vnics"][0]["nsgs"] = ["n1"]
        self.assertNotIn("NS007", rules(d))

    def test_nsg_reference_rules(self):
        d = inv([ing(source="nsg:web", ports=8080)], extra={"nsgs": [{"name": "web"}], "vnics": [{"name": "v", "nsgs": ["web"]}]})
        self.assertNotIn("NS010", rules(d))
        d["security_lists"][0]["ingress"][0]["source"] = "nsg:ghost"
        self.assertIn("NS010", rules(d))

    def test_dangling_references(self):
        d = inv(extra={"vnics": [{"name": "v", "nsgs": ["nope"]}]})
        d["subnets"][0]["security_lists"].append("missing")
        f = [x for x in run(d) if x.rule == "NS014"]
        self.assertEqual({x.subject for x in f}, {"subnet:s", "vnic:v"})

    def test_nsg_peer_is_not_a_cidr(self):
        d = inv([ing(source="nsg:a", ports=22)], extra={"nsgs": [{"name": "a"}], "vnics": [{"name": "v", "nsgs": ["a"]}]})
        self.assertEqual(rules(d), set())             # an NSG source is never "the internet"


class ValidationTests(unittest.TestCase):
    def bad(self, mutate):
        d = copy.deepcopy(GOOD)
        mutate(d)
        with self.assertRaises(model.ModelError):
            model.load(d)

    def test_errors(self):
        sl = lambda d: d["security_lists"][0]
        cases = [
            lambda d: sl(d)["ingress"][0].update(source="10.0.0.1/24"),     # host bits set
            lambda d: sl(d)["ingress"][0].update(source="not-a-cidr"),
            lambda d: sl(d)["ingress"][0].pop("source"),
            lambda d: sl(d)["ingress"][0].update(protocol="sctp"),
            lambda d: sl(d)["ingress"][0].update(ports=0),
            lambda d: sl(d)["ingress"][0].update(ports=70000),
            lambda d: sl(d)["ingress"][0].update(ports=True),
            lambda d: sl(d)["ingress"][0].update(ports=[500, 400]),
            lambda d: sl(d)["ingress"][0].update(ports=[1, 2, 3]),
            lambda d: sl(d)["ingress"][2].update(ports=22),                 # ports on icmp
            lambda d: sl(d)["ingress"][0].update(icmp_type=3),              # icmp_type on tcp
            lambda d: sl(d)["ingress"][2].update(icmp_type=300),
            lambda d: sl(d)["ingress"][0].update(stateless="yes"),
            lambda d: d["security_lists"].append(copy.deepcopy(sl(d))),
            lambda d: d["nsgs"].append(copy.deepcopy(d["nsgs"][0])),
            lambda d: d["subnets"].append(copy.deepcopy(d["subnets"][0])),
            lambda d: d["subnets"][0].update(public="yes"),
            lambda d: d["vnics"].append(copy.deepcopy(d["vnics"][0])),
            lambda d: d["vnics"][0].update(nsgs="app-nsg"),
            lambda d: sl(d).pop("name"),
        ]
        for i, m in enumerate(cases):
            with self.subTest(case=i):
                self.bad(m)

    def test_valid_forms_are_accepted(self):
        d = inv([ing(ports=[22, 22]), {"protocol": "6", "source": "10.0.0.0/8"}, {"protocol": "ICMP", "source": "::/0", "icmp_type": 0}])
        model.load(d)


class CliTests(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(main([os.path.join(EX, "good.json")]), 0)
        self.assertEqual(main([os.path.join(EX, "risky.json")]), 0)
        self.assertEqual(main([os.path.join(EX, "risky.json"), "--fail-on", "high"]), 2)
        self.assertEqual(main([os.path.join(EX, "good.json"), "--fail-on", "low"]), 0)

    def test_fail_on_levels(self):
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "i.json")
            json.dump(inv([{"protocol": "icmp", "source": "0.0.0.0/0"}]), open(p, "w", encoding="utf-8"))   # one low finding
            self.assertEqual(main([p, "--fail-on", "medium"]), 0)
            self.assertEqual(main([p, "--fail-on", "low"]), 2)

    def test_report_and_errors(self):
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "r.json")
            main([os.path.join(EX, "risky.json"), "--output", out])
            rep = json.load(open(out, encoding="utf-8"))
            self.assertIn("Not tested against a live tenancy", rep["disclaimer"])
            self.assertGreater(len(rep["findings"]), 14)
            bad = os.path.join(t, "b.json")
            open(bad, "w").write("{oops")
            self.assertEqual(main([bad]), 1)
            self.assertEqual(main([os.path.join(t, "none.json")]), 1)


if __name__ == "__main__":
    unittest.main()
