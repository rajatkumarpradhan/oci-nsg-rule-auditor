"""Reachability query: can source A reach target VNIC B on protocol/port P?

Evaluated over the effective rule sets (a VNIC's subnet security lists plus its NSGs).
Simplifications of the model, also in the README: VNICs have no IP addresses, so a CIDR
rule can only be evaluated against a CIDR source, and a "to anywhere" (prefix length 0)
egress rule is assumed to cover a VNIC target. Stateful rules track reply traffic; a
stateless allow needs a stateless egress return rule on the same effective set (the
return check matches protocol and peer, not ports). No routing tables or gateways.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .model import Group, Inventory, Rule


class ReachError(ValueError):
    pass


@dataclass
class Allow:
    subject: str        # e.g. "nsg:db-nsg/ingress[0]"
    detail: str         # human description of the rule


@dataclass
class ReachResult:
    reachable: bool
    allows: list[Allow] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _groups_for(inv: Inventory, vname: str) -> list[Group]:
    """The groups that govern a VNIC: its subnet's security lists plus its NSGs."""
    by = {(g.kind, g.name): g for g in inv.groups}
    groups: list[Group] = []
    sname = inv.vnic_subnets.get(vname)
    if sname is not None:
        for n in inv.subnets.get(sname, []):
            g = by.get(("security_list", n))
            if g:
                groups.append(g)
    for n in inv.vnics.get(vname, []):
        g = by.get(("nsg", n))
        if g:
            groups.append(g)
    return groups


def parse_endpoint(text: str, inv: Inventory, what: str, must_be_vnic: bool = False):
    """Return ("cidr", ip_network) or ("vnic", name)."""
    if not must_be_vnic:
        try:
            return ("cidr", ipaddress.ip_network(text, strict=False))
        except ValueError:
            pass
    if text in inv.vnics:
        return ("vnic", text)
    kind = "a VNIC in the inventory" if must_be_vnic else "a CIDR or a VNIC in the inventory"
    raise ReachError(f"{what} {text!r} is not {kind}")


def _peer_covers(rule: Rule, kind: str, val, inv: Inventory) -> bool:
    """Does the rule's peer cover this endpoint? See module docstring for VNIC limits."""
    if rule.is_cidr:
        if kind == "cidr":
            return rule.peer.version == val.version and val.subnet_of(rule.peer)
        return rule.peer.prefixlen == 0          # no VNIC IPs: only "anywhere" counts
    # NSG peer rule: the endpoint must be a VNIC attached to that NSG
    return kind == "vnic" and rule.peer[1] in inv.vnics.get(val, [])


def _packet_allowed(rule: Rule, kind: str, val, inv: Inventory, protocol: str, port: int | None) -> bool:
    if rule.protocol not in ("all", protocol):
        return False
    if protocol in ("tcp", "udp") and rule.protocol != "all":
        lo, hi = rule.ports()
        if not lo <= port <= hi:
            return False
    return _peer_covers(rule, kind, val, inv)


def _describe(rule: Rule) -> str:
    if rule.protocol == "all":
        return "all protocols"
    if rule.protocol == "icmp":
        return "ICMP" + (f" type {rule.icmp_type}" if rule.icmp_type is not None else " (all types)")
    lo, hi = rule.ports()
    ports = "all ports" if (lo, hi) == (1, 65535) else (f"port {lo}" if lo == hi else f"ports {lo}-{hi}")
    return f"{rule.protocol.upper()} {ports}"


def reach(inv: Inventory, source: str, target: str, protocol: str = "tcp", port: int | None = None) -> ReachResult:
    if protocol not in ("tcp", "udp", "icmp", "all"):
        raise ReachError(f"protocol must be tcp, udp, icmp or all, got {protocol!r}")
    if protocol in ("tcp", "udp") and port is None:
        raise ReachError(f"--port is required for {protocol}")
    if port is not None and not 1 <= port <= 65535:
        raise ReachError(f"port must be in [1, 65535], got {port}")
    skind, sval = parse_endpoint(source, inv, "source")
    tkind, tval = parse_endpoint(target, inv, "target", must_be_vnic=True)

    res = ReachResult(reachable=False)
    tgroups = _groups_for(inv, tval)

    # the source's own effective egress must let the packet out (VNIC sources only)
    if skind == "vnic":
        sgroups = _groups_for(inv, sval)
        if not any(r.direction == "egress" and _packet_allowed(r, tkind, tval, inv, protocol, port)
                   for g in sgroups for r in g.rules):
            res.notes.append(f"source {source} has no effective egress rule allowing this traffic")
            return res

    for g in tgroups:
        for r in g.rules:
            if r.direction != "ingress" or not _packet_allowed(r, skind, sval, inv, protocol, port):
                continue
            subject = f"{g.label}/ingress[{r.index}]"
            if not r.stateless:
                res.allows.append(Allow(subject, f"{r.peer_text}, {_describe(r)}, stateful"))
                continue
            # stateless: replies need their own stateless egress rule on the target's set
            if any(x.direction == "egress" and x.stateless
                   and x.protocol in ("all", protocol) and _peer_covers(x, skind, sval, inv)
                   for tg in tgroups for x in tg.rules):
                res.allows.append(Allow(subject, f"{r.peer_text}, {_describe(r)}, stateless with a return rule"))
            else:
                res.notes.append(f"{subject} would allow it, but it is stateless and the target has no stateless egress rule for the replies")
    res.reachable = bool(res.allows)
    if not res.reachable and not res.notes:
        res.notes.append("no rule in the target's effective ingress set allows this traffic")
    return res
