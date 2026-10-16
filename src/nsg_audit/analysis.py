"""Audit rules. Findings are review priorities from a simplified model, not a security assessment."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .model import Group, Inventory, Rule

SEV = {"high": 0, "medium": 1, "low": 2}
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DB_PORTS = {1433: "SQL Server", 1521: "Oracle DB", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}
WIDE_RANGE = 100          # a tcp/udp range of more than this many ports from anywhere is flagged (NS004)
BROAD_PREFIX_V4 = 16      # IPv4 sources shorter than /16 are "broad" (NS005)
BROAD_PREFIX_V6 = 32


@dataclass
class Finding:
    rule: str
    severity: str
    subject: str
    message: str
    evidence: dict

    def to_dict(self):
        return asdict(self)


def _anywhere(r: Rule) -> bool:
    return r.is_cidr and r.peer.prefixlen == 0


def _broad(r: Rule) -> bool:
    if not r.is_cidr:
        return False
    limit = BROAD_PREFIX_V4 if r.peer.version == 4 else BROAD_PREFIX_V6
    return 0 < r.peer.prefixlen < limit


def _covers_port(r: Rule, port: int) -> bool:
    if r.protocol == "all":
        return True
    if r.protocol != "tcp":
        return False
    lo, hi = r.ports()
    return lo <= port <= hi


def _key(r: Rule):
    return (r.direction, r.protocol, r.peer_text, r.stateless, r.port_min, r.port_max, r.icmp_type)


def _covers(a: Rule, b: Rule) -> bool:
    """True if every packet allowed by b is also allowed by a (same direction and statefulness)."""
    if a.direction != b.direction or a.stateless != b.stateless:
        return False
    if a.is_cidr != b.is_cidr:
        return False
    if a.is_cidr:
        if a.peer.version != b.peer.version or not b.peer.subnet_of(a.peer):
            return False
    elif a.peer != b.peer:
        return False
    if a.protocol != "all" and a.protocol != b.protocol:
        return False
    if a.protocol == "all":
        return True
    if a.protocol in ("tcp", "udp"):
        alo, ahi = a.ports()
        blo, bhi = b.ports()
        return alo <= blo and bhi <= ahi
    return a.icmp_type is None or a.icmp_type == b.icmp_type


def _where(g: Group, r: Rule) -> str:
    return f"{g.label}/{r.direction}[{r.index}]"


def _describe(r: Rule) -> str:
    if r.protocol == "all":
        return "all protocols"
    if r.protocol == "icmp":
        return "ICMP" + (f" type {r.icmp_type}" if r.icmp_type is not None else " (all types)")
    lo, hi = r.ports()
    ports = "all ports" if (lo, hi) == (1, 65535) else (f"port {lo}" if lo == hi else f"ports {lo}-{hi}")
    return f"{r.protocol.upper()} {ports}"



def _effective_groups(inv: Inventory, vname: str, out: list[Finding]) -> list[Group]:
    """Groups that govern one VNIC together: its subnet's security lists plus its NSGs."""
    by = {(g.kind, g.name): g for g in inv.groups}
    groups: list[Group] = []
    sname = inv.vnic_subnets.get(vname)
    if sname is not None:
        if sname not in inv.subnets:
            out.append(Finding("NS014", "medium", f"vnic:{vname}",
                               f"VNIC refers to subnet {sname!r}, which is not in the inventory.", {"subnet": sname}))
        else:
            groups.extend(by[("security_list", n)] for n in inv.subnets[sname] if ("security_list", n) in by)
    groups.extend(by[("nsg", n)] for n in inv.vnics[vname] if ("nsg", n) in by)
    return groups


def _cross_group(inv: Inventory, out: list[Finding]) -> None:
    """Duplicates and shadowing that only appear once a VNIC's groups are combined."""
    for vname in inv.vnics:
        groups = _effective_groups(inv, vname, out)
        for i, g1 in enumerate(groups):
            for g2 in groups[i + 1:]:
                for r in g1.rules:
                    for o in g2.rules:
                        if r.direction != o.direction:
                            continue
                        if _key(r) == _key(o):
                            out.append(Finding("NS015", "low", f"vnic:{vname} {g1.label}/{r.direction}[{r.index}]",
                                               f"Same rule also appears in {g2.label} ({o.direction}[{o.index}]). {vname} is governed by both groups, so one copy is redundant.",
                                               {"also_in": g2.label, "also_index": o.index}))
                        elif _covers(o, r):
                            out.append(Finding("NS016", "low", f"vnic:{vname} {g1.label}/{r.direction}[{r.index}]",
                                               f"Already allowed on {vname} by the broader {g2.label}/{o.direction}[{o.index}] ({o.peer_text}, {_describe(o)}); this rule adds nothing.",
                                               {"covered_by": f"{g2.label}/{o.direction}[{o.index}]"}))
                        elif _covers(r, o):
                            out.append(Finding("NS016", "low", f"vnic:{vname} {g2.label}/{o.direction}[{o.index}]",
                                               f"Already allowed on {vname} by the broader {g1.label}/{r.direction}[{r.index}] ({r.peer_text}, {_describe(r)}); this rule adds nothing.",
                                               {"covered_by": f"{g1.label}/{r.direction}[{r.index}]"}))

def analyze(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    nsgs = {g.name for g in inv.groups if g.kind == "nsg"}
    lists = {g.name for g in inv.groups if g.kind == "security_list"}
    attached_lists = {n for v in inv.subnets.values() for n in v}
    attached_nsgs = {n for v in inv.vnics.values() for n in v}

    for g in inv.groups:
        if g.kind == "security_list" and g.name not in attached_lists:
            out.append(Finding("NS008", "low", g.label, "Security list is not attached to any subnet.", {}))
        if g.kind == "nsg" and g.name not in attached_nsgs:
            out.append(Finding("NS007", "low", g.label, "Network security group is not attached to any VNIC.", {}))
        seen: dict = {}
        for r in g.rules:
            sub = _where(g, r)
            if not r.is_cidr and r.peer[1] not in nsgs:
                out.append(Finding("NS010", "medium", sub, f"Rule refers to NSG {r.peer[1]!r}, which is not in the inventory.", {"nsg": r.peer[1]}))
            k = _key(r)
            if k in seen:
                out.append(Finding("NS009", "low", sub, f"Duplicate of {r.direction}[{seen[k]}].", {"duplicate_of": seen[k]}))
            else:
                seen[k] = r.index
            if r.direction == "ingress":
                _ingress(g, r, sub, out)
            elif _anywhere(r) and r.protocol == "all":
                out.append(Finding("NS013", "low", sub, "Egress allows all protocols to anywhere. This is the usual default; tighten it if the workload has a known set of destinations.", {}))
        # shadowed rules (not exact duplicates, which NS009 already reports)
        for r in g.rules:
            for other in g.rules:
                if other is r or _key(other) == _key(r):
                    continue
                if _covers(other, r):
                    out.append(Finding("NS012", "low", _where(g, r),
                                       f"Already allowed by the broader {other.direction}[{other.index}] ({other.peer_text}, {_describe(other)}); this rule adds nothing.",
                                       {"covered_by": f"{other.direction}[{other.index}]"}))
                    break
        # stateless ingress needs an egress rule for the replies
        stateless_in = [r for r in g.rules if r.direction == "ingress" and r.stateless]
        if stateless_in and not any(r.direction == "egress" and r.stateless for r in g.rules):
            r = stateless_in[0]
            out.append(Finding("NS006", "medium", _where(g, r),
                               f"Stateless ingress rule(s) and no stateless egress rule in this group: reply traffic is not tracked, so replies need their own egress rule.",
                               {"stateless_ingress_rules": [x.index for x in stateless_in]}))

    for sname, names in inv.subnets.items():
        for n in names:
            if n not in lists:
                out.append(Finding("NS014", "medium", f"subnet:{sname}", f"Subnet refers to security list {n!r}, which is not in the inventory.", {"security_list": n}))
    for vname, names in inv.vnics.items():
        for n in names:
            if n not in nsgs:
                out.append(Finding("NS014", "medium", f"vnic:{vname}", f"VNIC refers to NSG {n!r}, which is not in the inventory.", {"nsg": n}))
    _cross_group(inv, out)
    out.sort(key=lambda f: (SEV[f.severity], f.rule, f.subject, f.message))
    return out


def _ingress(g: Group, r: Rule, sub: str, out: list[Finding]) -> None:
    if _anywhere(r):
        if r.protocol == "all":
            out.append(Finding("NS002", "high", sub, "Ingress allows all protocols and ports from anywhere.", {"source": r.peer_text}))
            return
        hit = False
        for port, name in ADMIN_PORTS.items():
            if _covers_port(r, port):
                hit = True
                out.append(Finding("NS001", "high", sub, f"{name} (port {port}) is open to the whole internet ({r.peer_text}).", {"port": port, "source": r.peer_text}))
        for port, name in DB_PORTS.items():
            if _covers_port(r, port):
                hit = True
                out.append(Finding("NS003", "high", sub, f"{name} (port {port}) is open to the whole internet ({r.peer_text}).", {"port": port, "source": r.peer_text}))
        if r.protocol in ("tcp", "udp"):
            lo, hi = r.ports()
            if hi - lo + 1 > WIDE_RANGE and not hit:
                out.append(Finding("NS004", "medium", sub, f"{_describe(r)} is open to the whole internet: {hi - lo + 1} ports in one rule.", {"ports": [lo, hi]}))
        if r.protocol == "icmp" and r.icmp_type is None:
            out.append(Finding("NS011", "low", sub, "All ICMP types are allowed from anywhere. Path MTU discovery (type 3 code 4) and echo are usually enough.", {}))
    elif _broad(r):
        hits = [(p, n) for p, n in {**ADMIN_PORTS, **DB_PORTS}.items() if _covers_port(r, p)]
        if hits:
            names = ", ".join(f"{n} ({p})" for p, n in hits)
            out.append(Finding("NS005", "medium", sub, f"Source {r.peer_text} is a very large range and reaches {names}.", {"source": r.peer_text, "ports": [p for p, _ in hits]}))
