"""Load and validate the simplified network security export.

Field names are this project's own simplified schema, not the OCI API response format.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field


class ModelError(ValueError):
    pass


PROTOCOLS = {"all": "all", "tcp": "tcp", "udp": "udp", "icmp": "icmp",
             "6": "tcp", "17": "udp", "1": "icmp", "-1": "all"}


@dataclass
class Rule:
    direction: str                  # "ingress" or "egress"
    protocol: str                   # all / tcp / udp / icmp
    peer: object                    # ip_network, or ("nsg", name) for an NSG reference
    stateless: bool = False
    port_min: int | None = None     # None for all ports (tcp/udp) or non-port protocols
    port_max: int | None = None
    icmp_type: int | None = None
    description: str = ""
    index: int = 0

    @property
    def peer_text(self) -> str:
        return f"nsg:{self.peer[1]}" if isinstance(self.peer, tuple) else str(self.peer)

    @property
    def is_cidr(self) -> bool:
        return not isinstance(self.peer, tuple)

    def ports(self) -> tuple[int, int] | None:
        if self.protocol not in ("tcp", "udp"):
            return None
        return (self.port_min if self.port_min is not None else 1, self.port_max if self.port_max is not None else 65535)


@dataclass
class Group:
    kind: str                       # "security_list" or "nsg"
    name: str
    rules: list[Rule] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.name}"


@dataclass
class Inventory:
    groups: list[Group] = field(default_factory=list)
    subnets: dict[str, list[str]] = field(default_factory=dict)   # subnet -> security list names
    vnics: dict[str, list[str]] = field(default_factory=dict)     # vnic -> nsg names
    public_subnets: set[str] = field(default_factory=set)


def _str(v, what):
    if not isinstance(v, str) or not v.strip():
        raise ModelError(f"{what} must be a non-empty string")
    return v


def _port(v, what):
    if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= 65535:
        raise ModelError(f"{what} must be an integer in [1, 65535], got {v!r}")
    return v


def _names(v, what):
    if not isinstance(v, list) or any(not isinstance(x, str) or not x for x in v):
        raise ModelError(f"{what} must be a list of names")
    return v


def _rule(r, direction, where, index) -> Rule:
    proto = PROTOCOLS.get(str(_str(r.get("protocol", "all") if not isinstance(r.get("protocol"), int) else str(r["protocol"]), f"{where}.protocol")).lower())
    if proto is None:
        raise ModelError(f"{where}.protocol must be all, tcp, udp, icmp (or 6, 17, 1, -1)")
    key = "source" if direction == "ingress" else "destination"
    peer_raw = r.get(key)
    if isinstance(peer_raw, str) and peer_raw.startswith("nsg:"):
        peer: object = ("nsg", _str(peer_raw[4:], f"{where}.{key}"))
    else:
        try:
            peer = ipaddress.ip_network(_str(peer_raw, f"{where}.{key}"), strict=True)
        except ValueError as e:
            raise ModelError(f"{where}.{key}: {e}") from None
    pmin = pmax = None
    if "ports" in r and r["ports"] is not None:
        if proto not in ("tcp", "udp"):
            raise ModelError(f"{where}: ports only apply to tcp or udp")
        p = r["ports"]
        if isinstance(p, int) and not isinstance(p, bool):
            pmin = pmax = _port(p, f"{where}.ports")
        elif isinstance(p, list) and len(p) == 2:
            pmin, pmax = _port(p[0], f"{where}.ports[0]"), _port(p[1], f"{where}.ports[1]")
            if pmin > pmax:
                raise ModelError(f"{where}.ports: min is greater than max")
        else:
            raise ModelError(f"{where}.ports must be a port number or [min, max]")
    itype = r.get("icmp_type")
    if itype is not None:
        if proto != "icmp" or isinstance(itype, bool) or not isinstance(itype, int) or not 0 <= itype <= 255:
            raise ModelError(f"{where}.icmp_type must be 0-255 and only applies to icmp")
    stateless = r.get("stateless", False)
    if not isinstance(stateless, bool):
        raise ModelError(f"{where}.stateless must be true or false")
    return Rule(direction, proto, peer, stateless, pmin, pmax, itype, str(r.get("description", "")), index)


def _group(kind, g, where) -> Group:
    name = _str(g["name"], f"{where}.name")
    rules = []
    for i, r in enumerate(g.get("ingress", [])):
        rules.append(_rule(r, "ingress", f"{where}.ingress[{i}]", i))
    for i, r in enumerate(g.get("egress", [])):
        rules.append(_rule(r, "egress", f"{where}.egress[{i}]", i))
    return Group(kind, name, rules)


def load(data: dict) -> Inventory:
    try:
        inv = Inventory()
        for kind, key in (("security_list", "security_lists"), ("nsg", "nsgs")):
            seen = set()
            for i, g in enumerate(data.get(key, [])):
                grp = _group(kind, g, f"{key}[{i}]")
                if grp.name in seen:
                    raise ModelError(f"duplicate {kind} {grp.name!r}")
                seen.add(grp.name)
                inv.groups.append(grp)
        for i, s in enumerate(data.get("subnets", [])):
            name = _str(s["name"], f"subnets[{i}].name")
            if name in inv.subnets:
                raise ModelError(f"duplicate subnet {name!r}")
            inv.subnets[name] = _names(s.get("security_lists", []), f"subnets[{i}].security_lists")
            pub = s.get("public", False)
            if not isinstance(pub, bool):
                raise ModelError(f"subnets[{i}].public must be true or false")
            if pub:
                inv.public_subnets.add(name)
        for i, v in enumerate(data.get("vnics", [])):
            name = _str(v["name"], f"vnics[{i}].name")
            if name in inv.vnics:
                raise ModelError(f"duplicate vnic {name!r}")
            inv.vnics[name] = _names(v.get("nsgs", []), f"vnics[{i}].nsgs")
    except (KeyError, TypeError, AttributeError) as e:
        raise ModelError(f"invalid model: {e!r}") from e
    return inv


def load_file(path: str) -> Inventory:
    with open(path, encoding="utf-8") as f:
        return load(json.load(f))
