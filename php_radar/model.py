from dataclasses import dataclass
from enum import Enum
from typing import Optional


# In every enum here the value is the member name, so .name and .value serialize alike.
class Verdict(Enum):
    EXPOSED = "EXPOSED"
    INDETERMINATE = "INDETERMINATE"
    LIKELY_PATCHED = "LIKELY_PATCHED"
    NOT_PHP = "NOT_PHP"


class Confidence(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Sapi(Enum):
    MOD_PHP = "MOD_PHP"
    FPM = "FPM"
    CGI = "CGI"
    CLI = "CLI"
    UNKNOWN = "UNKNOWN"


class Source(Enum):
    REPO = "REPO"
    CLOUD = "CLOUD"
    NETWORK = "NETWORK"
    HOST = "HOST"


@dataclass
class Evidence:
    source: Source
    location: str
    detected_version: Optional[str]
    sapi: Sapi
    signals: dict[str, str]
    note: str = ""


@dataclass
class Asset:
    key: str
    kind: str
    evidence: list[Evidence]

    def add(self, ev: Evidence) -> None:
        self.evidence.append(ev)


# Higher wins when sources disagree, ranked by authority: a host's own read, then the
# cloud's record of it, then an outside probe, and a version pinned in a repo last.
SOURCE_PRECEDENCE: dict[Source, int] = {
    Source.HOST: 3,
    Source.CLOUD: 2,
    Source.NETWORK: 1,
    Source.REPO: 0,
}


def normalize_hostname(name: str) -> str:
    """The form hostnames are compared in: trimmed, lowercased, one trailing dot dropped."""
    # A short name and its FQDN stay distinct: "web1" and "web1.corp.example" never merge.
    name = name.strip().lower()
    return name[:-1] if name.endswith(".") else name


def _named(ev: Evidence) -> dict[str, str]:
    # Identity signals that name something. Only the hostname is rewritten. The rest stay
    # exactly as given, because ARNs are case-sensitive.
    named: dict[str, str] = {}
    for key in ("resource", "hostname", "ip", "repo"):
        value = ev.signals.get(key, "")
        if key == "hostname":
            value = normalize_hostname(value)
        if value.strip():
            named[key] = value
    return named


def _strong(ev: Evidence) -> set[tuple[str, str]]:
    # What can merge evidence. Repo evidence merges on the repo alone, so a version pinned in
    # a Dockerfile never folds into a live host. An ip merges nothing: private and shared
    # ranges repeat across accounts, and a false merge could hide a vulnerable host.
    named = _named(ev)
    keys = ("repo",) if ev.source is Source.REPO else ("resource", "hostname")
    return {(key, named[key]) for key in keys if key in named}


def asset_identity(ev: Evidence) -> tuple[str, str]:
    """(kind, display key). The key names an asset and merges nothing."""
    named = _named(ev)
    if ev.source is Source.REPO:
        return "repo", named.get("repo", ev.location)
    for key in ("resource", "hostname", "ip"):
        if key in named:
            return "host", named[key]
    return "host", ev.location


class AssetInventory:
    """Evidence joins an asset when it shares a strong identifier with evidence already in one.

    assets() builds its list fresh on each call, in first-seen order, with each asset named
    by its earliest evidence.
    """

    def __init__(self) -> None:
        self._evidence: list[Evidence] = []
        # Union-find over evidence positions, so one record can join assets made earlier.
        self._parent: list[int] = []
        self._first: dict[tuple[str, str], int] = {}  # identifier -> first evidence carrying it

    def add(self, ev: Evidence) -> None:
        i = len(self._evidence)
        self._evidence.append(ev)
        self._parent.append(i)
        for ident in _strong(ev):
            self._join(i, self._first.setdefault(ident, i))

    def assets(self) -> list[Asset]:
        found: dict[int, Asset] = {}
        # Walking in arrival order makes the first evidence seen for a group its earliest.
        for i, ev in enumerate(self._evidence):
            root = self._root(i)
            if root not in found:
                kind, key = asset_identity(ev)
                found[root] = Asset(key, kind, [])
            found[root].add(ev)
        return list(found.values())

    def _root(self, i: int) -> int:
        while self._parent[i] != i:
            self._parent[i] = self._parent[self._parent[i]]
            i = self._parent[i]
        return i

    def _join(self, a: int, b: int) -> None:
        self._parent[self._root(a)] = self._root(b)
