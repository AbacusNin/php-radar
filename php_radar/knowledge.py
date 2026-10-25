"""Grades an asset against the PHP2Shell matrix in data/php2shell.json.

Anything the matrix does not recognize grades INDETERMINATE. A packaged build is graded by its
build string and never by its upstream number, because a backport makes that number lie.
"""
import json
import os
import string
from dataclasses import dataclass
from typing import Iterable, NamedTuple, Optional

from php_radar.model import SOURCE_PRECEDENCE, Asset, Confidence, Evidence, Source, Verdict
from php_radar.versions import PhpVersion, parse_branch

DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "php2shell.json")

# A string longer than this is not a package version. It also keeps int() inside its size limit.
_MAX_BUILD = 128

_STRONGEST_FIRST = (Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW)

# A composer constraint declares a minimum. It does not say which PHP runs, so it never grades
# as a build and counts as a read that saw nothing.
_FLOORS = frozenset({"composer-constraint"})

# Tags that make a build something other than the release they follow.
_PRERELEASE = ("rc", "alpha", "beta", "dev")

_BACKPORT_VERDICTS = {"LIKELY_PATCHED": Verdict.LIKELY_PATCHED, "EXPOSED": Verdict.EXPOSED}


class MatrixError(ValueError):
    """The matrix file is missing, unreadable, or malformed."""


@dataclass(frozen=True)
class Backport:
    distro: str
    build: str
    verdict: Verdict


def _at_or_after(known: str, got: str) -> bool:
    """True when got is the known build or a later revision of it."""
    if got == known:
        return True
    # A bare upstream version covers every release built from it: 8.3.36 and 8.3.36-150700.3.24.1.
    bare = not known.strip(string.digits + ".")
    if bare and got.startswith(known) and got[len(known)] in "-+":
        return True
    # Same series, higher revision: ubuntu2.28 to ubuntu2.29, ~deb13u1 to ~deb13u2, -r0 to -r1.
    head = known.rstrip(string.digits)
    tail, rev = known[len(head):], got[len(head):]
    if not tail or not got.startswith(head):
        return False
    # The last run of a bare version is a micro, and a micro keeps the width the matrix gives it.
    # 8.3.360 is no later than 8.3.36. Neither is 8.3.351, which is 8.3.35 with a release number
    # glued on. A revision after a distro tag is a counter, so 2.28 to 2.100 is fine.
    if bare and len(rev) > len(tail):
        return False
    return rev.isascii() and rev.isdigit() and int(rev) >= int(tail)


class Matrix:
    def __init__(self, fixed: dict[tuple[int, int], int], eol_through: tuple[int, int],
                 backports: list[Backport]) -> None:
        self._fixed = fixed
        self._eol_through = eol_through
        self._backports = backports

    def fixed_micro(self, branch: str) -> Optional[int]:
        key = parse_branch(branch)
        return None if key is None else self._fixed.get(key)

    def is_eol(self, branch: str) -> bool:
        key = parse_branch(branch)
        return key is not None and key <= self._eol_through

    def backport_verdict(self, distro: str, package_version: str) -> Optional[Verdict]:
        distro, build = distro.strip().lower(), package_version.strip()
        if not distro or not build or len(build) > _MAX_BUILD:
            return None
        hits = set()
        for b in self._backports:
            if b.distro != distro:
                continue
            # A patched build carries forward, since later revisions include its fix. A known
            # vulnerable build does not: the revision after it may be the fix.
            if b.verdict is Verdict.LIKELY_PATCHED:
                if _at_or_after(b.build, build):
                    hits.add(b.verdict)
            elif build == b.build:
                hits.add(b.verdict)
        # An exact known-vulnerable build outranks a patched series that happens to cover it.
        for verdict in (Verdict.EXPOSED, Verdict.LIKELY_PATCHED):
            if verdict in hits:
                return verdict
        return None


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    # json keeps the last of two equal keys, so in a hand-edited file a stale micro could
    # silently win.
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def load_matrix(path: str) -> Matrix:
    def bad(where: str, why: str) -> MatrixError:
        return MatrixError(f"{path}: {where}: {why}")

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f, object_pairs_hook=_unique)
    except (OSError, ValueError) as exc:
        raise MatrixError(f"{path}: {exc}") from exc
    if not isinstance(data, dict):
        raise bad("top level", "must be an object")

    def section(name: str, kind: type, article: str):
        value = data.get(name)
        if not isinstance(value, kind):
            raise bad(name, f"missing, or not {article}")
        return value

    fixed: dict[tuple[int, int], int] = {}
    for branch, row in section("fixed", dict, "an object").items():
        key = parse_branch(branch)
        if key is None:
            raise bad(f"fixed[{branch}]", "the key must be a branch like 8.3")
        if key in fixed:
            raise bad(f"fixed[{branch}]", "this branch is listed twice")
        micro = row.get("micro") if isinstance(row, dict) else None
        if type(micro) is not int or micro < 0:
            raise bad(f"fixed[{branch}]", "needs a whole number micro")
        fixed[key] = micro

    eol = section("eol", dict, "an object")
    through = parse_branch(eol["through"]) if isinstance(eol.get("through"), str) else None
    if through is None:
        raise bad("eol", "through must name a branch like 8.1")
    for major, minor in fixed:
        if (major, minor) <= through:
            raise bad("fixed", f"{major}.{minor} is inside the end-of-life range")

    backports = []
    for i, row in enumerate(section("backports", list, "a list")):
        where = f"backports[{i}]"
        if not isinstance(row, dict):
            raise bad(where, "must be an object")
        distro, build, verdict = row.get("distro"), row.get("build"), row.get("verdict")
        if not (isinstance(distro, str) and distro.strip()):
            raise bad(where, "needs a distro")
        if not (isinstance(build, str) and build.strip()) or len(build) > _MAX_BUILD:
            raise bad(where, "needs a build string")
        if not (isinstance(verdict, str) and verdict in _BACKPORT_VERDICTS):
            raise bad(where, "verdict must be LIKELY_PATCHED or EXPOSED")
        backports.append(Backport(distro.strip().lower(), build.strip(),
                                  _BACKPORT_VERDICTS[verdict]))

    return Matrix(fixed, through, backports)


def _s(value: object) -> str:
    # A signal that is None or not a string must not crash grading.
    return str(value or "").strip()


def _sig(ev: Evidence, key: str) -> str:
    return _s(ev.signals.get(key))


def _digit(c: str) -> bool:
    return len(c) == 1 and c in string.digits


def _is_revision(version: PhpVersion) -> bool:
    # A distro revision follows the micro as -1ubuntu2.28, -1~deb13u1, -r0 or -150700.3.24.1.
    # A variant like -fpm or -zts and a pre-release tag like RC1 or -dev are no distro build.
    s = version.suffix
    return len(s) > 1 and s[0] in "-+~" and (_digit(s[1]) or (s[1] == "r" and _digit(s[2:3])))


def _is_prerelease(version: PhpVersion) -> bool:
    return version.suffix.lstrip("-+~_").lower().startswith(_PRERELEASE)


def _agrees(detected: str, build: str) -> bool:
    # The detected version is the build itself or its upstream part: 8.1.2 for 8.1.2-1ubuntu2.28.
    if not build.startswith(detected):
        return False
    rest = build[len(detected):]
    return not rest or rest[0] not in string.digits + "."


def _build(package: str, text: str, version: Optional[PhpVersion]) -> str:
    """The build string a packaged PHP is recognized by, or "" when the signals disagree."""
    if not package:
        return text  # the detected version carries a distro revision, so it is the build
    # With a parseable detected version, the two signals have to describe the same PHP.
    return package if version is None or _agrees(text, package) else ""


def _declared(ev: Evidence) -> Confidence:
    # A repo scanner grades how exact its own pin is, and the grader takes that as given.
    name = _sig(ev, "confidence").upper()
    return Confidence[name] if name in Confidence.__members__ else Confidence.LOW


def _confidence(ev: Evidence, verdict: Verdict) -> Confidence:
    if verdict is Verdict.INDETERMINATE:
        # PHP is there and only its build is unknown. A repo pin declares a runtime, so LOW.
        return Confidence.LOW if ev.source is Source.REPO else Confidence.MEDIUM
    if ev.source is Source.REPO:
        return _declared(ev)
    if ev.source is Source.NETWORK:
        # A banner is easy to spoof or rewrite. From outside, a distro backport is invisible too.
        # A network read earns LOW for whatever it claims, a fix as much as an exposure.
        return Confidence.LOW
    return Confidence.HIGH


def _judge(ev: Evidence, matrix: Matrix) -> tuple[Verdict, Confidence, bool]:
    """Grade one evidence, and say whether it confirms PHP is there.

    A read can confirm PHP without placing its build. That differs from a read that saw nothing.
    """
    if _sig(ev, "kind").lower() in _FLOORS:
        # A constraint declares a minimum. It says nothing about what is installed or built.
        return Verdict.INDETERMINATE, Confidence.LOW, False
    text = _s(ev.detected_version)
    version = PhpVersion.parse(text) if text else None
    package = _sig(ev, "package_version")
    present = _sig(ev, "php_present").lower()

    if package or (version is not None and _is_revision(version)):
        # Package evidence. The upstream number of a packaged PHP lies, so only a build the
        # matrix recognizes settles it.
        verdict = matrix.backport_verdict(_sig(ev, "distro"), _build(package, text, version))
        if verdict is None:
            verdict = Verdict.INDETERMINATE
        return verdict, _confidence(ev, verdict), True

    if version is not None:
        fixed = matrix.fixed_micro(version.branch)
        if fixed is None:
            # No fix to compare with: end of life is exposed, and a newer branch is unknown.
            verdict = Verdict.EXPOSED if matrix.is_eol(version.branch) else Verdict.INDETERMINATE
        elif version.micro < fixed:
            verdict = Verdict.EXPOSED
        elif _is_prerelease(version):
            verdict = Verdict.INDETERMINATE  # an RC or dev build of the fixed release is no release
        else:
            verdict = Verdict.LIKELY_PATCHED
        return verdict, _confidence(ev, verdict), True

    if text or present == "true":
        return Verdict.INDETERMINATE, _confidence(ev, Verdict.INDETERMINATE), True

    # Silence clears nothing. Only a host read that says there is no PHP does.
    if present == "false" and ev.source is Source.HOST and not _s(ev.note):
        return Verdict.NOT_PHP, Confidence.HIGH, True
    return Verdict.INDETERMINATE, Confidence.LOW, False


def grade_evidence(ev: Evidence, matrix: Matrix) -> tuple[Verdict, Confidence]:
    """Grade one evidence. Every signal is read as a stripped string. The ones that matter:

    package_version: the build of a packaged PHP, looked up in the matrix for the distro. With
    none, a detected_version carrying a distro revision such as -1ubuntu2.28 is the build.
    Either is package evidence. A packaged PHP never grades on its upstream number.
    distro: picks the matrix rows to look in. A name alone is no package evidence, and a bare
    version still grades against the fixed micros, as it does for PHP built from source.
    kind: a composer-constraint declares a minimum, so it never grades as a build and counts as a
    read that saw nothing.
    php_present: "true" means PHP was seen without a version, and a host read says "false" when it
    found none.
    confidence: a repo scanner's own grade of its pin, taken as given for repo evidence.
    note: a note on a host read marks a problem with the read, so that read cannot clear.

    INDETERMINATE comes in two kinds. PHP confirmed but unplaced carries MEDIUM, or LOW for a repo
    pin, which declares a runtime and confirms nothing. A read that saw nothing carries LOW.
    """
    verdict, confidence, _ = _judge(ev, matrix)
    return verdict, confidence


class _Read(NamedTuple):
    rank: int
    verdict: Verdict
    confidence: Confidence
    sees_php: bool


def _strongest(confidences: Iterable[Confidence]) -> Confidence:
    return min(confidences, key=_STRONGEST_FIRST.index)


def _weakest(confidences: Iterable[Confidence]) -> Confidence:
    return max(confidences, key=_STRONGEST_FIRST.index)


def grade(asset: Asset, matrix: Matrix) -> tuple[Verdict, Confidence]:
    """The verdict and confidence for one asset.

    A read with no sign of PHP settles nothing and is dropped. Of the rest, an EXPOSED stands
    unless a more authoritative source has a LIKELY_PATCHED read. A higher source that only saw
    PHP, or found none, cannot clear it. With no exposure left, the most authoritative source
    decides, worst first: PHP seen but unplaced, then LIKELY_PATCHED, then NOT_PHP. So a weaker
    source never clears a read that saw PHP. A tie on EXPOSED keeps the strongest confidence, and
    a tie on anything milder keeps the weakest.
    """
    reads = [_Read(SOURCE_PRECEDENCE[e.source], *_judge(e, matrix)) for e in asset.evidence]
    live = [r for r in reads if r.sees_php]
    if not live:
        return Verdict.INDETERMINATE, Confidence.LOW

    exposed = [r for r in live if r.verdict is Verdict.EXPOSED]
    patched = [r.rank for r in live if r.verdict is Verdict.LIKELY_PATCHED]
    if exposed:
        top = max(r.rank for r in exposed)
        # Only a patched read on a strictly more authoritative source clears an exposure.
        if top >= max(patched, default=-1):
            return Verdict.EXPOSED, _strongest(r.confidence for r in exposed if r.rank == top)

    # An exposure still here sits below a patched read, so it cannot reach the top tier.
    top = max(r.rank for r in live)
    tier = [r for r in live if r.rank == top]
    unplaced = [r.confidence for r in tier if r.verdict is Verdict.INDETERMINATE]
    if unplaced:
        # PHP is there and its build is unknown. A weaker source never clears that.
        return Verdict.INDETERMINATE, _strongest(unplaced)
    patched_here = any(r.verdict is Verdict.LIKELY_PATCHED for r in tier)
    verdict = Verdict.LIKELY_PATCHED if patched_here else Verdict.NOT_PHP
    return verdict, _weakest(r.confidence for r in tier if r.verdict is verdict)
