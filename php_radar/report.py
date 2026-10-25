"""Renders graded assets as console text, JSON, or SARIF 2.1.0.

The three renderers all build from _row, and every string a row takes from the evidence has been
through redact. No renderer reads a raw value, so none can print one. Grading reads the caller's
evidence as given. Only what is printed gets filtered.
"""
import json
import re
from collections import Counter
from urllib.parse import quote

from php_radar.knowledge import Matrix, grade, grade_evidence
from php_radar.model import SOURCE_PRECEDENCE, Asset, Confidence, Evidence, Sapi, Source, Verdict

_MASK = "[REDACTED]"

# Words that mark a credential. A person types a password, so its value can hold spaces, and an
# Authorization value is a scheme and its parameters. The other words name machine-made secrets.
_LINE_WORDS = ("password", "passwd", "passphrase", "pwd", "authorization")
_TOKEN_WORDS = ("secret", "token", "key", "credential", "auth", "bearer")
# pass and pw mark a credential only as a word of their own (see _WHOLE), so passthru and bypass
# are left alone.
_WHOLE_WORDS = ("pass", "pw")

# A signal whose name holds one of these never reaches output, whatever its value is. Auth also
# covers oauth.
_SENSITIVE = _LINE_WORDS + _TOKEN_WORDS

# A banner can come from a hostile server, so every pattern below is length-bounded or anchored
# to stay linear on text built to make it backtrack.

# A private key block (RSA, EC, OpenSSH, PGP, and the rest), through its END line or to the end of
# the text when it never closes.
_PEM = re.compile(
    r"-----BEGIN[ A-Z0-9]{0,40}PRIVATE KEY(?: BLOCK)?-----.*?"
    r"(?:-----END[ A-Z0-9]{0,40}PRIVATE KEY(?: BLOCK)?-----|\Z)", re.S)

# user:password@ inside a URL. Greedy to the last @ before the path, so an unescaped @ in the
# password leaves no tail behind.
_USERINFO = re.compile(r"(?<=://)[^/?#\s]*@")

# The same when the password holds a / ? or #, which cuts the authority short. This one runs to the
# last @ before whitespace, so it comes after the exact rule and only sees what that missed. A URL
# with a port and a later @ in its path or query (https://h:8443/p?e=a@b) is masked too, the price
# of not leaking a password that holds a slash. An image digest (registry:5000/php@sha256:...) is
# no password.
_USERINFO_LOOSE = re.compile(r"(?<=://)[^\s/?#@:]{0,64}:\S{0,256}@(?!sha\d+:)", re.I)

# user:password@host with no scheme, as an error message prints it. It has to start a word, so a
# letter, a digit, _, or one of . + % ~ / : @ - right before it rules the match out. Any other
# character allows it, a backslash included, because repr and JSON write a newline as \n. It also
# skips what only looks like userinfo: mailto: and email: addresses, ARNs, purls, and image
# digests (php:8.3-fpm@sha256:...). The password cannot hold a / or \, so a path or a Windows
# profile directory named after an email address is safe.
_USERINFO_BARE = re.compile(
    r"(?<![\w.+%~/:@-])(?!(?:mailto|email|arn|pkg|urn):)"
    r"[\w.+%~-]{1,64}:[^\s/\\]{0,128}@(?=[\w\[])(?!sha\d+:)", re.I)

# A name whose last segment (split at _ or -) says it counts something, like token_ttl, key_size,
# or auth_port, holds a number and no credential. The segment has to be whole, so account_key,
# transport_secret, and portal_password are still credentials. Nothing about the value decides
# this. The lookahead runs from the credential word to the end of the name, so a spared name never
# matches and so never swallows what follows it.
_COUNTS = r"(?![\w-]{0,64}[_-](?:ttl|timeout|port|size|days|rotation|count|limit)(?![\w-]))"

# A word starts after anything but a letter or digit, after a literal \n, \r, or \t (repr and JSON
# print a newline or a tab that way), at a capital that follows a lowercase letter or digit
# (dbPass), and at a capitalized word that follows a run of capitals (DBPass). It ends before
# anything but a letter or digit, or before a capital that follows a lowercase letter (dbPassHash).
# The patterns are compiled with re.I, so the checks that read case switch it off. A name joined
# in one case (dbpass, DBPASS) is not split, because nothing in it marks where a word ends.
_UPPER, _LOWER = r"(?-i:[A-Z])", r"(?-i:[a-z])"
_WHOLE = (r"(?:(?<![A-Za-z0-9])|(?<=\\[nrt])|(?<=(?-i:[a-z0-9]))(?=" + _UPPER + r")"
          r"|(?<=" + _UPPER + r")(?=" + _UPPER + _LOWER + r"))"
          r"(?:" + "|".join(_WHOLE_WORDS) + r")"
          r"(?:(?![A-Za-z0-9])|(?<=" + _LOWER + r")(?=" + _UPPER + r"))")
# The signal screen reads a name with the same rule.
_WHOLE_NAME = re.compile(_WHOLE, re.I)


def _named(*words: str) -> str:
    # One of the words, the rest of the name, and no counting suffix.
    return r"(?:" + "|".join(words) + r")" + _COUNTS + r"[\w-]{0,64}"


_LINE = _named(*_LINE_WORDS, _WHOLE)
_ANY = _named(*_LINE_WORDS, *_TOKEN_WORDS, _WHOLE)

# The visibility var_dump adds to the key of an object property: ["name":protected]=> and
# ["name":"Class":private]=>. That colon is no separator.
_VISIBILITY = r'(?:protected|"[\w\\]{1,64}":private)'

# What can sit between a credential name and its value: = or := with a quote or closing bracket
# allowed in front (PHP writes $_ENV['API_TOKEN'] = x), or a colon with a quote or a space on at
# least one side. A colon with nothing on either side is _BARE's, and => is _ARROW's.
_OPS = r'''(?:["'\]]{0,3}\s*(?::=|=(?!>))|["']\s*:(?!''' + _VISIBILITY + r'''\])|\s+:|:(?=\s))'''

# A quoted span runs to its closing quote and steps over a backslash escape, so "ab\"cd" is one
# value. Every repeat starts at a backslash, which the plain run before it cannot match, so the
# loop has one way to match and stays linear.
_DQUOTED = r'"[^"\\]*(?:\\[\s\S][^"\\]*)*"?'
_SQUOTED = r"'[^'\\]*(?:\\[\s\S][^'\\]*)*'?"

# What a credential is set to. A quoted span, or else _VALUE stops at a delimiter and an auth
# scheme word in front of it goes with it. _LINE_VALUE takes the rest of the line, starting at the
# first character that is not a space.
_VALUE = (r"(" + _DQUOTED + "|" + _SQUOTED
          + r'''|(?:(?:bearer|basic|digest|negotiate|ntlm|token)\s+)?[^\s"',;&]+)''')
_LINE_VALUE = r"(" + _DQUOTED + "|" + _SQUOTED + r"|\S[^\r\n]*)"

# var_dump prints a pair as ["name"]=> and puts the value on the next line, as string(7) "hunter2".
# An object adds the visibility to the key (["name":protected]=>, ["name":"Class":private]=>).
# var_dump does not escape a quote, so the value is the rest of its line. The newline is crossed
# only when a type follows it, so print_r's empty pair does not reach over to the entry after it.
_VARDUMP = re.compile(
    r"(" + _ANY + r'''["']?(?::''' + _VISIBILITY + r''')?\][ \t]*=>\s*'''
    r"(?=(?:string|int|float|bool)\()(?:string\(\d+\)[ \t]*)?)(\S[^\r\n]*)", re.I)

# name => value, which is how php -i, print_r, and var_export print a pair. Any credential name
# takes the rest of the line, because php -i prints a second column after the first.
_ARROW = re.compile(r"(" + _ANY + r'''["'\]]{0,3}[ \t]*=>[ \t]*)''' + _LINE_VALUE, re.I)

# A password or Authorization name with a space after its separator takes the rest of the line
# (password: a long passphrase, Authorization: Negotiate <blob>). Written inline, with no space,
# its value stops at a delimiter like any other.
_SPACED = re.compile(r"(" + _LINE + _OPS + r"[ \t]+)" + _LINE_VALUE, re.I)

# name=value, name: value, name :value, "name": value, and name := value for any credential name.
_ASSIGNED = re.compile(r"(" + _ANY + _OPS + r"\s*)" + _VALUE, re.I)

# name:value with no space on either side of the colon, which is also how host:port and image:tag
# are written. The name has to start a word and cannot follow a / : or @, which keeps the segments
# of an ARN, an image reference, and a path out of it (function:auth-service:prod,
# registry/auth-api:v2). A bare keycloak:8443 reads as name:value and loses its port. Inside a URL
# it has a / in front and stays.
_BARE = re.compile(r"((?<![\w/:@-])[\w-]{0,64}?" + _ANY + r":)(?![=:])" + _VALUE, re.I)

# A bearer or basic credential with no name in front of it. Sixteen characters keeps prose such
# as "basic authentication" out, which is why no word boundary is needed in front.
_SCHEME = re.compile(r"(?:bearer|basic)\s+[\w.~+/=-]{16,}", re.I)

# Token and key shapes by prefix. None needs a boundary in front, so a token glued to a letter
# still goes, except sk-, which would otherwise match inside a name like disk-images. AKIA also
# allows _ in its tail, so a placeholder like AKIA_EXAMPLE_KEY goes with the real ones.
_SHAPES = re.compile(
    r"gh[pousr]_[A-Za-z0-9]{20,}"
    r"|github_pat_\w{20,}"
    r"|AKIA[A-Z0-9_]{8,}"
    r"|(?:ASIA|ABIA|ACCA)[A-Z0-9]{16}"
    r"|AIza[\w-]{35}"
    r"|xox[abeoprs]-[A-Za-z0-9-]{10,}"
    r"|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"
    r"|(?<![A-Za-z0-9])sk-[\w-]{20,}"
    r"|glpat-[\w-]{20,}"
    r"|npm_[A-Za-z0-9]{36}"
    r"|eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*")


def _mask_value(m: "re.Match[str]") -> str:
    # Keep the name and the quote marks, so masked text still reads as what it was.
    name, value = m.groups()
    q = value[0] if value[0] in "\"'" else ""
    return name + q + _MASK + q


# The name rules go before _USERINFO_BARE. A credential name keeps its whole value even when the
# value holds an @ (password:P@ssw0rd), and the bare userinfo rule sees what is left.
_STEPS = (
    (_PEM, _MASK),
    (_USERINFO, _MASK + "@"),
    (_USERINFO_LOOSE, _MASK + "@"),
    (_VARDUMP, _mask_value),
    (_ARROW, _mask_value),
    (_SPACED, _mask_value),
    (_ASSIGNED, _mask_value),
    (_BARE, _mask_value),
    (_USERINFO_BARE, _MASK + "@"),
    (_SCHEME, _MASK),
    (_SHAPES, _MASK),
)

# An AWS secret access key is 40 characters of base64 with no marker. Only a run with upper case,
# lower case, and a digit counts, so a git SHA or an ordinary name passes.
_B64_40 = re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])")


def _long_secret(m: "re.Match[str]") -> str:
    run = m.group()
    has = (any(c.islower() for c in run), any(c.isupper() for c in run),
           any(c.isdigit() for c in run))
    return _MASK if all(has) else run


# (level, kind, description) per verdict. A SARIF result of the default kind, fail, takes the level
# error, warning, or note. Any other kind takes none, so a patched or non-PHP asset reports as a
# pass or a not-applicable result.
_SARIF = {
    Verdict.EXPOSED: (
        "error", None, "PHP build is vulnerable to PHP2Shell (CVE-2026-109618, CVE-2026-109619)."),
    Verdict.INDETERMINATE: (
        "warning", None, "php-radar could not determine the PHP2Shell status of this asset."),
    Verdict.LIKELY_PATCHED: ("none", "pass", "PHP build carries the PHP2Shell fix."),
    Verdict.NOT_PHP: ("none", "notApplicable", "No PHP found on this asset."),
}


def redact(value: str, *, identifier: bool = False) -> str:
    """Mask the credential shapes found in value and leave the rest as it was.

    A secret with no recognizable shape passes through, which is why the renderers also drop
    signals by name.

    identifier says that value names a thing, such as an ARN, a URL, or a file path. Two rules
    read a value by its shape alone: a Bearer or Basic word with a long run after it, and a bare
    run of 40 base64 characters. A name can hold either by chance, so an identifier skips both.
    The rest still run. A credential in URL userinfo, in a name=value pair, or in a known token
    shape is masked in an identifier as it is anywhere else.
    """
    for pattern, mask in _STEPS:
        if not (identifier and pattern is _SCHEME):
            value = pattern.sub(mask, value)
    return value if identifier else _B64_40.sub(_long_secret, value)


def _text(value: object) -> str:
    # Signals are typed str, but a producer can hand over None or a number, and output has to cope.
    return "" if value is None else str(value)


def _clean(value: object) -> str:
    return redact(_text(value))


def _ident(value: object) -> str:
    # For the location of a read and its resource signal. Both name the thing the read covers.
    return redact(_text(value), identifier=True)


# An evidence with the verdict and confidence it earns alone.
_Graded = tuple[Evidence, Verdict, Confidence]


def _sensitive(name: str) -> bool:
    # _WHOLE decides pass and pw here as it does in the value patterns, so a name is never masked
    # in text and still printed as a signal, or the other way round.
    return (any(word in name.lower() for word in _SENSITIVE)
            or _WHOLE_NAME.search(name) is not None)


def _build(ev: Evidence) -> str:
    # A packaged PHP is graded on its build. Showing 8.1.2 alone would look end of life when
    # 8.1.2-1ubuntu2.28 is patched.
    return _text(ev.signals.get("package_version")).strip() or _text(ev.detected_version).strip()


def _reads(asset: Asset, verdict: Verdict, matrix: Matrix) -> list[_Graded]:
    """Each evidence with its own grade, the most telling first.

    A read that agrees with the asset verdict leads, then the more authoritative source. The sort
    is stable, so equal reads keep the order they arrived in.
    """
    reads = [(ev, *grade_evidence(ev, matrix)) for ev in asset.evidence]
    reads.sort(key=lambda r: (r[1] is not verdict, -SOURCE_PRECEDENCE[r[0].source]))
    return reads


def _entry(ev: Evidence, verdict: Verdict, confidence: Confidence) -> dict:
    return {
        "source": ev.source.name,
        "location": _ident(ev.location),
        "detected_version": None if ev.detected_version is None else _clean(ev.detected_version),
        "sapi": ev.sapi.name,
        "verdict": verdict.name,
        "confidence": confidence.name,
        "signals": {_clean(k): (_ident(v) if k == "resource" else _clean(v))
                    for k, v in ev.signals.items() if not _sensitive(_text(k))},
        "note": _clean(ev.note),
    }


def _key(asset: Asset) -> str:
    # A cloud asset is keyed by its resource signal and prints as that signal does. A key built from
    # a host name, an ip, or a repo id is scanned in full. A key that equals a read's resource
    # signal is printed no more freely than that signal already is.
    key = _text(asset.key)
    resources = (ev.signals["resource"] for ev in asset.evidence if "resource" in ev.signals)
    return _ident(key) if any(_text(r) == key for r in resources) else _clean(key)


def _row(asset: Asset, matrix: Matrix) -> dict:
    verdict, confidence = grade(asset, matrix)
    reads = _reads(asset, verdict, matrix)
    # The SAPI is a fact about the machine, so any read may name it. The build has to come from a
    # read that agrees with the verdict, or a NOT_PHP asset would show a stale banner's version.
    sapi = next((ev.sapi for ev, _, _ in reads if ev.sapi is not Sapi.UNKNOWN), Sapi.UNKNOWN)
    builds = [_build(ev) for ev, v, _ in reads if v is verdict]
    return {
        "key": _key(asset),
        "kind": _clean(asset.kind),
        "verdict": verdict.name,
        "confidence": confidence.name,
        "sapi": sapi.name,
        "version": _clean(next((b for b in builds if b), "")) or None,
        "evidence": [_entry(*r) for r in reads],
    }


def _rows(assets: list[Asset], matrix: Matrix) -> list[dict]:
    # One row per asset, in the order given. Asset.key is a display name and two assets can share
    # one, so nothing here is keyed on it.
    return [_row(a, matrix) for a in assets]


def _tally(rows: list[dict]) -> dict:
    count = Counter(r["verdict"] for r in rows)
    return {"total": len(rows), "by_verdict": {v.name: count[v.name] for v in Verdict}}


def render_json(assets: list[Asset], matrix: Matrix) -> str:
    """JSON with a summary and one entry per asset, in the order given.

    Each asset lists its evidence with its own grade, the read that decided the verdict first.
    """
    rows = _rows(assets, matrix)
    return json.dumps({"tool": "php-radar", "summary": _tally(rows), "assets": rows}, indent=2)


def _detail(row: dict) -> str:
    # With no version to show, say what is true of both a hidden version and a read that saw
    # nothing. Only NOT_PHP knows there is no PHP.
    if row["version"]:
        php = "PHP " + row["version"]
    else:
        php = "no PHP found" if row["verdict"] == Verdict.NOT_PHP.name else "no PHP version found"
    parts = [row["confidence"] + " confidence", php]
    if row["sapi"] != Sapi.UNKNOWN.name:
        parts.append(row["sapi"])
    return ", ".join(parts)


def _line(entry: dict) -> str:
    line = f"    {entry['source']:<7}  {entry['verdict']:<14}  {entry['confidence']:<6}  "
    line += entry["location"]
    if entry["detected_version"]:
        line += "  PHP " + entry["detected_version"]
    if entry["note"]:
        line += f"  ({entry['note']})"
    return line.rstrip()


def _plain(line: str) -> str:
    # Escape everything but printable ASCII. A banner from a hostile server can otherwise forge a
    # row with a newline or move the cursor, and a lookalike hostname would print as the real one.
    return "".join(c if c.isascii() and c.isprintable() else c.encode("unicode_escape").decode()
                   for c in line)


def render_console(assets: list[Asset], matrix: Matrix) -> str:
    """Text for a terminal, grouped by verdict with EXPOSED first.

    Within a group the surest finding comes first. Each line is printable ASCII.
    """
    rows = _rows(assets, matrix)
    tally = _tally(rows)["by_verdict"]
    noun = "asset" if len(rows) == 1 else "assets"
    counts = ", ".join(f"{name} {n}" for name, n in tally.items())
    lines = [f"php-radar: {len(rows)} {noun} ({counts})"]
    surest = {c.name: i for i, c in enumerate(Confidence)}
    # Verdict is declared worst-first and Confidence strongest-first, the order wanted here.
    for verdict in Verdict:
        group = [r for r in rows if r["verdict"] == verdict.name]
        if group:
            lines += ["", f"{verdict.name} ({len(group)})"]
        for row in sorted(group, key=lambda r: surest[r["confidence"]]):
            lines.append(f"  {row['key']} ({row['kind']}): {_detail(row)}")
            lines += [_line(entry) for entry in row["evidence"]]
    return "\n".join(_plain(line) for line in lines)


def _where(entry: dict) -> dict:
    # A file in a repository is a physical location. A host, an ARN, or a URL has no file behind
    # it, so it is a resource. Nothing here knows a line, so a file points at line 1.
    if entry["source"] == Source.REPO.name:
        # A file name with an undecodable byte reaches here as a lone surrogate, which quote
        # cannot encode. Spelling it out keeps one odd file name from losing the whole report.
        uri = quote(entry["location"].replace("\\", "/"), errors="backslashreplace")
        where = {"physicalLocation": {"artifactLocation": {"uri": uri},
                                      "region": {"startLine": 1}}}
    else:
        where = {"logicalLocations": [{"name": entry["location"], "kind": "resource"}]}
    where["message"] = {
        "text": f"{entry['source']}: {entry['verdict']}, {entry['confidence']} confidence"}
    return where


def _result(row: dict) -> dict:
    verdict = Verdict[row["verdict"]]
    level, kind, _ = _SARIF[verdict]
    where = [_where(entry) for entry in row["evidence"]]
    result = {
        "ruleId": "PHP2SHELL-" + verdict.name,
        "ruleIndex": list(Verdict).index(verdict),
        "level": level,
        "message": {"text": f"{verdict.name}: {row['key']} ({row['kind']}), {_detail(row)}"},
        # Code scanning draws a result at its first location only, so the read that decided the
        # verdict goes there and the others ride along as related locations.
        "locations": where[:1],
    }
    if kind:
        result["kind"] = kind
    if where[1:]:
        result["relatedLocations"] = [dict(w, id=i) for i, w in enumerate(where[1:])]
    result["properties"] = {k: row[k] for k in ("verdict", "confidence", "sapi", "version")}
    return result


def render_sarif(assets: list[Asset], matrix: Matrix) -> str:
    """A SARIF 2.1.0 log with one result per asset, in the order given."""
    rules = []
    for verdict in Verdict:
        level, _, text = _SARIF[verdict]
        rules.append({"id": "PHP2SHELL-" + verdict.name, "shortDescription": {"text": text},
                      "defaultConfiguration": {"level": level}})
    run = {
        "tool": {"driver": {"name": "php-radar", "rules": rules}},
        "results": [_result(row) for row in _rows(assets, matrix)],
    }
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [run]}
    return json.dumps(doc, indent=2)
