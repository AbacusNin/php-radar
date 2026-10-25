"""Finds where a local checkout pins or declares a PHP runtime.

scan_path walks a tree and reads the files that name a PHP version. Those are Dockerfiles, compose
files, GitHub Actions workflows that call setup-php, .php-version, .tool-versions, composer.json,
and devcontainer.json. Each file is read as text and picked apart with string handling. Nothing in
the tree is imported, run, or evaluated, and no link leads the scan out of it.

Each find is one Evidence, and its confidence follows how exactly the file names a build. An image
tag with a patch release scores high, and a floating tag such as 8.3-apache scores low. A Composer
requirement only sets a floor, so it carries the kind composer-constraint and no version, and the
grader sets it aside.
"""
import codecs
import hashlib
import json
import os
import stat
import string
from functools import partial
from typing import Callable, Iterator, NamedTuple, Optional

from php_radar.model import Confidence, Evidence, Sapi, Source
from php_radar.versions import PhpVersion

_Pins = list[tuple[str, Confidence]]

# No config file is this big. The cap bounds what one hostile file can cost to read and parse.
_MAX_BYTES = 1 << 20

# Past this many pins a file is a flood and not a config.
_MAX_PINS = 100

# A tag, version, or constraint longer than this is none of those. Docker caps a tag at 128
# characters. A longer value is reported as skipped and never read as a pin.
_MAX_TEXT = 256

# Folders that hold other people's code. Each dependency in vendor/ declares the PHP it supports.
# That says nothing about the project that installed it.
_SKIP_DIRS = frozenset({".git", "node_modules", "vendor"})

# A file with one of these endings documents a Dockerfile and is not one, so Dockerfile.md can
# quote any FROM line it likes.
_DOC_ENDINGS = (".md", ".markdown", ".rst", ".txt")

# What can follow the version in a tag of the official php image.
_VARIANTS = frozenset({
    "cli", "fpm", "apache", "zts", "alpine", "jessie", "stretch", "buster", "bullseye", "bookworm",
    "trixie", "windowsservercore", "nanoserver"})
# The variants that end in a number, like alpine3.20 and ltsc2022.
_NUMBERED = frozenset({"alpine", "ltsc"})

# Digest algorithm to hex length. Docker prints digests in lower case.
_DIGESTS = {"sha256": 64, "sha512": 128}
_HEX = frozenset("0123456789abcdef")

# A tag that names its server API says which SAPI the image runs. The first match wins.
_SAPIS = (("apache", Sapi.MOD_PHP), ("fpm", Sapi.FPM), ("cli", Sapi.CLI), ("zts", Sapi.CLI))

# The grader sets this kind aside, because a requirement says nothing about what runs.
_FLOOR_KIND = "composer-constraint"

# Confidence is declared strongest first.
_RANK = {c: i for i, c in enumerate(Confidence)}


def _is_digest(text: str) -> bool:
    algorithm, _, digits = text.partition(":")
    return len(digits) == _DIGESTS.get(algorithm, -1) and _HEX.issuperset(digits)


def _known(word: str) -> bool:
    return word in _VARIANTS or word.rstrip(string.digits + ".") in _NUMBERED


def _release(tag: str) -> Optional[PhpVersion]:
    # The digest is no part of the version, and parse would read its @ as junk after the micro.
    return PhpVersion.parse(tag.partition("@")[0])


def tag_confidence(tag: str) -> Confidence:
    """How exactly an image tag names a build.

    HIGH for a digest, or for a full major.minor.micro followed by nothing or by variants of the
    official php image (8.3.35, 8.3.35-fpm-alpine3.20). MEDIUM for a full version with a suffix
    those images do not use, since the tag may belong to some other image. LOW for anything that
    floats: 8.3, 8.3-apache, 8, latest, or a tag that a build variable fills in.
    """
    tag = tag.strip()
    name, at, digest = tag.partition("@")
    if _is_digest(digest if at else name):
        return Confidence.HIGH
    release = _release(tag)
    if release is None:
        return Confidence.LOW
    words = release.suffix.lstrip("-+~_").split("-")
    return Confidence.HIGH if not release.suffix or all(map(_known, words)) else Confidence.MEDIUM


def _pin_confidence(text: str) -> Confidence:
    # A version named outside an image tag, in .php-version or a workflow, is not what gets built.
    # So it stops at MEDIUM, and a version with no micro is LOW.
    return Confidence.MEDIUM if PhpVersion.parse(text) is not None else Confidence.LOW


def _at_most(confidence: Confidence, ceiling: Confidence) -> Confidence:
    return max(confidence, ceiling, key=_RANK.get)


def _uncomment(line: str) -> str:
    """line up to its comment. A # opens one at the start of the line or after whitespace."""
    for at, ch in enumerate(line):
        if ch == "#" and (not at or line[at - 1].isspace()):
            return line[:at]
    return line


def _scalar(value: str) -> str:
    """A YAML scalar without its quotes or its trailing comment."""
    value = value.strip()
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        return value[1:end] if end > 0 else value[1:]
    return _uncomment(value).rstrip()


def _pair(line: str) -> tuple[str, str]:
    """The key and scalar value of a YAML "key: value" line, or two empty strings."""
    key, colon, value = line.strip().lstrip("- ").partition(":")
    # YAML needs a space after the colon, so image:php:8 is one string and no pair.
    if not colon or (value and not value[0].isspace()):
        return "", ""
    return key.strip().strip("\"'"), _scalar(value)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _column(line: str) -> int:
    """Where the first key starts, past the indentation and a list dash."""
    return len(line) - len(line.lstrip(" -"))


def _unique(pins: _Pins) -> _Pins:
    seen: dict[str, Confidence] = {}
    for text, confidence in pins:
        if text:
            seen.setdefault(text, confidence)
    return list(seen.items())


def _member(node: object, key: str) -> object:
    return node.get(key) if isinstance(node, dict) else None


def _split_ref(ref: str) -> tuple[str, str, str]:
    """The repository, tag, and digest of an image reference. The tag and digest may be empty."""
    name, _, digest = ref.partition("@")
    head, slash, last = name.rpartition("/")
    base, _, tag = last.partition(":")
    return head + slash + base, tag, digest


def _is_php(repository: str) -> bool:
    path = repository.lower().split("/")
    # A first part with a dot or a colon is a registry host, as in localhost:5000/php.
    if len(path) > 1 and ("." in path[0] or ":" in path[0] or path[0] == "localhost"):
        path = path[1:]
    return path == ["php"] or path[-2:] in (["library", "php"], ["devcontainers", "php"])


def _php_image_tag(ref: str) -> Optional[str]:
    """The tag of a reference to the official php image, or None for any other image.

    No tag means latest. A digest stays on the end of the tag, where tag_confidence reads it.
    """
    repository, tag, digest = _split_ref(ref.strip())
    if not _is_php(repository):
        return None
    if digest:
        return tag + "@" + digest
    return tag or "latest"


def _sapi(tag: str) -> Sapi:
    words = tag.partition("@")[0].split("-")
    return next((sapi for word, sapi in _SAPIS if word in words), Sapi.UNKNOWN)


def _image_pin(tag: Optional[str]) -> _Pins:
    return [] if tag is None else [(tag, tag_confidence(tag))]


def _instructions(text: str) -> Iterator[str]:
    """Dockerfile lines with backslash continuations joined and comment lines dropped."""
    parts: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        if line.endswith("\\"):
            parts.append(line[:-1])
            continue
        parts.append(line)
        yield " ".join(parts)
        parts = []
    if parts:
        yield " ".join(parts)


def parse_dockerfile(text: str) -> _Pins:
    """The tag of each FROM line that pulls the official php image."""
    found: _Pins = []
    for line in _instructions(text):
        words = line.split()
        if len(words) > 1 and words[0].upper() == "FROM":
            # Flags such as --platform come before the image.
            image = next((w for w in words[1:] if not w.startswith("--")), "")
            found += _image_pin(_php_image_tag(image))
    return _unique(found)


def parse_compose(text: str) -> _Pins:
    """The tag of each image: entry that names the official php image."""
    found: _Pins = []
    for line in text.splitlines():
        key, value = _pair(line)
        if key == "image":
            found += _image_pin(_php_image_tag(value))
    return _unique(found)


def parse_ci_setup_php(text: str) -> _Pins:
    """The php-version of each shivammathur/setup-php step in a GitHub Actions workflow.

    A step runs from its uses: line to the first line indented less than that line's keys. The
    version is returned as written, so a matrix expression comes back as ${{ matrix.php }}.
    """
    found: _Pins = []
    floor: Optional[int] = None  # the column of the keys of the setup-php step now open
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        if floor is not None and _indent(line) < floor:
            floor = None
        key, value = _pair(line)
        if key == "uses" and value.lower().startswith("shivammathur/setup-php"):
            floor = _column(line)
        elif key == "php-version" and floor is not None and _indent(line) > floor:
            found.append((value, _pin_confidence(value)))
    return _unique(found)


def parse_dotfiles(name: str, text: str) -> _Pins:
    """The versions in a .php-version file (its first line) or a .tool-versions file (php lines)."""
    found: list[str] = []
    for line in text.splitlines():
        words = _uncomment(line).split()
        if not words:
            continue
        if name == ".php-version":
            found.append(words[0])
            break
        if name == ".tool-versions" and words[0] == "php":
            found.extend(words[1:])
    return _unique([(word, _pin_confidence(word)) for word in found])


def _no_number(text: str) -> None:
    # Neither parser reads a number. Turning a megabyte of digits into an int takes seconds before
    # Python 3.11, and 3.11 and later refuse it, which would cost the file its real pins.
    return None


def _load(text: str) -> object:
    return json.loads(text, parse_int=_no_number, parse_float=_no_number)


def parse_composer(text: str) -> _Pins:
    """The php requirement and the config.platform.php entry of a composer.json.

    Both only say what the project needs or asks Composer to assume, never what runs, so each
    comes back LOW. Raises ValueError or RecursionError on text that is not JSON.
    """
    data = _load(text)
    declared = (_member(_member(data, "require"), "php"),
                _member(_member(_member(data, "config"), "platform"), "php"))
    return _unique([(d.strip(), Confidence.LOW) for d in declared if isinstance(d, str)])


def _strip_jsonc(text: str) -> str:
    """text with its // and /* */ comments and trailing commas removed. VS Code allows both."""
    out: list[str] = []
    in_string = False
    comma = -1  # where in out a comma sits that no other token has followed yet
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\":
                out.append(text[i + 1:i + 2])  # the escaped character, whatever it is
                i += 1
            elif c == '"':
                in_string = False
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            if c in "}]" and comma >= 0:
                out[comma] = ""
            if c == ",":
                comma = len(out)
            elif not c.isspace():
                comma = -1
            in_string = c == '"'
            out.append(c)
            i += 1
    return "".join(out)


def parse_devcontainer(text: str) -> _Pins:
    """The image tag and the php feature's version in a devcontainer.json.

    A dev container is not what ships, so even an exact tag stops at MEDIUM. Raises ValueError or
    RecursionError on text that is not JSON once its comments are gone.
    """
    data = _load(_strip_jsonc(text))
    image = _member(data, "image")
    tag = _php_image_tag(image) if isinstance(image, str) else None
    found: _Pins = []
    if tag is not None:
        found.append((tag, _at_most(tag_confidence(tag), Confidence.MEDIUM)))
    features = _member(data, "features")
    if not isinstance(features, dict):
        features = {}
    for ref, options in features.items():
        if _split_ref(ref)[0].rsplit("/", 1)[-1] == "php":
            # A bare string is the spec's shorthand for the version option, and latest its default.
            version = options.get("version") if isinstance(options, dict) else options
            version = version.strip() if isinstance(version, str) and version.strip() else "latest"
            found.append((version, _pin_confidence(version)))
    return _unique(found)


class _Reader(NamedTuple):
    kind: str  # the kind signal of what it finds
    parse: Callable[[str], _Pins]


_DOCKERFILE = _Reader("dockerfile", parse_dockerfile)
_COMPOSE = _Reader("compose", parse_compose)
_CI = _Reader("ci-setup-php", parse_ci_setup_php)
_COMPOSER = _Reader(_FLOOR_KIND, parse_composer)
_DEVCONTAINER = _Reader("devcontainer", parse_devcontainer)
_BY_NAME = {
    ".php-version": _Reader("php-version-file", partial(parse_dotfiles, ".php-version")),
    ".tool-versions": _Reader("tool-versions", partial(parse_dotfiles, ".tool-versions")),
    "composer.json": _COMPOSER,
    "devcontainer.json": _DEVCONTAINER,
    ".devcontainer.json": _DEVCONTAINER,
}


def _is_dockerfile(name: str) -> bool:
    if name.endswith(_DOC_ENDINGS):
        return False
    for stem in ("dockerfile", "containerfile"):
        if name == stem or (name.startswith(stem) and name[len(stem)] in ".-_"):
            return True
    return name.endswith((".dockerfile", ".containerfile"))


def _is_compose(name: str) -> bool:
    stem = name.rsplit(".", 1)[0]
    return stem in ("compose", "docker-compose") or stem.startswith(
        ("compose.", "compose-", "docker-compose.", "docker-compose-"))


def _reader(rel: str) -> Optional[_Reader]:
    """The reader for a file, by its path relative to the repository, or None to leave it alone."""
    folder, _, name = rel.rpartition("/")
    name = name.lower()
    if _is_dockerfile(name):
        return _DOCKERFILE
    if name.endswith((".yml", ".yaml")):
        if folder == ".github/workflows" or folder.endswith("/.github/workflows"):
            return _CI
        return _COMPOSE if _is_compose(name) else None
    return _BY_NAME.get(name)


def _why(exc: OSError) -> str:
    # The message alone, because str(exc) carries the file name and so the absolute path.
    return exc.strerror or type(exc).__name__


def _skipped(repo: str, rel: str, reason: str) -> Evidence:
    """Evidence that a file or folder was passed over, with the reason in note.

    A skip is a gap in coverage. The scan knew the file by a name it reads, or met a folder it
    could not list or would not enter, and so could not see whether anything there pins an old
    build. It counts as PHP seen with no version. That holds the repo at INDETERMINATE while the
    gap is open, because a patched pin elsewhere must not clear a repo that has unread content.
    Every skip follows this one rule, including a link (its real content can sit under a name the
    scan does not read), a linked folder that leads out of the tree, and a composer.json.
    """
    signals = {"repo": repo, "kind": "skipped", "confidence": Confidence.LOW.name,
               "php_present": "true"}
    return Evidence(Source.REPO, rel, None, Sapi.UNKNOWN, signals, "skipped: " + reason)


def _evidence(repo: str, rel: str, reader: _Reader, declared: str,
              confidence: Confidence) -> Evidence:
    signals = {"repo": repo, "kind": reader.kind, "confidence": confidence.name,
               "declared": declared}
    version: Optional[str] = None
    if reader.kind == _FLOOR_KIND:
        # Not a version at all: the report shows detected_version as the PHP of an asset that
        # grades INDETERMINATE, and a requirement must not read as a build.
        note = f"php {declared} is a requirement, not the running build"
    else:
        release = _release(declared)
        if release is None:
            signals["php_present"] = "true"
            note = f"{declared} pins no patch release"
        else:
            version = f"{release.major}.{release.minor}.{release.micro}"
            note = ""
    return Evidence(Source.REPO, rel, version, _sapi(declared), signals, note)


def _finds(repo: str, rel: str, reader: _Reader, text: str) -> list[Evidence]:
    """The evidence in one file's text. It never raises, whatever the text holds."""
    try:
        pins = reader.parse(text)
    except Exception as exc:
        # The parsers read hostile text. Whatever one bad file makes them raise ends that file,
        # and the scan goes on with the next.
        return [_skipped(repo, rel, f"cannot parse it ({type(exc).__name__})")]
    fits = [pin for pin in pins if len(pin[0]) <= _MAX_TEXT]
    found = [_evidence(repo, rel, reader, declared, confidence)
             for declared, confidence in fits[:_MAX_PINS]]
    if len(fits) > _MAX_PINS:
        found.append(_skipped(
            repo, rel, f"it names more than {_MAX_PINS} PHP pins, and only the first {_MAX_PINS} "
            "were read"))
    if len(fits) < len(pins):
        over = len(pins) - len(fits)
        found.append(_skipped(
            repo, rel, f"it holds {over} {'value' if over == 1 else 'values'} over {_MAX_TEXT} "
            "characters, too long to be read as a pin"))
    return found


class _Skip(Exception):
    """A file to pass over. The message is the reason to record."""


def _decode(data: bytes) -> str:
    # PowerShell writes UTF-16 with a byte order mark when it redirects, and editors add a UTF-8
    # one. A file in any other encoding still reads, with the odd character replaced, because the
    # tokens that matter are ASCII.
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def _read(path: str) -> str:
    if not stat.S_ISREG(os.lstat(path).st_mode):
        # A named pipe with no writer would block the open for good.
        raise _Skip("it is not a regular file")
    with open(path, "rb") as f:
        # One byte past the cap tells a file at the limit from one over it. The size on disk is
        # no guide, because a pseudo-file can report none and then never end.
        data = f.read(_MAX_BYTES + 1)
    if len(data) > _MAX_BYTES:
        raise _Skip(f"it is larger than {_MAX_BYTES} bytes")
    return _decode(data)


def _scan_file(repo: str, rel: str, path: str, reader: _Reader) -> list[Evidence]:
    try:
        text = _read(path)
    except _Skip as skip:
        return [_skipped(repo, rel, str(skip))]
    except OSError as exc:
        return [_skipped(repo, rel, f"cannot read it ({_why(exc)})")]
    return _finds(repo, rel, reader, text)


def _is_plain(path: str) -> bool:
    # scandir calls a Windows junction an ordinary folder, but realpath resolves it, and then the
    # two spellings of the path differ.
    return os.path.normcase(os.path.realpath(path)) == os.path.normcase(path)


def _inside(root: str, path: str) -> bool:
    """True when path is root or sits under it. Both are resolved paths."""
    base = os.path.normcase(root).rstrip(os.sep)
    path = os.path.normcase(path)
    # The separator after the root keeps /srv/site2 from counting as inside /srv/site. A
    # filesystem root already ends in one, which is why the root is stripped before it is added.
    return path == base or path.startswith(base + os.sep)


def _repo_name(top: str) -> str:
    # The directory name keeps the id readable. Eight hex characters of a hash of the resolved path
    # keep /a/app and /b/app apart in one inventory, and only those eight leave the machine, not
    # the path. A filesystem root has no name, so its path stands in. The joiner is a tilde because
    # the report masks the value in name:value when the name holds a word like auth or token.
    digest = hashlib.sha256(os.fsencode(top)).hexdigest()[:8]
    return f"{os.path.basename(top) or top}~{digest}"


def scan_path(root: str) -> list[Evidence]:
    """One Evidence per PHP pin under root, in a fixed order, located relative to root.

    The repo signal on each is the name of the directory scanned, a tilde, and eight hex characters
    of a hash of its resolved path, so two checkouts that share a name stay two assets. Links
    inside the tree are not followed. A linked folder that leads out of the tree, and a linked
    file with a name the scan reads, are reported as skipped, and so is a file that cannot be read,
    is too large, or will not parse, with the reason in note. A folder link that stays inside the
    tree adds nothing, because the folder is read where it really sits. A skip counts as PHP seen
    with no version, so a repo with one cannot grade as patched. A root that is itself a link is
    resolved first. A root that cannot be listed raises OSError, because an empty list would read
    as a clean repository.
    """
    top = os.path.realpath(root)
    repo = _repo_name(top)
    found: list[Evidence] = []
    todo = [("", top)]  # folders still to read, as (path relative to root, path on disk)
    while todo:
        rel_dir, directory = todo.pop()
        try:
            with os.scandir(directory) as entries:
                listing = sorted(entries, key=lambda entry: entry.name)
        except OSError as exc:
            if not rel_dir:
                raise
            found.append(_skipped(repo, rel_dir, f"cannot list it ({_why(exc)})"))
            continue
        subdirs = []
        for entry in listing:
            rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            try:
                linked = entry.is_symlink()
                folder = entry.is_dir(follow_symlinks=False)
                # A link leads to a folder when its target is one. A dangling link leads nowhere.
                leads_to_folder = linked and entry.is_dir()
            except OSError as exc:
                found.append(_skipped(repo, rel, f"cannot inspect it ({_why(exc)})"))
                continue
            if folder or leads_to_folder:
                if entry.name in _SKIP_DIRS:
                    continue
                if folder and _is_plain(entry.path):
                    subdirs.append((rel, entry.path))
                elif not _inside(top, os.path.realpath(entry.path)):
                    # A symlink, or a junction that scandir takes for an ordinary folder, that
                    # leads out of this tree. Nothing in it is read, and a patched pin elsewhere
                    # must not clear the repo past it. A link that stays inside leads to a folder
                    # the walk reads where it really sits, so it is no gap and gets no row.
                    found.append(_skipped(repo, rel, "linked directory not traversed"))
                continue
            reader = _reader(rel)
            if reader is None:
                continue
            if linked:
                found.append(
                    _skipped(repo, rel, "it is a symbolic link, and links are not followed"))
            else:
                found += _scan_file(repo, rel, entry.path, reader)
        todo.extend(reversed(subdirs))
    return found
