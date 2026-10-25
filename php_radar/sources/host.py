"""Reads the PHP installed on a machine you control, this one or one reached over SSH.

inspect_local and inspect_ssh run php -v, php -i, and the package manager on the machine and
return one HOST Evidence. HOST outranks every other source. Each command is a fixed argument
list that goes to subprocess with no shell. The program is found by walking the absolute entries
of PATH, because Windows would run a php.exe or ssh.exe planted in the current directory first.
Over SSH the login shell on the far side still splits the command line. For that reason no value
read from a machine is ever put into a later command. A target also has to look like a host name
or address before ssh sees it.

Output from a machine is data. This module keeps the version, the SAPI, four ini settings, the OS
name, and the versions of PHP packages, each after a check on its length and characters. It drops
the rest of php -i, because the Environment section holds the environment of the process and any
credentials that were in it.

It sets the distro signal only when an installed package confirms that the running PHP is a distro
build, since a backport makes the upstream number lie. PHP built from source gets no distro signal
and grades on its number.

php_present is "false", with an empty note, only on a positive read: the machine answered, has no
php command, and lists no package with php in its name. Any read that fails leaves php_present
unset and says why in the note, so the grader returns INDETERMINATE and never NOT_PHP.

Limits. The ini values annotate and move no verdict. They come from the php that answered, and the
CLI often reads a different php.ini from the web SAPI. A machine with several PHP versions
installed reports the one that php runs. A package says what is installed and nothing about a
process that started before it was upgraded. A removed package whose configuration files remain
still lists under dpkg-query -W. That holds NOT_PHP back. So does phpmyadmin: the test for a PHP
package is loose on purpose, because packagers name PHP in many ways, while matching a build to
the running version is exact.
"""
import os
import socket
import string
import subprocess
from typing import Callable, NamedTuple, Optional

from php_radar.model import Evidence, Sapi, Source
from php_radar.versions import PhpVersion
# The grader decides what a distro revision is, and the network source tells a name from an
# address. Using theirs keeps a host read and the other reads of one machine in agreement.
from php_radar.knowledge import _is_revision
from php_radar.sources.network import _identity

# Seconds for one command. An ssh connect has a shorter limit of its own.
_TIMEOUT = 30.0

# The exit status of a POSIX shell for a command it cannot find, and the one ssh gives when the
# trouble is its own: the connection, the login, or the configuration.
_NOT_FOUND = 127
_SSH_FAILED = 255

# BatchMode keeps ssh from asking a question nobody is there to answer. The agent, X11, and any
# forwarding the user's config sets stay off, because the machine on the far side may be the one
# under suspicion. Keys, ports, jump hosts, and the host key check are left to the user's config.
_SSH = ["ssh", "-a", "-x", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "ClearAllForwardings=yes"]

_V = ("php", "-v")
_I = ("php", "-i")
_OS = ("cat", "/etc/os-release")
_DPKG = ("dpkg-query", "-W")
_RPM = ("rpm", "-qa")

_ALNUM = string.ascii_letters + string.digits
_NAME = frozenset(_ALNUM + "-._")  # a host name, a login name, an os-release ID or VERSION_ID
_HOST = _NAME | frozenset(":")  # an ssh host, which may be an IPv6 address
_HOST_START = frozenset(_ALNUM + ":")
_MAX_HOST = 253
_MAX_USER = 64
_MAX_ID = 32

_VERSION_CHARS = frozenset(_ALNUM + ".+~_-")
# No real version string is longer than this. A build string cut short would hand the grader a
# build that no machine printed, so a longer one is dropped.
_MAX_VERSION = 64
# The grader reads no package build longer than this.
_MAX_BUILD = 128
_MAX_NAME = 64

# The four settings take values like 128M, -1, On, and no value.
_VALUE_CHARS = frozenset(_ALNUM + " -")
_MAX_VALUE = 32

_DEB_NAME = frozenset(string.ascii_lowercase + string.digits + "+-.")
_DEB_VERSION = frozenset(_ALNUM + ".+-~")
_RPM_CHARS = frozenset(_ALNUM + "._+~")
_RPM_NAME = _RPM_CHARS | frozenset("-")
_ARCHES = frozenset({"x86_64", "i386", "i486", "i586", "i686", "aarch64", "armv7hl", "ppc64",
                     "ppc64le", "s390x", "noarch"})

# Four ini settings recorded as context for a triager. They annotate a finding and never clear
# one. No ini setting fixes the memory-corruption path of CVE-2026-109618, which a large
# multipart request reaches on its own, so session.upload_progress.enabled bears only on
# CVE-2026-109619, and memory_limit reads backwards: a finite limit is the condition the trigger
# needs and -1 is protective.
_INI = frozenset({"memory_limit", "post_max_size", "session.upload_progress.enabled",
                  "fatal_error_backtraces"})
_WANTED = _INI | {"PHP Version", "Server API"}

# Keyed by the lower-case name php -v puts in parentheses and by the one php -i prints.
_SAPIS = {
    "cli": Sapi.CLI, "command line interface": Sapi.CLI,
    "fpm-fcgi": Sapi.FPM, "fpm/fastcgi": Sapi.FPM,
    "cgi-fcgi": Sapi.CGI, "cgi": Sapi.CGI, "cgi/fastcgi": Sapi.CGI,
    "apache2handler": Sapi.MOD_PHP, "apache 2.0 handler": Sapi.MOD_PHP,
    "apache2filter": Sapi.MOD_PHP, "apache 2.0 filter": Sapi.MOD_PHP,
}

# The os-release IDs that the matrix data file keys as suse. Every other ID is its own key.
_ALIASES = {"sles": "suse", "sled": "suse", "sles_sap": "suse", "opensuse": "suse",
            "opensuse-leap": "suse", "opensuse-tumbleweed": "suse"}
_DEB_DISTROS = frozenset({"debian", "ubuntu"})
_RPM_DISTROS = frozenset({"suse", "rhel", "centos", "fedora", "rocky", "almalinux", "amzn", "ol"})

Run = Callable[[list], subprocess.CompletedProcess]


def _on_path(name: str) -> Optional[str]:
    """The full path of the program called name on PATH, or None.

    PATH is walked here and nothing else is searched. CreateProcess on Windows tries the current
    directory before PATH, and an empty or relative PATH entry means the current directory on
    POSIX. A php or ssh planted where the tool runs would then start as the operator. Only an
    absolute entry counts, and that includes one that names the current directory, because the
    operator put it on PATH. An empty entry is not absolute, so it is skipped with the relative
    ones. Windows allows an entry in double quotes. On Windows the program is name.exe, because a
    script would run through cmd.exe and its argument rules.
    """
    suffix = ".exe" if os.name == "nt" and not name.lower().endswith(".exe") else ""
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        entry = entry.strip('"')
        if not os.path.isabs(entry):
            continue
        path = os.path.join(entry, name + suffix)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _program(name: str) -> str:
    """The program to start for name: an absolute path as given, else its place on PATH."""
    if os.path.isabs(name):
        return name
    if os.path.basename(name) != name:
        # A relative path is the current directory again, under another spelling.
        raise ValueError("a program is a bare name or an absolute path")
    path = _on_path(name)
    if path is None:
        raise FileNotFoundError(2, "not found on PATH", name)
    return path


def subprocess_run(args: list, timeout: float = _TIMEOUT) -> subprocess.CompletedProcess:
    """Run one command and return what subprocess.run returns.

    This is the one place a process starts. It takes a list of strings and nothing else, because
    Windows splits a string into words even with the shell off. It finds the program itself, on
    the absolute entries of PATH, and starts it by its full path. A program that is not on PATH
    raises FileNotFoundError. Nothing waits on a terminal: stdin is closed and stderr is dropped.
    Output is read as UTF-8, and a byte that is not UTF-8 becomes a replacement character.
    """
    if not isinstance(args, list) or not args or not all(isinstance(a, str) for a in args):
        raise TypeError("a command is a list of strings")
    return subprocess.run(
        [_program(args[0])] + args[1:], shell=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False,
        encoding="utf-8", errors="replace")


class _Got(NamedTuple):
    out: Optional[str] = None  # stdout, when the command ran and exited 0
    missing: bool = False  # the command was not found
    why: str = ""  # what went wrong, in words fit for a note
    code: Optional[int] = None  # the exit status, when there was one


def _get(run: Run, argv: list) -> _Got:
    try:
        done = run(argv)
    except FileNotFoundError:
        return _Got(missing=True, why="not found")
    except subprocess.TimeoutExpired:
        return _Got(why="timed out")
    except OSError as exc:
        return _Got(why=f"could not start ({type(exc).__name__})")
    code = done.returncode
    if code == 0:
        return _Got(out=done.stdout or "", code=code)
    if code == _NOT_FOUND:
        return _Got(missing=True, why="not found", code=code)
    return _Got(why=f"exit {code}", code=code)


class _Machine:
    """One machine being read: how to reach it, and what its commands have printed so far."""

    def __init__(self, run: Run, wrap: Callable[[list], list]) -> None:
        self._run = run
        self._wrap = wrap
        self.raw: dict[str, str] = {}

    def read(self, cmd: tuple) -> _Got:
        got = _get(self._run, self._wrap(list(cmd)))
        if got.out is not None:
            self.raw[_key(cmd)] = got.out
        return got

    def list_packages(self, distro: str) -> None:
        """Read the listings that fit distro in order, and stop at the first one with packages."""
        for cmd in _managers(distro):
            self.read(cmd)
            if _listing(distro, self.raw) is not None:
                return


def _key(cmd: tuple) -> str:
    return " ".join(cmd)


def _fits(value: str, chars: frozenset, limit: int) -> bool:
    return 0 < len(value) <= limit and chars.issuperset(value)


def _version(token: str) -> Optional[PhpVersion]:
    """The version a token spells, or None when it is no version or longer than any real one."""
    if not _fits(token, _VERSION_CHARS, _MAX_VERSION):
        return None
    return PhpVersion.parse(token)


def _upstream(version: PhpVersion) -> str:
    """The upstream number. A distro revision is cut off, and a pre-release tag stays, because the
    grader reads 8.3.36-dev as a build that may not hold the fix."""
    base = f"{version.major}.{version.minor}.{version.micro}"
    return base if _is_revision(version) else base + version.suffix


def _banner(text: str) -> Optional[tuple[str, str]]:
    """(version, sapi) from the first line of php -v that reads like PHP 8.3.35 (cli)."""
    for line in text.splitlines():
        word, _, rest = line.partition(" ")
        token, _, tail = rest.partition(" ")
        if word == "PHP" and _version(token) is not None:
            tail = tail.strip()
            api = tail[1:].partition(")")[0] if tail.startswith("(") else ""
            return token, api.strip().lower()
    return None


def _first(text: str, names: frozenset) -> dict[str, str]:
    """The local value of each name from the name => value lines that php -i prints.

    The first line for a name decides. The Environment section comes after the directives, and a
    variable can be called anything.
    """
    found: dict[str, str] = {}
    for line in text.splitlines():
        name, arrow, rest = line.partition(" => ")
        if arrow and name in names and name not in found:
            found[name] = rest.partition(" => ")[0].strip()
    return found


def collect_ini(raw: dict) -> dict:
    """The ini settings that bear on PHP2Shell, taken from what php -i printed.

    raw maps a command line such as "php -i" to its output. A setting is recorded as php -i
    shows it for this run, and a value that is not a short plain word is left out. These are
    annotations. Nothing here changes the version that the grader reads.
    """
    found = _first(raw.get(_key(_I)) or "", _INI)
    return {name: value for name, value in found.items()
            if _fits(value, _VALUE_CHARS, _MAX_VALUE)}


class _Php(NamedTuple):
    # token is the version text as php printed it, revision included. It has passed the checks
    # only when version is set, so nothing reads it otherwise.
    token: str
    version: Optional[PhpVersion]
    sapi: Sapi


def _php(raw: dict) -> Optional[_Php]:
    """What php -v and php -i say about the PHP that answered, or None when neither shows PHP."""
    banner = _banner(raw.get(_key(_V)) or "")
    info = _first(raw.get(_key(_I)) or "", _WANTED)
    if banner is None and not info:
        return None
    token, api = banner if banner else (info.get("PHP Version", ""), "")
    sapi = _SAPIS.get(api, Sapi.UNKNOWN)
    if sapi is Sapi.UNKNOWN:
        sapi = _SAPIS.get(info.get("Server API", "").lower(), Sapi.UNKNOWN)
    return _Php(token, _version(token), sapi)


def _os_release(text: str) -> tuple[str, str]:
    """(ID, VERSION_ID) from os-release. Either is "" when it is missing or not a plain word."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        key, eq, value = line.partition("=")
        if eq and key in ("ID", "VERSION_ID") and key not in found:
            found[key] = value.strip().strip("\"'")
    ident, release = found.get("ID", "").lower(), found.get("VERSION_ID", "")
    return (ident if _fits(ident, _NAME, _MAX_ID) else "",
            release if _fits(release, _NAME, _MAX_ID) else "")


def _no_epoch(version: str) -> str:
    epoch, colon, rest = version.partition(":")
    return rest if colon and epoch.isdigit() else version


def _deb(text: str) -> list[tuple[str, str]]:
    """(name, version) for each line of dpkg-query -W. The epoch and the architecture are cut.

    A real version starts with a digit. Requiring that keeps an error message with a tab in it
    from passing as a listing, because an empty or invented listing could clear a host.
    """
    found = []
    for line in text.splitlines():
        name, _, version = line.partition("\t")
        name, colon, arch = name.partition(":")
        version = _no_epoch(version.strip())
        if (_fits(name, _DEB_NAME, _MAX_NAME) and (not colon or _fits(arch, _DEB_NAME, _MAX_NAME))
                and _fits(version, _DEB_VERSION, _MAX_BUILD) and version[0].isdigit()):
            found.append((name, version))
    return found


def _rpm(text: str) -> list[tuple[str, str]]:
    """(name, version-release) for each name-version-release.arch line of rpm -qa.

    The version has to start with a digit, so hyphenated words in an error message do not pass.
    """
    found = []
    for line in text.splitlines():
        rest, _, release = line.strip().rpartition("-")
        name, _, version = rest.rpartition("-")
        stem, dot, arch = release.rpartition(".")
        if dot and arch in _ARCHES:
            release = stem
        if (_fits(name, _RPM_NAME, _MAX_NAME) and _fits(version, _RPM_CHARS, _MAX_BUILD)
                and version[0].isdigit() and _fits(release, _RPM_CHARS, _MAX_BUILD)
                and len(version) + len(release) < _MAX_BUILD):
            found.append((name, f"{version}-{release}"))
    return found


_PARSERS = {_key(_DPKG): _deb, _key(_RPM): _rpm}


def _managers(distro: str) -> tuple:
    """The listing commands to try for a distro. Debian and Ubuntu use dpkg, the rpm distros use
    rpm, and any other distro gets dpkg and then rpm."""
    if distro in _DEB_DISTROS:
        return (_DPKG,)
    if distro in _RPM_DISTROS:
        return (_RPM,)
    return (_DPKG, _RPM)


def _listing(distro: str, raw: dict) -> Optional[list[tuple[str, str]]]:
    """The packages in the first listing of raw that has any, or None when none does."""
    for cmd in _managers(distro):
        packages = _PARSERS[_key(cmd)](raw.get(_key(cmd)) or "")
        if packages:
            return packages
    return None


def _php_package(name: str) -> bool:
    # For matching a build to the running version, which has to be exact. php, php-cli,
    # php8.1-fpm, php83 and php8-cli are PHP. phpmyadmin and phpunit are not.
    return name.startswith("php") and (len(name) == 3 or name[3] in string.digits + "-")


def _mentions_php(name: str) -> bool:
    # For deciding that a host has no PHP, which has to catch every packaging: plesk-php81-cli,
    # ea-php81-php-cli, lsphp81, alt-php81-cli, rh-php73-php-fpm, libapache2-mod-php8.1, and
    # libphp8.1-embed. A miss would clear a host that runs PHP, so phpmyadmin counts too.
    return "php" in name.lower()


class _Package(NamedTuple):
    # found: one installed build matches the running PHP. none: a listing was read and no PHP
    # package matches. mixed: packages of the running version disagree on the build. unlisted: no
    # listing could be read. unknown: php gave no version to match.
    state: str
    build: Optional[str] = None
    revision: Optional[str] = None


def _resolve(distro: str, raw: dict) -> _Package:
    php = _php(raw)
    if php is None or php.version is None:
        return _Package("unknown")
    packages = _listing(distro, raw)
    if packages is None:
        return _Package("unlisted")
    # A running version with a revision on it is the build itself, so only a package with exactly
    # that build counts. Without one, any package built from the same upstream number does.
    revision = _is_revision(php.version)
    builds = {build for name, build in packages if _php_package(name)
              and PhpVersion.parse(build) == php.version
              and (build == php.token or not revision)}
    if len(builds) != 1:
        return _Package("mixed" if builds else "none")
    (build,) = builds
    _, hyphen, tail = build.rpartition("-")
    return _Package("found", build, tail if hyphen else None)


def resolve_package(distro: str, raw: dict) -> tuple[Optional[str], Optional[str]]:
    """The installed build of the PHP that php reports, and its distro revision: (build, revision).

    raw maps a command line, such as "php -v", "dpkg-query -W", or "rpm -qa", to what it printed.
    distro is a key from the matrix data file: ubuntu, debian, alpine, or suse. It picks the
    package manager whose listing counts. Debian and Ubuntu use dpkg, the rpm distros use rpm,
    and any other distro tries dpkg and then rpm.

    The build comes from the PHP package built from the running version, with the epoch and the
    architecture cut. The revision is what follows its last hyphen, the mark of the distro's own
    rebuild. When php gave no version, no listing could be read, no package matches, or the
    matching packages disagree, the answer is (None, None). Nothing is guessed.
    """
    pkg = _resolve(distro, raw)
    return pkg.build, pkg.revision


def _unconfirmed(pkg: _Package, php: _Php, distro: str) -> str:
    """Why the distro of this PHP is not confirmed, or "" when nothing is in doubt."""
    if pkg.state == "unlisted":
        return "no package listing could be read"
    if pkg.state == "mixed":
        return "installed PHP packages carry different builds of this version"
    if pkg.state == "none" and php.version is not None and _is_revision(php.version):
        return "php reports a distro build that no installed package lists"
    if pkg.state == "found" and not distro:
        return "the distro name could not be read"
    return ""


def _who(host: str) -> dict[str, str]:
    # An IPv6 address can start with a hex letter, which would pass for the last label of a name.
    return {"ip": host} if ":" in host else _identity(host)


def _link(got: _Got) -> str:
    if got.code == _SSH_FAILED:
        # A php that dies at startup exits 255 as well, so the note does not claim more than that.
        return f"ssh exited {_SSH_FAILED} (the connection, the login, or the remote command failed)"
    return "ssh was not found" if got.missing else f"ssh {got.why}"


def _unread(name: str, got: _Got) -> str:
    return f"{name} gave no PHP output" if got.out is not None else f"{name} {got.why}"


def _without_php(m: _Machine, location: str, who: dict[str, str], v: _Got, i: _Got) -> Evidence:
    signals = dict(who)
    if not (v.missing and i.missing):
        note = f"php could not be read ({_unread('php -v', v)}; {_unread('php -i', i)})"
        return Evidence(Source.HOST, location, None, Sapi.UNKNOWN, signals, note)
    # Both reads say there is no php command. An install with only php-fpm or an Apache module has
    # no such command, so the package manager has to agree before this counts as no PHP.
    m.list_packages("")
    packages = _listing("", m.raw)
    if packages is None:
        note = ("no php command was found and no package listing could be read: "
                "PHP may still be installed")
    elif any(_mentions_php(name) for name, _ in packages):
        signals["php_present"] = "true"
        note = ("no php command was found, but a package with php in its name is installed: "
                "the build was not read")
    else:
        signals["php_present"] = "false"
        note = ""
    return Evidence(Source.HOST, location, None, Sapi.UNKNOWN, signals, note)


def _with_php(m: _Machine, location: str, who: dict[str, str], i: _Got, php: _Php) -> Evidence:
    m.read(_OS)
    ident, release = _os_release(m.raw.get(_key(_OS), ""))
    distro = _ALIASES.get(ident, ident)
    if php.version is not None:
        m.list_packages(distro)
    pkg = _resolve(distro, m.raw)

    signals = dict(who)
    signals["php_present"] = "true"
    if ident:
        signals["os"] = f"{ident} {release}" if release else ident
    if pkg.state == "found":
        signals["package_version"] = pkg.build
        if distro:
            signals["distro"] = distro
    elif php.version is not None and _is_revision(php.version):
        signals["package_version"] = php.token
    signals.update(collect_ini(m.raw))

    notes = []
    if i.out is None:
        notes.append(f"php -i {i.why}: ini settings not recorded")
    if php.version is None:
        notes.append("the PHP version could not be read")
    doubt = _unconfirmed(pkg, php, distro)
    if doubt:
        notes.append("provenance unconfirmed: " + doubt)
    detected = _upstream(php.version) if php.version else None
    return Evidence(Source.HOST, location, detected, php.sapi, signals, "; ".join(notes))


def _inspect(m: _Machine, location: str, who: dict[str, str], remote: bool) -> Evidence:
    v = m.read(_V)
    if remote and v.code in (None, _SSH_FAILED):
        # The link is down, so every other read would fail the same way and wait as long.
        return Evidence(Source.HOST, location, None, Sapi.UNKNOWN, dict(who),
                        "not inspected: " + _link(v))
    i = m.read(_I)
    php = _php(m.raw)
    if php is None:
        return _without_php(m, location, who, v, i)
    return _with_php(m, location, who, i, php)


def inspect_local(run: Run = subprocess_run) -> Evidence:
    """One HOST Evidence for the PHP on this machine.

    run is called with a list of strings and returns what subprocess.run returns. The evidence is
    named for the machine by hostname, or by ip when the name is an address.
    """
    name = socket.gethostname()
    who = _who(name) if _fits(name, _NAME, _MAX_HOST) else {}
    return _inspect(_Machine(run, list), name if who else "localhost", who, remote=False)


def _ssh_host(target: object) -> Optional[str]:
    """The host in a [user@]host target, or None when the target is anything else.

    A leading hyphen would read as an ssh option, and anything past name characters could read as
    more than a name to a shell on either side. The user name is checked for the same reasons.
    """
    if not isinstance(target, str):
        return None
    user, at, host = target.rpartition("@")
    if at and not (_fits(user, _NAME, _MAX_USER) and user[0] != "-"):
        return None
    if not (_fits(host, _HOST, _MAX_HOST) and host[0] in _HOST_START):
        return None
    return host


def inspect_ssh(target: str, run: Run = subprocess_run) -> Evidence:
    """One HOST Evidence for the PHP on the machine at target, a host name or address with an
    optional user@ in front.

    The commands run through the system ssh client, with the target and each word of the remote
    command as separate arguments. The evidence is named for the host in the target, the name the
    operator supplied, and never for a name the machine gives itself, because a machine under
    suspicion could claim another host's name. A target that is not a plain host is refused before
    anything runs.
    """
    host = _ssh_host(target)
    if host is None:
        return Evidence(Source.HOST, "ssh", None, Sapi.UNKNOWN, {},
                        "not inspected: the ssh target must be a host name or address, "
                        "with an optional user@ in front")
    machine = _Machine(run, lambda cmd: _SSH + ["--", target] + cmd)
    return _inspect(machine, host, _who(host), remote=True)
