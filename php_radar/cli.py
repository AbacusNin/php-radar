"""The php-radar command line, with one subcommand for each way of finding PHP.

repo reads a checkout or a GitHub organization, network sweeps a scope file, host reads this
machine or one reached over ssh, and cloud lists an account. Each gathers evidence into an
AssetInventory, grades it against the PHP2Shell matrix, and prints a console, JSON, or SARIF
report. The exit status is 1 when any asset grades EXPOSED and 2 for a usage or scope error.
Otherwise it is 0 when no read was skipped and 3 when one was, so a scan with a blind spot cannot
pass as clean. A network sweep exits 0 or 1. A target that does not answer is a finished check,
and the count line that ends the report shows how much of the scope was reached. A crash in
php-radar itself exits 4 with its traceback on stderr, and Ctrl-C exits 130. Left alone, a crash
would exit 1, which reads as an exposed asset.

Credentials come from the environment and the standard chains and never from a flag. Notes about
how far a run reached, such as the regions read or the targets a sweep left out, close a console
report. They go to stderr as well, except when that report is printed on stdout. So stdout stays
one document with json or sarif.
"""
import argparse
import json
import os
import sys
import traceback
from typing import NamedTuple, Optional

from php_radar.knowledge import DATA_PATH, Matrix, MatrixError, grade, load_matrix
from php_radar.model import Asset, AssetInventory, Evidence, Source, Verdict
# The report escapes whatever is not printable ASCII. The notes here carry names and paths typed
# at the keyboard, and they follow the same rule.
from php_radar.report import _plain, render_console, render_json, render_sarif
from php_radar.scope import ScopeError, guard, parse_scope
from php_radar.sources.cloud import get_cloud_source
from php_radar.sources.github import scan_github_org
from php_radar.sources.host import inspect_local, inspect_ssh
from php_radar.sources.network import sweep
from php_radar.sources.repo import scan_path

# A sweep starts at most this many probes a second. A /24 on the default ports takes about a
# minute. That pace is gentle on the network under test.
RATE = 10.0
DEFAULT_MAX_HOSTS = 1024
DEFAULT_WORKERS = 16
# At RATE, with a 5 second wait on a silent host, about 50 probes are in flight at once. More
# workers than this add nothing at that pace.
MAX_WORKERS = 64

_FORMATS = {"console": render_console, "json": render_json, "sarif": render_sarif}


class _Usage(Exception):
    """The command cannot be carried out as given. The message says why."""


class _Run(NamedTuple):
    evidence: list[Evidence]
    notes: list[str]  # what a reader needs to know about how far the run reached
    scan: Optional[dict] = None  # the same facts as numbers, for a JSON or SARIF document


def _whole(text: str) -> int:
    try:
        number = int(text)
    except ValueError:
        number = 0
    if number < 1:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number of 1 or more")
    return number


def _region(text: str) -> str:
    name = text.strip()
    if not name:
        raise argparse.ArgumentTypeError("a region name cannot be empty")
    return name


def _parser() -> argparse.ArgumentParser:
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--format", choices=list(_FORMATS), default="console",
                        help="report format (default: console)")
    shared.add_argument("--output", metavar="FILE",
                        help="write the report to FILE (default: stdout)")

    parser = argparse.ArgumentParser(
        prog="php-radar", allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Finds PHP and grades each find against PHP2Shell (CVE-2026-109618 and "
                    "CVE-2026-109619).\nIt detects. Nothing it sends is meant to trigger the bug.",
        epilog="exit status:\n"
               "  0  no asset grades EXPOSED and no read was skipped\n"
               "  1  at least one asset grades EXPOSED\n"
               "  2  a usage or scope error\n"
               "  3  no asset grades EXPOSED, but a read was skipped (an unreadable file, a\n"
               "     failed GitHub or AWS call, a host that could not be inspected), so the\n"
               "     scan is incomplete\n"
               "  4  an unexpected error in php-radar itself, with its traceback on stderr\n"
               "\n"
               "Ctrl-C ends a run with status 130.\n"
               "\n"
               "A network sweep exits 0 or 1, because a target that does not answer is a\n"
               "finished check. A sweep that reached nothing exits 0 too. The count line that\n"
               "ends its report (targets probed, reported, and left out) and the notes on its\n"
               "rows show what was reached.\n"
               "\n"
               "Credentials are never taken from a flag. repo reads GITHUB_TOKEN from the\n"
               "environment, and cloud uses the standard AWS credential chain.")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def command(name: str, **kwargs) -> argparse.ArgumentParser:
        # Flags are spelled in full, so --allow cannot stand in for the public override.
        return commands.add_parser(name, parents=[shared], allow_abbrev=False, **kwargs)

    repo = command("repo", help="find PHP pins in a checkout or a GitHub organization")
    repo.add_argument("path", nargs="?", help="folder to scan, or give --github-org")
    repo.add_argument("--github-org", metavar="NAME",
                      help="scan the default branches of this GitHub organization. GITHUB_TOKEN "
                           "is used when it is set")
    repo.set_defaults(handler=_repo)

    network = command(
        "network", help="sweep the targets in a scope file for PHP",
        description="Probes each target in the scope file with one GET of / and reads the "
                    "headers of the answer. The scope file is the authorization boundary.")
    network.add_argument("--scope", required=True, metavar="FILE",
                         help="the targets to probe, one per line: an IPv4 address, an IPv4 "
                              "range in CIDR form, or a hostname, each with an optional :port")
    network.add_argument("--allow-public", action="store_true",
                         help="turn on the explicit public override: public addresses and every "
                              "hostname but localhost. Without it only private space is probed")
    network.add_argument("--max-hosts", type=_whole, default=DEFAULT_MAX_HOSTS, metavar="N",
                         help="most targets to probe. A target is a host and port pair, so a "
                              f"host on two ports counts twice (default {DEFAULT_MAX_HOSTS})")
    network.add_argument("--workers", type=_whole, default=DEFAULT_WORKERS, metavar="N",
                         help=f"probes that can wait on a host at once, up to {MAX_WORKERS} "
                              f"(default {DEFAULT_WORKERS})")
    network.set_defaults(handler=_network)

    host = command("host", help="read the PHP installed on this machine or over ssh")
    host.add_argument("--ssh", metavar="TARGET",
                      help="inspect [USER@]HOST over ssh. Without the flag this machine is read")
    host.set_defaults(handler=_host)

    cloud = command("cloud", help="list the PHP an account runs, using read-only calls")
    cloud.add_argument("--provider", required=True, metavar="NAME", help="the cloud to read: aws")
    cloud.add_argument("--region", action="append", type=_region, metavar="NAME",
                       help="a region to read, repeated for several. Without it the session's "
                            "own region is read")
    cloud.set_defaults(handler=_cloud)
    return parser


def _say(line: str) -> None:
    print(_plain(line), file=sys.stderr)


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def _repo(args: argparse.Namespace) -> _Run:
    if (args.path is None) == (args.github_org is None):
        raise _Usage("name a path or --github-org, and only one of them")
    if args.github_org is not None:
        return _github(args.github_org)
    if not args.path.strip():
        # realpath("") is the current folder, and an unset shell variable makes an empty argument.
        raise _Usage("the path is empty, and an empty path would scan the current folder")
    try:
        found = scan_path(args.path)
    except OSError as exc:
        raise _Usage(f"cannot read {args.path}: {exc.strerror or type(exc).__name__}") from exc
    return _Run(found, [] if found else [f"no PHP pins found under {args.path}."])


def _github(org: str) -> _Run:
    token = os.environ.get("GITHUB_TOKEN", "")
    try:
        found = scan_github_org(org, token)
    except ValueError as exc:
        # The client says what it refused and never quotes the token.
        raise _Usage(f"cannot scan {org!r}: {exc}") from exc
    notes = []
    if not token.strip():
        notes.append("GITHUB_TOKEN is empty or not set, so the scan is anonymous. It sees public "
                     "repositories only, and GitHub allows 60 requests an hour.")
    if not found:
        notes.append(f"no PHP pins found for {org}. That can mean its repositories pin no PHP, "
                     "or that none of them was visible to this scan.")
    return _Run(found, notes)


def _network(args: argparse.Namespace) -> _Run:
    try:
        scope = parse_scope(args.scope)
        targets = guard(scope, args.allow_public, args.max_hosts)
    except ScopeError as exc:
        raise _Usage(str(exc)) from exc
    workers = min(args.workers, MAX_WORKERS)
    if workers < args.workers:
        _say(f"php-radar network: --workers {args.workers} is above the limit of {MAX_WORKERS}, "
             f"so {MAX_WORKERS} are used.")
    _say(f"php-radar network: about to probe {_count(len(targets), 'target')} (host and port "
         f"pairs) from the scope file {args.scope}.")
    _say("php-radar network: authorization acknowledgment. By continuing you confirm that you own "
         "these systems or hold written permission to test them.")
    if args.allow_public:
        _say("php-radar network: --allow-public is set, so public addresses and every hostname "
             "in the scope file can be probed.")
    found = sweep(targets, RATE, workers)
    # sweep drops a host that answered with no sign of PHP, so a clean perimeter comes back
    # empty. The count tells it from a sweep that probed nothing.
    probed, reported = len(targets), len(found)
    left = probed - reported
    note = (f"probed {_count(probed, 'target')}, reported {reported} of them, left out {left} "
            "that answered with no sign of PHP.")
    scan = {"targets_probed": probed, "targets_reported": reported,
            "targets_answered_without_php": left}
    return _Run(found, [note], scan)


def _host(args: argparse.Namespace) -> _Run:
    # An empty --ssh is still a request for ssh. Only an absent flag means this machine.
    ev = inspect_local() if args.ssh is None else inspect_ssh(args.ssh)
    return _Run([ev], [])


def _cloud(args: argparse.Namespace) -> _Run:
    try:
        source = get_cloud_source(args.provider)
    except (RuntimeError, ValueError) as exc:
        # RuntimeError: the extra is missing or no session starts. ValueError: no such provider.
        raise _Usage(str(exc)) from exc
    if args.region:
        # get_cloud_source takes no region, and inventory() reads this attribute on each call. A
        # region named twice would be read twice.
        source.regions = tuple(dict.fromkeys(args.region))
    return _Run(source.inventory(), _regions_note(source, bool(args.region)))


def _regions_note(source: object, chosen: bool) -> list[str]:
    # One region is read by default, so a clean report says nothing about the others.
    regions = getattr(source, "regions", None)
    if regions is None:
        return []
    names = [name for name in regions if name]
    if not names:
        return ["no AWS region is configured, so no region was read. Pass --region or set "
                "AWS_DEFAULT_REGION."]
    note = f"AWS regions read: {', '.join(names)}."
    return [note if chosen else note + " Only these are covered. Repeat --region to read more."]


def _is_skipped(ev: Evidence) -> bool:
    """True for a row that records a read that could not be made or could not conclude."""
    # Network rows never count. A range holds many addresses with no listener, and on an outside
    # sweep each is a finished check. Counting them would make nearly every sweep exit 3.
    if ev.source is Source.NETWORK:
        return False
    # The host source leaves php_present unset and says why in the note. A refused ssh target, a
    # dead link, and a php that would not answer all read that way.
    if ev.source is Source.HOST:
        return not ev.signals.get("php_present")
    # The repo, GitHub, and cloud sources mark a read they could not make with the kind skipped.
    return ev.signals.get("kind") == "skipped"


def _skipped_note(skipped: int) -> list[str]:
    # A read that finds no PHP leaves no row, so the rows cannot say how many reads were made.
    if not skipped:
        return []
    return [f"{_count(skipped, 'read')} skipped, so the result is incomplete. The notes on those "
            "rows give the reasons."]


def _render(fmt: str, assets: list[Asset], matrix: Matrix, scan: Optional[dict]) -> str:
    text = _FORMATS[fmt](assets, matrix)
    if scan is None or fmt == "console":
        return text
    doc = json.loads(text)
    if fmt == "json":
        doc["scan"] = scan
    else:
        doc["runs"][0].setdefault("properties", {})["scan"] = scan
    return json.dumps(doc, indent=2)


def _unwritable(path: str, exc: OSError) -> _Usage:
    return _Usage(f"cannot write {path}: {exc.strerror or type(exc).__name__}")


def _check_output(path: Optional[str]) -> None:
    # Checked before the run, because a sweep can take minutes and a report that cannot be
    # written would lose its findings, an exposed asset among them.
    if path is None:
        return
    if not path.strip():
        raise _Usage("the output path is empty")
    if os.path.isdir(path):
        raise _Usage(f"cannot write {path}: it is a folder")
    if not os.path.isdir(os.path.dirname(os.path.abspath(path))):
        raise _Usage(f"cannot write {path}: its folder does not exist")
    # Open for append, which leaves an existing file as it is. A file made by the probe is removed
    # again, so a run that stops early leaves no empty report behind.
    made = not os.path.lexists(path)
    try:
        with open(path, "ab"):
            pass
    except OSError as exc:
        raise _unwritable(path, exc) from exc
    if made:
        try:
            os.remove(path)
        except OSError:
            pass  # an empty file left behind is harmless, since the final write replaces it


def _deliver(args: argparse.Namespace, report: str, notes: list[str]) -> None:
    lines = [f"php-radar {args.command}: {note}" for note in notes]
    console = args.format == "console"
    if console and lines:
        report += "\n\n" + "\n".join(_plain(line) for line in lines)
    if args.output is None:
        print(report)
    else:
        try:
            # LF on every platform, so a report file is byte-identical wherever it was made.
            with open(args.output, "w", encoding="utf-8", newline="\n") as f:
                f.write(report + "\n")
        except OSError as exc:
            raise _unwritable(args.output, exc) from exc
    # A console report on stdout already ends with its notes.
    if not (console and args.output is None):
        for line in lines:
            _say(line)


def _execute(args: argparse.Namespace) -> int:
    # The matrix loads first, so a bad edit to the data file stops the run before any probe.
    matrix = load_matrix(DATA_PATH)
    _check_output(args.output)
    run = args.handler(args)
    inventory = AssetInventory()
    for ev in run.evidence:
        inventory.add(ev)
    assets = inventory.assets()
    skipped = sum(1 for ev in run.evidence if _is_skipped(ev))
    _deliver(args, _render(args.format, assets, matrix, run.scan),
             run.notes + _skipped_note(skipped))
    if any(grade(a, matrix)[0] is Verdict.EXPOSED for a in assets):
        return 1
    return 3 if skipped else 0


def main(argv: Optional[list[str]] = None) -> int:
    """Run php-radar on argv (the arguments after the program name) and return its exit status."""
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        # argparse has printed its help or its complaint. It exits 0 for help, 2 for a usage error.
        return exc.code if isinstance(exc.code, int) else 2
    try:
        return _execute(args)
    except (_Usage, MatrixError) as exc:
        _say(f"php-radar {args.command}: error: {exc}")
        return 2
    except KeyboardInterrupt:
        _say(f"php-radar {args.command}: interrupted")
        return 130
    except Exception as exc:
        # A bug. Python would exit 1 here, so the crash would read as an exposed asset. The
        # traceback goes through the same escaping as every other line.
        for line in traceback.format_exc().rstrip("\n").split("\n"):
            _say(line)
        _say(f"php-radar {args.command}: unexpected {type(exc).__name__}, so the run did not "
             "finish.")
        return 4
