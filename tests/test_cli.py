import ast
import functools
import json
import os
import pathlib
import re
import socket
import stat
import subprocess
import types
from urllib.parse import urlsplit

import pytest

from php_radar import cli
from php_radar.cli import main
from php_radar.http import Response
from php_radar.model import Evidence, Sapi, Source
from php_radar.scope import Scope, Target
from php_radar.sources import network as network_module
from php_radar.sources.cloud import get_cloud_source as real_get_cloud_source
from php_radar.sources.github import scan_github_org as real_scan_github_org
from php_radar.sources.host import inspect_local as real_inspect_local
from php_radar.sources.host import inspect_ssh as real_inspect_ssh
from php_radar.sources.network import sweep as real_sweep

# The shape of a GitHub token. It goes in the environment and must never come back out.
CANARY = "ghp_" + "Zq7" * 12

# Three targets: 10.0.0.1 on 80 and 443 (the default ports), and 10.0.0.2 on 8080.
SCOPE = "10.0.0.1\n10.0.0.2:8080\n"


# --- a JSON report, a missing scope, a public scope, an exposed find ---

def test_repo_subcommand_outputs_json(tmp_repo, capsys):
    rc = main(["repo", str(tmp_repo), "--format", "json"])
    assert rc in (0, 1)
    assert json.loads(capsys.readouterr().out)["assets"]


def test_network_without_scope_errors():
    assert main(["network"]) == 2


def test_network_public_requires_flag(public_scope_file):
    # the guardrail is a usage error, and nothing is sent
    assert main(["network", "--scope", public_scope_file]) == 2


def test_exposed_findings_exit_one(tmp_repo_exposed):
    assert main(["repo", str(tmp_repo_exposed)]) == 1


# --- helpers ---

def _tripwire(name):
    def refuse(*args, **kwargs):
        raise AssertionError(f"{name} ran for real")
    return refuse


@pytest.fixture(autouse=True)
def sealed(monkeypatch):
    # No test may reach a network, ssh, GitHub, AWS, or a token on the machine that runs it. A
    # test that wants a source puts a fake over the tripwire.
    for name in ("sweep", "scan_github_org", "inspect_local", "inspect_ssh", "get_cloud_source"):
        monkeypatch.setattr(cli, name, _tripwire(name))
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)


def make_repo(tmp_path, tag):
    root = tmp_path / "site"
    root.mkdir()
    (root / "Dockerfile").write_text(f"FROM php:{tag}\n")
    return root


@pytest.fixture
def tmp_repo(tmp_path):
    return make_repo(tmp_path, "8.3.36-fpm")  # the fixed release


@pytest.fixture
def tmp_repo_exposed(tmp_path):
    return make_repo(tmp_path, "8.3.35-fpm")  # one release before the fix


def write_scope(tmp_path, text=SCOPE, name="scope.txt"):
    path = tmp_path / name
    path.write_text(text)
    return str(path)


@pytest.fixture
def scope_file(tmp_path):
    return write_scope(tmp_path)


@pytest.fixture
def public_scope_file(tmp_path):
    return write_scope(tmp_path, "8.8.8.8\n", "public.txt")


def run(capsys, *argv):
    rc = main(list(argv))
    out, err = capsys.readouterr()
    return rc, out, err


def shown(text):
    # A path in a note is printed as ASCII. A temp folder with a letter like e-acute in its name
    # is compared in the form it is printed, so the tests pass wherever the suite runs.
    return cli._plain(text)


def pin(repo, version):
    # What the repo scan emits for an image tag that names a patch release.
    return Evidence(Source.REPO, "Dockerfile", version, Sapi.FPM,
                    {"repo": repo, "kind": "dockerfile", "confidence": "HIGH"}, "")


def skipped(repo="acme"):
    return Evidence(Source.REPO, ".", None, Sapi.UNKNOWN,
                    {"repo": repo, "kind": "skipped", "confidence": "LOW", "php_present": "true"},
                    "skipped: cannot list all the repositories (HTTP 404, not found)")


def header_read(host, version):
    return Evidence(Source.NETWORK, f"http://{host}:80/", version, Sapi.UNKNOWN,
                    {"ip": host, "php_present": "true"}, "")


def host_read(version):
    return Evidence(Source.HOST, "web1", version, Sapi.CLI,
                    {"hostname": "web1", "php_present": "true"}, "")


def cloud_gap(service="lambda"):
    return Evidence(Source.CLOUD, f"aws {service} us-east-1", None, Sapi.UNKNOWN,
                    {"service": service, "kind": "skipped"},
                    "not inventoried: ClientError (AccessDeniedException)")


def fake_sweep(monkeypatch, found=()):
    calls = []

    def sweep(targets, rate, workers, **kwargs):
        calls.append(types.SimpleNamespace(targets=targets, rate=rate, workers=workers))
        return list(found)

    monkeypatch.setattr(cli, "sweep", sweep)
    return calls


def fake_github(monkeypatch, found=()):
    calls = []

    def scan(org, token):
        calls.append((org, token))
        return list(found)

    monkeypatch.setattr(cli, "scan_github_org", scan)
    return calls


class FakeSource:
    def __init__(self, found=(), regions=("us-east-1",)):
        self.found = list(found)
        self.regions = regions

    def inventory(self):
        return list(self.found)


class FakeGcp:
    """Like GcpSource, it keeps the projects it reads in a plain attribute and has no regions."""

    def __init__(self, found=(), projects=("my-project",)):
        self.found = list(found)
        self.projects = projects

    def inventory(self):
        return list(self.found)


class FakeAzure:
    """Like AzureSource, it reads the subscriptions it was given. With none, it lists them during
    inventory(), so only a note made after the read can name them."""

    def __init__(self, found=(), subscriptions=(), listed=()):
        self.found = list(found)
        self.subscriptions = tuple(subscriptions)
        self._listed = tuple(listed)

    def inventory(self):
        self.subscriptions = self.subscriptions or self._listed
        return list(self.found)


def fake_cloud(monkeypatch, source):
    asked = []

    def get_cloud_source(name):
        asked.append(name)
        return source

    monkeypatch.setattr(cli, "get_cloud_source", get_cloud_source)
    return asked


# --- usage errors ---

@pytest.mark.parametrize("argv", [
    [],
    ["nonsense"],
    ["repo"],
    ["repo", ".", "--github-org", "acme"],
    ["repo", ""],
    ["repo", ".", "--format", "xml"],
    ["network"],
    ["network", "--scope"],
    ["host", "--ssh"],
    ["cloud"],
    ["cloud", "--provider"],
])
def test_a_usage_error_is_exit_two_and_a_message(argv, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # an empty path or a "." must not find anything to scan
    rc, out, err = run(capsys, *argv)
    assert rc == 2
    assert out == ""
    assert err.strip()
    assert "Traceback" not in err


@pytest.mark.parametrize("flags", [["--allow"], ["--allow-pub"], ["--max", "5"], ["--work", "2"]])
def test_a_flag_has_to_be_spelled_in_full(flags, public_scope_file, monkeypatch, capsys):
    # A short form of --allow-public would open the public gate by accident.
    calls = fake_sweep(monkeypatch)
    rc, out, err = run(capsys, "network", "--scope", public_scope_file, *flags)
    assert rc == 2
    assert "unrecognized arguments" in err
    assert calls == []


def test_help_exits_zero_and_lists_every_exit_status(capsys):
    rc, out, err = run(capsys, "--help")
    assert rc == 0
    text = " ".join(out.split())
    assert "usage: php-radar" in text
    assert "0 no asset grades EXPOSED and no read was skipped" in text
    assert "1 at least one asset grades EXPOSED" in text
    assert "2 a usage or scope error" in text
    assert "3 no asset grades EXPOSED, but a read was skipped" in text
    assert "so the scan is incomplete" in text
    assert "4 an unexpected error in php-radar itself, with its traceback on stderr" in text
    assert "Ctrl-C ends a run with status 130" in text
    assert "A network sweep exits 0 or 1" in text
    assert "A sweep that reached nothing exits 0 too" in text
    assert "The count line that ends its report" in text


FLAGS = {
    "repo": {"--help", "--format", "--output", "--github-org"},
    "network": {"--help", "--format", "--output", "--scope", "--allow-public", "--max-hosts",
                "--workers"},
    "host": {"--help", "--format", "--output", "--ssh"},
    "cloud": {"--help", "--format", "--output", "--provider", "--region", "--project",
              "--subscription"},
}


@pytest.mark.parametrize("command", sorted(FLAGS))
def test_each_subcommand_takes_these_flags_and_none_takes_a_secret(command, capsys):
    rc, out, err = run(capsys, command, "--help")
    assert rc == 0
    flags = set(re.findall(r"--[a-z][a-z-]*", out))
    assert flags == FLAGS[command]
    for flag in flags:
        assert not any(word in flag for word in ("token", "secret", "password", "key", "cred"))


def test_the_network_help_says_what_the_counts_mean_and_where_they_stop(capsys):
    rc, out, err = run(capsys, "network", "--help")
    text = " ".join(out.split())
    assert "A target is a host and port pair" in text
    assert "counts twice" in text
    assert f"(default {cli.DEFAULT_MAX_HOSTS})" in text
    assert f"up to {cli.MAX_WORKERS} (default {cli.DEFAULT_WORKERS})" in text


# --- repo ---

def test_a_repo_scan_prints_the_console_report_by_default(tmp_repo, capsys):
    rc, out, err = run(capsys, "repo", str(tmp_repo))
    assert rc == 0
    assert out.startswith("php-radar: 1 asset")
    assert "LIKELY_PATCHED" in out
    assert err == ""


def test_a_repo_scan_to_json_is_one_document(tmp_repo, capsys):
    rc, out, err = run(capsys, "repo", str(tmp_repo), "--format", "json")
    doc = json.loads(out)
    assert rc == 0
    assert doc["tool"] == "php-radar"
    assert doc["summary"]["total"] == 1
    assert doc["assets"][0]["verdict"] == "LIKELY_PATCHED"
    assert "scan" not in doc


def test_a_repo_scan_to_sarif_is_a_sarif_log(tmp_repo_exposed, capsys):
    rc, out, err = run(capsys, "repo", str(tmp_repo_exposed), "--format", "sarif")
    doc = json.loads(out)
    assert rc == 1
    assert doc["version"] == "2.1.0"
    assert [r["level"] for r in doc["runs"][0]["results"]] == ["error"]


def test_a_repo_with_no_pins_is_a_clean_run_that_says_what_it_found(tmp_path, capsys):
    root = tmp_path / "bare"
    root.mkdir()
    (root / "README.md").write_text("nothing here\n")
    rc, out, err = run(capsys, "repo", str(root))
    assert rc == 0
    assert out.startswith("php-radar: 0 assets")
    assert shown(f"no PHP pins found under {root}") in out


def test_a_repo_with_no_pins_in_json_keeps_stdout_a_document(tmp_path, capsys):
    root = tmp_path / "bare"
    root.mkdir()
    rc, out, err = run(capsys, "repo", str(root), "--format", "json")
    assert rc == 0
    assert json.loads(out)["assets"] == []
    assert "no PHP pins found" in err


def test_a_bad_repo_path_is_a_usage_error(tmp_path, capsys):
    missing = tmp_path / "missing"
    rc, out, err = run(capsys, "repo", str(missing))
    assert rc == 2
    assert out == ""
    assert shown(f"cannot read {missing}") in err
    assert "Traceback" not in err


def test_a_file_is_refused_as_a_repo_path(tmp_path, capsys):
    plain = tmp_path / "file.txt"
    plain.write_text("x")
    rc, out, err = run(capsys, "repo", str(plain))
    assert rc == 2
    assert "cannot read" in err


def test_an_empty_path_does_not_scan_the_current_folder(tmp_repo_exposed, monkeypatch, capsys):
    # realpath of "" is the current folder, and an unset shell variable gives an empty argument.
    monkeypatch.chdir(tmp_repo_exposed)
    rc, out, err = run(capsys, "repo", "")
    assert rc == 2
    assert out == ""
    assert "empty" in err


def test_an_unreadable_pin_file_is_called_out_as_an_incomplete_scan(tmp_repo, capsys):
    (tmp_repo / "composer.json").write_text("{")
    rc, out, err = run(capsys, "repo", str(tmp_repo))
    assert rc == 3
    assert "1 read skipped, so the result is incomplete" in out


# --- repo, GitHub ---

def test_the_token_comes_from_the_environment_and_goes_to_the_scan(monkeypatch, capsys):
    calls = fake_github(monkeypatch, [pin("acme/web", "8.3.36")])
    monkeypatch.setenv("GITHUB_TOKEN", CANARY)
    rc, out, err = run(capsys, "repo", "--github-org", "acme")
    assert rc == 0
    assert calls == [("acme", CANARY)]


def test_without_a_token_the_scan_is_anonymous_and_says_so(monkeypatch, capsys):
    calls = fake_github(monkeypatch, [pin("acme/web", "8.3.36")])
    rc, out, err = run(capsys, "repo", "--github-org", "acme")
    assert calls == [("acme", "")]
    assert "GITHUB_TOKEN is empty or not set, so the scan is anonymous" in out


def test_with_a_token_the_scan_does_not_claim_to_be_anonymous(monkeypatch, capsys):
    fake_github(monkeypatch, [pin("acme/web", "8.3.36")])
    monkeypatch.setenv("GITHUB_TOKEN", CANARY)
    rc, out, err = run(capsys, "repo", "--github-org", "acme")
    assert "anonymous" not in out


@pytest.mark.parametrize("fmt", ["console", "json", "sarif"])
def test_the_token_is_never_printed(fmt, monkeypatch, capsys):
    fake_github(monkeypatch, [pin("acme/web", "8.3.35"), skipped("acme")])
    monkeypatch.setenv("GITHUB_TOKEN", CANARY)
    rc, out, err = run(capsys, "repo", "--github-org", "acme", "--format", fmt)
    assert rc == 1
    assert CANARY not in out + err


def test_a_token_the_client_refuses_is_a_usage_error_that_does_not_echo_it(monkeypatch, capsys):
    # The real client checks the token before it sends anything.
    monkeypatch.setattr(cli, "scan_github_org", real_scan_github_org)
    monkeypatch.setenv("GITHUB_TOKEN", "has a space " + CANARY)
    rc, out, err = run(capsys, "repo", "--github-org", "acme")
    assert rc == 2
    assert out == ""
    assert "cannot scan" in err
    assert CANARY not in err


def test_a_bad_org_name_is_a_usage_error(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan_github_org", real_scan_github_org)
    rc, out, err = run(capsys, "repo", "--github-org", "not/an/org")
    assert rc == 2
    assert "not the name of a GitHub organization" in err


def test_no_rows_from_github_get_a_hedged_note(monkeypatch, capsys):
    fake_github(monkeypatch, [])
    rc, out, err = run(capsys, "repo", "--github-org", "acme")
    assert rc == 0
    assert out.startswith("php-radar: 0 assets")
    assert "no PHP pins found for acme" in out
    assert "none of them was visible to this scan" in out


def test_a_total_github_failure_reads_as_an_incomplete_scan(monkeypatch, capsys):
    fake_github(monkeypatch, [skipped("acme")])
    rc, out, err = run(capsys, "repo", "--github-org", "acme")
    assert rc == 3
    assert "INDETERMINATE (1)" in out
    assert "1 read skipped, so the result is incomplete" in out


def test_one_exposed_repo_among_patched_ones_exits_one(monkeypatch, capsys):
    rows = [pin("acme/a", "8.3.36"), pin("acme/b", "8.3.35"), pin("acme/c", "8.3.36")]
    fake_github(monkeypatch, rows)
    assert run(capsys, "repo", "--github-org", "acme")[0] == 1


def test_a_path_and_an_org_together_scan_neither(tmp_repo_exposed, monkeypatch, capsys):
    rc, out, err = run(capsys, "repo", str(tmp_repo_exposed), "--github-org", "acme")
    assert rc == 2
    assert "only one of them" in err


# --- network: the guardrails ---

def test_a_public_scope_is_refused_before_anything_is_sent(public_scope_file, monkeypatch, capsys):
    calls = fake_sweep(monkeypatch)
    rc, out, err = run(capsys, "network", "--scope", public_scope_file)
    assert rc == 2
    assert out == ""
    assert "public" in err
    assert "Traceback" not in err
    assert calls == []


def test_allow_public_opens_the_gate(public_scope_file, monkeypatch, capsys):
    calls = fake_sweep(monkeypatch)
    rc, out, err = run(capsys, "network", "--scope", public_scope_file, "--allow-public")
    assert rc == 0
    assert calls[0].targets == [Target("8.8.8.8", 80), Target("8.8.8.8", 443)]
    assert "--allow-public is set" in err


def test_the_banner_does_not_mention_the_override_when_it_is_off(scope_file, monkeypatch, capsys):
    fake_sweep(monkeypatch)
    rc, out, err = run(capsys, "network", "--scope", scope_file)
    assert "--allow-public" not in err


def test_guard_gets_a_real_bool_and_a_real_int(scope_file, monkeypatch):
    fake_sweep(monkeypatch)
    seen = []
    real = cli.guard

    def spy(scope, allow_public, max_hosts):
        seen.append((allow_public, max_hosts))
        return real(scope, allow_public, max_hosts)

    monkeypatch.setattr(cli, "guard", spy)
    main(["network", "--scope", scope_file])
    main(["network", "--scope", scope_file, "--allow-public", "--max-hosts", "50"])
    (off, cap), (on, cap_on) = seen
    assert off is False and type(cap) is int and cap == cli.DEFAULT_MAX_HOSTS
    assert on is True and type(cap_on) is int and cap_on == 50


def test_the_sweep_takes_the_list_guard_returned(scope_file, monkeypatch):
    calls = fake_sweep(monkeypatch)
    returned = []
    real = cli.guard

    def spy(*args, **kwargs):
        returned.append(real(*args, **kwargs))
        return returned[-1]

    monkeypatch.setattr(cli, "guard", spy)
    main(["network", "--scope", scope_file])
    assert calls[0].targets is returned[0]
    assert returned[0] == [Target("10.0.0.1", 80), Target("10.0.0.1", 443),
                           Target("10.0.0.2", 8080)]


def test_the_scope_is_never_expanded_outside_guard(scope_file, monkeypatch):
    # Scope.targets() skips the checks that guard makes.
    def boom(self):
        raise AssertionError("scope.targets() was called")

    monkeypatch.setattr(Scope, "targets", boom)
    calls = fake_sweep(monkeypatch)
    assert main(["network", "--scope", scope_file]) == 0
    assert len(calls[0].targets) == 3


def test_the_breadth_cap_counts_host_and_port_pairs(scope_file, monkeypatch, capsys):
    calls = fake_sweep(monkeypatch)
    rc, out, err = run(capsys, "network", "--scope", scope_file, "--max-hosts", "2")
    assert rc == 2
    assert "cap of 2 targets" in err
    assert calls == []
    assert run(capsys, "network", "--scope", scope_file, "--max-hosts", "3")[0] == 0
    assert len(calls[0].targets) == 3


@pytest.mark.parametrize("flag, value", [
    ("--max-hosts", "0"), ("--max-hosts", "-4"), ("--max-hosts", "many"),
    ("--workers", "0"), ("--workers", "-1"), ("--workers", "lots"),
])
def test_a_count_that_is_not_a_whole_number_of_one_or_more_is_refused(
        flag, value, scope_file, monkeypatch, capsys):
    calls = fake_sweep(monkeypatch)
    rc, out, err = run(capsys, "network", "--scope", scope_file, flag, value)
    assert rc == 2
    assert calls == []


def test_workers_above_the_limit_are_clamped_and_the_clamp_is_announced(
        scope_file, monkeypatch, capsys):
    calls = fake_sweep(monkeypatch)
    rc, out, err = run(capsys, "network", "--scope", scope_file, "--workers", "5000")
    assert calls[0].workers == cli.MAX_WORKERS
    assert f"--workers 5000 is above the limit of {cli.MAX_WORKERS}" in err


def test_the_limit_itself_is_allowed_and_one_past_it_is_clamped(scope_file, monkeypatch, capsys):
    calls = fake_sweep(monkeypatch)
    at = cli.MAX_WORKERS
    assert "above the limit" not in run(capsys, "network", "--scope", scope_file,
                                        "--workers", str(at))[2]
    assert "above the limit" in run(capsys, "network", "--scope", scope_file,
                                    "--workers", str(at + 1))[2]
    assert [c.workers for c in calls] == [at, at]


def test_workers_within_the_limit_pass_through(scope_file, monkeypatch):
    calls = fake_sweep(monkeypatch)
    main(["network", "--scope", scope_file, "--workers", "3"])
    main(["network", "--scope", scope_file])
    assert [c.workers for c in calls] == [3, cli.DEFAULT_WORKERS]
    assert [c.rate for c in calls] == [cli.RATE, cli.RATE]


def test_the_pace_and_the_limits_are_ones_the_real_sweep_accepts():
    assert cli.DEFAULT_WORKERS <= cli.MAX_WORKERS
    assert type(cli.DEFAULT_MAX_HOSTS) is int and cli.DEFAULT_MAX_HOSTS >= 1
    assert real_sweep([], cli.RATE, cli.DEFAULT_WORKERS) == []
    assert real_sweep([], cli.RATE, cli.MAX_WORKERS) == []


def test_a_path_with_an_accented_letter_prints_as_ascii(tmp_path, monkeypatch, capsys):
    # A console can be set to a code page that cannot print every letter, and a report line is
    # always printable ASCII. The banner goes to stderr and the closing note to the report.
    folder = tmp_path / "caf\N{LATIN SMALL LETTER E WITH ACUTE}"
    folder.mkdir()
    fake_sweep(monkeypatch)
    rc, out, err = run(capsys, "network", "--scope", write_scope(folder))
    assert rc == 0
    assert "caf\\xe9" in err
    assert err.isascii() and out.isascii()


def test_a_note_in_the_report_prints_as_ascii_too(tmp_path, capsys):
    root = tmp_path / "caf\N{LATIN SMALL LETTER E WITH ACUTE}"
    root.mkdir()
    rc, out, err = run(capsys, "repo", str(root))
    assert "no PHP pins found under" in out
    assert "caf\\xe9" in out
    assert out.isascii()


def test_a_missing_scope_file_is_a_usage_error(tmp_path, capsys):
    rc, out, err = run(capsys, "network", "--scope", str(tmp_path / "nothing.txt"))
    assert rc == 2
    assert "cannot read scope file" in err
    assert "Traceback" not in err


def test_a_malformed_scope_line_is_a_usage_error_that_names_the_line(tmp_path, capsys):
    scope = write_scope(tmp_path, "10.0.0.1\nnot a target\n")
    rc, out, err = run(capsys, "network", "--scope", scope)
    assert rc == 2
    assert "line 2" in err
    assert "Traceback" not in err


def test_a_broken_matrix_stops_the_run_before_the_sweep(scope_file, tmp_path, monkeypatch, capsys):
    calls = fake_sweep(monkeypatch)
    monkeypatch.setattr(cli, "DATA_PATH", str(tmp_path / "no-matrix.json"))
    rc, out, err = run(capsys, "network", "--scope", scope_file)
    assert rc == 2
    assert "no-matrix.json" in err
    assert calls == []


# --- network: the banner and the count ---

def test_the_authorization_banner_comes_before_the_sweep_and_the_count_after(
        scope_file, monkeypatch, capsys):
    before = []

    def sweep(targets, rate, workers):
        before.append(capsys.readouterr())
        return []

    monkeypatch.setattr(cli, "sweep", sweep)
    assert main(["network", "--scope", scope_file]) == 0
    (seen,) = before
    assert seen.out == ""
    assert "authorization" in seen.err.lower()
    assert shown(scope_file) in seen.err
    assert "3 targets" in seen.err
    assert "probed" not in seen.err
    after = capsys.readouterr()
    assert "probed 3 targets" in after.out


def test_the_count_shows_hosts_the_sweep_dropped(scope_file, monkeypatch, capsys):
    fake_sweep(monkeypatch, [header_read("10.0.0.1", "8.3.36")])
    rc, out, err = run(capsys, "network", "--scope", scope_file)
    assert rc == 0
    assert out.rstrip().endswith("probed 3 targets, reported 1 of them, "
                                 "left out 2 that answered with no sign of PHP.")
    assert "probed" not in err  # the note closes the report and is not said twice


def test_a_clean_perimeter_still_shows_what_was_probed(scope_file, monkeypatch, capsys):
    fake_sweep(monkeypatch, [])
    rc, out, err = run(capsys, "network", "--scope", scope_file)
    assert rc == 0
    assert out.startswith("php-radar: 0 assets")
    assert "probed 3 targets, reported 0 of them, left out 3" in out


def test_json_carries_the_count_in_the_document_and_keeps_stdout_pure(
        scope_file, monkeypatch, capsys):
    fake_sweep(monkeypatch, [header_read("10.0.0.1", "8.3.36")])
    rc, out, err = run(capsys, "network", "--scope", scope_file, "--format", "json")
    doc = json.loads(out)
    assert doc["scan"] == {"targets_probed": 3, "targets_reported": 1,
                           "targets_answered_without_php": 2}
    assert doc["summary"]["total"] == 1
    assert "probed 3 targets" in err
    assert "authorization" in err.lower()


def test_sarif_carries_the_count_in_the_run_properties(scope_file, monkeypatch, capsys):
    fake_sweep(monkeypatch, [header_read("10.0.0.1", "8.3.36")])
    rc, out, err = run(capsys, "network", "--scope", scope_file, "--format", "sarif")
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["properties"]["scan"]["targets_probed"] == 3
    assert len(doc["runs"][0]["results"]) == 1


def test_a_console_report_in_a_file_holds_the_count_and_the_terminal_gets_it_too(
        scope_file, tmp_path, monkeypatch, capsys):
    fake_sweep(monkeypatch, [])
    report = tmp_path / "report.txt"
    rc, out, err = run(capsys, "network", "--scope", scope_file, "--output", str(report))
    assert out == ""
    assert "probed 3 targets" in report.read_text()
    assert "probed 3 targets" in err


def test_an_exposed_header_read_exits_one(scope_file, monkeypatch, capsys):
    fake_sweep(monkeypatch, [header_read("10.0.0.1", "8.3.36"), header_read("10.0.0.2", "8.1.2")])
    rc, out, err = run(capsys, "network", "--scope", scope_file)
    assert rc == 1
    assert "EXPOSED (1)" in out


def test_a_sweep_through_the_real_prober_reports_two_assets_that_share_a_key(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(network_module, "_sleep", lambda seconds: None)
    answers = {"10.0.0.1": Response(200, {"server": "nginx"}, b""),
               "10.0.0.2": Response(200, {"x-powered-by": "PHP/8.1.2"}, b"")}

    def get(url, headers, timeout, verify=True, read_body=True):
        return answers[urlsplit(url).hostname]

    monkeypatch.setattr(cli, "sweep", functools.partial(real_sweep, get=get))
    scope = write_scope(tmp_path, "10.0.0.1\n10.0.0.2\n")
    rc, out, err = run(capsys, "network", "--scope", scope, "--format", "json")
    doc = json.loads(out)
    # Two ports on one address are two assets that print under one key.
    assert [a["key"] for a in doc["assets"]] == ["10.0.0.2", "10.0.0.2"]
    assert doc["scan"] == {"targets_probed": 4, "targets_reported": 2,
                           "targets_answered_without_php": 2}
    assert rc == 1


# --- host ---

def test_host_with_no_flag_inspects_this_machine(monkeypatch, capsys):
    calls = []

    def local():
        calls.append("local")
        return host_read("8.3.36")

    monkeypatch.setattr(cli, "inspect_local", local)
    rc, out, err = run(capsys, "host")
    assert rc == 0
    assert calls == ["local"]
    assert "web1 (host)" in out


def test_host_ssh_inspects_the_target_as_given_and_not_this_machine(monkeypatch, capsys):
    calls = []

    def ssh(target):
        calls.append(target)
        return host_read("8.3.36")

    monkeypatch.setattr(cli, "inspect_ssh", ssh)
    # Checking the target is inspect_ssh's job, so a stray space reaches it and is refused there.
    for target in ("deploy@web1.corp.example", " web1 "):
        assert run(capsys, "host", "--ssh", target)[0] == 0
    assert calls == ["deploy@web1.corp.example", " web1 "]


def test_an_empty_ssh_target_still_goes_to_ssh(monkeypatch, capsys):
    calls = []

    def ssh(target):
        calls.append(target)
        return host_read("8.3.36")

    monkeypatch.setattr(cli, "inspect_ssh", ssh)
    run(capsys, "host", "--ssh", "")
    assert calls == [""]


def test_an_exposed_host_exits_one_and_a_patched_one_exits_zero(monkeypatch, capsys):
    monkeypatch.setattr(cli, "inspect_local", lambda: host_read("8.1.2"))
    assert run(capsys, "host")[0] == 1
    monkeypatch.setattr(cli, "inspect_local", lambda: host_read("8.3.36"))
    assert run(capsys, "host")[0] == 0


def test_a_refused_ssh_target_is_an_incomplete_scan(monkeypatch, capsys):
    # The real inspect_ssh refuses this target before it starts any program.
    monkeypatch.setattr(cli, "inspect_ssh", real_inspect_ssh)
    rc, out, err = run(capsys, "host", "--ssh", "not a host!")
    assert rc == 3
    assert "INDETERMINATE (1)" in out
    assert "not inspected" in out
    assert "1 read skipped, so the result is incomplete" in out
    assert "Traceback" not in err


# --- cloud ---

def test_cloud_reads_the_provider_and_prints_the_regions(monkeypatch, capsys):
    asked = fake_cloud(monkeypatch, FakeSource([], regions=("us-east-1",)))
    rc, out, err = run(capsys, "cloud", "--provider", "aws")
    assert rc == 0
    assert asked == ["aws"]
    assert "AWS regions read: us-east-1." in out
    assert "Repeat --region to read more" in out


def test_cloud_keeps_stdout_a_document_in_json(monkeypatch, capsys):
    fake_cloud(monkeypatch, FakeSource([], regions=("eu-west-1", "ap-south-1")))
    rc, out, err = run(capsys, "cloud", "--provider", "aws", "--format", "json")
    assert json.loads(out)["assets"] == []
    assert "AWS regions read: eu-west-1, ap-south-1." in err


def test_a_missing_region_is_said_plainly(monkeypatch, capsys):
    fake_cloud(monkeypatch, FakeSource([cloud_gap()], regions=(None,)))
    rc, out, err = run(capsys, "cloud", "--provider", "aws")
    assert rc == 3
    assert "no AWS region is configured, so no region was read" in out


def test_an_aws_failure_is_surfaced_as_an_incomplete_scan(monkeypatch, capsys):
    gaps = [cloud_gap("elasticbeanstalk"), cloud_gap("lambda"), cloud_gap("ecr")]
    fake_cloud(monkeypatch, FakeSource(gaps))
    rc, out, err = run(capsys, "cloud", "--provider", "aws")
    assert rc == 3
    assert "INDETERMINATE (3)" in out
    assert "not inventoried" in out
    assert "3 reads skipped, so the result is incomplete" in out


def test_an_exposed_cloud_find_exits_one(monkeypatch, capsys):
    arn = "arn:aws:lambda:us-east-1:111111111111:function:f"
    exposed = Evidence(Source.CLOUD, arn, "8.1.2", Sapi.UNKNOWN,
                       {"resource": arn, "php_present": "true"}, "")
    fake_cloud(monkeypatch, FakeSource([exposed]))
    assert run(capsys, "cloud", "--provider", "aws")[0] == 1


def test_a_cloud_find_with_a_version_is_a_read_that_concluded(monkeypatch, capsys):
    # Only a host row is judged by php_present. A cloud row is skipped by its kind.
    arn = "arn:aws:lambda:us-east-1:111111111111:function:f"
    patched = Evidence(Source.CLOUD, arn, "8.3.36", Sapi.UNKNOWN, {"resource": arn}, "")
    fake_cloud(monkeypatch, FakeSource([patched]))
    rc, out, err = run(capsys, "cloud", "--provider", "aws")
    assert rc == 0
    assert "skipped" not in out + err


def test_a_missing_extra_is_a_message_and_exit_two(monkeypatch, capsys):
    # The real call, with boto3 reported absent whether or not it is installed.
    monkeypatch.setattr(cli, "get_cloud_source",
                        functools.partial(real_get_cloud_source, _boto3=None))
    rc, out, err = run(capsys, "cloud", "--provider", "aws")
    assert rc == 2
    assert out == ""
    assert 'pip install "php-radar[aws]"' in err
    assert "Traceback" not in err


def test_an_unknown_provider_is_a_message_and_exit_two(monkeypatch, capsys):
    monkeypatch.setattr(cli, "get_cloud_source",
                        functools.partial(real_get_cloud_source, _boto3=None))
    rc, out, err = run(capsys, "cloud", "--provider", "bogus")
    assert rc == 2
    assert "unknown cloud provider 'bogus', the choices are: aws, gcp, azure" in err
    assert "Traceback" not in err


def test_a_session_that_cannot_start_is_a_message_and_exit_two(monkeypatch, capsys):
    def refuse(name):
        raise RuntimeError("boto3 could not start a session (ProfileNotFound)")

    monkeypatch.setattr(cli, "get_cloud_source", refuse)
    rc, out, err = run(capsys, "cloud", "--provider", "aws")
    assert rc == 2
    assert "ProfileNotFound" in err


class StubClient:
    def describe_environments(self, **kwargs):
        return {"Environments": []}

    def list_functions(self, **kwargs):
        return {"Functions": []}

    def describe_repositories(self, **kwargs):
        return {"repositories": []}


class StubSession:
    region_name = "us-east-1"

    def __init__(self):
        self.asked = []

    def client(self, service, region_name=None):
        self.asked.append(region_name)
        return StubClient()


def test_region_flags_are_the_regions_the_real_source_reads(monkeypatch, capsys):
    session = StubSession()
    boto3 = types.SimpleNamespace(Session=lambda: session)
    monkeypatch.setattr(cli, "get_cloud_source",
                        functools.partial(real_get_cloud_source, _boto3=boto3))
    rc, out, err = run(capsys, "cloud", "--provider", "aws", "--region", "eu-west-1",
                       "--region", "ap-south-1")
    assert rc == 0
    assert sorted(session.asked) == ["ap-south-1"] * 3 + ["eu-west-1"] * 3
    assert "AWS regions read: eu-west-1, ap-south-1." in out
    assert "Repeat --region" not in out


def test_a_region_named_twice_is_read_once(monkeypatch, capsys):
    session = StubSession()
    boto3 = types.SimpleNamespace(Session=lambda: session)
    monkeypatch.setattr(cli, "get_cloud_source",
                        functools.partial(real_get_cloud_source, _boto3=boto3))
    rc, out, err = run(capsys, "cloud", "--provider", "aws", "--region", "eu-west-1",
                       "--region", "eu-west-1")
    assert session.asked == ["eu-west-1"] * 3
    assert "AWS regions read: eu-west-1." in out


def test_without_a_region_flag_the_real_source_reads_the_session_region(monkeypatch, capsys):
    session = StubSession()
    boto3 = types.SimpleNamespace(Session=lambda: session)
    monkeypatch.setattr(cli, "get_cloud_source",
                        functools.partial(real_get_cloud_source, _boto3=boto3))
    run(capsys, "cloud", "--provider", "aws")
    assert session.asked == ["us-east-1"] * 3


def test_an_empty_region_is_refused(monkeypatch, capsys):
    asked = fake_cloud(monkeypatch, FakeSource([]))
    rc, out, err = run(capsys, "cloud", "--provider", "aws", "--region", " ")
    assert rc == 2
    assert asked == []
    assert "a region name cannot be empty" in err


# --- cloud: gcp and azure ---

GUID = "00000000-0000-0000-0000-000000000001"
OTHER_GUID = "00000000-0000-0000-0000-000000000002"
MIXED_GUID = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d"


def test_cloud_reads_the_gcp_project_of_the_credentials_and_prints_it(monkeypatch, capsys):
    asked = fake_cloud(monkeypatch, FakeGcp(projects=("adc-project",)))
    rc, out, err = run(capsys, "cloud", "--provider", "gcp")
    assert rc == 0
    assert asked == ["gcp"]
    assert "GCP projects read: adc-project. Only these are covered." in out
    assert "Repeat --project to read more" in out
    assert "AWS" not in out


def test_project_flags_are_the_projects_the_source_reads_and_one_named_twice_is_read_once(
        monkeypatch, capsys):
    source = FakeGcp(projects=("adc-project",))
    fake_cloud(monkeypatch, source)
    rc, out, err = run(capsys, "cloud", "--provider", "gcp", "--project", "p1", "--project", "p2",
                       "--project", " p1 ")
    assert rc == 0
    assert source.projects == ("p1", "p2")
    assert "GCP projects read: p1, p2." in out
    assert "Repeat --project" not in out


def test_a_missing_gcp_project_is_said_plainly(monkeypatch, capsys):
    gap = Evidence(Source.CLOUD, "gcp appengine", None, Sapi.UNKNOWN,
                   {"service": "appengine", "kind": "skipped"},
                   "not inventoried: no GCP project is configured")
    fake_cloud(monkeypatch, FakeGcp([gap], projects=(None,)))
    rc, out, err = run(capsys, "cloud", "--provider", "gcp")
    assert rc == 3
    assert "no GCP project is configured, so no project was read" in out
    assert "Pass --project or set GOOGLE_CLOUD_PROJECT" in out


def test_gcp_keeps_stdout_a_document_in_json(monkeypatch, capsys):
    fake_cloud(monkeypatch, FakeGcp(projects=("adc-project",)))
    rc, out, err = run(capsys, "cloud", "--provider", "gcp", "--format", "json")
    assert json.loads(out)["assets"] == []
    assert "GCP projects read: adc-project." in err


def test_cloud_reads_the_azure_subscription_it_was_told_to_and_prints_it(monkeypatch, capsys):
    source = FakeAzure(listed=(OTHER_GUID,))
    asked = fake_cloud(monkeypatch, source)
    rc, out, err = run(capsys, "cloud", "--provider", "azure", "--subscription", GUID)
    assert rc == 0
    assert asked == ["azure"]
    assert source.subscriptions == (GUID,)
    assert f"Azure subscriptions read: {GUID}." in out
    assert "Repeat --subscription" not in out


def test_the_azure_note_names_what_the_source_found_during_the_read(monkeypatch, capsys):
    # With nothing named the source lists the subscriptions inside inventory(), so a note made
    # before the read would find none. What it listed is everything the credential can list, and
    # the note does not offer more.
    fake_cloud(monkeypatch, FakeAzure(listed=(GUID, OTHER_GUID)))
    rc, out, err = run(capsys, "cloud", "--provider", "azure")
    assert rc == 0
    assert (f"Azure subscriptions read: {GUID}, {OTHER_GUID}. That is every subscription the "
            "credential can list.") in out
    assert "Only these are covered" not in out and "Repeat --subscription" not in out


def test_a_subscription_the_source_started_with_is_not_called_everything_it_can_list(
        monkeypatch, capsys):
    # A default from the environment names one subscription, and the credential can list others.
    fake_cloud(monkeypatch, FakeAzure(subscriptions=(GUID,), listed=(OTHER_GUID,)))
    rc, out, err = run(capsys, "cloud", "--provider", "azure")
    assert rc == 0
    assert (f"Azure subscriptions read: {GUID}. Only these are covered. "
            "Repeat --subscription to read more.") in out
    assert "every subscription the credential can list" not in out


def test_azure_keeps_stdout_a_document_in_json(monkeypatch, capsys):
    fake_cloud(monkeypatch, FakeAzure(listed=(GUID,)))
    rc, out, err = run(capsys, "cloud", "--provider", "azure", "--format", "json")
    assert json.loads(out)["assets"] == []
    assert f"Azure subscriptions read: {GUID}." in err


def test_no_azure_subscription_read_is_said_plainly(monkeypatch, capsys):
    gap = Evidence(Source.CLOUD, "azure subscriptions", None, Sapi.UNKNOWN,
                   {"service": "subscriptions", "kind": "skipped"},
                   "not inventoried: no Azure subscription is configured and none could be "
                   "enumerated")
    fake_cloud(monkeypatch, FakeAzure([gap]))
    rc, out, err = run(capsys, "cloud", "--provider", "azure")
    assert rc == 3
    assert "no Azure subscription was named, and none could be listed, so none was read" in out
    assert "Pass --subscription or set AZURE_SUBSCRIPTION_ID" in out


def test_a_source_that_reports_no_scope_adds_no_note_and_does_not_crash(monkeypatch, capsys):
    source = types.SimpleNamespace(subscriptions=None, inventory=lambda: [])
    fake_cloud(monkeypatch, source)
    rc, out, err = run(capsys, "cloud", "--provider", "azure")
    assert rc == 0
    assert "Azure subscriptions" not in out + err


def test_a_subscription_id_is_read_in_lower_case_and_once(monkeypatch, capsys):
    source = FakeAzure()
    fake_cloud(monkeypatch, source)
    rc, out, err = run(capsys, "cloud", "--provider", "azure", "--subscription",
                       MIXED_GUID.upper(), "--subscription", f" {MIXED_GUID} ")
    assert source.subscriptions == (MIXED_GUID,)
    assert f"Azure subscriptions read: {MIXED_GUID}." in out


@pytest.mark.parametrize("value", ["", " ", "\t"])
def test_an_empty_subscription_is_refused_because_it_would_read_them_all(
        monkeypatch, capsys, value):
    asked = fake_cloud(monkeypatch, FakeAzure())
    rc, out, err = run(capsys, "cloud", "--provider", "azure", "--subscription", value)
    assert rc == 2
    assert out == ""
    assert asked == []
    assert "a subscription id cannot be empty" in err
    assert "every subscription the credential can list" in err


@pytest.mark.parametrize("value", [
    "Azure for Students", "prod", GUID[:-1], GUID + "0", GUID.replace("-", ""), "{" + GUID + "}",
    "urn:uuid:" + GUID, "0000000g-0000-0000-0000-000000000001", f"{GUID},{OTHER_GUID}", "*"])
def test_a_subscription_that_is_no_id_is_refused_before_anything_is_built(
        monkeypatch, capsys, value):
    asked = fake_cloud(monkeypatch, FakeAzure())
    rc, out, err = run(capsys, "cloud", "--provider", "azure", "--subscription", value)
    assert rc == 2
    assert out == ""
    assert asked == []
    assert "is not a subscription id" in err
    assert "use its id instead" in err
    assert "Traceback" not in err


@pytest.mark.parametrize("value", ["", " ", "\t"])
def test_an_empty_project_is_refused(monkeypatch, capsys, value):
    asked = fake_cloud(monkeypatch, FakeGcp())
    rc, out, err = run(capsys, "cloud", "--provider", "gcp", "--project", value)
    assert rc == 2
    assert asked == []
    assert "a project id cannot be empty" in err


@pytest.mark.parametrize("argv, flag, owner", [
    (["--provider", "gcp", "--region", "us-east-1"], "--region", "aws"),
    (["--provider", "azure", "--region", "us-east-1"], "--region", "aws"),
    (["--provider", "aws", "--project", "p"], "--project", "gcp"),
    (["--provider", "azure", "--project", "p"], "--project", "gcp"),
    (["--provider", "aws", "--subscription", GUID], "--subscription", "azure"),
    (["--provider", "gcp", "--subscription", GUID], "--subscription", "azure")])
def test_a_scope_flag_for_another_provider_is_refused_and_not_ignored(
        monkeypatch, capsys, argv, flag, owner):
    # Ignoring it would leave the run wider than the person who typed it meant.
    asked = fake_cloud(monkeypatch, FakeSource([]))
    rc, out, err = run(capsys, "cloud", *argv)
    assert rc == 2
    assert out == ""
    assert asked == []
    assert f"{flag} is for --provider {owner}" in err


def test_an_unknown_provider_is_reported_even_when_a_scope_flag_is_given(monkeypatch, capsys):
    monkeypatch.setattr(cli, "get_cloud_source",
                        functools.partial(real_get_cloud_source, _boto3=None))
    rc, out, err = run(capsys, "cloud", "--provider", "bogus", "--region", "us-east-1")
    assert rc == 2
    assert "unknown cloud provider 'bogus'" in err


def test_the_cloud_help_names_the_three_providers_and_says_what_a_scope_flag_takes(capsys):
    rc, out, err = run(capsys, "cloud", "--help")
    text = " ".join(out.split())
    assert "the cloud to read: aws, gcp, or azure" in text
    assert "aws: a region to read" in text
    assert "gcp: a project to read" in text
    assert "Application Default Credentials" in text
    assert "azure: a subscription to read, given by its id (a GUID)" in text
    assert "AZURE_SUBSCRIPTION_ID" in text


def test_aws_credentials_in_the_environment_are_never_printed(monkeypatch, capsys):
    for name in ("AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID"):
        monkeypatch.setenv(name, CANARY)
    fake_cloud(monkeypatch, FakeSource([cloud_gap()]))
    for fmt in ("console", "json", "sarif"):
        rc, out, err = run(capsys, "cloud", "--provider", "aws", "--format", fmt)
        assert CANARY not in out + err


# --- exit status: 0 clean and complete, 1 exposed, 2 usage, 3 incomplete ---

def machine(answers):
    """Stands in for the host source's process runner, with no process behind it.

    answers maps a program to (exit code, output). A program with no answer is not installed.
    """
    def run_program(args):
        answer = answers.get(args[0])
        if answer is None:
            raise FileNotFoundError(2, "not found", args[0])
        code, text = answer
        return subprocess.CompletedProcess(args, code, text, "")

    return run_program


def php_banner(version):
    return f"PHP {version} (cli) (built: Oct 21 2026 10:00:00) (NTS)\n"


@pytest.fixture
def named_machine(monkeypatch):
    monkeypatch.setattr(socket, "gethostname", lambda: "web1.example.com")


class BrokenSession:
    region_name = "us-east-1"

    def client(self, service, region_name=None):
        raise RuntimeError("the account would not answer")


def test_the_four_exit_codes_side_by_side(tmp_path, capsys):
    folders = {}
    for name, tag in (("clean", "8.3.36-fpm"), ("exposed", "8.3.35-fpm"), ("blind", "8.3.36-fpm")):
        folders[name] = tmp_path / name
        folders[name].mkdir()
        (folders[name] / "Dockerfile").write_text(f"FROM php:{tag}\n")
    (folders["blind"] / "composer.json").write_text("{")  # a file the scan cannot read
    missing = tmp_path / "missing"
    codes = [run(capsys, "repo", str(path))[0]
             for path in (folders["clean"], folders["exposed"], missing, folders["blind"])]
    assert codes == [0, 1, 2, 3]


def test_a_clean_and_complete_scan_exits_zero(tmp_repo, capsys):
    rc, out, err = run(capsys, "repo", str(tmp_repo))
    assert rc == 0
    assert "skipped" not in out + err


def test_an_indeterminate_result_from_a_complete_scan_exits_zero(tmp_path, capsys):
    root = make_repo(tmp_path, "8.3-apache")  # a floating tag pins no patch release
    rc, out, err = run(capsys, "repo", str(root))
    assert rc == 0
    assert "INDETERMINATE (1)" in out
    assert "skipped" not in out + err


def test_an_exposed_find_still_exits_one_when_a_read_was_skipped(tmp_repo_exposed, capsys):
    (tmp_repo_exposed / "composer.json").write_text("{")
    rc, out, err = run(capsys, "repo", str(tmp_repo_exposed))
    assert rc == 1
    assert "1 read skipped, so the result is incomplete" in out


# --- exit status 4 and 130: a crash and Ctrl-C ---

def failing(exc):
    def fail(*args, **kwargs):
        raise exc
    return fail


def test_a_crash_exits_four_and_keeps_its_traceback(monkeypatch, capsys):
    # Python's own status for an uncaught exception is 1, which here would read as an exposed asset.
    monkeypatch.setattr(cli, "inspect_local", failing(RuntimeError("the table moved")))
    rc, out, err = run(capsys, "host")
    assert rc == 4
    assert out == ""
    assert "Traceback (most recent call last)" in err
    assert "RuntimeError: the table moved" in err
    assert err.splitlines()[-1] == (
        "php-radar host: unexpected RuntimeError, so the run did not finish.")


def test_a_crash_message_cannot_drive_the_terminal(monkeypatch, capsys):
    message = "bad" + chr(27) + "[2J reply\rEXPOSED (9)"
    monkeypatch.setattr(cli, "inspect_local", failing(ValueError(message)))
    rc, out, err = run(capsys, "host")
    assert rc == 4
    assert chr(27) not in err and "\r" not in err
    assert "ValueError: bad\\x1b[2J reply\\rEXPOSED (9)" in err
    assert err.isascii()


@pytest.mark.parametrize("source, argv", [
    ("inspect_local", lambda scope, repo: ["host"]),
    ("sweep", lambda scope, repo: ["network", "--scope", scope]),
    ("scan_path", lambda scope, repo: ["repo", str(repo)]),
], ids=["host", "network", "repo"])
def test_ctrl_c_exits_130_with_no_traceback(source, argv, scope_file, tmp_repo, monkeypatch,
                                            capsys):
    monkeypatch.setattr(cli, source, failing(KeyboardInterrupt()))
    rc, out, err = run(capsys, *argv(scope_file, tmp_repo))
    assert rc == 130
    assert out == ""
    assert "interrupted" in err
    assert "Traceback" not in err


CLEAN = Response(200, {"server": "nginx"}, b"")  # answered with no sign of PHP, so sweep drops it
FIXED_PHP = Response(200, {"x-powered-by": "PHP/8.3.36"}, b"")
OLD_PHP = Response(200, {"x-powered-by": "PHP/8.1.2"}, b"")
UNKNOWN_PHP = Response(200, {"x-powered-by": "PHP"}, b"")  # PHP with no version to grade


def sweep_of(tmp_path, monkeypatch, answers):
    """Install the real sweep and prober with a scripted answer for each address in answers.

    An answer is a Response, or "down" for an address with nothing listening. Returns a scope file
    that lists the addresses.
    """
    monkeypatch.setattr(network_module, "_sleep", lambda seconds: None)

    def get(url, headers, timeout, verify=True, read_body=True):
        answer = answers[urlsplit(url).hostname]
        if answer == "down":
            raise OSError("refused")
        return answer

    monkeypatch.setattr(cli, "sweep", functools.partial(real_sweep, get=get))
    return write_scope(tmp_path, "".join(f"{host}\n" for host in answers))


def test_a_sweep_that_reached_nothing_exits_zero_and_the_count_shows_it(
        tmp_path, monkeypatch, capsys):
    # An address with no listener is a finished check on an outside sweep. A range holds many.
    scope = sweep_of(tmp_path, monkeypatch, {"10.0.0.1": "down", "10.0.0.2": "down"})
    rc, out, err = run(capsys, "network", "--scope", scope)
    assert rc == 0
    assert "INDETERMINATE (4)" in out
    assert "no answer" in out
    assert "probed 4 targets, reported 4 of them, left out 0" in out
    assert "skipped" not in out + err


@pytest.mark.parametrize("reached", [CLEAN, FIXED_PHP], ids=["a clean answer", "a fixed php"])
def test_a_sweep_with_an_unreachable_host_and_nothing_exposed_exits_zero(
        reached, tmp_path, monkeypatch, capsys):
    scope = sweep_of(tmp_path, monkeypatch, {"10.0.0.1": reached, "10.0.0.2": "down"})
    rc, out, err = run(capsys, "network", "--scope", scope)
    assert rc == 0
    assert "skipped" not in out + err


@pytest.mark.parametrize("unusable, why", [
    pytest.param(Response(403, {}, b""), "access blocked or gated", id="gated by a login"),
    pytest.param(Response(429, {}, b""), "access blocked or gated", id="rate limited"),
    pytest.param(Response(503, {}, b""), "a server error", id="a server error"),
])
def test_an_answer_that_shows_nothing_about_the_site_leaves_the_exit_status_alone(
        unusable, why, tmp_path, monkeypatch, capsys):
    scope = sweep_of(tmp_path, monkeypatch, {"10.0.0.1": CLEAN, "10.0.0.2": unusable})
    rc, out, err = run(capsys, "network", "--scope", scope)
    assert rc == 0
    assert why in out
    assert "skipped" not in out + err


def test_a_sweep_that_reached_every_host_with_nothing_exposed_exits_zero(
        tmp_path, monkeypatch, capsys):
    answers = {"10.0.0.1": CLEAN, "10.0.0.2": FIXED_PHP, "10.0.0.3": UNKNOWN_PHP}
    scope = sweep_of(tmp_path, monkeypatch, answers)
    rc, out, err = run(capsys, "network", "--scope", scope)
    assert rc == 0
    assert "INDETERMINATE (2)" in out  # PHP seen, with no version to place
    assert "probed 6 targets, reported 4 of them, left out 2" in out
    assert "skipped" not in out + err


def test_a_network_row_never_makes_the_scan_incomplete(scope_file, monkeypatch, capsys):
    # Neither signal that marks a skipped read on another source counts on a network row.
    unanswered = Evidence(Source.NETWORK, "http://10.0.0.5:80/", None, Sapi.UNKNOWN,
                          {"ip": "10.0.0.5"}, "no answer: refused")
    marked = Evidence(Source.NETWORK, "http://10.0.0.6:80/", None, Sapi.UNKNOWN,
                      {"ip": "10.0.0.6", "kind": "skipped"}, "not probed")
    fake_sweep(monkeypatch, [unanswered, marked])
    rc, out, err = run(capsys, "network", "--scope", scope_file)
    assert rc == 0
    assert "skipped" not in out + err


def test_an_exposed_host_still_exits_one_in_a_sweep_with_an_unreachable_host(
        tmp_path, monkeypatch, capsys):
    scope = sweep_of(tmp_path, monkeypatch, {"10.0.0.1": OLD_PHP, "10.0.0.2": "down"})
    rc, out, err = run(capsys, "network", "--scope", scope)
    assert rc == 1
    assert "EXPOSED (2)" in out
    assert "skipped" not in out + err


@pytest.mark.parametrize("answers", [
    pytest.param({}, id="no php and no package manager"),
    pytest.param({"php": (1, "")}, id="a php that will not answer"),
])
def test_a_local_read_that_could_not_conclude_exits_three(
        answers, named_machine, monkeypatch, capsys):
    monkeypatch.setattr(cli, "inspect_local",
                        functools.partial(real_inspect_local, run=machine(answers)))
    rc, out, err = run(capsys, "host")
    assert rc == 3
    assert "INDETERMINATE (1)" in out
    assert "1 read skipped, so the result is incomplete" in out


@pytest.mark.parametrize("answers, why", [
    pytest.param({"ssh": (255, "")}, "ssh exited 255", id="the link is down"),
    pytest.param({}, "ssh was not found", id="there is no ssh client"),
])
def test_an_ssh_host_that_could_not_be_reached_exits_three(answers, why, monkeypatch, capsys):
    monkeypatch.setattr(cli, "inspect_ssh",
                        functools.partial(real_inspect_ssh, run=machine(answers)))
    rc, out, err = run(capsys, "host", "--ssh", "deploy@web1.corp.example")
    assert rc == 3
    assert why in out
    assert "1 read skipped, so the result is incomplete" in out


@pytest.mark.parametrize("answers, code, group", [
    pytest.param({"dpkg-query": (0, "bash\t5.2.15-2\n")}, 0, "NOT_PHP (1)",
                 id="no php and a package list without it"),
    pytest.param({"php": (0, php_banner("8.3.36"))}, 0, "LIKELY_PATCHED (1)",
                 id="a fixed php with its provenance unconfirmed"),
    pytest.param({"dpkg-query": (0, "php8.1-cli\t8.1.2-1ubuntu2.14\n")}, 0, "INDETERMINATE (1)",
                 id="a php package and no php command"),
    pytest.param({"php": (0, php_banner("8.1.2"))}, 1, "EXPOSED (1)", id="an end-of-life php"),
])
def test_a_local_read_that_concluded_is_complete(
        answers, code, group, named_machine, monkeypatch, capsys):
    monkeypatch.setattr(cli, "inspect_local",
                        functools.partial(real_inspect_local, run=machine(answers)))
    rc, out, err = run(capsys, "host")
    assert rc == code
    assert group in out
    assert "skipped" not in out + err


@pytest.mark.parametrize("status, token, why", [
    pytest.param(401, CANARY, "GitHub rejected the token", id="a token GitHub rejects"),
    pytest.param(404, "", "not found, or hidden from this token",
                 id="no token, an org it cannot see"),
])
def test_a_github_org_that_cannot_be_listed_exits_three(status, token, why, monkeypatch, capsys):
    def get(url, headers, timeout):
        return Response(status, {}, b"")

    monkeypatch.setattr(cli, "scan_github_org", functools.partial(real_scan_github_org, get=get))
    monkeypatch.setenv("GITHUB_TOKEN", token)
    rc, out, err = run(capsys, "repo", "--github-org", "acme")
    assert rc == 3
    assert why in out
    assert CANARY not in out + err


def test_an_aws_account_that_cannot_be_read_exits_three(monkeypatch, capsys):
    boto3 = types.SimpleNamespace(Session=BrokenSession)
    monkeypatch.setattr(cli, "get_cloud_source",
                        functools.partial(real_get_cloud_source, _boto3=boto3))
    rc, out, err = run(capsys, "cloud", "--provider", "aws")
    assert rc == 3
    assert "3 reads skipped, so the result is incomplete" in out


# --- output ---

def test_output_writes_the_report_to_the_file_and_leaves_stdout_empty(tmp_repo, tmp_path, capsys):
    target = tmp_path / "out.json"
    rc, out, err = run(capsys, "repo", str(tmp_repo), "--format", "json", "--output", str(target))
    assert rc == 0
    assert out == ""
    on_screen = json.loads(run(capsys, "repo", str(tmp_repo), "--format", "json")[1])
    assert json.loads(target.read_text(encoding="utf-8")) == on_screen


@pytest.mark.parametrize("fmt", ["console", "json", "sarif"])
def test_output_is_the_stdout_report_byte_for_byte_with_unix_line_endings(
        fmt, tmp_repo, tmp_path, capsys):
    # A file opened in text mode gets CRLF on Windows, and a report should be the same bytes on
    # every platform, so a hash or a diff of one agrees with another.
    on_screen = run(capsys, "repo", str(tmp_repo), "--format", fmt)[1]
    target = tmp_path / "out.report"
    run(capsys, "repo", str(tmp_repo), "--format", fmt, "--output", str(target))
    written = target.read_bytes()
    assert b"\r" not in written
    assert written == on_screen.encode("utf-8")


def test_output_names_a_folder_that_does_not_exist_before_anything_runs(
        scope_file, tmp_path, monkeypatch, capsys):
    calls = fake_sweep(monkeypatch)
    rc, out, err = run(capsys, "network", "--scope", scope_file, "--output",
                       str(tmp_path / "no-such-folder" / "r.json"))
    assert rc == 2
    assert "its folder does not exist" in err
    assert calls == []


def test_output_that_is_a_folder_is_refused_before_anything_runs(
        scope_file, tmp_path, monkeypatch, capsys):
    calls = fake_sweep(monkeypatch)
    rc, out, err = run(capsys, "network", "--scope", scope_file, "--output", str(tmp_path))
    assert rc == 2
    assert "it is a folder" in err
    assert calls == []


def test_a_report_that_cannot_be_written_is_a_usage_error_and_keeps_the_old_file(
        tmp_repo, tmp_path, capsys):
    target = tmp_path / "locked.json"
    target.write_text("old")
    target.chmod(stat.S_IREAD)
    try:
        if os.access(target, os.W_OK):
            pytest.skip("this account can write a read-only file")
        rc, out, err = run(capsys, "repo", str(tmp_repo), "--format", "json",
                           "--output", str(target))
    finally:
        target.chmod(stat.S_IREAD | stat.S_IWRITE)
    assert rc == 2
    assert shown(f"cannot write {target}") in err
    assert target.read_text() == "old"


def test_an_empty_output_path_is_refused_before_anything_runs(scope_file, monkeypatch, capsys):
    calls = fake_sweep(monkeypatch)
    rc, out, err = run(capsys, "network", "--scope", scope_file, "--output", "")
    assert rc == 2
    assert "the output path is empty" in err
    assert calls == []


def test_an_output_file_that_cannot_be_written_is_refused_before_the_scan(
        scope_file, tmp_path, monkeypatch, capsys):
    # The sweep would find an exposed asset. A report that cannot be written must not run it, or
    # the finding has nowhere to go.
    calls = fake_sweep(monkeypatch, [header_read("10.0.0.1", "8.3.35")])
    target = tmp_path / "locked.json"
    target.write_text("old")
    target.chmod(stat.S_IREAD)
    try:
        if os.access(target, os.W_OK):
            pytest.skip("this account can write a read-only file")
        rc, out, err = run(capsys, "network", "--scope", scope_file, "--output", str(target))
    finally:
        target.chmod(stat.S_IREAD | stat.S_IWRITE)
    assert rc == 2
    assert shown(f"cannot write {target}") in err
    assert calls == []
    assert target.read_text() == "old"


def test_the_writability_check_leaves_an_existing_report_as_it_was(
        public_scope_file, tmp_path, capsys):
    # The public range is refused after the output path has been checked.
    target = tmp_path / "r.json"
    target.write_text("old")
    rc, out, err = run(capsys, "network", "--scope", public_scope_file, "--output", str(target))
    assert rc == 2
    assert "public" in err
    assert target.read_text() == "old"


def test_the_sarif_scan_block_joins_run_properties_that_are_already_there(monkeypatch):
    def render(assets, matrix):
        return json.dumps({"runs": [{"properties": {"owner": "ci"}, "results": []}]})

    monkeypatch.setitem(cli._FORMATS, "sarif", render)
    doc = json.loads(cli._render("sarif", [], None, {"targets_probed": 3}))
    assert doc["runs"][0]["properties"] == {"owner": "ci", "scan": {"targets_probed": 3}}


def test_a_refused_run_leaves_no_output_file_behind(public_scope_file, tmp_path, capsys):
    target = tmp_path / "r.json"
    rc, out, err = run(capsys, "network", "--scope", public_scope_file, "--output", str(target))
    assert rc == 2
    assert not target.exists()


# --- credentials and source hygiene ---

CLI_SOURCE = pathlib.Path(cli.__file__).read_text(encoding="utf-8")


def test_the_only_environment_variable_read_is_github_token():
    uses = [n for n in ast.walk(ast.parse(CLI_SOURCE))
            if isinstance(n, ast.Attribute) and n.attr in ("environ", "getenv")]
    assert len(uses) == 1
    assert 'os.environ.get("GITHUB_TOKEN"' in CLI_SOURCE


@pytest.mark.parametrize("path", [pathlib.Path(cli.__file__), pathlib.Path(__file__)])
def test_the_source_is_plain_ascii_within_the_line_limit(path):
    text = path.read_bytes().decode("ascii")  # a stray non-ASCII byte raises here
    assert max(len(line) for line in text.splitlines()) <= 100


def test_the_cli_parses_as_python_3_9_and_never_starts_a_shell():
    ast.parse(CLI_SOURCE, feature_version=(3, 9))
    assert "shell=True" not in CLI_SOURCE
    assert "subprocess" not in CLI_SOURCE
