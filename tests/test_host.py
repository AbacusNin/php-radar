import ast
import inspect
import os
import pathlib
import random
import socket
import string as pystring
import subprocess
import sys
from typing import NamedTuple

import pytest

from php_radar.knowledge import DATA_PATH, grade, grade_evidence, load_matrix
from php_radar.model import AssetInventory, Confidence, Evidence, Sapi, Source, Verdict
from php_radar.report import render_console, render_json, render_sarif
from php_radar.sources import host
from php_radar.sources.host import (
    collect_ini, inspect_local, inspect_ssh, resolve_package, subprocess_run)

MATRIX = load_matrix(DATA_PATH)

# Built from pieces so that no token-shaped string sits in the source.
CANARY = "ghp_CANARY" + "x" * 30
PLAIN_SECRET = "hunter2-" + "CANARY-env"

# Every command the inspectors may run. Nothing read from a machine is ever added to this set.
READS = {("php", "-v"), ("php", "-i"), ("cat", "/etc/os-release"), ("dpkg-query", "-W"),
         ("rpm", "-qa")}


# --- stand-ins ---

class Call(NamedTuple):
    args: object  # exactly what the inspector passed
    shell: bool  # False unless the inspector asked for a shell


class FakeRun:
    """Stands in for subprocess_run and answers from a script.

    script() maps a command line, written as a person would type it, to the output text (exit 0),
    to an (exit code, output) pair, or to an exception to raise. A key matches the end of the
    arguments, so "php -v" also matches that command behind ssh and its target. A command with no
    script is a missing command. A local one raises FileNotFoundError, and one behind ssh exits
    127, as a shell does.
    """

    def __init__(self):
        self.calls = []
        self._script = {}

    def script(self, answers):
        for line, answer in answers.items():
            self._script[tuple(line.split())] = answer

    def __call__(self, args, **kwargs):
        self.calls.append(Call(args, kwargs.get("shell", False)))
        words = tuple(args)
        for key in sorted(self._script, key=len, reverse=True):
            if words[-len(key):] == key:
                return self._answer(args, self._script[key])
        if words[0] == "ssh":
            return subprocess.CompletedProcess(args, 127, "", "")
        raise FileNotFoundError(2, "No such file or directory", words[0])

    @staticmethod
    def _answer(args, answer):
        if isinstance(answer, BaseException) or (
                isinstance(answer, type) and issubclass(answer, BaseException)):
            raise answer
        code, text = answer if isinstance(answer, tuple) else (0, answer)
        return subprocess.CompletedProcess(args, code, text, "")


@pytest.fixture
def fake_run():
    return FakeRun()


@pytest.fixture(autouse=True)
def this_machine(monkeypatch):
    monkeypatch.setattr(socket, "gethostname", lambda: "web1.example.com")


def commands(fake):
    """The commands that ran, in order, with any ssh options and target taken off."""
    return [tuple(c.args[c.args.index("--") + 2:]) if c.args[0] == "ssh" else tuple(c.args)
            for c in fake.calls]


WINDOWS = sys.platform == "win32"
PROGRAMS = ("php", "ssh", "cat", "dpkg-query", "rpm")


def make_program(directory, name):
    """A zero-byte stand-in for a program: name.exe on Windows, an executable file elsewhere."""
    path = directory / (name + (".exe" if WINDOWS else ""))
    path.write_bytes(b"")
    path.chmod(0o755)
    return path


@pytest.fixture
def programs(tmp_path, monkeypatch):
    """PATH holds only stand-ins for the five programs, so no real one can start.

    Returns {name: full path}. The stand-ins are empty files. A test that uses them replaces
    subprocess.run, so nothing runs.
    """
    where = tmp_path / "bin"
    where.mkdir()
    monkeypatch.setenv("PATH", str(where))
    return {name: str(make_program(where, name)) for name in PROGRAMS}


# --- what the machines print ---

def php_v(version="8.3.35", sapi="cli"):
    return (f"PHP {version} ({sapi}) (built: Jun 17 2024 08:12:07) (NTS)\n"
            "Copyright (c) The PHP Group\n"
            "Zend Engine v4.3.35, Copyright (c) Zend Technologies\n")


def php_i(version="8.3.35", api="Command Line Interface"):
    # The Environment and PHP Variables sections print the environment of the process. They carry
    # whatever credentials it held, and a memory_limit variable that tries to overwrite the setting.
    return "\n".join([
        "phpinfo()",
        f"PHP Version => {version}",
        "",
        "System => Linux web1 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 x86_64",
        f"Server API => {api}",
        "Loaded Configuration File => /etc/php/8.3/cli/php.ini",
        "",
        "Core",
        "",
        f"PHP Version => {version}",
        "",
        "Directive => Local Value => Master Value",
        "display_errors => Off => Off",
        "fatal_error_backtraces => Off => Off",
        "memory_limit => -1 => -1",
        "post_max_size => 8M => 8M",
        "",
        "session",
        "",
        "Session Support => enabled",
        "",
        "Directive => Local Value => Master Value",
        "session.auto_start => Off => Off",
        "session.upload_progress.enabled => On => On",
        "",
        "Environment",
        "",
        "Variable => Value",
        "HOME => /root",
        f"GITHUB_TOKEN => {CANARY}",
        f"DB_PASSWORD => {PLAIN_SECRET}",
        "memory_limit => 1",
        "",
        "PHP Variables",
        "",
        "Variable => Value",
        f"$_SERVER['GITHUB_TOKEN'] => {CANARY}",
    ]) + "\n"


UBUNTU_OS = ('PRETTY_NAME="Ubuntu 22.04.5 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
             'VERSION="22.04.5 LTS (Jammy Jellyfish)"\nID=ubuntu\nID_LIKE=debian\n')
DEBIAN_OS = ('PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nNAME="Debian GNU/Linux"\n'
             'VERSION_ID="13"\nID=debian\n')
SLES_OS = 'NAME="SLES"\nVERSION_ID="15.7"\nID="sles"\nID_LIKE="suse"\n'
ALPINE_OS = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.24.0\n"

DPKG_UBUNTU = ("base-files\t12ubuntu4.7\n"
               "libc6:amd64\t2.35-0ubuntu3.8\n"
               "php-cli\t2:8.1+92ubuntu1\n"
               "php-common\t2:93ubuntu2\n"
               "php8.1-cli\t8.1.2-1ubuntu2.28\n"
               "php8.1-common\t8.1.2-1ubuntu2.28\n"
               "php8.1-opcache\t8.1.2-1ubuntu2.28\n"
               "phpmyadmin\t4:5.1.1+dfsg-1\n"
               "zlib1g:amd64\t1:1.2.11.dfsg-2ubuntu9.2\n")
DPKG_DEBIAN = ("bash\t5.2.37-2\n"
               "php8.4-cli\t8.4.27-1~deb13u1\n"
               "php8.4-common\t8.4.27-1~deb13u1\n")
DPKG_NO_PHP = ("base-files\t12ubuntu4.7\n"
               "bash\t5.1-6ubuntu1.1\n"
               "libc6:amd64\t2.35-0ubuntu3.8\n"
               "nginx\t1.18.0-6ubuntu14.4\n")
DPKG_FPM_ONLY = DPKG_NO_PHP + "php8.1-common\t8.1.2-1ubuntu2.28\nphp8.1-fpm\t8.1.2-1ubuntu2.28\n"
RPM_SUSE = ("bash-5.2.15-150500.1.1.x86_64\n"
            "php8-8.3.36-150700.3.24.1.x86_64\n"
            "php8-cli-8.3.36-150700.3.24.1.x86_64\n"
            "php8-fpm-8.3.36-150700.3.24.1.x86_64\n"
            "zlib-1.2.13-150500.4.5.1.x86_64\n")
RPM_NO_PHP = "bash-5.2.15-150500.1.1.x86_64\nzlib-1.2.13-150500.4.5.1.x86_64\n"


def box(version, os_text, listing_command, listing, sapi="cli"):
    return {"php -v": php_v(version, sapi), "php -i": php_i(version),
            "cat /etc/os-release": os_text, listing_command: listing}


UBUNTU_BOX = box("8.1.2-1ubuntu2.28", UBUNTU_OS, "dpkg-query -W", DPKG_UBUNTU)
DEBIAN_BOX = box("8.4.27", DEBIAN_OS, "dpkg-query -W", DPKG_DEBIAN)
SUSE_BOX = box("8.3.36", SLES_OS, "rpm -qa", RPM_SUSE)
SELF_BUILT = box("8.3.35", UBUNTU_OS, "dpkg-query -W", DPKG_UBUNTU)


# --- the interfaces other code imports ---

def test_the_functions_other_code_imports_have_these_signatures():
    assert list(inspect.signature(inspect_local).parameters) == ["run"]
    assert list(inspect.signature(inspect_ssh).parameters) == ["target", "run"]
    assert list(inspect.signature(resolve_package).parameters) == ["distro", "raw"]
    assert list(inspect.signature(collect_ini).parameters) == ["raw"]
    assert inspect.signature(inspect_local).parameters["run"].default is subprocess_run
    assert inspect.signature(inspect_ssh).parameters["run"].default is subprocess_run


# --- a version, a SAPI, and an ini setting through a fake runner ---

def test_local_reads_version_and_sapi(fake_run):
    fake_run.script({"php -v": "PHP 8.3.35 (fpm-fcgi)"})
    ev = inspect_local(run=fake_run)
    assert ev.detected_version == "8.3.35"
    assert ev.sapi == Sapi.FPM


def test_subprocess_never_uses_shell(monkeypatch, programs):
    # The real subprocess_run is in the path here and only subprocess.run is replaced, so this
    # sees what the inspectors hand the operating system. A fake runner could not show that: it
    # records a shell flag that the inspectors never pass.
    seen = []

    def fake(args, **kwargs):
        seen.append((args, kwargs))
        return subprocess.CompletedProcess(args, 127, "", "")

    monkeypatch.setattr(subprocess, "run", fake)
    inspect_local()
    inspect_ssh("deploy@web1.example.com")
    assert len(seen) > 4
    for args, kwargs in seen:
        assert isinstance(args, list) and all(isinstance(a, str) for a in args)
        assert kwargs["shell"] is False
        assert args[0] in programs.values()


def test_ini_modifiers_are_annotations_only(fake_run):
    fake_run.script({"php -i": "session.upload_progress.enabled => 0 => 0"})
    ev = inspect_local(run=fake_run)
    assert ev.signals["session.upload_progress.enabled"] == "0"


# --- the commands and the shell ---

def test_every_local_read_is_a_fixed_argument_list_with_no_shell(fake_run):
    fake_run.script(UBUNTU_BOX)
    inspect_local(run=fake_run)
    assert fake_run.calls  # a loop over no calls passes without checking anything
    for call in fake_run.calls:
        assert isinstance(call.args, list) and all(isinstance(a, str) for a in call.args)
        assert call.shell is False
    assert commands(fake_run) == [("php", "-v"), ("php", "-i"), ("cat", "/etc/os-release"),
                                  ("dpkg-query", "-W")]


def test_every_ssh_read_is_a_fixed_argument_list_with_no_shell(fake_run):
    fake_run.script(UBUNTU_BOX)
    inspect_ssh("deploy@web1.example.com", run=fake_run)
    assert fake_run.calls
    for call in fake_run.calls:
        assert isinstance(call.args, list) and all(isinstance(a, str) for a in call.args)
        assert call.shell is False
        assert call.args[0] == "ssh"
    assert commands(fake_run) == [("php", "-v"), ("php", "-i"), ("cat", "/etc/os-release"),
                                  ("dpkg-query", "-W")]


def test_the_package_manager_is_tried_after_dpkg_when_the_distro_is_unknown(fake_run):
    fake_run.script({"php -v": php_v(), "rpm -qa": RPM_NO_PHP})
    inspect_local(run=fake_run)
    assert commands(fake_run) == [("php", "-v"), ("php", "-i"), ("cat", "/etc/os-release"),
                                  ("dpkg-query", "-W"), ("rpm", "-qa")]


def test_a_distro_that_uses_rpm_does_not_run_dpkg_and_one_that_uses_dpkg_does_not_run_rpm(
        fake_run):
    fake_run.script(SUSE_BOX)
    inspect_local(run=fake_run)
    assert ("dpkg-query", "-W") not in commands(fake_run)
    other = FakeRun()
    other.script({**UBUNTU_BOX, "rpm -qa": RPM_SUSE})
    inspect_local(run=other)
    assert ("rpm", "-qa") not in commands(other)


def test_a_machine_with_no_php_does_not_read_its_os_release(fake_run):
    fake_run.script({"dpkg-query -W": DPKG_NO_PHP})
    inspect_local(run=fake_run)
    assert commands(fake_run) == [("php", "-v"), ("php", "-i"), ("dpkg-query", "-W")]


def test_text_a_machine_prints_never_becomes_a_command(fake_run):
    hostile = "$(touch /tmp/x); `id` | rm -rf / && echo hi > /etc/passwd\n"
    fake_run.script({
        "php -v": "PHP 8.1.2-1ubuntu2.28;id (cli)\n" + hostile + php_v("8.1.2-1ubuntu2.28"),
        "php -i": hostile + php_i("8.1.2-1ubuntu2.28") + hostile,
        "cat /etc/os-release": hostile + "ID=ubuntu; id\nID=ubuntu\n",
        "dpkg-query -W": (DPKG_UBUNTU + hostile
                          + "php8.1-cli;touch /tmp/x\t8.1.2-1ubuntu2.28\n"
                          + "php8.1-$(id)\t8.1.2-1ubuntu2.28\n"),
    })
    ev = inspect_local(run=fake_run)
    assert set(commands(fake_run)) <= READS
    assert len(fake_run.calls) == 4
    for value in ev.signals.values():
        assert value.isascii() and value.isprintable()


def test_ssh_never_gets_a_command_built_from_what_it_read(fake_run):
    hostile = "$(touch /tmp/x); `id` | rm -rf / && echo hi\n"
    fake_run.script({**UBUNTU_BOX, "php -i": hostile + php_i("8.1.2-1ubuntu2.28"),
                     "cat /etc/os-release": UBUNTU_OS + hostile})
    inspect_ssh("deploy@web1.example.com", run=fake_run)
    assert set(commands(fake_run)) <= READS
    for call in fake_run.calls:
        assert call.args.count("--") == 1
        assert not any("touch" in a or "$(" in a for a in call.args)


# --- subprocess_run ---

def never_started(*args, **kwargs):
    raise AssertionError("a process was started")


def test_subprocess_run_gives_subprocess_a_list_and_no_shell(monkeypatch, programs):
    seen = []

    def fake(args, **kwargs):
        seen.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, "out", "")

    monkeypatch.setattr(subprocess, "run", fake)
    done = subprocess_run(["php", "-v"])
    (args, kwargs), = seen
    assert args == [programs["php"], "-v"] and isinstance(args, list)
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.DEVNULL
    assert kwargs["check"] is False
    assert kwargs["encoding"] == "utf-8" and kwargs["errors"] == "replace"
    assert 0 < kwargs["timeout"] <= 120
    assert done.stdout == "out"


def test_subprocess_run_takes_a_timeout(monkeypatch, programs):
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: seen.append(kw["timeout"]))
    subprocess_run(["php", "-v"], timeout=3)
    assert seen == [3]


@pytest.mark.parametrize("bad", [
    "php -v", "php", "", [], ["php", 7], ["php", None], ["php", b"-v"], ("php", "-v"), None,
    b"php -v", {"php": "-v"}])
def test_subprocess_run_refuses_anything_but_a_list_of_strings(monkeypatch, bad):
    # Windows reads a string as a command line and splits it into words, shell or not.
    monkeypatch.setattr(subprocess, "run", never_started)
    with pytest.raises(TypeError):
        subprocess_run(bad)


# --- finding the program ---

windows_only = pytest.mark.skipif(not WINDOWS, reason="a Windows rule")
posix_only = pytest.mark.skipif(WINDOWS, reason="a POSIX rule")


def exe(name):
    return name + (".exe" if WINDOWS else "")


def test_subprocess_run_starts_the_program_by_its_full_path(monkeypatch, programs):
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: seen.append(args))
    subprocess_run(["php", "-v"])
    subprocess_run(["ssh", "-T", "--", "web1", "php", "-v"])
    assert seen == [[programs["php"], "-v"], [programs["ssh"], "-T", "--", "web1", "php", "-v"]]


def test_a_program_that_is_not_on_path_is_not_found_and_nothing_starts(monkeypatch, programs):
    monkeypatch.setattr(subprocess, "run", never_started)
    with pytest.raises(FileNotFoundError) as raised:
        subprocess_run(["no-such-program", "-v"])
    assert raised.value.filename == "no-such-program"


def test_an_absolute_program_path_is_started_as_given(monkeypatch, tmp_path):
    stand_in = make_program(tmp_path, "tool")
    monkeypatch.setenv("PATH", str(tmp_path / "elsewhere"))
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: seen.append(args))
    subprocess_run([str(stand_in), "-v"])
    assert seen == [[str(stand_in), "-v"]]


@pytest.mark.parametrize("name", [
    "bin/php", "./php", "../php", "a/b/c", os.path.join("bin", "php"),
    os.curdir + os.sep + "php", os.pardir + os.sep + "php",
    pytest.param("C:php", marks=windows_only), pytest.param("bin\\php", marks=windows_only)])
def test_a_relative_path_is_not_a_program_name(monkeypatch, programs, name):
    monkeypatch.setattr(subprocess, "run", never_started)
    with pytest.raises(ValueError):
        subprocess_run([name, "-v"])


def test_a_program_that_is_missing_reads_as_a_missing_command_all_the_way_up(monkeypatch,
                                                                              tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))  # a directory with no programs in it
    monkeypatch.setattr(subprocess, "run", never_started)
    assert inspect_local().note == ("no php command was found and no package listing could be "
                                    "read: PHP may still be installed")
    assert inspect_ssh("web1").note == "not inspected: ssh was not found"


def test_a_program_is_found_on_an_absolute_path_entry(programs):
    for name in PROGRAMS:
        assert host._on_path(name) == programs[name]


def test_a_program_that_is_nowhere_on_path_is_not_found(programs):
    assert host._on_path("no-such-program") is None


@pytest.mark.parametrize("value", [None, ""])
def test_with_no_path_at_all_nothing_is_found(monkeypatch, tmp_path, value):
    make_program(tmp_path, "php")
    monkeypatch.chdir(tmp_path)
    if value is None:
        monkeypatch.delenv("PATH", raising=False)
    else:
        monkeypatch.setenv("PATH", value)
    assert host._on_path("php") is None


def test_the_first_path_entry_that_has_the_program_wins(tmp_path, monkeypatch):
    first, second = tmp_path / "a", tmp_path / "b"
    for directory in (first, second):
        directory.mkdir()
        make_program(directory, "php")
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "none"), str(first), str(second)]))
    assert host._on_path("php") == str(first / exe("php"))


@pytest.mark.parametrize("entries", [
    [""], ["."], ["./"], [".."], ["bin"], [os.path.join(".", "bin")], [os.path.join("..", "x")],
    ["", ".", "bin"], [" "]])
def test_an_empty_or_relative_path_entry_is_never_searched(tmp_path, monkeypatch, entries):
    (tmp_path / "bin").mkdir()
    make_program(tmp_path, "php")  # in the current directory
    make_program(tmp_path / "bin", "php")  # under it, where the entry "bin" would point
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", os.pathsep.join(entries))
    assert host._on_path("php") is None


def test_a_program_planted_in_the_current_directory_is_not_started(tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    for name in ("php", "ssh"):
        make_program(tmp_path, name)
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", str(elsewhere)]))
    monkeypatch.setattr(subprocess, "run", never_started)
    for command in (["php", "-v"], ["ssh", "-V"]):
        with pytest.raises(FileNotFoundError):
            subprocess_run(command)
    assert inspect_local().signals.get("php_present") != "false"


def test_an_absolute_entry_that_names_the_current_directory_is_honored(tmp_path, monkeypatch):
    # The operator listed it. Skipping it would hide a PHP that is on PATH, and with a package
    # listing that has no PHP in it the host would read as having none.
    stand_in = make_program(tmp_path, "php")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert host._on_path("php") == str(stand_in)


def test_an_entry_in_double_quotes_is_read_without_them(tmp_path, monkeypatch):
    stand_in = make_program(tmp_path, "php")
    monkeypatch.setenv("PATH", '"' + str(tmp_path) + '"')
    assert host._on_path("php") == str(stand_in)


def test_a_directory_with_the_program_name_is_not_a_program(tmp_path, monkeypatch):
    (tmp_path / exe("php")).mkdir()
    monkeypatch.setenv("PATH", str(tmp_path))
    assert host._on_path("php") is None


@posix_only
def test_a_file_without_the_execute_bit_is_not_a_program(tmp_path, monkeypatch):
    path = tmp_path / "php"
    path.write_bytes(b"")
    path.chmod(0o644)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert host._on_path("php") is None


@posix_only
def test_off_windows_no_extension_is_added(tmp_path, monkeypatch):
    stand_in = tmp_path / "php.exe"
    stand_in.write_bytes(b"")
    stand_in.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert host._on_path("php") is None
    assert host._on_path("php.exe") == str(stand_in)


@windows_only
def test_on_windows_only_an_exe_counts(tmp_path, monkeypatch):
    for name in ("php", "php.bat", "php.cmd", "php.com", "php.ps1"):
        (tmp_path / name).write_bytes(b"")
    monkeypatch.setenv("PATH", str(tmp_path))
    assert host._on_path("php") is None
    (tmp_path / "php.exe").write_bytes(b"")
    assert host._on_path("php") == str(tmp_path / "php.exe")
    assert host._on_path("PHP.EXE") == str(tmp_path / "PHP.EXE")


@windows_only
def test_a_php_exe_planted_in_the_current_directory_is_neither_found_nor_started(
        tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    for name in ("php.exe", "ssh.exe"):
        (tmp_path / name).write_bytes(b"")  # planted where the tool runs
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(elsewhere))
    monkeypatch.setattr(subprocess, "run", never_started)
    assert host._on_path("php") is None
    assert host._on_path("ssh") is None
    for command in (["php", "-v"], ["ssh", "-V"]):
        with pytest.raises(FileNotFoundError):
            subprocess_run(command)


@windows_only
def test_windows_does_start_a_program_from_the_current_directory_before_path(
        tmp_path, monkeypatch):
    # The reason for the lookup. A zero-byte stand-in cannot run, but Windows picks it, so the
    # error is a bad executable and not "not found". NoDefaultCurrentDirectoryInExePath turns
    # that search off for the process, and a test environment may set it, so it is removed here.
    (tmp_path / "radar-stand-in.exe").write_bytes(b"")
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))
    with pytest.raises(OSError) as raised:
        subprocess.run(["radar-stand-in"])
    assert not isinstance(raised.value, FileNotFoundError)


# --- the ssh command line ---

def test_the_target_is_one_argument_after_a_double_dash_and_the_command_follows_it(fake_run):
    inspect_ssh("deploy@web1.example.com", run=fake_run)
    first = fake_run.calls[0].args
    dash = first.index("--")
    assert first[0] == "ssh"
    assert first[dash + 1] == "deploy@web1.example.com"
    assert first[dash + 2:] == ["php", "-v"]
    assert first.count("deploy@web1.example.com") == 1


def test_ssh_never_asks_a_question_and_never_forwards_anything(fake_run):
    inspect_ssh("web1", run=fake_run)
    for call in fake_run.calls:
        options = call.args[:call.args.index("--")]
        assert "BatchMode=yes" in options
        assert {"-a", "-x", "-T"} <= set(options)
        assert "ClearAllForwardings=yes" in options
        assert "ConnectTimeout=10" in options
        assert not any("StrictHostKeyChecking" in a or "UserKnownHostsFile" in a
                       for a in call.args)


GOOD_TARGETS = ["web1", "WEB1", "web-1", "web_1", "web1.example.com", "web1.example.com.",
                "deploy@web1", "deploy.ops@web1.example.com", "_svc-1@web1", "10.0.0.5",
                "root@10.0.0.5", "::1", "fe80::1", "user@fe80::1"]


@pytest.mark.parametrize("target", GOOD_TARGETS)
def test_a_host_name_or_address_reaches_ssh_as_its_own_argument(fake_run, target):
    inspect_ssh(target, run=fake_run)
    first = fake_run.calls[0].args
    dash = first.index("--")
    assert first[dash + 1] == target
    assert target not in first[:dash]
    assert first[dash + 2:] == ["php", "-v"]


BAD_TARGETS = [
    "", " ", "-", "--", "-p", "-oProxyCommand=touch /tmp/x", "-user@host", "user@-host",
    "user@-oProxyCommand=x", "a b", "host name", " host", "host ", "host;id", "host&id", "host|id",
    "$(id)", "`id`", "host\nid", "host\tid", "host\x00id", "host\rid", "a@b@c", "@", "@host",
    "user@",
    "ssh://host", "host/..", "host'x", 'host"x', "host\\x", "ho$st", "host*", "host?", "host{a,b}",
    "host<x", "host>x", "host(x)", "host!x", "host#x", "host~x", "host%x", "host=x", "host,x",
    ".host", "_host", ".", "_", "host+x", "user name@host", "us:er@host", "u$er@host",
    "h\u00f6st", "\u202ehost", "x" * 300,
    "a" * 254, None, 7, b"host", ["host"]]


@pytest.mark.parametrize("target", BAD_TARGETS, ids=[str(n) for n in range(len(BAD_TARGETS))])
def test_a_target_that_is_not_a_host_is_refused_before_anything_runs(fake_run, target):
    ev = inspect_ssh(target, run=fake_run)
    assert fake_run.calls == []
    assert ev.source is Source.HOST
    assert ev.location == "ssh"
    assert ev.detected_version is None and ev.sapi is Sapi.UNKNOWN
    assert ev.signals == {}
    assert ev.note.startswith("not inspected: the ssh target")
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)


def test_a_refused_target_is_not_repeated_in_the_evidence(fake_run):
    ev = inspect_ssh("root:hunter2@web1 ; id", run=fake_run)
    assert "hunter2" not in repr(ev)


# --- an ssh link that does not work ---

def test_ssh_exit_255_ends_the_inspection_with_one_call(fake_run):
    fake_run.script({"php -v": (255, "")})
    ev = inspect_ssh("web1", run=fake_run)
    assert len(fake_run.calls) == 1
    assert ev.note == ("not inspected: ssh exited 255 "
                       "(the connection, the login, or the remote command failed)")
    assert ev.signals == {"hostname": "web1"}
    assert "php_present" not in ev.signals
    assert ev.detected_version is None
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)


def test_a_machine_without_an_ssh_client_ends_the_inspection_with_one_call():
    tried = []

    def no_ssh(args, **kwargs):
        tried.append(args)
        raise FileNotFoundError(2, "No such file or directory", "ssh")

    ev = inspect_ssh("web1", run=no_ssh)
    assert len(tried) == 1
    assert ev.note == "not inspected: ssh was not found"
    assert ev.signals == {"hostname": "web1"}
    assert "php_present" not in ev.signals


def test_an_ssh_that_times_out_ends_the_inspection_with_one_call(fake_run):
    fake_run.script({"php -v": subprocess.TimeoutExpired("ssh", 30)})
    ev = inspect_ssh("web1", run=fake_run)
    assert len(fake_run.calls) == 1
    assert ev.note == "not inspected: ssh timed out"
    assert ev.signals == {"hostname": "web1"}
    assert "php_present" not in ev.signals


def test_an_ssh_that_cannot_start_ends_the_inspection_with_one_call(fake_run):
    fake_run.script({"php -v": PermissionError(13, "Permission denied")})
    ev = inspect_ssh("web1", run=fake_run)
    assert len(fake_run.calls) == 1
    assert ev.note == "not inspected: ssh could not start (PermissionError)"
    assert ev.signals == {"hostname": "web1"}


def test_a_later_exit_255_is_one_failed_read_and_not_the_end(fake_run):
    fake_run.script({"php -v": php_v(), "php -i": (255, "")})
    ev = inspect_ssh("web1", run=fake_run)
    assert ev.detected_version == "8.3.35"
    assert len(fake_run.calls) > 2
    assert "php -i exit 255" in ev.note


def test_the_user_name_in_a_target_is_not_in_the_evidence(fake_run):
    fake_run.script(UBUNTU_BOX)
    ev = inspect_ssh("deploy@web1.example.com", run=fake_run)
    assert "deploy" not in repr(ev)


# --- who the evidence names ---

def test_a_local_read_is_host_evidence_named_for_this_machine(fake_run):
    fake_run.script(UBUNTU_BOX)
    ev = inspect_local(run=fake_run)
    assert ev.source is Source.HOST
    assert ev.location == "web1.example.com"
    assert ev.signals["hostname"] == "web1.example.com"
    assert "ip" not in ev.signals
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in ev.signals.items())


@pytest.mark.parametrize("name, named, location", [
    ("web1", {"hostname": "web1"}, "web1"),
    ("WEB1.Example.COM.", {"hostname": "WEB1.Example.COM."}, "WEB1.Example.COM."),
    ("db_1", {"hostname": "db_1"}, "db_1"),
    ("10.0.0.5", {"ip": "10.0.0.5"}, "10.0.0.5"),
    ("", {}, "localhost"),
    ("web 1", {}, "localhost"),
    ("web1\nx", {}, "localhost"),
    ("h\u00f6st", {}, "localhost"),
    ("x" * 300, {}, "localhost"),
])
def test_the_local_name_is_a_hostname_an_address_or_nothing(
        monkeypatch, fake_run, name, named, location):
    monkeypatch.setattr(socket, "gethostname", lambda: name)
    ev = inspect_local(run=fake_run)
    assert {k: v for k, v in ev.signals.items() if k in ("hostname", "ip")} == named
    assert ev.location == location


@pytest.mark.parametrize("target, named, location", [
    ("web1", {"hostname": "web1"}, "web1"),
    ("deploy@web1.example.com", {"hostname": "web1.example.com"}, "web1.example.com"),
    ("WEB1.Example.COM.", {"hostname": "WEB1.Example.COM."}, "WEB1.Example.COM."),
    ("10.0.0.5", {"ip": "10.0.0.5"}, "10.0.0.5"),
    ("root@10.0.0.5", {"ip": "10.0.0.5"}, "10.0.0.5"),
    ("2130706433", {"ip": "2130706433"}, "2130706433"),
    ("0x7f.1", {"ip": "0x7f.1"}, "0x7f.1"),
    ("::1", {"ip": "::1"}, "::1"),
    ("fe80::1", {"ip": "fe80::1"}, "fe80::1"),
    ("user@fe80::1", {"ip": "fe80::1"}, "fe80::1"),
])
def test_an_ssh_target_names_a_host_or_an_address_and_never_both(
        fake_run, target, named, location):
    ev = inspect_ssh(target, run=fake_run)
    assert {k: v for k, v in ev.signals.items() if k in ("hostname", "ip")} == named
    assert ev.location == location


def test_an_ssh_read_and_a_network_read_of_one_host_merge_and_the_host_read_decides():
    run = FakeRun()
    run.script(UBUNTU_BOX)
    from_host = inspect_ssh("deploy@web1.example.com", run=run)
    from_network = Evidence(Source.NETWORK, "https://web1.example.com:443/", "8.1.2", Sapi.UNKNOWN,
                            {"hostname": "web1.example.com", "php_present": "true"})
    assert grade_evidence(from_network, MATRIX)[0] is Verdict.EXPOSED
    inv = AssetInventory()
    inv.add(from_network)
    inv.add(from_host)
    (asset,) = inv.assets()
    assert grade(asset, MATRIX) == (Verdict.LIKELY_PATCHED, Confidence.HIGH)


def test_a_host_read_by_address_merges_with_nothing():
    run = FakeRun()
    run.script(UBUNTU_BOX)
    from_host = inspect_ssh("10.0.0.5", run=run)
    from_network = Evidence(Source.NETWORK, "http://10.0.0.5:80/", "8.1.2", Sapi.UNKNOWN,
                            {"ip": "10.0.0.5", "php_present": "true"})
    inv = AssetInventory()
    inv.add(from_network)
    inv.add(from_host)
    assert len(inv.assets()) == 2


# --- the version and the SAPI ---

BANNERS = [
    ("PHP 8.3.35 (cli) (built: Jun 17 2024 08:12:07) (NTS)", "8.3.35", Sapi.CLI),
    ("PHP 8.3.35 (fpm-fcgi) (built: Jun 17 2024 08:12:07) (NTS)", "8.3.35", Sapi.FPM),
    ("PHP 8.3.35 (cgi-fcgi) (built: Jun 17 2024 08:12:07) (NTS)", "8.3.35", Sapi.CGI),
    ("PHP 8.3.35 (cgi) (built: Jun 17 2024 08:12:07) (NTS)", "8.3.35", Sapi.CGI),
    ("PHP 8.3.35 (apache2handler)", "8.3.35", Sapi.MOD_PHP),
    ("PHP 8.3.35 (apache2filter)", "8.3.35", Sapi.MOD_PHP),
    ("PHP 8.3.35 (CLI)", "8.3.35", Sapi.CLI),
    ("PHP 8.3.35 ( cli )", "8.3.35", Sapi.CLI),
    ("PHP 8.3.35 (litespeed)", "8.3.35", Sapi.UNKNOWN),
    ("PHP 8.3.35 (embed)", "8.3.35", Sapi.UNKNOWN),
    ("PHP 8.3.35 ()", "8.3.35", Sapi.UNKNOWN),
    ("PHP 8.3.35", "8.3.35", Sapi.UNKNOWN),
    ("PHP 8.3.35 (cli)\r\n", "8.3.35", Sapi.CLI),
    ("PHP 8.3.35  (cli)", "8.3.35", Sapi.CLI),
    ("PHP 8.3.35 xcli)", "8.3.35", Sapi.UNKNOWN),
    ("PHP 8.3.35_1 (cli)", "8.3.35_1", Sapi.CLI),
    ("PHP 8.2.12 (cli) (built: Oct 24 2023 18:07:04) (ZTS Visual C++ 2019 x64)", "8.2.12",
     Sapi.CLI),
    ("PHP Warning:  PHP Startup: Unable to load dynamic library 'x' in Unknown on line 0\n"
     "Warning: PHP Startup: Unable to load dynamic library 'x' in Unknown on line 0\n"
     "PHP 8.3.35 (cli) (built: Jun 17 2024 08:12:07) (NTS)", "8.3.35", Sapi.CLI),
]


@pytest.mark.parametrize("banner, version, sapi", BANNERS)
def test_php_v_gives_the_version_and_the_sapi(fake_run, banner, version, sapi):
    fake_run.script({"php -v": banner})
    ev = inspect_local(run=fake_run)
    assert ev.detected_version == version
    assert ev.sapi is sapi
    assert ev.signals["php_present"] == "true"


@pytest.mark.parametrize("token, clean", [
    ("8.1.2-1ubuntu2.28", "8.1.2"),
    ("8.2.10-1+ubuntu22.04.1+deb.sury.org+1", "8.2.10"),
    ("8.4.27-1~deb13u1", "8.4.27"),
    ("8.3.36-150700.3.24.1", "8.3.36"),
    ("8.3.36-r0", "8.3.36"),
    ("8.4.0-dev", "8.4.0-dev"),
    ("8.5.0RC1", "8.5.0RC1"),
    ("8.3.35", "8.3.35"),
])
def test_the_detected_version_is_the_upstream_number_and_keeps_a_pre_release_tag(
        fake_run, token, clean):
    fake_run.script({"php -v": f"PHP {token} (cli)"})
    assert inspect_local(run=fake_run).detected_version == clean


def test_a_dev_build_of_a_fixed_release_does_not_grade_as_patched(fake_run):
    fake_run.script({"php -v": "PHP 8.3.36-dev (cli)"})
    ev = inspect_local(run=fake_run)
    assert ev.detected_version == "8.3.36-dev"
    assert grade_evidence(ev, MATRIX)[0] is Verdict.INDETERMINATE


NO_BANNER = [
    "", "   \n", "\n\n", "PHP", "PHP ", "PHP (cli)", "PHP 8.3 (cli)", "PHP 8 (cli)",
    "PHP Warning:  something broke", "PHP 8.3.35;id (cli)", "PHP 8.3.35`id` (cli)",
    "PHP 8.3.35-$(id) (cli)", "PHP 8.3.35-" + "a" * 100 + " (cli)", "php 8.3.35 (cli)",
    "Php 8.3.35 (cli)", "HHVM 8.3.35 (cli)", "PHP v8.3.35 (cli)", "PHP \u0668.3.35 (cli)",
    "bash: php: command not found", "PHP 8.3.35\x00 (cli)", "PHP 8.3.35-;id (cli)",
]


@pytest.mark.parametrize("text", NO_BANNER, ids=[str(n) for n in range(len(NO_BANNER))])
def test_text_that_is_no_php_banner_gives_no_version_and_no_clearance(fake_run, text):
    fake_run.script({"php -v": text})
    ev = inspect_local(run=fake_run)
    assert ev.detected_version is None
    assert "php_present" not in ev.signals
    assert ev.note.startswith("php could not be read (php -v ")
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)


def test_php_i_supplies_the_version_and_the_sapi_when_php_v_gives_none(fake_run):
    fake_run.script({"php -i": php_i("8.3.35", "FPM/FastCGI")})
    ev = inspect_local(run=fake_run)
    assert ev.detected_version == "8.3.35"
    assert ev.sapi is Sapi.FPM
    assert ev.signals["php_present"] == "true"


def test_php_v_wins_over_php_i_when_the_two_disagree(fake_run):
    fake_run.script({"php -v": php_v("8.3.35", "cli"), "php -i": php_i("8.3.20", "FPM/FastCGI")})
    ev = inspect_local(run=fake_run)
    assert ev.detected_version == "8.3.35"
    assert ev.sapi is Sapi.CLI


def test_php_i_names_the_sapi_when_php_v_does_not(fake_run):
    fake_run.script({"php -v": php_v("8.3.35", "litespeed"),
                     "php -i": php_i("8.3.35", "CGI/FastCGI")})
    assert inspect_local(run=fake_run).sapi is Sapi.CGI


@pytest.mark.parametrize("api, sapi", [
    ("Command Line Interface", Sapi.CLI), ("command line interface", Sapi.CLI),
    ("FPM/FastCGI", Sapi.FPM), ("CGI/FastCGI", Sapi.CGI), ("Apache 2.0 Handler", Sapi.MOD_PHP),
    ("Apache 2.0 Filter", Sapi.MOD_PHP), ("LiteSpeed V8.0", Sapi.UNKNOWN),
    ("Built-in HTTP server", Sapi.UNKNOWN), ("", Sapi.UNKNOWN), ("<script>", Sapi.UNKNOWN)])
def test_php_i_names_the_server_api(fake_run, api, sapi):
    fake_run.script({"php -i": php_i("8.3.35", api)})
    assert inspect_local(run=fake_run).sapi is sapi


def test_a_php_version_in_php_i_that_is_not_a_version_gives_none(fake_run):
    fake_run.script({"php -i": "PHP Version => 8.3.35;id\nServer API => FPM/FastCGI\n"})
    ev = inspect_local(run=fake_run)
    assert ev.detected_version is None
    assert ev.sapi is Sapi.FPM
    assert ev.signals["php_present"] == "true"
    assert "the PHP version could not be read" in ev.note


@pytest.mark.parametrize("text", ["memory_limit\n", "PHP Version\n", "Server API\n",
                                  "PHP Version\nServer API\nmemory_limit\npost_max_size\n"])
def test_a_php_i_line_with_no_arrow_is_no_php_output(fake_run, text):
    fake_run.script({"php -i": text})
    ev = inspect_local(run=fake_run)
    assert "php_present" not in ev.signals
    assert ev.note == "php could not be read (php -v not found; php -i gave no PHP output)"


def test_a_runner_that_returns_no_stdout_ran_a_command_that_printed_nothing(fake_run):
    fake_run.script({"php -v": (0, None)})
    ev = inspect_local(run=fake_run)
    assert ev.note.startswith("php could not be read (php -v gave no PHP output")


def test_php_that_answers_php_i_only_is_present_with_no_version(fake_run):
    fake_run.script({"php -i": "session.upload_progress.enabled => 0 => 0"})
    ev = inspect_local(run=fake_run)
    assert ev.detected_version is None
    assert ev.signals["php_present"] == "true"
    assert "the PHP version could not be read" in ev.note
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


# --- ini settings ---

def test_collect_ini_records_the_four_settings_from_php_i():
    assert collect_ini({"php -i": php_i()}) == {
        "memory_limit": "-1", "post_max_size": "8M", "session.upload_progress.enabled": "On",
        "fatal_error_backtraces": "Off"}


def test_collect_ini_takes_the_local_value():
    raw = {"php -i": "memory_limit => 256M => 128M\npost_max_size => 16M\n"}
    assert collect_ini(raw) == {"memory_limit": "256M", "post_max_size": "16M"}


def test_collect_ini_takes_the_first_line_for_a_name_and_not_a_later_one():
    # The Environment section comes after the directives, and a variable can be named anything.
    raw = {"php -i": "memory_limit => 128M => 128M\nmemory_limit => 1\n"}
    assert collect_ini(raw) == {"memory_limit": "128M"}


def test_collect_ini_leaves_out_a_setting_the_text_does_not_have():
    assert collect_ini({"php -i": "memory_limit => 128M => 128M\n"}) == {"memory_limit": "128M"}
    assert collect_ini({"php -i": "display_errors => Off => Off\n"}) == {}


@pytest.mark.parametrize("raw", [{}, {"php -v": php_v()}, {"php -i": ""}, {"php -i": None}])
def test_collect_ini_with_nothing_to_read_gives_nothing(raw):
    assert collect_ini(raw) == {}


@pytest.mark.parametrize("line", [
    "memory_limit_x => 1 => 1", "Memory_Limit => 1 => 1", " memory_limit => 1 => 1",
    "xmemory_limit => 1 => 1", "memory_limit=>1=>1", "memory_limit =>1 =>1",
    "$_SERVER['memory_limit'] => 1", "HTTP_MEMORY_LIMIT => 1",
])
def test_collect_ini_matches_a_setting_by_its_exact_name(line):
    assert collect_ini({"php -i": line + "\n"}) == {}


@pytest.mark.parametrize("value", [
    "128M; rm -rf /", "$(id)", "`id`", "1\t28M", "<b>1</b>", "1\x00", "128M\u00e9", "x" * 33,
    "a=b", "a/b", "a,b", "'1'", '"1"', "1\\2"])
def test_collect_ini_drops_a_value_that_is_not_a_plain_setting(value):
    assert collect_ini({"php -i": f"memory_limit => {value} => 1\n"}) == {}


@pytest.mark.parametrize("value", ["-1", "0", "1", "128M", "1G", "On", "Off", "no value", "x" * 32])
def test_collect_ini_keeps_a_plain_setting(value):
    assert collect_ini({"php -i": f"memory_limit => {value} => 1\n"}) == {"memory_limit": value}


@pytest.mark.parametrize("value", [
    "1.5M", "1+1", "a_b", "E_ALL", "1.0", "1;2", "1&2", "1|2", "1$2", "1`2", "1(2)", "1<2", "1>2",
    "1'2", '1"2', "1=2", "1/2", "1,2", "1:2", "1*2", "1?2", "1[2]", "1{2}", "1!2", "1#2", "1~2",
    "1%2", "1@2", "1^2"])
def test_collect_ini_keeps_only_letters_digits_spaces_and_hyphens(value):
    assert collect_ini({"php -i": f"memory_limit => {value} => 1\n"}) == {}


def test_an_empty_value_is_no_value():
    assert collect_ini({"php -i": "memory_limit =>  => \n"}) == {}


@pytest.mark.parametrize("version, verdict", [
    ("8.3.35", Verdict.EXPOSED), ("8.3.36", Verdict.LIKELY_PATCHED), ("8.1.2", Verdict.EXPOSED),
    ("8.4.27", Verdict.LIKELY_PATCHED), ("8.5.11", Verdict.EXPOSED)])
@pytest.mark.parametrize("ini", [
    "", "memory_limit => 1M => 1M\n", "post_max_size => 0 => 0\n",
    "session.upload_progress.enabled => Off => Off\n", "fatal_error_backtraces => On => On\n",
    "memory_limit => 1M => 1M\npost_max_size => 1K => 1K\n"
    "session.upload_progress.enabled => Off => Off\nfatal_error_backtraces => Off => Off\n"])
def test_ini_settings_annotate_and_never_move_a_verdict(version, verdict, ini):
    alone, annotated = FakeRun(), FakeRun()
    alone.script({"php -v": php_v(version)})
    annotated.script({"php -v": php_v(version),
                      "php -i": f"phpinfo()\nPHP Version => {version}\n" + ini})
    plain, marked = inspect_local(run=alone), inspect_local(run=annotated)
    assert grade_evidence(plain, MATRIX)[0] is verdict
    assert grade_evidence(marked, MATRIX) == grade_evidence(plain, MATRIX)
    assert marked.detected_version == plain.detected_version


def test_ini_settings_change_nothing_but_their_own_signals():
    with_ini, without = FakeRun(), FakeRun()
    with_ini.script(UBUNTU_BOX)
    without.script({**UBUNTU_BOX, "php -i": "phpinfo()\nPHP Version => 8.1.2-1ubuntu2.28\n"})
    a, b = inspect_local(run=with_ini), inspect_local(run=without)
    names = {"memory_limit", "post_max_size", "session.upload_progress.enabled",
             "fatal_error_backtraces"}
    assert {k: v for k, v in a.signals.items() if k not in names} == b.signals
    assert names <= set(a.signals)
    assert (a.detected_version, a.sapi, a.note) == (b.detected_version, b.sapi, b.note)


# --- distro builds and builds from source ---

def test_a_distro_package_carries_its_build_and_its_distro(fake_run):
    fake_run.script(UBUNTU_BOX)
    ev = inspect_local(run=fake_run)
    assert ev.detected_version == "8.1.2"
    assert ev.signals["distro"] == "ubuntu"
    assert ev.signals["package_version"] == "8.1.2-1ubuntu2.28"
    assert ev.signals["os"] == "ubuntu 22.04"
    assert ev.note == ""
    assert grade_evidence(ev, MATRIX) == (Verdict.LIKELY_PATCHED, Confidence.HIGH)


def test_an_older_distro_build_is_not_called_patched_or_exposed(fake_run):
    fake_run.script(box("8.1.2-1ubuntu2.14", UBUNTU_OS, "dpkg-query -W",
                        DPKG_UBUNTU.replace("2.28", "2.14")))
    ev = inspect_local(run=fake_run)
    assert ev.signals["package_version"] == "8.1.2-1ubuntu2.14"
    assert ev.signals["distro"] == "ubuntu"
    assert grade_evidence(ev, MATRIX)[0] is Verdict.INDETERMINATE


def test_a_debian_package_reports_a_bare_upstream_number_and_the_installed_build(fake_run):
    fake_run.script(DEBIAN_BOX)
    ev = inspect_local(run=fake_run)
    assert ev.detected_version == "8.4.27"
    assert ev.signals["distro"] == "debian"
    assert ev.signals["package_version"] == "8.4.27-1~deb13u1"
    assert ev.signals["os"] == "debian 13"
    assert grade_evidence(ev, MATRIX) == (Verdict.LIKELY_PATCHED, Confidence.HIGH)


def test_a_suse_package_is_read_from_rpm_and_keyed_suse(fake_run):
    fake_run.script(SUSE_BOX)
    ev = inspect_local(run=fake_run)
    assert ev.detected_version == "8.3.36"
    assert ev.signals["distro"] == "suse"
    assert ev.signals["package_version"] == "8.3.36-150700.3.24.1"
    assert ev.signals["os"] == "sles 15.7"
    assert grade_evidence(ev, MATRIX) == (Verdict.LIKELY_PATCHED, Confidence.HIGH)


@pytest.mark.parametrize("os_id", ["sles", "sled", "sles_sap", "opensuse", "opensuse-leap",
                                   "opensuse-tumbleweed", "suse"])
def test_every_suse_spelling_is_keyed_suse(fake_run, os_id):
    fake_run.script(box("8.3.36", f'ID="{os_id}"\nVERSION_ID="15.7"\n', "rpm -qa", RPM_SUSE))
    assert inspect_local(run=fake_run).signals["distro"] == "suse"


@pytest.mark.parametrize("os_id", ["ubuntu", "debian", "raspbian", "kali"])
def test_any_other_distro_is_keyed_by_its_os_release_id(fake_run, os_id):
    fake_run.script(box("8.4.27", f"ID={os_id}\n", "dpkg-query -W", DPKG_DEBIAN))
    assert inspect_local(run=fake_run).signals["distro"] == os_id


def test_an_rpm_distro_the_matrix_does_not_know_still_carries_its_build(fake_run):
    rpm = ("php-cli-8.0.30-3.el9_2.x86_64\nphp-common-8.0.30-3.el9_2.x86_64\n"
           "bash-5.1.8-6.el9.x86_64\n")
    fake_run.script(box("8.0.30", 'ID="rocky"\nVERSION_ID="9.2"\n', "rpm -qa", rpm))
    ev = inspect_local(run=fake_run)
    assert ev.signals["distro"] == "rocky"
    assert ev.signals["package_version"] == "8.0.30-3.el9_2"
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


def test_php_built_from_source_sets_no_distro_and_no_package_version(fake_run):
    fake_run.script(SELF_BUILT)
    ev = inspect_local(run=fake_run)
    assert ev.detected_version == "8.3.35"
    assert "distro" not in ev.signals
    assert "package_version" not in ev.signals
    assert ev.signals["os"] == "ubuntu 22.04"
    assert ev.note == ""
    assert grade_evidence(ev, MATRIX) == (Verdict.EXPOSED, Confidence.HIGH)


def test_php_built_from_source_at_the_fixed_micro_grades_as_patched(fake_run):
    fake_run.script(box("8.3.36", UBUNTU_OS, "dpkg-query -W", DPKG_UBUNTU))
    ev = inspect_local(run=fake_run)
    assert "distro" not in ev.signals and "package_version" not in ev.signals
    assert grade_evidence(ev, MATRIX) == (Verdict.LIKELY_PATCHED, Confidence.HIGH)


def test_the_os_signal_has_no_effect_on_grading(fake_run):
    other = FakeRun()
    fake_run.script(SELF_BUILT)
    other.script({**SELF_BUILT, "cat /etc/os-release": "ID=nothing\n"})
    a, b = inspect_local(run=fake_run), inspect_local(run=other)
    assert a.signals["os"] != b.signals["os"]
    assert grade_evidence(a, MATRIX) == grade_evidence(b, MATRIX)


def test_php_built_from_source_on_a_box_with_no_php_packages_sets_no_distro(fake_run):
    fake_run.script(box("8.3.35", UBUNTU_OS, "dpkg-query -W", DPKG_NO_PHP))
    ev = inspect_local(run=fake_run)
    assert "distro" not in ev.signals and "package_version" not in ev.signals
    assert ev.note == ""


def test_a_distro_package_of_another_micro_does_not_make_this_php_a_distro_build(fake_run):
    fake_run.script(box("8.3.35", UBUNTU_OS, "dpkg-query -W",
                        DPKG_UBUNTU + "php8.3-cli\t8.3.36-0ubuntu1\n"))
    ev = inspect_local(run=fake_run)
    assert "distro" not in ev.signals and "package_version" not in ev.signals


def test_with_two_php_versions_installed_the_running_one_is_matched(fake_run):
    listing = ("php8.1-cli\t8.1.2-1ubuntu2.28\nphp8.1-common\t8.1.2-1ubuntu2.28\n"
               "php8.4-cli\t8.4.27-1~deb13u1\nphp8.4-common\t8.4.27-1~deb13u1\n")
    fake_run.script(box("8.4.27", DEBIAN_OS, "dpkg-query -W", listing))
    ev = inspect_local(run=fake_run)
    assert ev.signals["package_version"] == "8.4.27-1~deb13u1"
    assert ev.signals["distro"] == "debian"


def test_a_package_listing_that_cannot_be_read_leaves_the_distro_unconfirmed(fake_run):
    fake_run.script({"php -v": php_v("8.3.35"), "cat /etc/os-release": UBUNTU_OS})
    ev = inspect_local(run=fake_run)
    assert "distro" not in ev.signals and "package_version" not in ev.signals
    assert ev.signals["os"] == "ubuntu 22.04"
    assert "provenance unconfirmed: no package listing could be read" in ev.note
    assert grade_evidence(ev, MATRIX) == (Verdict.EXPOSED, Confidence.HIGH)


def test_a_distro_build_with_no_listing_keeps_the_build_php_reports(fake_run):
    fake_run.script({"php -v": php_v("8.1.2-1ubuntu2.28"), "cat /etc/os-release": UBUNTU_OS})
    ev = inspect_local(run=fake_run)
    assert ev.detected_version == "8.1.2"
    assert ev.signals["package_version"] == "8.1.2-1ubuntu2.28"
    assert "distro" not in ev.signals
    assert grade_evidence(ev, MATRIX)[0] is Verdict.INDETERMINATE


def test_a_listing_that_fails_leaves_the_distro_unconfirmed(fake_run):
    fake_run.script({**UBUNTU_BOX, "dpkg-query -W": (2, DPKG_UBUNTU)})
    ev = inspect_local(run=fake_run)
    assert "distro" not in ev.signals
    assert "provenance unconfirmed: no package listing could be read" in ev.note


@pytest.mark.parametrize("listing", ["", "\n\n", "not a package list\n", "php8.1-cli;id\t8.1.2-1\n",
                                     "php8.1-cli\n", "\t8.1.2-1\n", "PHP8.1-CLI\t8.1.2-1\n"])
def test_a_listing_with_no_package_in_it_is_no_listing(fake_run, listing):
    fake_run.script({**UBUNTU_BOX, "dpkg-query -W": listing})
    ev = inspect_local(run=fake_run)
    assert "distro" not in ev.signals
    assert "provenance unconfirmed: no package listing could be read" in ev.note


def test_a_distro_build_that_no_installed_package_lists_is_unconfirmed(fake_run):
    fake_run.script(box("8.1.2-1ubuntu2.28", UBUNTU_OS, "dpkg-query -W",
                        DPKG_UBUNTU.replace("2.28", "2.14")))
    ev = inspect_local(run=fake_run)
    assert "distro" not in ev.signals
    assert ev.signals["package_version"] == "8.1.2-1ubuntu2.28"
    assert "no installed package lists" in ev.note
    assert grade_evidence(ev, MATRIX)[0] is Verdict.INDETERMINATE


def test_packages_that_carry_different_builds_of_the_running_version_are_unconfirmed(fake_run):
    listing = "php8.1-cli\t8.1.2-1ubuntu2.28\nphp8.1-fpm\t8.1.2-1ubuntu2.14\n"
    fake_run.script(box("8.1.2", UBUNTU_OS, "dpkg-query -W", listing))
    ev = inspect_local(run=fake_run)
    assert "distro" not in ev.signals and "package_version" not in ev.signals
    assert "different builds" in ev.note


def test_the_running_build_picks_among_packages_that_differ(fake_run):
    listing = "php8.1-cli\t8.1.2-1ubuntu2.28\nphp8.1-fpm\t8.1.2-1ubuntu2.14\n"
    fake_run.script(box("8.1.2-1ubuntu2.28", UBUNTU_OS, "dpkg-query -W", listing))
    ev = inspect_local(run=fake_run)
    assert ev.signals["package_version"] == "8.1.2-1ubuntu2.28"
    assert ev.signals["distro"] == "ubuntu"
    assert ev.note == ""


def test_a_package_without_a_distro_name_carries_its_build_and_says_so(fake_run):
    fake_run.script({**DEBIAN_BOX, "cat /etc/os-release": ""})
    ev = inspect_local(run=fake_run)
    assert ev.signals["package_version"] == "8.4.27-1~deb13u1"
    assert "distro" not in ev.signals and "os" not in ev.signals
    assert "the distro name could not be read" in ev.note


@pytest.mark.parametrize("os_text", [
    "", "ID=\n", "ID=Ubuntu Linux\n", "ID=ub;id\n", "ID=$(id)\n", "ID=" + "a" * 40 + "\n",
    "NAME=Ubuntu\n", "garbage\n", "ID=ubuntu\x00\n"])
def test_an_os_release_with_no_usable_id_names_no_distro(fake_run, os_text):
    fake_run.script({**UBUNTU_BOX, "cat /etc/os-release": os_text})
    ev = inspect_local(run=fake_run)
    assert "distro" not in ev.signals and "os" not in ev.signals


@pytest.mark.parametrize("text, name", [
    ('ID=ubuntu\nVERSION_ID="22.04"\n', "ubuntu 22.04"),
    ("ID='ubuntu'\nVERSION_ID='22.04'\n", "ubuntu 22.04"),
    ("ID=ubuntu\n", "ubuntu"),
    ("ID=ubuntu\nVERSION_ID=\n", "ubuntu"),
    ("ID=ubuntu\nVERSION_ID=$(id)\n", "ubuntu"),
    ("ID=Ubuntu\nVERSION_ID=22.04\n", "ubuntu 22.04"),
    ("ID=ubuntu\r\nVERSION_ID=22.04\r\n", "ubuntu 22.04"),
    ("ID=ubuntu\nID=debian\n", "ubuntu"),
    ('NAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\n', "ubuntu 22.04"),
    ("ID=ubuntu\nVERSION_ID=" + "1" * 40 + "\n", "ubuntu"),
])
def test_the_os_signal_reads_id_and_version_id(fake_run, text, name):
    fake_run.script({**SELF_BUILT, "cat /etc/os-release": text})
    assert inspect_local(run=fake_run).signals["os"] == name


def test_an_os_release_line_with_no_equals_sign_is_skipped(fake_run):
    text = "ID\nVERSION_ID\nID=ubuntu\nVERSION_ID=22.04\n"
    fake_run.script({**SELF_BUILT, "cat /etc/os-release": text})
    assert inspect_local(run=fake_run).signals["os"] == "ubuntu 22.04"


def test_an_alpine_box_has_no_package_listing_to_read(fake_run):
    fake_run.script({"php -v": php_v("8.3.36"), "cat /etc/os-release": ALPINE_OS})
    ev = inspect_local(run=fake_run)
    assert ev.signals["os"] == "alpine 3.24.0"
    assert "distro" not in ev.signals
    assert "no package listing could be read" in ev.note
    assert grade_evidence(ev, MATRIX) == (Verdict.LIKELY_PATCHED, Confidence.HIGH)


@pytest.mark.parametrize("os_id", ["ubuntu", "debian"])
def test_an_rpm_package_list_is_not_believed_for_a_dpkg_distro(fake_run, os_id):
    fake_run.script({**box("8.3.36", f"ID={os_id}\n", "rpm -qa", RPM_SUSE),
                     "dpkg-query -W": FileNotFoundError()})
    ev = inspect_local(run=fake_run)
    assert "distro" not in ev.signals
    assert ("rpm", "-qa") not in commands(fake_run)


@pytest.mark.parametrize("os_id", ["suse", "rhel", "centos", "fedora", "rocky", "almalinux",
                                   "amzn", "ol"])
def test_an_rpm_distro_reads_rpm_and_never_dpkg(fake_run, os_id):
    fake_run.script({**box("8.3.36", f"ID={os_id}\n", "rpm -qa", RPM_SUSE),
                     "dpkg-query -W": DPKG_DEBIAN})
    ev = inspect_local(run=fake_run)
    assert ev.signals["distro"] == os_id
    assert ev.signals["package_version"] == "8.3.36-150700.3.24.1"
    assert ("dpkg-query", "-W") not in commands(fake_run)


def test_no_package_listing_is_read_when_php_gives_no_version(fake_run):
    fake_run.script({"php -i": "session.upload_progress.enabled => 0 => 0",
                     "dpkg-query -W": DPKG_UBUNTU})
    inspect_local(run=fake_run)
    assert commands(fake_run) == [("php", "-v"), ("php", "-i"), ("cat", "/etc/os-release")]


# --- resolve_package ---

UBUNTU_RAW = {"php -v": php_v("8.1.2-1ubuntu2.28"), "dpkg-query -W": DPKG_UBUNTU}


def test_resolve_package_gives_the_installed_build_and_its_revision():
    assert resolve_package("ubuntu", UBUNTU_RAW) == ("8.1.2-1ubuntu2.28", "1ubuntu2.28")
    assert resolve_package("debian", {"php -v": php_v("8.4.27"),
                                      "dpkg-query -W": DPKG_DEBIAN}) == (
        "8.4.27-1~deb13u1", "1~deb13u1")
    assert resolve_package("suse", {"php -v": php_v("8.3.36"), "rpm -qa": RPM_SUSE}) == (
        "8.3.36-150700.3.24.1", "150700.3.24.1")


def test_resolve_package_reads_the_version_from_php_i_when_php_v_is_missing():
    raw = {"php -i": php_i("8.1.2-1ubuntu2.28"), "dpkg-query -W": DPKG_UBUNTU}
    assert resolve_package("ubuntu", raw) == ("8.1.2-1ubuntu2.28", "1ubuntu2.28")


def test_resolve_package_drops_an_epoch_and_an_architecture():
    raw = {"php -v": php_v("8.1.2-1ubuntu2.28"),
           "dpkg-query -W": "php8.1-cli:amd64\t1:8.1.2-1ubuntu2.28\n"}
    assert resolve_package("ubuntu", raw) == ("8.1.2-1ubuntu2.28", "1ubuntu2.28")


def test_resolve_package_for_a_build_with_no_revision():
    raw = {"php -v": php_v("8.3.36"), "dpkg-query -W": "php8.3-cli\t8.3.36\n"}
    assert resolve_package("debian", raw) == ("8.3.36", None)


@pytest.mark.parametrize("raw", [
    {},
    {"dpkg-query -W": DPKG_UBUNTU},
    {"php -v": php_v("8.1.2-1ubuntu2.28")},
    {"php -v": "no banner", "dpkg-query -W": DPKG_UBUNTU},
    {"php -v": php_v("8.3.35"), "dpkg-query -W": DPKG_UBUNTU},
    {"php -v": php_v("8.1.2"), "dpkg-query -W": DPKG_NO_PHP},
    {"php -v": php_v("8.1.2"),
     "dpkg-query -W": "php8.1-cli\t8.1.2-1ubuntu2.28\nphp8.1-fpm\t8.1.2-1ubuntu2.14\n"},
    {"php -v": php_v("8.1.2-1ubuntu2.28"), "dpkg-query -W": "php8.1-cli\t8.1.2-1ubuntu2.14\n"},
    {"php -v": php_v("8.1.2-1ubuntu2.28"), "dpkg-query -W": None},
])
def test_resolve_package_with_nothing_to_confirm_gives_none(raw):
    assert resolve_package("ubuntu", raw) == (None, None)


def test_resolve_package_only_believes_the_manager_of_the_distro():
    both = {"php -v": php_v("8.3.36"), "dpkg-query -W": "php8.3-cli\t8.3.36-1~deb13u1\n",
            "rpm -qa": RPM_SUSE}
    assert resolve_package("suse", both) == ("8.3.36-150700.3.24.1", "150700.3.24.1")
    assert resolve_package("debian", both) == ("8.3.36-1~deb13u1", "1~deb13u1")
    assert resolve_package("ubuntu", {"php -v": php_v("8.3.36"), "rpm -qa": RPM_SUSE}) == (
        None, None)
    assert resolve_package("suse", {"php -v": php_v("8.3.36"),
                                    "dpkg-query -W": "php8.3-cli\t8.3.36-1~deb13u1\n"}) == (
        None, None)


def test_resolve_package_tries_dpkg_and_then_rpm_for_a_distro_it_does_not_know():
    both = {"php -v": php_v("8.3.36"), "dpkg-query -W": "php8.3-cli\t8.3.36-1~deb13u1\n",
            "rpm -qa": RPM_SUSE}
    assert resolve_package("", both)[0] == "8.3.36-1~deb13u1"
    assert resolve_package("kali", both)[0] == "8.3.36-1~deb13u1"
    rpm_only = {"php -v": php_v("8.3.36"), "rpm -qa": RPM_SUSE}
    assert resolve_package("", rpm_only)[0] == "8.3.36-150700.3.24.1"
    assert resolve_package("kali", {"php -v": php_v("8.3.36"), "dpkg-query -W": "\n",
                                    "rpm -qa": RPM_SUSE})[0] == "8.3.36-150700.3.24.1"


@pytest.mark.parametrize("name", ["phpmyadmin", "phpunit", "phpldapadmin", "xphp8.1", "libphp8.1",
                                  "ph", "ph8.1-cli"])
def test_resolve_package_does_not_count_a_package_that_is_not_php_itself(name):
    raw = {"php -v": php_v("8.1.2"), "dpkg-query -W": f"{name}\t8.1.2-1\n"}
    assert resolve_package("debian", raw) == (None, None)


@pytest.mark.parametrize("name", ["php", "php-cli", "php-fpm", "php8.1-cli", "php8-cli", "php83",
                                  "php83-fpm", "php8.1"])
def test_resolve_package_counts_the_names_php_packages_go_by(name):
    raw = {"php -v": php_v("8.1.2"), "dpkg-query -W": f"{name}\t8.1.2-1\n"}
    assert resolve_package("debian", raw) == ("8.1.2-1", "1")


@pytest.mark.parametrize("line", [
    "php8.1-cli\t8.1.2-1ubuntu2.28 \n", "php8.1-cli\t8.1.2-1ubuntu2.28\r\n",
    "\nphp8.1-cli\t8.1.2-1ubuntu2.28\n\n"])
def test_resolve_package_reads_a_listing_line_however_it_ends(line):
    raw = {"php -v": php_v("8.1.2-1ubuntu2.28"), "dpkg-query -W": line}
    assert resolve_package("ubuntu", raw)[0] == "8.1.2-1ubuntu2.28"


@pytest.mark.parametrize("line", [
    "php8.1-cli\t8.1.2-1;id\n", "php8.1-cli\t8.1.2-1 ubuntu\n", "php8.1-cli\t8.1.2-$(id)\n",
    "php8.1-cli 8.1.2-1ubuntu2.28\n", "php8.1-cli\t" + "8.1.2-" + "1" * 130 + "\n",
    "php8.1-cli\t8.1.2-1\x00\n", "php8.1-cli\t\u0668.1.2-1\n", "php8.1-cli:evil;id\t8.1.2-1\n",
    "php8.1-cli:\t8.1.2-1\n", "php8.1-cli:$(id)\t8.1.2-1\n"])
def test_resolve_package_skips_a_listing_line_that_is_not_a_package(line):
    raw = {"php -v": php_v("8.1.2"), "dpkg-query -W": line}
    assert resolve_package("debian", raw) == (None, None)


@pytest.mark.parametrize("line, build", [
    ("php-cli-8.3.36-150700.3.24.1.x86_64", "8.3.36-150700.3.24.1"),
    ("php-cli-8.3.36-150700.3.24.1.noarch", "8.3.36-150700.3.24.1"),
    ("php-cli-8.3.36-150700.3.24.1.aarch64", "8.3.36-150700.3.24.1"),
    ("php-cli-8.3.36-150700.3.24.1", "8.3.36-150700.3.24.1"),
    ("php-cli-8.3.36-1.el9_2.x86_64", "8.3.36-1.el9_2"),
    ("php-cli-8.3.36-1.el9_2", "8.3.36-1.el9_2"),
    ("php83-php-cli-8.3.36-1.el9.remi.x86_64", "8.3.36-1.el9.remi"),
])
def test_resolve_package_reads_an_rpm_name_version_release_and_architecture(line, build):
    raw = {"php -v": php_v("8.3.36"), "rpm -qa": "bash-5.2-1.x86_64\n" + line + "\n"}
    assert resolve_package("suse", raw) == (build, build.partition("-")[2])


@pytest.mark.parametrize("line", [
    "php-cli-8.3.36-150700.3.24.1.x86_64;id", "php-cli-8.3.36", "php-cli", "8.3.36-1.x86_64",
    "php-cli-abc-1.x86_64", "php-cli--1.x86_64", "php-cli-8.3.36-.x86_64", "-8.3.36-1.x86_64",
    "php-cli-8.3.36-$(id).x86_64", "php cli-8.3.36-1.x86_64", "php-cli;id-8.3.36-1.x86_64"])
def test_resolve_package_skips_an_rpm_line_that_is_not_a_package(line):
    raw = {"php -v": php_v("8.3.36"), "rpm -qa": line + "\n"}
    assert resolve_package("suse", raw) == (None, None)


@pytest.mark.parametrize("line", [
    "php-cli-8.3.36-1.el9.x86_64  ", "php-cli-8.3.36-1.el9.x86_64\t",
    "  php-cli-8.3.36-1.el9.x86_64"])
def test_resolve_package_reads_an_rpm_line_with_spaces_around_it(line):
    raw = {"php -v": php_v("8.3.36"), "rpm -qa": line + "\n"}
    assert resolve_package("suse", raw) == ("8.3.36-1.el9", "1.el9")


@pytest.mark.parametrize("text", ["this-is-not-a-listing\n", "error-no-such-thing\n",
                                  "rpm-database-is-locked\n"])
def test_hyphenated_text_is_no_rpm_listing(fake_run, text):
    fake_run.script({"rpm -qa": text})
    ev = inspect_local(run=fake_run)
    assert "php_present" not in ev.signals
    assert ev.note.startswith("no php command was found and no package listing")


@pytest.mark.parametrize("text", ["error\tsomething\n", "dpkg-query\tfailed\n", "php8.1-cli\t1:\n",
                                  "base-files\tx12\n", "libfoo\t1:2:3\n", "libfoo\t1:2;3\n"])
def test_tabbed_text_with_no_version_is_no_dpkg_listing(fake_run, text):
    fake_run.script({"dpkg-query -W": text})
    ev = inspect_local(run=fake_run)
    assert "php_present" not in ev.signals
    assert ev.note.startswith("no php command was found and no package listing")


def test_a_sury_build_with_plus_signs_is_read():
    build = "8.2.10-1+ubuntu22.04.1+deb.sury.org+1"
    raw = {"php -v": php_v(build), "dpkg-query -W": f"php8.2-cli\t{build}\n"}
    assert resolve_package("ubuntu", raw) == (build, "1+ubuntu22.04.1+deb.sury.org+1")


@pytest.mark.parametrize("release", ["1.fc40+git1", "0.1~rc1.fc40"])
def test_resolve_package_reads_an_rpm_release_with_a_plus_or_a_tilde(release):
    raw = {"php -v": php_v("8.3.36"), "rpm -qa": f"php-cli-8.3.36-{release}.x86_64\n"}
    assert resolve_package("suse", raw) == (f"8.3.36-{release}", release)


def test_package_names_with_plus_signs_make_a_listing(fake_run):
    fake_run.script({"dpkg-query -W": "libstdc++6\t13.2.0-4ubuntu3\ng++\t4:13.2.0-7ubuntu1\n"})
    ev = inspect_local(run=fake_run)
    assert ev.signals["php_present"] == "false"


def test_the_revision_is_what_follows_the_last_hyphen():
    raw = {"php -v": php_v("8.1.2"), "dpkg-query -W": "php8.1-cli\t8.1.2-1-ubuntu1\n"}
    assert resolve_package("debian", raw) == ("8.1.2-1-ubuntu1", "ubuntu1")


def test_an_epoch_is_a_number_before_a_colon_and_nothing_else():
    raw = {"php -v": php_v("8.1.2"), "dpkg-query -W": "php8.1-cli\tx:8.1.2-1\n"}
    assert resolve_package("debian", raw) == (None, None)


@pytest.mark.parametrize("arch", ["x86_64", "i386", "i486", "i586", "i686", "aarch64", "armv7hl",
                                  "ppc64", "ppc64le", "s390x", "noarch"])
def test_resolve_package_cuts_each_rpm_architecture(arch):
    raw = {"php -v": php_v("8.3.36"), "rpm -qa": f"php-cli-8.3.36-1.el9.{arch}\n"}
    assert resolve_package("suse", raw) == ("8.3.36-1.el9", "1.el9")


@pytest.mark.parametrize("length, kept", [(121, True), (122, False)])
def test_resolve_package_reads_an_rpm_build_of_at_most_128_characters(length, kept):
    build = "8.3.36-" + "1" * length
    raw = {"php -v": php_v("8.3.36"), "rpm -qa": f"php-cli-{build}.x86_64\n"}
    assert resolve_package("suse", raw)[0] == (build if kept else None)


@pytest.mark.parametrize("length, kept", [(128, True), (129, False)])
def test_resolve_package_reads_a_dpkg_build_of_at_most_128_characters(length, kept):
    build = "8.3.36-" + "1" * (length - 7)
    assert len(build) == length
    raw = {"php -v": php_v("8.3.36"), "dpkg-query -W": f"php8.3-cli\t{build}\n"}
    assert resolve_package("debian", raw)[0] == (build if kept else None)


@pytest.mark.parametrize("length, kept", [(64, True), (65, False)])
def test_a_package_name_is_read_up_to_64_characters(length, kept):
    name = "php8.3-" + "a" * (length - 7)
    raw = {"php -v": php_v("8.3.36"), "dpkg-query -W": f"{name}\t8.3.36-1\n"}
    assert resolve_package("debian", raw)[0] == ("8.3.36-1" if kept else None)


# --- limits on what is read ---

def test_a_version_of_the_longest_length_is_read_and_one_more_character_is_not(fake_run):
    token = "8.3.35-" + "a" * 57
    assert len(token) == 64
    fake_run.script({"php -v": f"PHP {token} (cli)"})
    assert inspect_local(run=fake_run).detected_version == token
    longer = FakeRun()
    longer.script({"php -v": f"PHP {token}a (cli)"})
    assert inspect_local(run=longer).detected_version is None


@pytest.mark.parametrize("id_length, version_length, shown", [
    (32, 32, "a" * 32 + " " + "1" * 32), (33, 5, None), (5, 33, "a" * 5), (1, 1, "a 1")])
def test_an_os_release_id_and_version_are_read_up_to_32_characters(
        fake_run, id_length, version_length, shown):
    text = f"ID={'a' * id_length}\nVERSION_ID={'1' * version_length}\n"
    fake_run.script({**SELF_BUILT, "cat /etc/os-release": text})
    assert inspect_local(run=fake_run).signals.get("os") == shown


@pytest.mark.parametrize("length, kept", [(32, True), (33, False)])
def test_an_ini_value_is_read_up_to_32_characters(length, kept):
    raw = {"php -i": f"memory_limit => {'1' * length} => 1\n"}
    assert collect_ini(raw) == ({"memory_limit": "1" * length} if kept else {})


@pytest.mark.parametrize("line", ["memory_limit => 128M   ", "memory_limit =>    128M => 1",
                                  "memory_limit => 128M    => 1"])
def test_an_ini_value_loses_the_spaces_around_it(line):
    assert collect_ini({"php -i": line + "\n"}) == {"memory_limit": "128M"}


@pytest.mark.parametrize("length, kept", [(253, True), (254, False)])
def test_a_local_name_is_kept_up_to_253_characters(monkeypatch, fake_run, length, kept):
    monkeypatch.setattr(socket, "gethostname", lambda: "a" * length)
    assert ("hostname" in inspect_local(run=fake_run).signals) is kept


@pytest.mark.parametrize("target, refused", [
    ("a" * 253, False), ("a" * 254, True), ("u" * 64 + "@web1", False),
    ("u" * 65 + "@web1", True)])
def test_an_ssh_target_is_read_up_to_253_characters_of_host_and_64_of_user(
        fake_run, target, refused):
    inspect_ssh(target, run=fake_run)
    assert (fake_run.calls == []) is refused


# --- a machine with no PHP, and a read that fails ---

def test_no_php_command_and_a_listing_without_php_is_a_positive_no_php_read(fake_run):
    fake_run.script({"dpkg-query -W": DPKG_NO_PHP})
    ev = inspect_local(run=fake_run)
    assert ev.signals == {"hostname": "web1.example.com", "php_present": "false"}
    assert ev.note == ""
    assert ev.detected_version is None and ev.sapi is Sapi.UNKNOWN
    assert ev.source is Source.HOST
    assert grade_evidence(ev, MATRIX) == (Verdict.NOT_PHP, Confidence.HIGH)


def test_the_positive_no_php_read_works_from_an_rpm_listing(fake_run):
    fake_run.script({"rpm -qa": RPM_NO_PHP})
    ev = inspect_local(run=fake_run)
    assert ev.signals["php_present"] == "false" and ev.note == ""
    assert grade_evidence(ev, MATRIX)[0] is Verdict.NOT_PHP


def test_the_positive_no_php_read_works_over_ssh(fake_run):
    fake_run.script({"dpkg-query -W": DPKG_NO_PHP})
    ev = inspect_ssh("deploy@web1.example.com", run=fake_run)
    assert ev.signals["php_present"] == "false" and ev.note == ""
    assert ev.signals["hostname"] == "web1.example.com"
    assert grade_evidence(ev, MATRIX)[0] is Verdict.NOT_PHP


def test_exit_127_is_a_missing_command_for_php_and_for_the_listing(fake_run):
    fake_run.script({"php -v": (127, ""), "php -i": (127, ""), "dpkg-query -W": (127, ""),
                     "rpm -qa": (127, "")})
    ev = inspect_local(run=fake_run)
    assert "php_present" not in ev.signals
    assert "no package listing could be read" in ev.note


def test_an_ssh_machine_that_has_no_php_package_manager_cannot_be_cleared(fake_run):
    ev = inspect_ssh("web1", run=fake_run)
    assert "php_present" not in ev.signals
    assert ev.note == ("no php command was found and no package listing could be read: "
                       "PHP may still be installed")
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)


PACKAGE_NOTE = ("no php command was found, but a package with php in its name is installed: "
                "the build was not read")


def test_no_php_command_but_a_php_package_is_php_present_and_unplaced(fake_run):
    fake_run.script({"dpkg-query -W": DPKG_FPM_ONLY})
    ev = inspect_local(run=fake_run)
    assert ev.signals == {"hostname": "web1.example.com", "php_present": "true"}
    assert ev.detected_version is None
    assert ev.note == PACKAGE_NOTE
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


def test_no_php_command_and_a_php_package_in_the_rpm_listing_is_php_present(fake_run):
    fake_run.script({"rpm -qa": RPM_NO_PHP + "php8-fpm-8.3.36-150700.3.24.1.x86_64\n"})
    ev = inspect_local(run=fake_run)
    assert ev.signals["php_present"] == "true"
    assert grade_evidence(ev, MATRIX)[0] is Verdict.INDETERMINATE


PHP_PACKAGES = [
    "plesk-php81-cli", "ea-php81-php-cli", "lsphp81", "alt-php81-cli", "rh-php73-php-fpm",
    "libapache2-mod-php8.1", "libphp8.1-embed", "php", "php8.1-fpm", "php-cgi", "phpmyadmin",
    "php-doc", "libphp-adodb"]
NO_PHP_LISTINGS = {"dpkg-query -W": (DPKG_NO_PHP, "{}\t8.1.28-1\n"),
                   "rpm -qa": (RPM_NO_PHP, "{}-8.1.28-1.x86_64\n")}


@pytest.mark.parametrize("command", ["dpkg-query -W", "rpm -qa"])
@pytest.mark.parametrize("name", PHP_PACKAGES)
def test_a_package_with_php_in_its_name_is_never_a_host_with_no_php(fake_run, name, command):
    # Packagers name PHP many ways. A miss here clears a host that runs it.
    listing, line = NO_PHP_LISTINGS[command]
    fake_run.script({command: listing + line.format(name)})
    ev = inspect_local(run=fake_run)
    assert ev.signals == {"hostname": "web1.example.com", "php_present": "true"}
    assert ev.note == PACKAGE_NOTE
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


@pytest.mark.parametrize("name", ["phpMyAdmin", "PHP_CodeSniffer", "LSPHP81"])
def test_a_package_name_is_read_without_regard_to_case(fake_run, name):
    fake_run.script({"rpm -qa": RPM_NO_PHP + f"{name}-5.2.1-1.el9.noarch\n"})
    ev = inspect_local(run=fake_run)
    assert ev.signals["php_present"] == "true"


@pytest.mark.parametrize("name", ["nginx", "apache2", "libapache2-mod-wsgi-py3", "python3",
                                  "perl", "ph", "pgp", "mysql-server", "libpq5"])
def test_a_package_without_php_in_its_name_does_not_stop_a_no_php_read(fake_run, name):
    fake_run.script({"dpkg-query -W": DPKG_NO_PHP + f"{name}\t1.2.3-1\n"})
    ev = inspect_local(run=fake_run)
    assert ev.signals["php_present"] == "false" and ev.note == ""
    assert grade_evidence(ev, MATRIX)[0] is Verdict.NOT_PHP


@pytest.mark.parametrize("listing", ["", "\n", "junk\n", (1, DPKG_NO_PHP), (100, DPKG_NO_PHP),
                                     subprocess.TimeoutExpired("dpkg-query", 30),
                                     PermissionError(13, "denied")],
                         ids=["empty", "blank", "junk", "exit 1", "exit 100", "timeout", "denied"])
def test_no_php_command_and_a_listing_that_cannot_be_read_is_not_a_clearance(fake_run, listing):
    fake_run.script({"dpkg-query -W": listing, "rpm -qa": (1, "")})
    ev = inspect_local(run=fake_run)
    assert "php_present" not in ev.signals
    assert ev.note
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)


FAILURES = [
    ((1, ""), "exit 1"),
    ((2, "usage: php"), "exit 2"),
    ((255, "PHP Fatal error: Unable to start module"), "exit 255"),
    ((-9, ""), "exit -9"),
    (subprocess.TimeoutExpired("php", 30), "timed out"),
    (PermissionError(13, "Permission denied"), "could not start (PermissionError)"),
    (OSError(8, "Exec format error"), "could not start (OSError)"),
]


@pytest.mark.parametrize("answer, reason", FAILURES, ids=[r for _, r in FAILURES])
def test_a_php_that_fails_is_a_read_that_failed_and_never_a_clearance(fake_run, answer, reason):
    fake_run.script({"php -v": answer, "php -i": answer, "dpkg-query -W": DPKG_NO_PHP})
    ev = inspect_local(run=fake_run)
    assert ev.signals == {"hostname": "web1.example.com"}
    assert ev.detected_version is None
    assert ev.note == f"php could not be read (php -v {reason}; php -i {reason})"
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)


def test_a_php_that_is_missing_for_one_read_and_broken_for_the_other_is_not_a_clearance(fake_run):
    fake_run.script({"php -i": (1, ""), "dpkg-query -W": DPKG_NO_PHP})
    ev = inspect_local(run=fake_run)
    assert "php_present" not in ev.signals
    assert ev.note == "php could not be read (php -v not found; php -i exit 1)"


def test_a_php_that_answers_with_something_else_is_not_a_clearance(fake_run):
    fake_run.script({"php -v": "this is not php\n", "php -i": "nor is this\n",
                     "dpkg-query -W": DPKG_NO_PHP})
    ev = inspect_local(run=fake_run)
    assert "php_present" not in ev.signals
    assert ev.note == ("php could not be read "
                       "(php -v gave no PHP output; php -i gave no PHP output)")


def test_only_a_positive_read_ever_sets_php_present_false(fake_run):
    cases = [
        {}, {"php -v": "garbage"}, {"dpkg-query -W": (1, DPKG_NO_PHP)},
        {"dpkg-query -W": DPKG_FPM_ONLY}, {"php -v": php_v()},
        {"php -v": subprocess.TimeoutExpired("php", 30), "dpkg-query -W": DPKG_NO_PHP},
        {"php -v": (1, ""), "php -i": (1, ""), "dpkg-query -W": DPKG_NO_PHP},
        {"php -v": (127, ""), "php -i": (1, ""), "dpkg-query -W": DPKG_NO_PHP},
    ]
    for answers in cases:
        run = FakeRun()
        run.script(answers)
        ev = inspect_local(run=run)
        assert ev.signals.get("php_present") != "false", answers


def test_a_php_present_read_names_why_nothing_else_was_read(fake_run):
    fake_run.script({"php -v": php_v("8.3.35"), "php -i": (1, "")})
    ev = inspect_local(run=fake_run)
    assert "php -i exit 1: ini settings not recorded" in ev.note
    assert ev.detected_version == "8.3.35"


def test_a_php_i_that_is_missing_is_named_in_the_note(fake_run):
    fake_run.script({"php -v": php_v("8.3.35")})
    ev = inspect_local(run=fake_run)
    assert "php -i not found: ini settings not recorded" in ev.note


def test_the_notes_of_one_read_are_separated_by_semicolons(fake_run):
    fake_run.script({"php -v": php_v("8.3.35")})
    ev = inspect_local(run=fake_run)
    assert ev.note == ("php -i not found: ini settings not recorded; "
                       "provenance unconfirmed: no package listing could be read")


@pytest.mark.parametrize("error", [RuntimeError("a bug in the runner"), ValueError("embedded null"),
                                   TypeError("not a list"), KeyError("php")])
def test_an_error_that_is_no_failure_to_run_a_command_is_not_swallowed(error):
    def broken(args, **kwargs):
        raise error

    with pytest.raises(type(error)):
        inspect_local(run=broken)
    with pytest.raises(type(error)):
        inspect_ssh("web1", run=broken)


def test_output_of_a_failed_command_is_never_echoed(fake_run):
    fake_run.script({"php -v": (1, f"Fatal: {CANARY}"), "php -i": (1, PLAIN_SECRET),
                     "dpkg-query -W": (1, CANARY)})
    ev = inspect_local(run=fake_run)
    assert CANARY not in repr(ev) and PLAIN_SECRET not in repr(ev)
    assert "Fatal" not in repr(ev)


def test_a_missing_php_over_ssh_and_a_broken_one_are_told_apart(fake_run):
    fake_run.script({"php -v": (1, ""), "php -i": (1, ""), "dpkg-query -W": DPKG_NO_PHP})
    broken = inspect_ssh("web1", run=fake_run)
    assert "php_present" not in broken.signals
    other = FakeRun()
    other.script({"dpkg-query -W": DPKG_NO_PHP})
    assert inspect_ssh("web1", run=other).signals["php_present"] == "false"


# --- what a machine prints is data ---

def test_nothing_from_the_environment_of_php_i_reaches_the_evidence(fake_run):
    fake_run.script(UBUNTU_BOX)
    ev = inspect_local(run=fake_run)
    shown = repr(ev)
    assert CANARY not in shown and PLAIN_SECRET not in shown and "/root" not in shown
    assert "GITHUB_TOKEN" not in shown and "DB_PASSWORD" not in shown


def test_nothing_from_the_environment_reaches_any_report(fake_run):
    fake_run.script(UBUNTU_BOX)
    inv = AssetInventory()
    inv.add(inspect_local(run=fake_run))
    assets = inv.assets()
    for out in (render_console(assets, MATRIX), render_json(assets, MATRIX),
                render_sarif(assets, MATRIX)):
        assert CANARY not in out and PLAIN_SECRET not in out


def test_the_evidence_holds_only_known_signals(fake_run):
    fake_run.script(UBUNTU_BOX)
    ev = inspect_local(run=fake_run)
    assert set(ev.signals) == {
        "hostname", "php_present", "distro", "package_version", "os", "memory_limit",
        "post_max_size", "session.upload_progress.enabled", "fatal_error_backtraces"}


def test_a_version_longer_than_any_real_one_is_not_recorded(fake_run):
    fake_run.script({"php -v": "PHP 8.3.35-" + "a" * 100 + " (cli)"})
    ev = inspect_local(run=fake_run)
    assert ev.detected_version is None


def test_signal_values_are_one_printable_line_of_ascii(fake_run):
    hostile = "\x1b[31m\u202e\r\n"
    fake_run.script({
        "php -v": php_v("8.1.2-1ubuntu2.28"),
        "php -i": php_i("8.1.2-1ubuntu2.28") + f"memory_limit => 1{hostile}\n",
        "cat /etc/os-release": f"ID=ubuntu{hostile}VERSION_ID=22.04\n",
        "dpkg-query -W": DPKG_UBUNTU,
    })
    ev = inspect_local(run=fake_run)
    for key, value in ev.signals.items():
        assert key.isascii() and key.isprintable()
        assert value.isascii() and value.isprintable() and "\n" not in value
    assert ev.note.isascii() and ev.note.isprintable()


def test_a_very_long_listing_is_read(fake_run):
    lines = "".join(f"libfoo{n}\t1.{n}-1\n" for n in range(60000))
    fake_run.script({**UBUNTU_BOX, "dpkg-query -W": lines + DPKG_UBUNTU})
    assert inspect_local(run=fake_run).signals["package_version"] == "8.1.2-1ubuntu2.28"


# --- fuzz: nothing a machine prints crashes the inspectors or slips past a bound ---

SIGNAL_KEYS = {"hostname", "ip", "php_present", "distro", "package_version", "os", "memory_limit",
               "post_max_size", "session.upload_progress.enabled", "fatal_error_backtraces"}
LINE_ENDS = [chr(10), chr(13), chr(13) + chr(10), chr(11), chr(12), chr(0x1c), chr(0x85),
             chr(0x2028)]
ODD = (pystring.printable + chr(0) + chr(0x202e) + chr(0x2028) + chr(0xe9) + chr(0x668)
       + chr(0x1f600))
SAMPLES = [php_v(), php_v("8.1.2-1ubuntu2.28"), php_i(), UBUNTU_OS, SLES_OS, DPKG_UBUNTU,
           DPKG_FPM_ONLY, RPM_SUSE, RPM_NO_PHP]


def noise(rng):
    kind = rng.randrange(9)
    sample = rng.choice(SAMPLES)
    if kind == 0:
        return ""
    if kind == 1:
        return "".join(rng.choice(pystring.printable) for _ in range(rng.randrange(1, 200)))
    if kind == 2:
        return "".join(rng.choice(ODD) for _ in range(rng.randrange(1, 80)))
    if kind == 3:
        chars = list(sample)
        for _ in range(rng.randrange(1, 8)):
            if chars:
                at = rng.randrange(len(chars))
                if rng.randrange(3) == 0:
                    del chars[at]
                elif rng.randrange(2):
                    chars.insert(at, rng.choice(ODD))
                else:
                    chars[at] = rng.choice(ODD)
        return "".join(chars)
    if kind == 4:
        return sample[:rng.randrange(len(sample) + 1)]
    if kind == 5:
        return rng.choice(["A", "1.", "php8.1-cli\t", "PHP ", " => "]) * rng.randrange(1, 20000)
    if kind == 6:
        return rng.choice(LINE_ENDS).join(sample.splitlines())
    if kind == 7:
        return sample + rng.choice(LINE_ENDS) + rng.choice(SAMPLES)
    return sample


def answer(rng):
    """(what to script or None for nothing, whether the command reads as missing)."""
    kind = rng.randrange(10)
    if kind == 0:
        return None, True
    if kind == 1:
        return (127, noise(rng)), True
    if kind == 2:
        return FileNotFoundError(), True
    if kind == 3:
        return (rng.choice([1, 2, 255, -9, 100]), noise(rng)), False
    if kind == 4:
        return rng.choice([subprocess.TimeoutExpired("x", 1), PermissionError(), OSError()]), False
    return noise(rng), False


COMMANDS = ("php -v", "php -i", "cat /etc/os-release", "dpkg-query -W", "rpm -qa")
BOXES = [UBUNTU_BOX, DEBIAN_BOX, SUSE_BOX, SELF_BUILT, {"dpkg-query -W": DPKG_NO_PHP},
         {"rpm -qa": RPM_NO_PHP}, {"dpkg-query -W": DPKG_FPM_ONLY}]


def reads(rng):
    """A script for the five commands, as {command: (answer or None, reads as missing)}.

    Two in three are random text. The rest start from a box that holds together, so the fuzz
    reaches the distro paths, and then damage up to two of its reads.
    """
    if rng.randrange(3):
        return {command: answer(rng) for command in COMMANDS}
    base = rng.choice(BOXES)
    built = {command: (base.get(command), command not in base) for command in COMMANDS}
    for command in rng.sample(COMMANDS, rng.randrange(3)):
        built[command] = answer(rng)
    return built


@pytest.mark.parametrize("seed", range(8))
def test_nothing_a_machine_prints_crashes_the_inspectors_or_slips_past_a_bound(seed):
    rng = random.Random(seed)
    for _ in range(250):
        run, missing = FakeRun(), {}
        for command, (scripted, missing[command]) in reads(rng).items():
            if scripted is not None:
                run.script({command: scripted})
        if rng.randrange(2):
            ev = inspect_local(run=run)
        else:
            ev = inspect_ssh(rng.choice(["web1", "deploy@web1.example.com", "10.0.0.5"]), run=run)
        assert ev.source is Source.HOST
        assert set(ev.signals) <= SIGNAL_KEYS
        for value in list(ev.signals.values()) + [ev.location, ev.note, ev.detected_version or ""]:
            assert value.isascii() and value.isprintable() and len(value) <= 253
        assert ev.detected_version is None or len(ev.detected_version) <= 64
        assert ("distro" in ev.signals) <= ("package_version" in ev.signals)
        assert set(commands(run)) <= READS and len(run.calls) <= 5
        if ev.signals.get("php_present") == "false":
            assert ev.note == "" and ev.detected_version is None and not ev.signals.keys() - {
                "hostname", "ip", "php_present"}
            assert missing["php -v"] and missing["php -i"]
        grade_evidence(ev, MATRIX)


# --- the source ---

def test_the_module_is_standard_library_only_and_has_no_way_to_run_a_shell():
    source = pathlib.Path(host.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source, feature_version=(3, 9))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"os", "php_radar", "socket", "string", "subprocess", "typing"}
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {"getenv", "putenv", "environb", "print", "logging", "system", "popen",
                        "Popen", "call", "check_call", "check_output", "getoutput",
                        "getstatusoutput", "eval", "exec", "compile", "__import__", "shlex",
                        "shutil", "which", "chdir", "getcwd", "execv", "spawnv"}
    used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name) and n.value.id == "subprocess"}
    assert used <= {"run", "DEVNULL", "PIPE", "CompletedProcess", "TimeoutExpired"}
    # os is there to walk PATH: read it, join a path, and look at a file. Nothing else.
    os_used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
               and isinstance(n.value, ast.Name) and n.value.id == "os"}
    assert os_used <= {"environ", "pathsep", "name", "path", "access", "X_OK"}
    path_used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                 and isinstance(n.value, ast.Attribute) and n.value.attr == "path"
                 and isinstance(n.value.value, ast.Name) and n.value.value.id == "os"}
    assert path_used <= {"isabs", "isfile", "join", "basename"}
    # The environment is read in one place, for PATH, and for nothing else.
    environ = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr == "environ"]
    gets = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute) and n.func.attr == "get"
            and isinstance(n.func.value, ast.Attribute) and n.func.value.attr == "environ"]
    assert len(environ) == len(gets) == 1
    assert isinstance(gets[0].args[0], ast.Constant) and gets[0].args[0].value == "PATH"
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "shell":
            assert isinstance(node.value, ast.Constant) and node.value.value is False
    launches = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute) and n.func.attr == "run"]
    assert len(launches) == 1


def test_the_source_is_plain_ascii_with_no_dash_or_curly_quote():
    source = pathlib.Path(host.__file__).read_text(encoding="utf-8")
    assert source.isascii()
    assert not set(source) & set("\u2014\u2013\u2018\u2019\u201c\u201d")
    assert not [c for c in source if ord(c) < 32 and c != "\n"]
