"""How php-radar is launched and shipped: python -m, and the wheel built from this tree."""
import importlib.metadata
import importlib.resources
import json
import shutil
import subprocess
import sys
import types
import zipfile
from email import message_from_string
from pathlib import Path

import pytest

from php_radar.knowledge import DATA_PATH, load_matrix

ROOT = Path(__file__).resolve().parents[1]


def run_module(*args, cwd=ROOT):
    """php-radar as `python -m php_radar`, in a fresh interpreter started in cwd."""
    return subprocess.run([sys.executable, "-m", "php_radar", *args], cwd=str(cwd),
                          capture_output=True, text=True, timeout=60)


# --- python -m php_radar ---

def test_python_dash_m_runs_the_cli():
    done = run_module("--help")
    assert done.returncode == 0
    assert "usage: php-radar" in done.stdout


def test_python_dash_m_exits_with_the_status_main_returns(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM php:8.3.35-fpm\n")  # one release before the fix
    exposed = run_module("repo", str(tmp_path))
    assert exposed.returncode == 1
    assert "EXPOSED (1)" in exposed.stdout
    dockerfile.write_text("FROM php:8.3.36-fpm\n")  # the fixed release
    assert run_module("repo", str(tmp_path)).returncode == 0
    usage = run_module("repo")
    assert usage.returncode == 2
    assert usage.stdout == ""
    assert "name a path or --github-org" in usage.stderr


# --- the matrix is found from the package ---

def test_importlib_resources_finds_the_matrix_where_the_loader_looks():
    found = importlib.resources.files("php_radar") / "data" / "php2shell.json"
    assert found.is_file()
    assert Path(str(found)).resolve() == Path(DATA_PATH).resolve()


# --- the wheel ---

@pytest.fixture(scope="module")
def wheel(tmp_path_factory):
    """The wheel setuptools builds from a copy of this tree, unpacked as an install would be.

    The tree is copied first, so the build leaves no build or egg-info folder in the checkout.
    The build backend is called directly, which needs no network and no wheel package.
    """
    try:
        major = int(importlib.metadata.version("setuptools").split(".")[0])
    except importlib.metadata.PackageNotFoundError:
        major = 0
    if major < 77:
        pytest.skip("building the wheel needs setuptools 77 or later")
    work = tmp_path_factory.mktemp("wheel")
    tree, dist, installed = work / "tree", work / "dist", work / "installed"
    tree.mkdir()
    dist.mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE", "NOTICE"):
        shutil.copy(str(ROOT / name), str(tree / name))
    shutil.copytree(str(ROOT / "php_radar"), str(tree / "php_radar"),
                    ignore=shutil.ignore_patterns("__pycache__"))
    build = ("import sys\nfrom setuptools import build_meta\n"
             "build_meta.build_wheel(sys.argv[1])\n")
    done = subprocess.run([sys.executable, "-c", build, str(dist)], cwd=str(tree),
                          capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-2000:]
    (built,) = dist.glob("*.whl")
    with zipfile.ZipFile(str(built)) as archive:
        archive.extractall(str(installed))
        names = archive.namelist()
    return types.SimpleNamespace(path=built, installed=installed, names=names)


def run_installed(wheel, code):
    """Run code in a fresh interpreter whose php_radar is the unpacked wheel's.

    -I keeps the checkout and the environment's path settings out, and the wheel goes first on
    the path, so a php-radar installed elsewhere cannot answer in its place.
    """
    head = "import json, sys\nsys.path.insert(0, sys.argv[1])\n"
    return subprocess.run([sys.executable, "-I", "-c", head + code, str(wheel.installed)],
                          capture_output=True, text=True, timeout=60)


def dist_info(wheel):
    (found,) = wheel.installed.glob("*.dist-info")
    return found, message_from_string((found / "METADATA").read_text(encoding="utf-8"))


ENTRY_POINT = """
import importlib.metadata as md
dist = next(d for d in md.distributions(path=[sys.argv[1]]) if d.metadata["Name"] == "php-radar")
scripts = {e.name: e.value for e in dist.entry_points if e.group == "console_scripts"}
main = next(e for e in dist.entry_points if e.name == "php-radar").load()
print(json.dumps({"scripts": scripts, "callable": callable(main),
                  "file": sys.modules[main.__module__].__file__}))
sys.exit(main(["--help"]))
"""


def test_entry_point_resolves(wheel):
    done = run_installed(wheel, ENTRY_POINT)
    assert done.stdout, done.stderr  # nothing printed means the entry point did not load
    facts = json.loads(done.stdout.splitlines()[0])
    assert facts["scripts"] == {"php-radar": "php_radar.cli:main"}
    assert facts["callable"]
    # The module the script loads has to be the wheel's own copy of the CLI.
    assert Path(facts["file"]).resolve().is_relative_to(wheel.installed.resolve())
    # And calling it, as the console script does, runs the CLI.
    assert done.returncode == 0
    assert "usage: php-radar" in done.stdout


MATRIX = """
import importlib.resources
from php_radar.knowledge import DATA_PATH, load_matrix
found = importlib.resources.files("php_radar") / "data" / "php2shell.json"
print(json.dumps({"path": DATA_PATH, "resource": str(found), "is_file": found.is_file(),
                  "fixed_8_3": load_matrix(DATA_PATH).fixed_micro("8.3")}))
"""


def test_the_wheel_ships_the_matrix_and_load_matrix_reads_it_from_the_installed_copy(wheel):
    assert "php_radar/data/php2shell.json" in wheel.names
    done = run_installed(wheel, MATRIX)
    assert done.returncode == 0, done.stderr
    facts = json.loads(done.stdout)
    here = wheel.installed.resolve()
    assert Path(facts["path"]).resolve().is_relative_to(here)
    assert Path(facts["resource"]).resolve() == Path(facts["path"]).resolve()
    assert facts["is_file"]
    # It is the same data this tree has, not a stale or an empty file.
    assert facts["fixed_8_3"] == load_matrix(DATA_PATH).fixed_micro("8.3")
    shipped = (wheel.installed / "php_radar" / "data" / "php2shell.json").read_bytes()
    assert shipped == (ROOT / "php_radar" / "data" / "php2shell.json").read_bytes()


def test_python_dash_m_runs_from_the_wheel_too(wheel):
    assert "php_radar/__main__.py" in wheel.names
    done = run_installed(wheel, "import runpy\nsys.argv = ['php-radar', '--help']\n"
                                "runpy.run_module('php_radar', run_name='__main__')\n")
    assert done.returncode == 0, done.stderr
    assert "usage: php-radar" in done.stdout


def test_the_wheel_carries_the_license_and_the_notice(wheel):
    where, meta = dist_info(wheel)
    assert meta["License-Expression"] == "LicenseRef-Apache-2.0-with-Commons-Clause"
    assert sorted(meta.get_all("License-File")) == ["LICENSE", "NOTICE"]
    license_text = (where / "licenses" / "LICENSE").read_text(encoding="utf-8")
    assert license_text.startswith('"Commons Clause" License Condition v1.0')
    assert "Software: php-radar" in license_text
    assert "Apache License" in license_text
    assert "Version 2.0, January 2004" in license_text
    notice = (where / "licenses" / "NOTICE").read_text(encoding="utf-8")
    assert notice.startswith("php-radar")
    assert "Copyright 2026 Abacus\n" in notice
    assert "Commons Clause" in notice


# What each extra installs. Left unpinned, as aws always was: whoever installs an extra gets the
# current release of each SDK.
EXTRAS = {
    "aws": ["boto3"],
    "gcp": ["google-cloud-appengine-admin", "google-cloud-functions",
            "google-cloud-artifact-registry"],
    "azure": ["azure-identity", "azure-mgmt-web", "azure-mgmt-appcontainers",
              "azure-mgmt-containerregistry", "azure-containerregistry",
              "azure-mgmt-resource-subscriptions"],
}


def test_the_wheel_carries_the_release_version_and_the_python_floor(wheel):
    _, meta = dist_info(wheel)
    assert meta["Name"] == "php-radar"
    assert meta["Version"] == "0.2.0"
    # Every extra includes an SDK whose current release needs 3.10, and 3.9 is end of life.
    # azure-mgmt-resource-subscriptions also has no release that installs on 3.9.
    assert meta["Requires-Python"] == ">=3.10"


def test_the_core_needs_nothing_and_each_extra_names_exactly_its_sdk_packages(wheel):
    _, meta = dist_info(wheel)
    assert sorted(meta.get_all("Provides-Extra")) == sorted(EXTRAS)
    requires = [r.replace(" ", "").replace("'", '"') for r in meta.get_all("Requires-Dist") or []]
    wanted = [f'{pkg};extra=="{extra}"' for extra, pkgs in EXTRAS.items() for pkg in pkgs]
    # Equal as lists, so a package beyond these, a version pin, or a requirement that sits outside
    # every extra fails it.
    assert sorted(requires) == sorted(wanted)


# Refuses every cloud SDK by name, so a machine with one installed answers as a machine with none
# does. It then builds the source of each provider, which cannot start without its SDK.
NO_SDK = """
for name in ("boto3", "botocore", "google", "azure"):
    sys.modules[name] = None
import php_radar.sources.cloud.azure, php_radar.sources.cloud.gcp
from php_radar.sources.cloud import get_cloud_source
said = {}
for provider in ("aws", "gcp", "azure"):
    try:
        get_cloud_source(provider)
    except RuntimeError as exc:
        said[provider] = str(exc)
print(json.dumps({"file": php_radar.sources.cloud.gcp.__file__, "said": said}))
"""


def test_the_wheel_imports_the_cloud_modules_with_no_sdk_installed(wheel):
    for module in ("_common", "aws", "azure", "gcp"):
        assert f"php_radar/sources/cloud/{module}.py" in wheel.names
    done = run_installed(wheel, NO_SDK)
    assert done.returncode == 0, done.stderr
    facts = json.loads(done.stdout)
    # The wheel's own copy answered, so the import did not come from the checkout.
    assert Path(facts["file"]).resolve().is_relative_to(wheel.installed.resolve())


def test_a_provider_without_its_sdk_says_to_install_an_extra_the_wheel_declares(wheel):
    done = run_installed(wheel, NO_SDK)
    assert done.returncode == 0, done.stderr
    said = json.loads(done.stdout)["said"]
    # Each refused with a RuntimeError. An ImportError would have ended the run above.
    assert sorted(said) == ["aws", "azure", "gcp"]
    # The hint quotes the extra, because zsh reads the brackets as a glob and refuses the command.
    named = {provider: message.partition('pip install "php-radar[')[2].partition(']"')[0]
             for provider, message in said.items()}
    assert named == {"aws": "aws", "gcp": "gcp", "azure": "azure"}
    # A hint is only true when the wheel has the extra it names.
    _, meta = dist_info(wheel)
    assert set(named.values()) <= set(meta.get_all("Provides-Extra"))
