import ast
import codecs
import hashlib
import json
import os
import pathlib
import random
import subprocess
import sys
import threading
import time

import pytest

from php_radar.knowledge import DATA_PATH, grade, load_matrix
from php_radar.model import Asset, AssetInventory, Confidence, Sapi, Source, Verdict
from php_radar.report import redact, render_console, render_json, render_sarif
from php_radar.sources import repo as repo_module
from php_radar.sources.repo import (
    parse_ci_setup_php,
    parse_compose,
    parse_composer,
    parse_devcontainer,
    parse_dockerfile,
    parse_dotfiles,
    scan_path,
    tag_confidence,
)

HIGH, MEDIUM, LOW = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW
EXPOSED, INDETERMINATE, LIKELY_PATCHED = (
    Verdict.EXPOSED, Verdict.INDETERMINATE, Verdict.LIKELY_PATCHED)

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "repo")
DIGEST = "sha256:" + "ab" * 32


def test_exact_image_tag_high_confidence():
    evs = scan_path(FIXTURE)
    assert any(e.detected_version == "8.3.35" and e.signals["confidence"] == "HIGH" for e in evs)


def test_floating_tag_low_confidence():
    # A floating tag names a branch, so it cannot say which patch release runs.
    assert tag_confidence("8.3-apache") == Confidence.LOW
    assert tag_confidence("8.3.35-fpm") == Confidence.HIGH


def test_composer_constraint_is_a_floor_not_a_build():
    evs = scan_path(FIXTURE)
    assert any(e.signals.get("kind") == "composer-constraint" for e in evs)


# --- helpers ---

@pytest.fixture
def site(tmp_path):
    # tmp_path is named after the test and holds the checkout, so the checkout gets a plain name.
    root = tmp_path / "site"
    root.mkdir()
    return root


@pytest.fixture(scope="module")
def matrix():
    return load_matrix(DATA_PATH)


def put(root, rel, text="", raw=None):
    path = root.joinpath(*rel.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8") if raw is None else raw)
    return path


def scan(root):
    return scan_path(str(root))


def repo_id(path):
    # What the repo signal of a scan of path has to be, worked out here and not by the module.
    real = os.path.realpath(str(path))
    return os.path.basename(real) + "~" + hashlib.sha256(os.fsencode(real)).hexdigest()[:8]


def verdict_of(evs, matrix):
    return grade(Asset("site", "repo", list(evs)), matrix)


def skipped(evs):
    return [e for e in evs if e.signals["kind"] == "skipped"]


# --- tag_confidence ---

@pytest.mark.parametrize("tag, want", [
    # A full release is as exact as a tag gets, with or without a known variant.
    ("8.3.35", HIGH),
    ("8.3.35-fpm", HIGH),
    ("8.3.35-cli", HIGH),
    ("8.3.35-zts", HIGH),
    ("8.3.35-apache-bookworm", HIGH),
    ("8.3.35-fpm-alpine3.20", HIGH),
    ("8.3.35-cli-windowsservercore-ltsc2022", HIGH),
    ("8.3.35-nanoserver", HIGH),
    ("7.0.33-cli-jessie", HIGH),
    ("7.2.34-stretch", HIGH),
    ("7.4.33-buster", HIGH),
    ("8.1.2-bullseye", HIGH),
    ("8.4.1-fpm-trixie", HIGH),
    ("  8.3.35-fpm  ", HIGH),
    # A digest fixes the image whatever the tag says.
    ("8.3.35@" + DIGEST, HIGH),
    ("8.3-fpm@" + DIGEST, HIGH),
    ("@" + DIGEST, HIGH),
    (DIGEST, HIGH),
    ("8.3@sha512:" + "cd" * 64, HIGH),
    # A full release with a suffix the official image does not use may be some other image.
    ("8.3.35-myfork", MEDIUM),
    ("8.3.35-fpm-custom", MEDIUM),
    ("8.5.0RC1", MEDIUM),
    ("8.3.35_build7", MEDIUM),
    # No patch release, or none that can be read.
    ("8.3", LOW),
    ("8.3-apache", LOW),
    ("8", LOW),
    ("8-fpm", LOW),
    ("latest", LOW),
    ("fpm", LOW),
    ("apache-bookworm", LOW),
    ("", LOW),
    ("   ", LOW),
    ("${PHP_VERSION}-fpm", LOW),
    ("8.3.${MICRO}", LOW),
    ("${TAG}", LOW),
    ("8.3.35.1", LOW),
    # Text after an @ that is not a digest earns nothing.
    ("8.3@sha1:" + "ab" * 20, LOW),
    ("8.3@sha256:" + "ab" * 31, LOW),
    ("8.3@sha256:" + "AB" * 32, LOW),
    ("8.3@sha256:" + "zz" * 32, LOW),
    ("latest@sha256:", LOW),
])
def test_tag_confidence(tag, want):
    assert tag_confidence(tag) == want


# --- Dockerfile ---

@pytest.mark.parametrize("text, want", [
    ("FROM php:8.3.35-fpm\n", [("8.3.35-fpm", HIGH)]),
    ("from php:8.3.35-fpm as app\n", [("8.3.35-fpm", HIGH)]),
    ("  FROM php:8.3.35  \n", [("8.3.35", HIGH)]),
    ("FROM php:8.3.35-weird\n", [("8.3.35-weird", MEDIUM)]),
    ("FROM php:8.3-apache\n", [("8.3-apache", LOW)]),
    ("FROM php:8\n", [("8", LOW)]),
    ("FROM php:latest\n", [("latest", LOW)]),
    ("FROM php\n", [("latest", LOW)]),
    ("FROM php:${PHP_VERSION}-fpm\n", [("${PHP_VERSION}-fpm", LOW)]),
    ("FROM php:8.3.35-fpm@" + DIGEST + "\n", [("8.3.35-fpm@" + DIGEST, HIGH)]),
    ("FROM php@" + DIGEST + "\n", [("@" + DIGEST, HIGH)]),
    ("FROM --platform=linux/amd64 php:8.3.35 AS base\n", [("8.3.35", HIGH)]),
    ("FROM --platform=$BUILDPLATFORM php:8.3.35\n", [("8.3.35", HIGH)]),
    # The official image under its other spellings.
    ("FROM library/php:8.3.35\n", [("8.3.35", HIGH)]),
    ("FROM docker.io/php:8.3.35\n", [("8.3.35", HIGH)]),
    ("FROM docker.io/library/php:8.3.35-cli\n", [("8.3.35-cli", HIGH)]),
    ("FROM public.ecr.aws/docker/library/php:8.3.35\n", [("8.3.35", HIGH)]),
    ("FROM localhost:5000/php:8.3.35\n", [("8.3.35", HIGH)]),
    ("FROM localhost/php:8.3.35\n", [("8.3.35", HIGH)]),
    ("FROM mcr.microsoft.com/devcontainers/php:1-8.3-bookworm\n", [("1-8.3-bookworm", LOW)]),
    # A line can continue, and a comment can sit inside the continuation.
    ("FROM \\\n  php:8.3.35-fpm\n", [("8.3.35-fpm", HIGH)]),
    ("FROM php:8.3.35 \\\n# note\n AS app\n", [("8.3.35", HIGH)]),
    # A comment line is dropped whole, even when it ends in a backslash like a Windows path.
    ("# copy to C:\\dir\\\nFROM php:8.3.35\n", [("8.3.35", HIGH)]),
    ("FROM php:8.3.35-fpm\r\nRUN true\r\n", [("8.3.35-fpm", HIGH)]),
    # One pin per distinct tag, in file order.
    ("FROM composer:2 AS vendor\nFROM php:8.3.35-fpm\n", [("8.3.35-fpm", HIGH)]),
    ("FROM php:8.3.35-fpm AS a\nFROM php:8.2.28-cli AS b\n",
     [("8.3.35-fpm", HIGH), ("8.2.28-cli", HIGH)]),
    ("FROM php:8.3.35-fpm AS a\nFROM php:8.3.35-fpm AS b\n", [("8.3.35-fpm", HIGH)]),
    # Other images, other registries' own php images, and things that only look like FROM.
    ("FROM mysql:8\n", []),
    ("FROM composer:2 AS vendor\n", []),
    ("FROM myorg/php:8.3.35\n", []),
    ("FROM registry.example.com/team/php:8.3.35\n", []),
    ("FROM base AS build\n", []),
    ("FROM $BASE\n", []),
    ("FROM ${IMAGE}:8.3\n", []),
    ("FROM scratch\n", []),
    ("# FROM php:7.4\n", []),
    ("RUN echo FROM php:7.4\n", []),
    ("ARG FROM=php:7.4\n", []),
    ("FROM\n", []),
    ("FROM --platform=linux/amd64\n", []),
    ("", []),
    ("\n\n", []),
])
def test_parse_dockerfile(text, want):
    assert parse_dockerfile(text) == want


# --- compose ---

@pytest.mark.parametrize("text, want", [
    ("services:\n  web:\n    image: php:8.3-apache\n", [("8.3-apache", LOW)]),
    ("    image: \"php:8.3.35-fpm\"\n", [("8.3.35-fpm", HIGH)]),
    ("    \"image\": php:8.3.35-fpm\n", [("8.3.35-fpm", HIGH)]),
    ("    'image': 'php:8.3.35-fpm'\n", [("8.3.35-fpm", HIGH)]),
    ("    image: 'php:8.3.35-fpm' # pinned\n", [("8.3.35-fpm", HIGH)]),
    ("    image: php:8.3.35-fpm   # pinned\n", [("8.3.35-fpm", HIGH)]),
    ("  - image: php:8.3.35\n", [("8.3.35", HIGH)]),
    ("    image: php\n", [("latest", LOW)]),
    ("    image: php:${PHP_VERSION:-8.3}-fpm\n", [("${PHP_VERSION:-8.3}-fpm", LOW)]),
    ("    image: docker.io/library/php:8.3.35\r\n", [("8.3.35", HIGH)]),
    ("a:\n  image: php:8.3.35-fpm\nb:\n  image: php:8.2-cli\n",
     [("8.3.35-fpm", HIGH), ("8.2-cli", LOW)]),
    ("a:\n  image: php:8.3.35-fpm\nb:\n  image: php:8.3.35-fpm\n", [("8.3.35-fpm", HIGH)]),
    ("    image: mysql:8.4\n", []),
    ("    image: myorg/php:8.3\n", []),
    ("    image: ${PHP_IMAGE}\n", []),
    ("    image: ${PHP_IMAGE:-php:8.2-fpm}\n", []),
    ("    # image: php:7.4\n", []),
    ("    build: .\n", []),
    ("    image:php:8.3\n", []),
    ("    image:\n", []),
    ("    container_image: php:7.4\n", []),
    ("", []),
])
def test_parse_compose(text, want):
    assert parse_compose(text) == want


# --- GitHub Actions ---

def workflow(*with_lines):
    # One setup-php step, with the given lines under its with: key.
    body = "".join("          " + line + "\n" for line in with_lines)
    return ("jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n"
            "      - uses: shivammathur/setup-php@v2\n        with:\n" + body)


@pytest.mark.parametrize("text, want", [
    (workflow("php-version: '8.3'"), [("8.3", LOW)]),
    (workflow('php-version: "8.3.12"'), [("8.3.12", MEDIUM)]),
    (workflow("php-version: 8.2"), [("8.2", LOW)]),
    (workflow("php-version: latest # newest"), [("latest", LOW)]),
    (workflow("extensions: mbstring", "php-version: '8.3.12'", "tools: composer"),
     [("8.3.12", MEDIUM)]),
    (workflow("# the runtime", "", "php-version: '8.3'"), [("8.3", LOW)]),
    (workflow("php-version: ${{ matrix.php }}"), [("${{ matrix.php }}", LOW)]),
    (workflow("php-version: '8.3'").replace("\n", "\r\n"), [("8.3", LOW)]),
    # The action name is matched without regard to case, and a pinned SHA still counts.
    (workflow("php-version: '8.3'").replace("shivammathur/setup-php@v2",
                                            "Shivammathur/Setup-PHP@abc123def # v2"),
     [("8.3", LOW)]),
    # uses need not be the first key of the step.
    ("steps:\n  - name: PHP\n    uses: shivammathur/setup-php@v2\n    with:\n"
     "      php-version: '8.1'\n", [("8.1", LOW)]),
    # Two steps, one value twice.
    (workflow("php-version: '8.3'") + workflow("php-version: '8.2'"),
     [("8.3", LOW), ("8.2", LOW)]),
    (workflow("php-version: '8.3'") + workflow("php-version: '8.3'"), [("8.3", LOW)]),
    # No version here: it comes from a file the scan reads on its own, or from nowhere.
    # A blank line or a comment at column zero inside the with: block does not end the step.
    (workflow("extensions: mbstring") + "\n          php-version: '8.3'\n", [("8.3", LOW)]),
    (workflow("extensions: mbstring") + "# a note\n          php-version: '8.3'\n",
     [("8.3", LOW)]),
    (workflow("php-version-file: .php-version"), []),
    (workflow("php-version:"), []),
    (workflow("extensions: mbstring"), []),
    ("steps:\n  - uses: shivammathur/setup-php@v2\n", []),
    # A php-version that belongs to another action or the next step is not setup-php's.
    ("steps:\n  - uses: other/setup@v1\n    with:\n      php-version: '7.4'\n", []),
    ("steps:\n  - uses: shivammathur/setup-php@v2\n    with:\n      extensions: x\n"
     "  - uses: other/setup@v1\n    with:\n      php-version: '7.4'\n", []),
    ("steps:\n  - uses: shivammathur/setup-php@v2\n  - run: echo php-version: 7.4\n", []),
    ("steps:\n  - uses: shivammathur/setup-php@v2\n  - name: other\n    with:\n"
     "      php-version: '7.4'\n", []),
    # php-version is an input, so it has to sit under with: and not beside uses:.
    ("steps:\n  - uses: shivammathur/setup-php@v2\n    php-version: '8.3'\n", []),
    ("steps:\n  - uses: shivammathur/setup-php@v2\n    with:\n      extensions: x\n"
     "  - name: step\n    php-version: '7.4'\n", []),
    ("steps:\n  - uses: ./.github/actions/setup-php\n    with:\n      php-version: '7.4'\n", []),
    ("# uses: shivammathur/setup-php@v2\n    with:\n      php-version: '7.4'\n", []),
    ("", []),
])
def test_parse_ci_setup_php(text, want):
    assert parse_ci_setup_php(text) == want


# --- .php-version and .tool-versions ---

@pytest.mark.parametrize("name, text, want", [
    (".php-version", "8.3.35\n", [("8.3.35", MEDIUM)]),
    (".php-version", "8.3.35", [("8.3.35", MEDIUM)]),
    (".php-version", "8.3.35 \r\n", [("8.3.35", MEDIUM)]),
    (".php-version", "\n\n  8.3.35\n", [("8.3.35", MEDIUM)]),
    (".php-version", "# the runtime\n8.3.35\n", [("8.3.35", MEDIUM)]),
    (".php-version", "8.3.35 # prod\n", [("8.3.35", MEDIUM)]),
    (".php-version", "8.3.35\n7.4.33\n", [("8.3.35", MEDIUM)]),
    (".php-version", "8.3\n", [("8.3", LOW)]),
    (".php-version", "system\n", [("system", LOW)]),
    (".php-version", "", []),
    (".php-version", "\n \n", []),
    (".php-version", "# nothing\n", []),
    (".tool-versions", "nodejs 20.1.0\nphp 8.3.35\n", [("8.3.35", MEDIUM)]),
    (".tool-versions", "php 8.3.35\r\nnodejs 20\r\n", [("8.3.35", MEDIUM)]),
    (".tool-versions", "php   8.3 # dev\n", [("8.3", LOW)]),
    (".tool-versions", "php 8.3.35 8.2.28\n", [("8.3.35", MEDIUM), ("8.2.28", MEDIUM)]),
    (".tool-versions", "php ref:master\n", [("ref:master", LOW)]),
    (".tool-versions", "php ref:v1#2 # note\n", [("ref:v1#2", LOW)]),
    (".tool-versions", "php\n", []),
    (".tool-versions", "phpunit 10.5.1\n", []),
    (".tool-versions", "# php 7.4.33\nnodejs 18\n", []),
    (".tool-versions", "nodejs 18\n", []),
    (".tool-versions", "", []),
    ("Gemfile", "php 8.3.35\n", []),
])
def test_parse_dotfiles(name, text, want):
    assert parse_dotfiles(name, text) == want


# --- composer.json ---

@pytest.mark.parametrize("text, want", [
    ('{"require": {"php": ">=8.2"}}', [(">=8.2", LOW)]),
    ('{"require": {"php": "^8.1 || ^8.2"}}', [("^8.1 || ^8.2", LOW)]),
    ('{"require": {"php": " 8.2.12 "}}', [("8.2.12", LOW)]),
    ('{"require": {"php": ">=8.2"}, "config": {"platform": {"php": "8.2.12"}}}',
     [(">=8.2", LOW), ("8.2.12", LOW)]),
    ('{"config": {"platform": {"php": "8.2.12"}}}', [("8.2.12", LOW)]),
    ('{"require": {"php": "8.2.12"}, "config": {"platform": {"php": "8.2.12"}}}',
     [("8.2.12", LOW)]),
    ('{"require": {"ext-mbstring": "*"}}', []),
    ('{"require": {"php": ""}}', []),
    ('{"require": {"php": 8}}', []),
    ('{"require": {"php": 8.3}}', []),
    ('{"require": {"php": null}}', []),
    # A number of any size is skipped over and does not cost the file its pins.
    ('{"n": ' + "9" * 5000 + ', "require": {"php": ">=8.2"}}', [(">=8.2", LOW)]),
    ('{"n": 1e999, "require": {"php": ">=8.2"}}', [(">=8.2", LOW)]),
    ('{"require": {"php": ["8.2"]}}', []),
    ('{"require": []}', []),
    ('{"require": "php"}', []),
    ('{"config": {"platform": {"php": false}}}', []),
    ('{"config": {"platform": []}}', []),
    ('{"config": 5}', []),
    ('{}', []),
    ('[]', []),
    ('"php"', []),
    ('null', []),
    ('7', []),
])
def test_parse_composer(text, want):
    assert parse_composer(text) == want


@pytest.mark.parametrize("text", ["", "{", "not json", '{"require": {"php": ">=8.2",}}',
                                  '{"require": {"php": ">=8.2"}} {}', "// c\n{}"])
def test_parse_composer_refuses_what_is_not_json(text):
    # The scan turns this into a recorded skip. Composer itself reads strict JSON.
    with pytest.raises(ValueError):
        parse_composer(text)


# --- devcontainer.json ---

@pytest.mark.parametrize("text, want", [
    ('{"image": "mcr.microsoft.com/devcontainers/php:1-8.3-bookworm"}',
     [("1-8.3-bookworm", LOW)]),
    ('{"image": "php:8.3"}', [("8.3", LOW)]),
    # A dev container is not what ships, so even an exact tag stops at MEDIUM.
    ('{"image": "php:8.3.35-cli"}', [("8.3.35-cli", MEDIUM)]),
    ('{"image": "php:8.3.35-cli@' + DIGEST + '"}', [("8.3.35-cli@" + DIGEST, MEDIUM)]),
    ('{"features": {"ghcr.io/devcontainers/features/php:1": {"version": "8.3.12"}}}',
     [("8.3.12", MEDIUM)]),
    ('{"features": {"ghcr.io/devcontainers/features/php:1": {"version": "8.3"}}}',
     [("8.3", LOW)]),
    ('{"features": {"ghcr.io/devcontainers/features/php:1": {}}}', [("latest", LOW)]),
    ('{"features": {"ghcr.io/devcontainers/features/php:1": {"version": " "}}}',
     [("latest", LOW)]),
    ('{"features": {"ghcr.io/devcontainers/features/php:1": {"version": " 8.3.12 "}}}',
     [("8.3.12", MEDIUM)]),
    ('{"features": {"ghcr.io/devcontainers/features/php:1": true}}', [("latest", LOW)]),
    ('{"features": {"ghcr.io/devcontainers/features/php:1": "8.2"}}', [("8.2", LOW)]),
    ('{"features": {"localhost:5000/features/php:1": {"version": "8.3.12"}}}',
     [("8.3.12", MEDIUM)]),
    ('{"image": "php:8.3.35", "features": {"x/php:1": {"version": "8.3.12"}}}',
     [("8.3.35", MEDIUM), ("8.3.12", MEDIUM)]),
    ('{"image": "node:20", "features": {"ghcr.io/devcontainers/features/node:1": {}}}', []),
    ('{"features": {"ghcr.io/devcontainers/features/phpunit:1": {"version": "10"}}}', []),
    ('{"image": 5, "features": []}', []),
    ('{"image": ["php:8.3"]}', []),
    ('{"features": {"x/php:1": {"version": 8.3}}}', [("latest", LOW)]),
    ('{"n": ' + "9" * 5000 + ', "image": "php:8.3.35"}', [("8.3.35", MEDIUM)]),
    ('{}', []),
    ('[]', []),
    # VS Code allows comments and trailing commas in this file.
    ('{\n  // the runtime\n  "image": "php:8.3.35-cli", /* pinned */\n}\n',
     [("8.3.35-cli", MEDIUM)]),
    ('{"features": {"x/php:1": {"version": "8.3.12",},},}', [("8.3.12", MEDIUM)]),
    ('{"features": {"x/php:1": {"version": "8.3.12"}, // note\n  },\n}', [("8.3.12", MEDIUM)]),
    ('[1, 2,\n/* gone */\n]', []),
    # Comment markers and brackets inside a string are text.
    ('{"name": "http://x.test // not a comment /* nor this */", "image": "php:8.3.35"}',
     [("8.3.35", MEDIUM)]),
    ('{"name": "a \\" // still the string", "image": "php:8.3.35"}', [("8.3.35", MEDIUM)]),
    ('{"name": "ends with ,]", "image": "php:8.3.35"}', [("8.3.35", MEDIUM)]),
    ('{"image": "php:8.3.35"} /* never closed', [("8.3.35", MEDIUM)]),
])
def test_parse_devcontainer(text, want):
    assert parse_devcontainer(text) == want


@pytest.mark.parametrize("text", ["", "{", '{"image": }', "nope", '{"image": "php:8.3"} []'])
def test_parse_devcontainer_refuses_what_is_not_json(text):
    with pytest.raises(ValueError):
        parse_devcontainer(text)


# --- what scan_path emits for the fixture ---

EXPECTED = [
    # location, declared, kind, detected_version, confidence, sapi
    (".php-version", "8.3.35", "php-version-file", "8.3.35", "MEDIUM", Sapi.UNKNOWN),
    ("Dockerfile", "8.3.35-fpm", "dockerfile", "8.3.35", "HIGH", Sapi.FPM),
    ("composer.json", ">=8.2", "composer-constraint", None, "LOW", Sapi.UNKNOWN),
    ("composer.json", "8.2.12", "composer-constraint", None, "LOW", Sapi.UNKNOWN),
    ("docker-compose.yml", "8.3-apache", "compose", None, "LOW", Sapi.MOD_PHP),
    (".github/workflows/ci.yml", "8.2", "ci-setup-php", None, "LOW", Sapi.UNKNOWN),
]


def test_the_fixture_gives_one_evidence_per_pin_and_nothing_else():
    got = [(e.location, e.signals["declared"]) for e in scan_path(FIXTURE)]
    assert sorted(got) == sorted((loc, declared) for loc, declared, *_ in EXPECTED)


@pytest.mark.parametrize("location, declared, kind, version, confidence, sapi", EXPECTED)
def test_each_fixture_evidence(location, declared, kind, version, confidence, sapi):
    (ev,) = [e for e in scan_path(FIXTURE)
             if (e.location, e.signals["declared"]) == (location, declared)]
    assert ev.source is Source.REPO
    assert ev.signals["kind"] == kind
    assert ev.detected_version == version
    assert ev.signals["confidence"] == confidence
    assert ev.sapi is sapi


@pytest.mark.parametrize("tag, want", [
    ("8.3.35-fpm", Sapi.FPM),
    ("8.3.35-fpm-alpine3.20", Sapi.FPM),
    ("fpm", Sapi.FPM),
    ("${PHP_VERSION}-fpm", Sapi.FPM),
    ("8.3.35-fpm@" + DIGEST, Sapi.FPM),
    ("8.3-apache", Sapi.MOD_PHP),
    ("apache-bookworm", Sapi.MOD_PHP),
    ("8.3.35-cli", Sapi.CLI),
    ("8.3.35-zts", Sapi.CLI),
    ("zts-alpine3.20", Sapi.CLI),
    # A tag that does not say gets no guess, and a word only counts whole.
    ("8.3.35", Sapi.UNKNOWN),
    ("8.3.35-alpine", Sapi.UNKNOWN),
    ("latest", Sapi.UNKNOWN),
    ("8.3.35-fpmx", Sapi.UNKNOWN),
    ("8.3.35-myfpm", Sapi.UNKNOWN),
])
def test_the_variant_in_an_image_tag_names_the_sapi(site, tag, want):
    put(site, "Dockerfile", f"FROM php:{tag}\n")
    (ev,) = scan(site)
    assert ev.sapi is want


def test_a_pin_that_is_not_an_image_tag_names_no_sapi(site):
    put(site, "composer.json", '{"require": {"php": ">=8.2"}}')
    put(site, ".php-version", "8.3.35\n")
    assert {e.sapi for e in scan(site)} == {Sapi.UNKNOWN}


def test_every_signal_value_is_a_string():
    for ev in scan_path(FIXTURE):
        assert all(isinstance(k, str) and isinstance(v, str) for k, v in ev.signals.items())


def test_every_find_carries_the_repo_signal_the_kind_and_the_confidence():
    evs = scan_path(FIXTURE)
    assert evs
    for ev in evs:
        assert ev.source is Source.REPO
        assert ev.signals["repo"] == repo_id(FIXTURE)
        assert ev.signals["kind"]
        assert ev.signals["confidence"] in Confidence.__members__


def test_the_fixture_scan_is_the_same_every_time_and_in_a_fixed_order():
    first = scan_path(FIXTURE)
    assert scan_path(FIXTURE) == first
    assert [e.location for e in first] == [
        ".php-version", "Dockerfile", "composer.json", "composer.json", "docker-compose.yml",
        ".github/workflows/ci.yml"]


def test_a_pin_with_no_patch_release_says_so_and_a_pin_with_one_does_not():
    by_declared = {e.signals["declared"]: e for e in scan_path(FIXTURE)}
    assert "8.3-apache" in by_declared["8.3-apache"].note
    assert by_declared["8.3-apache"].signals["php_present"] == "true"
    assert by_declared["8.3.35-fpm"].note == ""
    assert "php_present" not in by_declared["8.3.35-fpm"].signals


def test_a_composer_find_is_a_requirement_with_no_version_to_mistake_for_a_build():
    floors = [e for e in scan_path(FIXTURE) if e.location == "composer.json"]
    assert len(floors) == 2
    for ev in floors:
        assert ev.detected_version is None
        assert ev.signals["kind"] == "composer-constraint"
        assert "requirement" in ev.note


# --- identity and location ---

def test_locations_are_relative_to_the_scanned_root_and_use_forward_slashes(site):
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    put(site, "services/api/Dockerfile", "FROM php:8.3.35\n")
    put(site, "services/api/docker/compose.yaml", "image: php:8.3\n")
    put(site, ".github/workflows/ci.yaml", workflow("php-version: '8.3'"))
    put(site, ".devcontainer/devcontainer.json", '{"image": "php:8.3"}')
    locations = sorted(e.location for e in scan(site))
    assert locations == sorted([
        "Dockerfile", "services/api/Dockerfile", "services/api/docker/compose.yaml",
        ".github/workflows/ci.yaml", ".devcontainer/devcontainer.json"])
    for location in locations:
        assert not os.path.isabs(location)
        assert "\\" not in location
        assert not location.startswith("..")


# The digests are sha256 of the path as UTF-8, first eight hex characters, worked out apart from
# the module so this pins the format and not just the module's own idea of it.
@pytest.mark.parametrize("top, want", [
    ("/srv/www/site", "site~077dac42"),
    ("/a/app", "app~8463b373"),
    ("/b/app", "app~b6bec32a"),
    # A filesystem root has no name, so its path stands in.
    ("/", "/~8a5edab2"),
    ("C:\\", "C:\\~28f709d7"),
])
def test_the_repo_id_is_the_directory_name_and_eight_hex_characters_of_a_hash_of_its_path(
        top, want):
    assert repo_module._repo_name(top) == want


def test_the_repo_signal_is_the_directory_name_and_a_short_hash_of_its_resolved_path(site):
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    (got,) = {e.signals["repo"] for e in scan(site)}
    name, tilde, digest = got.rpartition("~")
    assert (name, tilde) == ("site", "~")
    assert len(digest) == 8 and set(digest) <= set("0123456789abcdef")
    assert got == repo_id(site)
    # The path itself stays out. Only its hash is in the signal.
    assert str(site.parent) not in got


# The reporters mask the value in name:value when the name holds a word like these, and a joiner
# that triggered it would show a repo called auth-api as auth-api:[REDACTED].
SECRET_NAMES = [
    "auth-api", "token-service", "key-manager", "password-vault", "secret-santa", "pwd-tools",
    "api_key_rotator", "oauth-proxy", "DB_PASS", "dbPassword", "bearer-svc", "credential-store",
    "passwd", "AUTH", "Token", "secrets", "apikey", "access-token-service", "auth", "key", "pw",
]


@pytest.mark.parametrize("name", SECRET_NAMES)
def test_the_repo_id_survives_the_reporters_redaction_whatever_the_directory_is_called(name):
    repo = repo_module._repo_name("/srv/www/" + name)
    assert repo.startswith(name + "~")
    assert redact(repo) == repo


def test_a_repo_with_a_secret_word_in_its_name_reads_the_same_in_every_report(tmp_path, matrix):
    root = tmp_path / "token-service"
    put(root, "Dockerfile", "FROM php:8.3.35-fpm\n")
    inventory = AssetInventory()
    for ev in scan(root):
        inventory.add(ev)
    assets = inventory.assets()
    want = repo_id(root)
    assert want.startswith("token-service~")
    for text in (render_console(assets, matrix), render_json(assets, matrix),
                 render_sarif(assets, matrix)):
        assert want in text
        assert "REDACTED" not in text


def test_the_same_checkout_reached_by_any_spelling_has_one_repo_id(site, monkeypatch):
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    spelled = [str(site), str(site) + os.sep, str(site / "." / ".." / "site")]
    monkeypatch.chdir(site)
    spelled.append(".")
    assert {e.signals["repo"] for path in spelled for e in scan_path(path)} == {repo_id(site)}


def test_same_file_in_two_repositories_stays_two_assets(tmp_path):
    for name in ("alpha", "beta"):
        root = tmp_path / name
        root.mkdir()
        put(root, "Dockerfile", "FROM php:8.3.35-fpm\n")
    inventory = AssetInventory()
    for name in ("alpha", "beta"):
        for ev in scan(tmp_path / name):
            inventory.add(ev)
    assets = inventory.assets()
    assert sorted(a.key for a in assets) == sorted(
        [repo_id(tmp_path / "alpha"), repo_id(tmp_path / "beta")])
    assert all(a.kind == "repo" and len(a.evidence) == 1 for a in assets)


def test_two_checkouts_that_share_a_directory_name_stay_two_assets(tmp_path):
    # /a/app and /b/app hold the same Dockerfile, and nothing but the full path tells them apart.
    for parent in ("a", "b"):
        put(tmp_path / parent / "app", "Dockerfile", "FROM php:8.3.35-fpm\n")
    inventory = AssetInventory()
    for parent in ("a", "b"):
        for ev in scan(tmp_path / parent / "app"):
            inventory.add(ev)
    first, second = inventory.assets()
    assert first.key != second.key
    assert first.key.startswith("app~") and second.key.startswith("app~")
    assert [len(first.evidence), len(second.evidence)] == [1, 1]


def test_scanning_a_checkout_twice_is_one_asset(site):
    put(site, "Dockerfile", "FROM php:8.3.35-fpm\n")
    inventory = AssetInventory()
    for ev in scan(site) + scan(site):
        inventory.add(ev)
    (asset,) = inventory.assets()
    assert len(asset.evidence) == 2


def test_one_repository_is_one_asset():
    inventory = AssetInventory()
    for ev in scan_path(FIXTURE):
        inventory.add(ev)
    (asset,) = inventory.assets()
    assert (asset.key, asset.kind, len(asset.evidence)) == (repo_id(FIXTURE), "repo", 6)


def test_no_absolute_path_reaches_any_field(site, tmp_path, monkeypatch):
    # Evidence ends up in JSON that gets shared, and a home directory name does not belong in it.
    put(site, "Dockerfile", "FROM php:8.3-apache\n")
    put(site, "composer.json", '{"require": {"php": ">=8.2"}}')
    put(site, "docker-compose.yml", "image: php:8.3.35\n")
    put(site, "bad/composer.json", "{")
    put(site, ".php-version", "8.3.35")
    put(site, "other/Dockerfile", "FROM php:8.2.28\n")
    real_open = open

    def flaky(path, mode="r"):
        if path.endswith(os.path.join("other", "Dockerfile")):
            raise PermissionError(13, "Permission denied", path)
        return real_open(path, mode)

    monkeypatch.setattr(repo_module, "open", flaky, raising=False)
    evs = scan(site)
    assert len(evs) == 6
    assert any("Permission denied" in e.note for e in evs)
    assert any(e.note.startswith("skipped: cannot parse it") for e in evs)
    for ev in evs:
        assert str(tmp_path) not in repr(ev)
        assert str(site) not in repr(ev)


@pytest.mark.parametrize("make", [
    lambda root: root / "missing",
    lambda root: put(root, "Dockerfile", "FROM php:8.3\n"),
])
def test_a_root_that_is_not_a_directory_is_an_error_and_not_an_empty_scan(site, make):
    # An empty list would read as a clean repository.
    with pytest.raises(OSError):
        scan_path(str(make(site)))


def test_a_checkout_with_no_php_pins_gives_nothing(site):
    put(site, "README.md", "FROM php:7.4\n")
    put(site, "package.json", '{"engines": {"php": "7.4"}}')
    put(site, "Dockerfile", "FROM node:20\n")
    assert scan(site) == []


# --- which files are read ---

@pytest.mark.parametrize("name, text", [
    ("Dockerfile", "FROM php:8.3.35\n"),
    ("dockerfile", "FROM php:8.3.35\n"),
    ("Dockerfile.dev", "FROM php:8.3.35\n"),
    ("Dockerfile-prod", "FROM php:8.3.35\n"),
    ("Dockerfile_ci", "FROM php:8.3.35\n"),
    ("php.Dockerfile", "FROM php:8.3.35\n"),
    ("Containerfile", "FROM php:8.3.35\n"),
    ("docker/php/Dockerfile", "FROM php:8.3.35\n"),
    ("docker-compose.yml", "image: php:8.3.35\n"),
    ("docker-compose.yaml", "image: php:8.3.35\n"),
    ("docker-compose.override.yml", "image: php:8.3.35\n"),
    ("docker-compose-dev.yml", "image: php:8.3.35\n"),
    ("compose.yaml", "image: php:8.3.35\n"),
    ("compose.prod.yml", "image: php:8.3.35\n"),
    (".github/workflows/ci.yml", workflow("php-version: '8.3.35'")),
    (".github/workflows/deploy.yaml", workflow("php-version: '8.3.35'")),
    ("sub/.github/workflows/ci.yml", workflow("php-version: '8.3.35'")),
    (".php-version", "8.3.35\n"),
    (".tool-versions", "php 8.3.35\n"),
    ("composer.json", '{"require": {"php": "8.3.35"}}'),
    ("packages/api/composer.json", '{"require": {"php": "8.3.35"}}'),
    ("devcontainer.json", '{"image": "php:8.3.35"}'),
    (".devcontainer.json", '{"image": "php:8.3.35"}'),
    (".devcontainer/devcontainer.json", '{"image": "php:8.3.35"}'),
    (".devcontainer/php/devcontainer.json", '{"image": "php:8.3.35"}'),
])
def test_known_file_names_are_read(site, name, text):
    put(site, name, text)
    assert [e.location for e in scan(site)] == [name]


@pytest.mark.parametrize("name, text", [
    # The character after the stem has to be a separator, and the ending here is not a document.
    ("dockerfilelint.sh", "FROM php:8.3.35\n"),
    ("Dockerfile2", "FROM php:8.3.35\n"),
    ("composer.yml", "image: php:8.3.35\n"),
    ("docker-compose.txt", "image: php:8.3.35\n"),
    ("ci.yml", workflow("php-version: '8.3.35'")),
    (".github/ci.yml", workflow("php-version: '8.3.35'")),
    ("workflows/ci.yml", workflow("php-version: '8.3.35'")),
    ("php-version", "8.3.35\n"),
    ("tool-versions", "php 8.3.35\n"),
    ("composer.lock", '{"platform": {"php": "8.3.35"}}'),
    ("composer.json.dist", '{"require": {"php": "8.3.35"}}'),
    ("package.json", '{"require": {"php": "8.3.35"}}'),
    ("docs/devcontainer.md", '{"image": "php:8.3.35"}'),
    # Documentation that quotes a Dockerfile is not one.
    ("Dockerfile.md", "FROM php:7.4.33\n"),
    ("docs/Dockerfile.md", "```\nFROM php:7.4.33\n```\n"),
    ("Dockerfile.markdown", "FROM php:7.4.33\n"),
    ("Dockerfile.rst", "FROM php:7.4.33\n"),
    ("dockerfile.txt", "FROM php:7.4.33\n"),
    ("Containerfile.md", "FROM php:7.4.33\n"),
    ("php.Dockerfile.md", "FROM php:7.4.33\n"),
])
def test_other_file_names_are_left_alone(site, name, text):
    put(site, name, text)
    assert scan(site) == []


def test_a_markdown_example_of_an_old_dockerfile_does_not_expose_the_repo(site, matrix):
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    put(site, "docs/Dockerfile.md", "An old setup used:\n\nFROM php:7.4.33\n")
    evs = scan(site)
    assert [e.location for e in evs] == ["Dockerfile"]
    assert verdict_of(evs, matrix) == (LIKELY_PATCHED, HIGH)


@pytest.mark.parametrize("name", ["Dockerfile.dev", "Dockerfile.prod.php", "Dockerfile.mdx-site"])
def test_a_dockerfile_whose_suffix_is_not_documentation_is_still_read(site, name):
    # Only the documentation endings are excluded, so a suffix that merely starts with them is not.
    put(site, name, "FROM php:8.3.35\n")
    assert [e.location for e in scan(site)] == [name]


@pytest.mark.parametrize(
    "folder", ["vendor", "node_modules", ".git", "a/b/vendor", "src/node_modules"])
def test_folders_that_hold_other_peoples_code_are_not_read(site, folder):
    # Each dependency in vendor/ declares the PHP it supports. That says nothing about this project.
    put(site, folder + "/pkg/composer.json", '{"require": {"php": ">=7.2"}}')
    put(site, folder + "/pkg/Dockerfile", "FROM php:7.4.33\n")
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    assert [e.location for e in scan(site)] == ["Dockerfile"]


def test_the_root_may_itself_be_named_like_a_skipped_folder(tmp_path):
    root = tmp_path / "vendor"
    root.mkdir()
    put(root, "Dockerfile", "FROM php:8.3.35\n")
    assert [e.location for e in scan(root)] == ["Dockerfile"]


def test_dot_folders_that_hold_config_are_read(site):
    put(site, ".github/workflows/ci.yml", workflow("php-version: '8.3.35'"))
    put(site, ".devcontainer/devcontainer.json", '{"image": "php:8.3.35"}')
    assert len(scan(site)) == 2


def test_several_pins_in_one_file_give_one_evidence_each_and_a_repeat_gives_one(site):
    put(site, "Dockerfile",
        "FROM php:8.3.35-fpm AS a\nFROM php:8.2.28-cli AS b\nFROM php:8.3.35-fpm AS c\n")
    evs = scan(site)
    assert [e.signals["declared"] for e in evs] == ["8.3.35-fpm", "8.2.28-cli"]
    assert [e.location for e in evs] == ["Dockerfile", "Dockerfile"]


def test_the_same_pin_in_two_files_is_two_evidence(site):
    put(site, "api/Dockerfile", "FROM php:8.3.35-fpm\n")
    put(site, "web/Dockerfile", "FROM php:8.3.35-fpm\n")
    assert [e.location for e in scan(site)] == ["api/Dockerfile", "web/Dockerfile"]


def test_folders_are_walked_in_name_order_and_each_is_finished_before_the_next(site):
    for rel in ("b/Dockerfile", "a/x/Dockerfile", "a/Dockerfile", "c/Dockerfile", "Dockerfile"):
        put(site, rel, "FROM php:8.3.35\n")
    assert [e.location for e in scan(site)] == [
        "Dockerfile", "a/Dockerfile", "a/x/Dockerfile", "b/Dockerfile", "c/Dockerfile"]


# --- what is read from the file ---

def test_text_encodings_that_editors_and_shells_write_are_read(site):
    put(site, ".php-version", raw=codecs.BOM_UTF8 + b"8.3.35\r\n")
    put(site, "a/.php-version", raw="8.2.28\r\n".encode("utf-16"))
    put(site, "b/.php-version", raw=codecs.BOM_UTF16_BE + "8.1.2\n".encode("utf-16-be"))
    put(site, "Dockerfile", raw=codecs.BOM_UTF8 + b"FROM php:8.3.35-fpm\r\n")
    found = {e.location: e.detected_version for e in scan(site)}
    assert found == {".php-version": "8.3.35", "a/.php-version": "8.2.28",
                     "b/.php-version": "8.1.2", "Dockerfile": "8.3.35"}


def test_bytes_that_are_not_text_do_not_hide_a_pin(site):
    # A comment in some legacy encoding must not cost the FROM line under it.
    put(site, "Dockerfile", raw=b"# caf\xe9 \xff\xfe\nFROM php:8.3.35-fpm\n")
    (ev,) = scan(site)
    assert ev.detected_version == "8.3.35"


def test_a_file_of_noise_is_skipped_without_a_crash(site):
    put(site, "Dockerfile", raw=random.Random(7).randbytes(20000))
    put(site, "docker-compose.yml", raw=random.Random(8).randbytes(20000))
    put(site, ".php-version", raw=random.Random(9).randbytes(2000))
    for ev in scan(site):
        assert ev.source is Source.REPO


# --- files that cannot be read ---

def test_an_oversized_file_is_skipped_with_the_reason_recorded(site):
    limit = repo_module._MAX_BYTES
    put(site, "Dockerfile", raw=b"#" * limit + b"\nFROM php:7.4.33\n")
    put(site, "docker-compose.yml", "image: php:8.3.35\n")
    by_location = {e.location: e for e in scan(site)}
    row = by_location["Dockerfile"]
    assert row.signals["kind"] == "skipped"
    assert row.detected_version is None
    assert row.note.startswith("skipped: ")
    assert "larger than" in row.note
    assert by_location["docker-compose.yml"].detected_version == "8.3.35"


def test_a_file_exactly_at_the_limit_is_still_read(site):
    padding = repo_module._MAX_BYTES - len(b"\nFROM php:8.3.35\n")
    put(site, "Dockerfile", raw=b"#" * padding + b"\nFROM php:8.3.35\n")
    (ev,) = scan(site)
    assert ev.detected_version == "8.3.35"


def test_a_file_that_misreports_its_size_is_read_no_further_than_the_limit(site, monkeypatch):
    # A pseudo-file can report size 0 and then never stop.
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    asked = []

    class Endless:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, n=-1):
            asked.append(n)
            return b"a" * (n if n >= 0 else 10 * repo_module._MAX_BYTES)

    monkeypatch.setattr(repo_module, "open", lambda path, mode="r": Endless(), raising=False)
    (ev,) = scan(site)
    assert ev.signals["kind"] == "skipped"
    assert asked
    assert all(0 <= n <= repo_module._MAX_BYTES + 1 for n in asked)


def test_an_unreadable_file_is_skipped_and_the_scan_goes_on(site, monkeypatch):
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    put(site, "docker-compose.yml", "image: php:8.2.28\n")
    real_open = open

    def flaky(path, mode="r"):
        if os.path.basename(path) == "Dockerfile":
            raise PermissionError(13, "Permission denied", path)
        return real_open(path, mode)

    monkeypatch.setattr(repo_module, "open", flaky, raising=False)
    by_location = {e.location: e for e in scan(site)}
    assert by_location["Dockerfile"].signals["kind"] == "skipped"
    assert by_location["Dockerfile"].note == "skipped: cannot read it (Permission denied)"
    assert by_location["Dockerfile"].signals["php_present"] == "true"
    assert by_location["docker-compose.yml"].detected_version == "8.2.28"


# The ids are spelled out because pytest would otherwise put 200000 brackets in the test name.
@pytest.mark.parametrize("name, text, why", [
    pytest.param("composer.json", "{", "JSONDecodeError", id="composer-truncated"),
    pytest.param("composer.json", "[" * 200000, "RecursionError", id="composer-nesting"),
    pytest.param(".devcontainer/devcontainer.json", '{"image": ', "JSONDecodeError",
                 id="devcontainer-truncated"),
    pytest.param(".devcontainer/devcontainer.json", "[" * 200000, "RecursionError",
                 id="devcontainer-nesting"),
])
def test_a_file_that_will_not_parse_is_skipped_with_the_reason_recorded(site, name, text, why):
    put(site, name, text)
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    by_location = {e.location: e for e in scan(site)}
    assert by_location[name].signals["kind"] == "skipped"
    assert why in by_location[name].note
    assert by_location["Dockerfile"].detected_version == "8.3.35"


def test_a_parser_that_fails_for_any_reason_costs_only_its_file(site, monkeypatch):
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    put(site, "docker-compose.yml", "image: php:8.2.28\n")

    def broken(text):
        raise IndexError("boom")

    monkeypatch.setattr(repo_module, "_COMPOSE", repo_module._COMPOSE._replace(parse=broken))
    by_location = {e.location: e for e in scan(site)}
    assert by_location["docker-compose.yml"].note == "skipped: cannot parse it (IndexError)"
    assert by_location["Dockerfile"].detected_version == "8.3.35"


def test_a_flood_of_pins_in_one_file_is_cut_off_and_says_so(site):
    limit = repo_module._MAX_PINS
    put(site, "Dockerfile", "".join(f"FROM php:8.3.{n}\n" for n in range(limit + 50)))
    evs = scan(site)
    assert len(evs) == limit + 1
    assert evs[-1].signals["kind"] == "skipped"
    assert evs[-1].signals["php_present"] == "true"
    assert str(limit) in evs[-1].note


def test_a_value_too_long_to_be_a_tag_is_reported_and_not_read(site):
    limit = repo_module._MAX_TEXT
    put(site, "Dockerfile", "FROM php:8.3.35-" + "x" * 5000 + "\nFROM php:8.2.28\n")
    evs = scan(site)
    assert [e.signals["declared"] for e in evs if e.signals["kind"] != "skipped"] == ["8.2.28"]
    (row,) = skipped(evs)
    assert row.location == "Dockerfile"
    assert row.note == (
        f"skipped: it holds 1 value over {limit} characters, too long to be read as a pin")
    assert row.signals["php_present"] == "true"


def test_several_overlong_values_are_counted_in_one_note(site):
    limit = repo_module._MAX_TEXT
    put(site, "Dockerfile", "".join(f"FROM php:8.3.{n}-{'x' * (limit + 5)}\n" for n in range(3)))
    (row,) = scan(site)
    assert row.signals["kind"] == "skipped"
    assert f"it holds 3 values over {limit} characters" in row.note


def test_a_value_exactly_at_the_limit_is_still_a_pin(site):
    limit = repo_module._MAX_TEXT
    tag = "8.3.35-" + "x" * (limit - len("8.3.35-"))
    put(site, "Dockerfile", f"FROM php:{tag}\n")
    (ev,) = scan(site)
    assert ev.signals["declared"] == tag and len(tag) == limit


# --- a skip is a gap in coverage ---
#
# A skipped file is one the scan knows by a name it reads and could not read, so it might pin an
# old build. It counts as PHP seen with no version, and a repo with one cannot grade as patched.

def test_a_skipped_file_beside_a_patched_pin_holds_the_repo_at_indeterminate(site, matrix):
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    assert verdict_of(scan(site), matrix) == (LIKELY_PATCHED, HIGH)
    put(site, "docker-compose.yml", raw=b"#" * (repo_module._MAX_BYTES + 1))
    evs = scan(site)
    (row,) = skipped(evs)
    assert row.location == "docker-compose.yml"
    assert "larger than" in row.note
    assert row.signals["php_present"] == "true"
    assert verdict_of(evs, matrix) == (INDETERMINATE, LOW)


def test_a_skipped_file_beside_an_exposed_pin_leaves_the_repo_exposed(site, matrix):
    put(site, "Dockerfile", "FROM php:8.3.35-fpm\n")
    put(site, "docker-compose.yml", raw=b"#" * (repo_module._MAX_BYTES + 1))
    evs = scan(site)
    assert len(skipped(evs)) == 1
    assert verdict_of(evs, matrix) == (EXPOSED, HIGH)


def too_big(site):
    put(site, "docker-compose.yml", raw=b"#" * (repo_module._MAX_BYTES + 1))


def not_json_composer(site):
    put(site, "composer.json", "{")


def not_json_devcontainer(site):
    put(site, ".devcontainer/devcontainer.json", '{"image": ')


def deep_devcontainer(site):
    put(site, ".devcontainer/devcontainer.json", "[" * 200000)


def one_long_tag(site):
    put(site, "api/Dockerfile", "FROM php:8.3.36-" + "x" * 5000 + "\n")


def a_flood(site):
    limit = repo_module._MAX_PINS
    put(site, "api/Dockerfile", "".join(f"FROM php:8.3.{36 + n}\n" for n in range(limit + 20)))


@pytest.mark.parametrize("make", [
    too_big, not_json_composer, not_json_devcontainer, deep_devcontainer, one_long_tag, a_flood])
def test_every_kind_of_skip_claims_php_and_holds_a_patched_repo_at_indeterminate(
        site, matrix, make):
    # A composer.json is in the list on purpose. One rule covers every skip.
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    make(site)
    evs = scan(site)
    rows = skipped(evs)
    assert rows
    for row in rows:
        assert row.signals["php_present"] == "true"
        assert row.detected_version is None
        assert row.note.startswith("skipped: ")
    assert verdict_of(evs, matrix) == (INDETERMINATE, LOW)


def test_an_unreadable_file_beside_a_patched_pin_holds_the_repo_at_indeterminate(
        site, matrix, monkeypatch):
    put(site, "Dockerfile", "FROM php:7.4.33\n")
    put(site, "docker-compose.yml", "image: php:8.3.36-fpm\n")
    real_open = open

    def flaky(path, mode="r"):
        if os.path.basename(path) == "Dockerfile":
            raise PermissionError(13, "Permission denied", path)
        return real_open(path, mode)

    monkeypatch.setattr(repo_module, "open", flaky, raising=False)
    evs = scan(site)
    (row,) = skipped(evs)
    assert row.location == "Dockerfile"
    assert row.signals["php_present"] == "true"
    assert verdict_of(evs, matrix) == (INDETERMINATE, LOW)


def test_a_repo_whose_only_file_was_skipped_is_indeterminate_and_not_clean(site, matrix):
    # Nothing in it is live, and a scan that found nothing must never read as a clear.
    put(site, "Dockerfile", raw=b"#" * (repo_module._MAX_BYTES + 1))
    evs = scan(site)
    assert len(skipped(evs)) == 1
    assert verdict_of(evs, matrix) == (INDETERMINATE, LOW)


# --- links are never followed ---

def link_or_skip(target, link, directory=False):
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("this machine will not create symbolic links")


def test_a_linked_file_out_of_the_tree_is_not_read(site, tmp_path):
    outside = put(tmp_path / "elsewhere", "Dockerfile", "FROM php:7.4.33\n")
    link_or_skip(outside, site / "Dockerfile")
    put(site, "docker-compose.yml", "image: php:8.3.35\n")
    by_location = {e.location: e for e in scan(site)}
    assert "7.4.33" not in repr(list(by_location.values()))
    assert by_location["Dockerfile"].signals["kind"] == "skipped"
    assert "link" in by_location["Dockerfile"].note
    assert by_location["Dockerfile"].signals["php_present"] == "true"
    assert by_location["docker-compose.yml"].detected_version == "8.3.35"


def test_the_reader_itself_refuses_a_link(site, tmp_path):
    # The walk filters links before it gets here, so this pins only that _read does not follow a
    # link it is handed. A file swapped for a link between the walk's look and the open is a race
    # that lstat does not close. It sits outside the threat model, which is a local checkout that
    # holds still while it is scanned.
    outside = put(tmp_path / "elsewhere", "Dockerfile", "FROM php:7.4.33\n")
    link_or_skip(outside, site / "Dockerfile")
    with pytest.raises(repo_module._Skip):
        repo_module._read(str(site / "Dockerfile"))


def test_a_linked_file_inside_the_tree_is_skipped_and_its_target_is_read_once(site):
    put(site, "base/Dockerfile", "FROM php:8.3.35-fpm\n")
    link_or_skip(site / "base" / "Dockerfile", site / "Dockerfile")
    by_location = {e.location: e for e in scan(site)}
    assert by_location["base/Dockerfile"].detected_version == "8.3.35"
    assert by_location["Dockerfile"].signals["kind"] == "skipped"


def test_a_linked_dockerfile_whose_content_has_an_unread_name_holds_the_repo(site, matrix):
    # The link is skipped, and what it points at has a name the scan does not read, so nothing else
    # shows that content. A link that claimed nothing would let the patched pin clear the repo.
    put(site, "api/Dockerfile", "FROM php:8.3.36-fpm\n")
    put(site, "build/prod.docker", "FROM php:7.4.33\n")
    (site / "web").mkdir()
    link_or_skip(site / "build" / "prod.docker", site / "web" / "Dockerfile")
    evs = scan(site)
    assert sorted(e.location for e in evs) == ["api/Dockerfile", "web/Dockerfile"]
    (row,) = skipped(evs)
    assert row.location == "web/Dockerfile"
    assert row.signals["php_present"] == "true"
    assert verdict_of(evs, matrix) == (INDETERMINATE, LOW)


# A linked folder is never entered. One that leads out of the tree goes unread, which is a gap like
# any other skip, so it gets a row that carries php_present and holds a patched repo at
# INDETERMINATE. One that stays inside the tree leads to a folder the scan reads where it really
# sits, so it is no gap and gets no row.
LINKED_DIRECTORY = "skipped: linked directory not traversed"


def only_skip(evs):
    (row,) = skipped(evs)
    return row


def test_a_linked_folder_is_not_entered_and_is_reported(site, tmp_path):
    put(tmp_path / "elsewhere", "Dockerfile", "FROM php:7.4.33\n")
    put(tmp_path / "elsewhere", "composer.json", '{"require": {"php": ">=5.6"}}')
    link_or_skip(tmp_path / "elsewhere", site / "linked", directory=True)
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    evs = scan(site)
    assert [e.location for e in evs] == ["Dockerfile", "linked"]
    row = only_skip(evs)
    assert row.note == LINKED_DIRECTORY
    assert row.signals["php_present"] == "true"
    assert row.detected_version is None
    assert "7.4.33" not in repr(evs)


def test_a_linked_folder_with_an_old_pin_holds_a_patched_repo_at_indeterminate(
        site, tmp_path, matrix):
    # The pin in the linked folder is never read, and the patched pin beside it cannot clear it.
    put(tmp_path / "elsewhere", "Dockerfile", "FROM php:7.4.33\n")
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    assert verdict_of(scan(site), matrix) == (LIKELY_PATCHED, HIGH)
    link_or_skip(tmp_path / "elsewhere", site / "linked", directory=True)
    evs = scan(site)
    assert only_skip(evs).location == "linked"
    assert verdict_of(evs, matrix) == (INDETERMINATE, LOW)


def test_a_linked_folder_below_the_root_is_located_from_the_root(site, tmp_path):
    put(tmp_path / "elsewhere", "Dockerfile", "FROM php:7.4.33\n")
    (site / "public").mkdir()
    link_or_skip(tmp_path / "elsewhere", site / "public" / "storage", directory=True)
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    assert [e.location for e in scan(site)] == ["Dockerfile", "public/storage"]


@pytest.mark.parametrize("name", ["vendor", "node_modules", ".git"])
def test_a_link_with_a_name_the_scan_never_enters_is_not_reported(site, tmp_path, name):
    # Those folders are other people's code by design, so a link to one has nothing to report.
    put(tmp_path / "elsewhere", "Dockerfile", "FROM php:7.4.33\n")
    link_or_skip(tmp_path / "elsewhere", site / name, directory=True)
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    assert [e.location for e in scan(site)] == ["Dockerfile"]


def test_a_link_to_a_file_with_an_ordinary_name_is_not_reported(site, tmp_path):
    # Only a folder leaves PHP files unread. A link to a file the scan would never read adds noise.
    notes = put(tmp_path / "elsewhere", "notes.txt", "hello\n")
    link_or_skip(notes, site / "notes-link")
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    assert [e.location for e in scan(site)] == ["Dockerfile"]


def test_a_dangling_link_is_not_reported(site, tmp_path):
    link_or_skip(tmp_path / "nowhere", site / "dangling")
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    assert [e.location for e in scan(site)] == ["Dockerfile"]


def test_a_link_back_up_the_tree_does_not_loop_and_is_no_gap(site):
    # It leads to the root, which is being scanned, so there is nothing unread to report.
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    link_or_skip(site, site / "loop", directory=True)
    evs = scan(site)
    assert [e.location for e in evs] == ["Dockerfile"]
    assert not skipped(evs)


def test_a_folder_link_that_stays_in_the_tree_adds_no_row_and_keeps_the_verdict(site, matrix):
    # Laravel's public/storage is a link to storage/app/public, and the scan reads that folder
    # where it sits. A row for the link would hold every Laravel repo at INDETERMINATE.
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    put(site, "storage/app/public/.gitignore", "*\n")
    (site / "public").mkdir()
    link_or_skip(os.path.join("..", "storage", "app", "public"), site / "public" / "storage",
                 directory=True)
    evs = scan(site)
    assert not skipped(evs)
    assert [e.location for e in evs] == ["Dockerfile"]
    assert verdict_of(evs, matrix) == (LIKELY_PATCHED, HIGH)


def test_an_in_tree_link_is_judged_against_the_resolved_root_however_the_root_is_spelled(
        site, tmp_path, monkeypatch):
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    put(site, "storage/app/public/.gitignore", "*\n")
    (site / "public").mkdir()
    link_or_skip(os.path.join("..", "storage", "app", "public"), site / "public" / "storage",
                 directory=True)
    alias = tmp_path / "alias"
    link_or_skip(site, alias, directory=True)
    monkeypatch.chdir(site)
    for spelling in (str(site), str(site) + os.sep, str(alias), ".", os.path.join("public", "..")):
        assert not skipped(scan_path(spelling)), spelling


def test_a_folder_link_that_stays_in_the_tree_leaves_its_target_read_once_where_it_sits(
        site, matrix):
    # Skipping the row is safe because the old pin behind the link is found at its real path.
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    put(site, "build/base/Dockerfile", "FROM php:7.4.33\n")
    (site / "services").mkdir()
    link_or_skip(site / "build" / "base", site / "services" / "api", directory=True)
    evs = scan(site)
    assert sorted(e.location for e in evs) == ["Dockerfile", "build/base/Dockerfile"]
    assert not skipped(evs)
    assert verdict_of(evs, matrix) == (EXPOSED, HIGH)


def test_a_chain_of_links_that_stays_in_the_tree_adds_no_rows(site, matrix):
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    (site / "real").mkdir()
    link_or_skip(site / "real", site / "second", directory=True)
    link_or_skip(site / "second", site / "first", directory=True)
    evs = scan(site)
    assert not skipped(evs)
    assert verdict_of(evs, matrix) == (LIKELY_PATCHED, HIGH)


def test_a_chain_of_links_is_judged_by_where_it_ends(site, tmp_path, matrix):
    # first leads to second, which is in the tree, but second leads out of it.
    put(tmp_path / "elsewhere", "Dockerfile", "FROM php:7.4.33\n")
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    link_or_skip(tmp_path / "elsewhere", site / "second", directory=True)
    link_or_skip(site / "second", site / "first", directory=True)
    evs = scan(site)
    assert sorted(e.location for e in skipped(evs)) == ["first", "second"]
    assert verdict_of(evs, matrix) == (INDETERMINATE, LOW)


def test_a_link_to_a_sibling_named_like_the_root_with_more_on_the_end_is_out_of_the_tree(
        site, tmp_path, matrix):
    # .../site2 starts with .../site, and only the separator after the root tells them apart.
    neighbor = site.parent / (site.name + "2")
    put(neighbor, "Dockerfile", "FROM php:7.4.33\n")
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    link_or_skip(neighbor, site / "neighbor", directory=True)
    evs = scan(site)
    assert only_skip(evs).location == "neighbor"
    assert verdict_of(evs, matrix) == (INDETERMINATE, LOW)


def test_a_link_to_the_parent_of_the_root_is_out_of_the_tree(site):
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    put(site.parent / "other", "Dockerfile", "FROM php:7.4.33\n")
    link_or_skip(site.parent, site / "up", directory=True)
    evs = scan(site)
    assert [e.location for e in evs] == ["Dockerfile", "up"]
    assert only_skip(evs).note == LINKED_DIRECTORY
    assert "7.4.33" not in repr(evs)


def test_a_link_that_points_at_itself_is_reported_and_the_scan_goes_on(site):
    # stat on it fails with "too many levels of links", which is a folder the scan cannot inspect.
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    link_or_skip("selfie", site / "selfie")
    evs = scan(site)
    assert [e.location for e in evs] == ["Dockerfile", "selfie"]
    row = only_skip(evs)
    assert row.note.startswith("skipped: cannot inspect it")
    assert row.signals["php_present"] == "true"


def junction_or_skip(link, target):
    made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                          capture_output=True)
    if made.returncode != 0:
        pytest.skip("this machine will not create junctions")


@pytest.mark.skipif(sys.platform != "win32", reason="junctions only exist on Windows")
def test_a_junction_out_of_the_tree_is_not_entered_and_is_reported(site, tmp_path):
    # scandir reports a junction as an ordinary folder, so only its resolved path gives it away.
    put(tmp_path / "elsewhere", "Dockerfile", "FROM php:7.4.33\n")
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    link = site / "linked"
    junction_or_skip(link, tmp_path / "elsewhere")
    try:
        evs = scan(site)
    finally:
        os.rmdir(link)
    assert [e.location for e in evs] == ["Dockerfile", "linked"]
    row = only_skip(evs)
    assert row.note == LINKED_DIRECTORY
    assert row.signals["php_present"] == "true"
    assert "7.4.33" not in repr(evs)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions only exist on Windows")
def test_a_junction_with_an_old_pin_holds_a_patched_repo_at_indeterminate(site, tmp_path, matrix):
    put(tmp_path / "elsewhere", "Dockerfile", "FROM php:7.4.33\n")
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    assert verdict_of(scan(site), matrix) == (LIKELY_PATCHED, HIGH)
    link = site / "linked"
    junction_or_skip(link, tmp_path / "elsewhere")
    try:
        evs = scan(site)
    finally:
        os.rmdir(link)
    assert only_skip(evs).location == "linked"
    assert verdict_of(evs, matrix) == (INDETERMINATE, LOW)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions only exist on Windows")
@pytest.mark.parametrize("name", ["vendor", "node_modules"])
def test_a_junction_with_a_name_the_scan_never_enters_is_not_reported(site, tmp_path, name):
    put(tmp_path / "elsewhere", "Dockerfile", "FROM php:7.4.33\n")
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    link = site / name
    junction_or_skip(link, tmp_path / "elsewhere")
    try:
        evs = scan(site)
    finally:
        os.rmdir(link)
    assert [e.location for e in evs] == ["Dockerfile"]


@pytest.mark.skipif(sys.platform != "win32", reason="junctions only exist on Windows")
def test_a_junction_back_up_the_tree_does_not_loop_and_is_no_gap(site):
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    link = site / "loop"
    junction_or_skip(link, site)
    try:
        evs = scan(site)
    finally:
        os.rmdir(link)
    assert [e.location for e in evs] == ["Dockerfile"]
    assert not skipped(evs)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions only exist on Windows")
def test_a_junction_that_stays_in_the_tree_adds_no_row_and_keeps_the_verdict(site, matrix):
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    put(site, "storage/app/public/.gitignore", "*\n")
    (site / "public").mkdir()
    link = site / "public" / "storage"
    junction_or_skip(link, site / "storage" / "app" / "public")
    try:
        evs = scan(site)
    finally:
        os.rmdir(link)
    assert not skipped(evs)
    assert [e.location for e in evs] == ["Dockerfile"]
    assert verdict_of(evs, matrix) == (LIKELY_PATCHED, HIGH)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions only exist on Windows")
def test_a_junction_that_stays_in_the_tree_leaves_its_target_read_once_where_it_sits(
        site, matrix):
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    put(site, "build/base/Dockerfile", "FROM php:7.4.33\n")
    (site / "services").mkdir()
    link = site / "services" / "api"
    junction_or_skip(link, site / "build" / "base")
    try:
        evs = scan(site)
    finally:
        os.rmdir(link)
    assert sorted(e.location for e in evs) == ["Dockerfile", "build/base/Dockerfile"]
    assert not skipped(evs)
    assert verdict_of(evs, matrix) == (EXPOSED, HIGH)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions only exist on Windows")
def test_a_junction_to_a_sibling_named_like_the_root_with_more_on_the_end_is_out_of_the_tree(
        site, matrix):
    neighbor = site.parent / (site.name + "2")
    put(neighbor, "Dockerfile", "FROM php:7.4.33\n")
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    link = site / "neighbor"
    junction_or_skip(link, neighbor)
    try:
        evs = scan(site)
    finally:
        os.rmdir(link)
    assert only_skip(evs).location == "neighbor"
    assert verdict_of(evs, matrix) == (INDETERMINATE, LOW)


# --- whether a resolved path is inside the scanned root ---

ROOT = os.sep + "srv" + os.sep + "site"
FS_ROOT = os.path.abspath(os.sep)


@pytest.mark.parametrize("root, path, want", [
    (ROOT, ROOT, True),
    (ROOT, ROOT + os.sep + "public", True),
    (ROOT, ROOT + os.sep + "storage" + os.sep + "app", True),
    (ROOT + os.sep, ROOT + os.sep + "public", True),
    (ROOT, ROOT + "2", False),
    (ROOT, ROOT + "2" + os.sep + "public", False),
    (ROOT, ROOT[:-1], False),
    # The root has to be the start of the path, not just somewhere in it.
    (ROOT, os.sep + "other" + ROOT + os.sep + "public", False),
    (ROOT, os.sep + "srv", False),
    (ROOT, os.sep + "etc", False),
    (ROOT, os.sep, False),
    # A filesystem root already ends in a separator, so adding another would match nothing.
    (FS_ROOT, FS_ROOT, True),
    (FS_ROOT, os.path.join(FS_ROOT, "anything"), True),
])
def test_inside_means_the_root_itself_or_something_under_it(root, path, want):
    assert repo_module._inside(root, path) is want


@pytest.mark.skipif(os.name != "nt", reason="only Windows ignores case in a path")
@pytest.mark.parametrize("root, path, want", [
    ("C:\\Srv\\Site", "c:\\srv\\SITE\\Public", True),
    ("C:\\Srv\\Site", "c:\\SRV\\site2", False),
    ("C:\\Srv\\Site", "D:\\Srv\\Site\\Public", False),
])
def test_inside_ignores_case_on_windows(root, path, want):
    assert repo_module._inside(root, path) is want


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_named_pipe_is_skipped_and_does_not_hang_the_scan(site):
    # Opening a pipe with no writer blocks forever, so the scan runs in a thread it can lose.
    os.mkfifo(site / "Dockerfile")
    result = []
    worker = threading.Thread(target=lambda: result.extend(scan(site)), daemon=True)
    worker.start()
    worker.join(10)
    assert not worker.is_alive()
    (ev,) = result
    assert ev.signals["kind"] == "skipped"
    assert "regular file" in ev.note


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_an_unreadable_folder_is_recorded_and_the_rest_is_still_scanned(site, matrix):
    put(site, "locked/Dockerfile", "FROM php:7.4.33\n")
    put(site, "Dockerfile", "FROM php:8.3.36\n")
    os.chmod(site / "locked", 0)
    try:
        evs = scan(site)
    finally:
        os.chmod(site / "locked", 0o700)
    by_location = {e.location: e for e in evs}
    assert by_location["locked"].signals["kind"] == "skipped"
    assert by_location["locked"].signals["php_present"] == "true"
    assert by_location["Dockerfile"].detected_version == "8.3.36"
    # What is in the folder could be anything, and the patched pin beside it must not clear it.
    assert verdict_of(evs, matrix) == (INDETERMINATE, LOW)


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_an_unreadable_root_is_an_error(site):
    put(site, "Dockerfile", "FROM php:8.3.35\n")
    os.chmod(site, 0)
    try:
        with pytest.raises(OSError):
            scan(site)
    finally:
        os.chmod(site, 0o700)


# --- reading is not running ---

def test_nothing_in_the_tree_is_run_or_imported(site, tmp_path):
    marker = tmp_path / "ran"
    code = f"open({str(marker)!r}, 'w').write('x')\n"
    for rel in ("setup.py", "conftest.py", "sitecustomize.py", "__init__.py", "json.py",
                "composer.py", "usercustomize.py", "Dockerfile.py"):
        put(site, rel, code)
    put(site, "composer.json", json.dumps({
        "require": {"php": ">=8.2"},
        "scripts": {"post-install-cmd": "python -c \"open(%r, 'w')\"" % str(marker)},
    }))
    put(site, "Dockerfile", f"FROM php:8.3.35\nRUN python -c \"open({str(marker)!r}, 'w')\"\n")
    before = set(sys.path)
    scan(site)
    assert not marker.exists()
    assert set(sys.path) == before
    assert not [m for m in list(sys.modules.values())
                if str(site) in (getattr(m, "__file__", None) or "")]


def test_the_scanner_has_no_way_to_run_code():
    source = pathlib.Path(repo_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    stdlib = {"codecs", "functools", "hashlib", "json", "os", "stat", "string", "typing"}
    assert imported <= stdlib | {"php_radar"}
    called = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    called |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not called & {"eval", "exec", "compile", "__import__", "system", "popen", "Popen",
                         "run", "call", "import_module", "execv", "execl", "spawnl", "startfile"}


def test_the_source_parses_under_the_python_3_9_grammar():
    # A grammar check only. It catches a match statement or a parenthesized with, and nothing in
    # the standard library that arrived after 3.9, because this runs on a newer Python.
    source = pathlib.Path(repo_module.__file__).read_text(encoding="utf-8")
    ast.parse(source, feature_version=(3, 9))


# --- what the grader makes of it ---

def test_the_fixture_repo_is_exposed_on_the_strength_of_its_exact_image_tag(matrix):
    assert verdict_of(scan_path(FIXTURE), matrix) == (EXPOSED, HIGH)


@pytest.mark.parametrize("dockerfile", [
    "FROM php:8.3-apache\n",
    "FROM php:8\n",
    "FROM php:latest\n",
    "FROM php\n",
    "FROM php:${PHP_VERSION}-fpm\n",
    "FROM php:7.4-apache\n",
    "FROM php:8.3@" + DIGEST + "\n",
])
def test_a_floating_tag_is_indeterminate_at_low_and_never_exposed(site, matrix, dockerfile):
    put(site, "Dockerfile", dockerfile)
    assert verdict_of(scan(site), matrix) == (INDETERMINATE, LOW)


@pytest.mark.parametrize("dockerfile, want", [
    ("FROM php:8.3.35-fpm\n", (EXPOSED, HIGH)),
    ("FROM php:8.3.35-fpm@" + DIGEST + "\n", (EXPOSED, HIGH)),
    ("FROM php:8.3.35@" + DIGEST + "\n", (EXPOSED, HIGH)),
    ("FROM php:8.1.2\n", (EXPOSED, HIGH)),
    ("FROM php:8.3.35-custom\n", (EXPOSED, MEDIUM)),
    ("FROM php:8.3.36-fpm\n", (LIKELY_PATCHED, HIGH)),
    ("FROM php:8.5.12-cli-alpine3.20\n", (LIKELY_PATCHED, HIGH)),
    ("FROM php:8.3.36-custom\n", (LIKELY_PATCHED, MEDIUM)),
])
def test_an_exact_tag_is_graded_by_the_matrix_at_the_tags_own_confidence(
        site, matrix, dockerfile, want):
    put(site, "Dockerfile", dockerfile)
    assert verdict_of(scan(site), matrix) == want


def test_a_composer_floor_alone_is_indeterminate_and_does_not_unsettle_an_exact_pin(site, matrix):
    put(site, "composer.json", '{"require": {"php": ">=7.4"}}')
    assert verdict_of(scan(site), matrix) == (INDETERMINATE, LOW)
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    assert verdict_of(scan(site), matrix) == (LIKELY_PATCHED, HIGH)
    put(site, "Dockerfile", "FROM php:8.3.35-fpm\n")
    assert verdict_of(scan(site), matrix) == (EXPOSED, HIGH)


def test_an_exact_platform_version_is_still_only_a_declaration(site, matrix):
    put(site, "composer.json", '{"config": {"platform": {"php": "7.4.33"}}}')
    assert verdict_of(scan(site), matrix) == (INDETERMINATE, LOW)


def test_a_version_file_is_graded_at_medium(site, matrix):
    put(site, ".php-version", "8.3.36\n")
    assert verdict_of(scan(site), matrix) == (LIKELY_PATCHED, MEDIUM)
    put(site, ".php-version", "8.3.35\n")
    assert verdict_of(scan(site), matrix) == (EXPOSED, MEDIUM)


def test_a_floating_tag_beside_a_patched_pin_leaves_the_repo_indeterminate(site, matrix):
    put(site, "Dockerfile", "FROM php:8.3.36-fpm\n")
    put(site, "docker-compose.yml", "image: php:8.3-apache\n")
    assert verdict_of(scan(site), matrix) == (INDETERMINATE, LOW)


def test_a_composer_find_shows_no_version_in_the_report_of_the_asset_it_belongs_to(site, matrix):
    put(site, "composer.json", '{"require": {"php": ">=8.2"}}')
    inventory = AssetInventory()
    for ev in scan(site):
        inventory.add(ev)
    text = render_console(inventory.assets(), matrix)
    assert "no PHP version found" in text
    assert "PHP >=8.2" not in text


# --- hostile text ---

FRAGMENTS = [
    "FROM ", "php", ":", "8.3.35", "-fpm", "@sha256:", DIGEST, "image: ", "uses: ",
    "shivammathur/setup-php@v2", "with:", "php-version: ", "php-version-file: ", "\n", "\r\n", " ",
    "    ", "- ", "#", "'", '"', "${", "}", "$", "\\", "\\\n", "{", "[", "]", ",", "//", "/*",
    "*/", "\x00", chr(0xE9), chr(0xD800), "require", "platform", '"php"', '"image"', '"features"',
    "devcontainers/php", "1-8.3-bookworm", "latest", "8.3", ">=8.2", "AS ", "--platform=x ",
    "ref:", ".php-version", "x" * 300,
]

PARSERS = [
    parse_dockerfile,
    parse_compose,
    parse_ci_setup_php,
    lambda text: parse_dotfiles(".php-version", text),
    lambda text: parse_dotfiles(".tool-versions", text),
    parse_composer,
    parse_devcontainer,
]


def junk(rng):
    return "".join(rng.choice(FRAGMENTS) for _ in range(rng.randrange(0, 50)))


def test_the_parsers_return_clean_pairs_for_any_text():
    rng = random.Random(2026)
    for _ in range(1500):
        text = junk(rng)
        for parse in PARSERS:
            try:
                got = parse(text)
            except (ValueError, RecursionError):
                # Only the two parsers that decode JSON may refuse, and the scan records it.
                assert parse in (parse_composer, parse_devcontainer)
                continue
            assert isinstance(got, list)
            texts = [t for t, _ in got]
            assert len(set(texts)) == len(texts)
            for declared, confidence in got:
                # A parser may return an overlong value. The scan reports it and does not read it.
                assert isinstance(declared, str) and declared
                assert isinstance(confidence, Confidence)


def test_a_tree_of_hostile_files_scans_without_a_crash(site):
    rng = random.Random(11)
    names = ["Dockerfile", "docker-compose.yml", ".github/workflows/ci.yml", ".php-version",
             ".tool-versions", "composer.json", ".devcontainer/devcontainer.json"]
    for round_ in range(60):
        for name in names:
            put(site, f"r{round_}/{name}", raw=junk(rng).encode("utf-8", "surrogatepass"))
    evs = scan(site)
    for ev in evs:
        assert ev.source is Source.REPO
        assert ev.signals["repo"] == repo_id(site)
        assert ev.signals["kind"]
        assert ev.signals["confidence"] in Confidence.__members__
        assert not os.path.isabs(ev.location)
        assert len(ev.signals.get("declared", "")) <= repo_module._MAX_TEXT
        if ev.signals["kind"] == "skipped":
            assert ev.signals["php_present"] == "true"
            assert ev.detected_version is None


@pytest.mark.parametrize("parse, unit", [
    (parse_dockerfile, "FROM php:8.3.35 \\\n"),
    (parse_dockerfile, "\\\n"),
    (parse_dockerfile, "FROM php:8.3.35-" + "x" * 200 + "\n"),
    (parse_compose, "image: php:8.3.35\n"),
    (parse_compose, "  - - - image: '\n"),
    (parse_ci_setup_php, "- uses: shivammathur/setup-php@v2\n"),
    (parse_ci_setup_php, "uses: shivammathur/setup-php@v2\n  php-version: 8.3\n"),
    (lambda text: parse_dotfiles(".tool-versions", text), "php 8.3.35 8.3.34\n"),
    (lambda text: parse_dotfiles(".php-version", text), "# x\n"),
    (parse_composer, '{"require":'),
    (parse_composer, "["),
    (parse_devcontainer, "/*"),
    (parse_devcontainer, ",]"),
    (parse_devcontainer, '"\\'),
    (parse_devcontainer, "// x\n"),
])
def test_hostile_input_costs_time_in_proportion_to_its_size(parse, unit):
    # A parser that rescans the rest of the file for every line would take hours on this much text.
    # Every case here runs in well under a second, so the bound only has to be far below hours and
    # far above what a loaded machine adds.
    text = unit * ((1 << 18) // len(unit))
    started = time.perf_counter()
    try:
        parse(text)
    except (ValueError, RecursionError):
        pass
    assert time.perf_counter() - started < 60
