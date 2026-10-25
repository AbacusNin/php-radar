import copy
import itertools
import json
import os

import pytest

import php_radar
from php_radar.knowledge import (
    DATA_PATH, MatrixError, _at_or_after, grade, grade_evidence, load_matrix)
from php_radar.model import Asset, Confidence, Evidence, Sapi, Source, Verdict
from php_radar.versions import PhpVersion


def test_matrix_fixed_micro():
    m = load_matrix(DATA_PATH)
    assert m.fixed_micro("8.3") == 36
    assert m.fixed_micro("8.5") == 12

def test_selfbuilt_below_fix_is_exposed_high_on_host():
    m = load_matrix(DATA_PATH)
    a = Asset("web1", "host", [Evidence(Source.HOST, "web1", "8.3.35", Sapi.FPM, {})])
    assert grade(a, m) == (Verdict.EXPOSED, Confidence.HIGH)

def test_patched_micro_is_likely_patched():
    m = load_matrix(DATA_PATH)
    a = Asset("web1", "host", [Evidence(Source.HOST, "web1", "8.3.36", Sapi.FPM, {})])
    assert grade(a, m)[0] == Verdict.LIKELY_PATCHED

def test_ubuntu_backport_not_exposed():
    # 8.1.2 is end of life upstream. This Ubuntu build carries the fix, so the build decides.
    m = load_matrix(DATA_PATH)
    a = Asset("web1", "host", [Evidence(Source.HOST, "web1", "8.1.2", Sapi.FPM,
             {"distro": "ubuntu", "package_version": "8.1.2-1ubuntu2.28"})])
    assert grade(a, m)[0] in (Verdict.LIKELY_PATCHED, Verdict.INDETERMINATE)
    assert grade(a, m)[0] != Verdict.EXPOSED

def test_hidden_version_is_indeterminate():
    m = load_matrix(DATA_PATH)
    a = Asset("web1", "host", [Evidence(Source.NETWORK, "web1", None, Sapi.UNKNOWN, {"php_present": "true"})])
    assert grade(a, m)[0] == Verdict.INDETERMINATE


EXPOSED = Verdict.EXPOSED
INDETERMINATE = Verdict.INDETERMINATE
PATCHED = Verdict.LIKELY_PATCHED
NOT_PHP = Verdict.NOT_PHP
HIGH, MEDIUM, LOW = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW
HOST, CLOUD, NETWORK, REPO = Source.HOST, Source.CLOUD, Source.NETWORK, Source.REPO


@pytest.fixture(scope="module")
def matrix():
    return load_matrix(DATA_PATH)


def ev(source, version, signals=None, note=""):
    return Evidence(source, "loc", version, Sapi.FPM, signals or {}, note)


def asset(*evidence):
    return Asset("web1", "host", list(evidence))


def host(version, **signals):
    return asset(ev(HOST, version, signals))


def packaged(reported, distro, build):
    return host(reported, distro=distro, package_version=build)


def upstream(build):
    # What php -v prints for a package build: 8.1.2 for 8.1.2-1ubuntu2.28.
    v = PhpVersion.parse(build)
    return f"{v.major}.{v.minor}.{v.micro}"


# The shipped matrix

@pytest.mark.parametrize("branch, micro", [("8.5", 12), ("8.4", 27), ("8.3", 36), ("8.2", 35)])
def test_fixed_micros_match_the_advisories(matrix, branch, micro):
    assert matrix.fixed_micro(branch) == micro


@pytest.mark.parametrize("branch", ["8.6", "9.0", "8.1", "8.0", "7.4", "abc", "", "8", "8.3.36"])
def test_fixed_micro_is_none_for_anything_without_a_listed_fix(matrix, branch):
    assert matrix.fixed_micro(branch) is None


@pytest.mark.parametrize("branch", ["8.1", "8.0", "7.4", "7.3", "7.0", "5.6", "5.2", "4.4"])
def test_end_of_life_branches_have_no_fix(matrix, branch):
    assert matrix.is_eol(branch)
    assert matrix.fixed_micro(branch) is None


@pytest.mark.parametrize(
    "branch", ["8.2", "8.3", "8.4", "8.5", "8.6", "9.0", "10.0", "abc", "", "8"])
def test_supported_and_unknown_branches_are_not_end_of_life(matrix, branch):
    assert not matrix.is_eol(branch)


def test_data_path_is_the_packaged_matrix():
    package = os.path.dirname(php_radar.__file__)
    assert os.path.isfile(DATA_PATH)
    assert os.path.samefile(os.path.dirname(DATA_PATH), os.path.join(package, "data"))


def test_shipped_matrix_documents_every_entry_in_plain_ascii():
    with open(DATA_PATH, encoding="utf-8") as f:
        text = f.read()
    assert text.isascii()
    data = json.loads(text)
    entries = [*data["fixed"].values(), data["eol"], *data["backports"]]
    assert all(isinstance(e.get("notes"), str) and e["notes"].strip() for e in entries)


# Version against the matrix

@pytest.mark.parametrize("version, verdict", [
    ("8.5.11", EXPOSED), ("8.5.12", PATCHED), ("8.5.13", PATCHED),
    ("8.4.26", EXPOSED), ("8.4.27", PATCHED),
    ("8.3.0", EXPOSED), ("8.3.35", EXPOSED), ("8.3.36", PATCHED), ("8.3.100", PATCHED),
    ("8.2.34", EXPOSED), ("8.2.35", PATCHED),
    # End of life: upstream shipped no fix at any micro.
    ("8.1.99", EXPOSED), ("8.0.30", EXPOSED), ("7.4.33", EXPOSED), ("5.6.40", EXPOSED),
    # A branch the matrix has never heard of is not guessed at.
    ("8.6.0", INDETERMINATE), ("9.0.1", INDETERMINATE),
    # Present but not a full build: no micro, or a header line nobody parsed.
    ("8.3", INDETERMINATE), ("8.3-apache", INDETERMINATE), ("latest", INDETERMINATE),
    ("PHP/8.3.35", INDETERMINATE), ("garbage", INDETERMINATE),
])
def test_version_against_the_matrix_on_a_host(matrix, version, verdict):
    # A version that places nothing still confirms PHP is there, which is MEDIUM.
    want = MEDIUM if verdict is INDETERMINATE else HIGH
    assert grade(host(version), matrix) == (verdict, want)


@pytest.mark.parametrize("version, verdict", [
    # A variant is no distro build, so with no distro signal the bare number decides.
    ("8.3.35-fpm", EXPOSED), ("8.3.35-cli", EXPOSED), ("8.3.36-fpm", PATCHED),
    ("8.3.36-apache", PATCHED), ("8.3.36-zts", PATCHED), ("8.3.36-nts", PATCHED),
    # A pre-release of the fixed release is no release, so at or above the fix it is unknown.
    ("8.3.36RC1", INDETERMINATE), ("8.3.36-RC1", INDETERMINATE), ("8.3.36-dev", INDETERMINATE),
    ("8.3.37-dev", INDETERMINATE), ("8.4.27alpha2", INDETERMINATE),
    ("8.5.12beta1", INDETERMINATE),
    # Below the fix it stays exposed, and an end-of-life branch has no fix to wait for.
    ("8.3.35RC1", EXPOSED), ("8.3.35-dev", EXPOSED), ("8.4.0alpha2", EXPOSED),
    ("8.1.99-dev", EXPOSED),
])
def test_build_variants_and_prerelease_tags_on_a_host(matrix, version, verdict):
    want = MEDIUM if verdict is INDETERMINATE else HIGH
    assert grade(host(version), matrix) == (verdict, want)


def test_sapi_never_changes_the_verdict(matrix):
    results = {grade(asset(Evidence(HOST, "web1", "8.3.35", s, {})), matrix) for s in Sapi}
    assert results == {(EXPOSED, HIGH)}


# Reads the later sections combine

# A host that confirms PHP is there on a package the matrix does not list.
UNPLACED = packaged("8.3.6", "ubuntu", "8.3.6-0ubuntu0.24.04.13").evidence[0]
# A host whose read found no PHP, and hosts whose reads said nothing at all.
NO_PHP = ev(HOST, None, {"php_present": "false"})
SILENT = ev(HOST, None)
FAILED = ev(HOST, None, note="ssh timed out")
SILENCES = [SILENT, FAILED]
# A host that reported a version string nobody can place.
GARBLED = ev(HOST, "garbage")


# Confidence

@pytest.mark.parametrize("source", [HOST, CLOUD])
def test_inside_reads_that_settle_it_are_high_confidence(matrix, source):
    assert grade(asset(ev(source, "8.3.35")), matrix) == (EXPOSED, HIGH)
    assert grade(asset(ev(source, "8.3.36")), matrix) == (PATCHED, HIGH)


@pytest.mark.parametrize("source", [HOST, CLOUD, NETWORK])
def test_a_read_that_saw_php_without_placing_it_is_indeterminate_at_medium(matrix, source):
    for version in ("8.6.0", "9.0.1", "8.3", "garbage"):
        assert grade(asset(ev(source, version)), matrix) == (INDETERMINATE, MEDIUM)


def test_a_repo_declaration_that_places_nothing_stays_low(matrix):
    # A repo pin declares a runtime, so it keeps LOW whatever it declares.
    for version in ("8.6.0", "9.0.1", "8.3", "8.3-apache", "garbage"):
        assert grade(asset(ev(REPO, version)), matrix) == (INDETERMINATE, LOW)


def test_network_below_fix_is_a_low_confidence_lead(matrix):
    # An outside read cannot see a distro backport, so EXPOSED from the network stays a lead.
    assert grade(asset(ev(NETWORK, "8.3.35")), matrix) == (EXPOSED, LOW)
    assert grade(asset(ev(NETWORK, "7.4.33")), matrix) == (EXPOSED, LOW)


def test_a_patched_network_read_is_a_low_confidence_lead(matrix):
    # A banner is easy to spoof or rewrite, so a fix it claims earns no more confidence than an
    # exposure it claims.
    assert grade(asset(ev(NETWORK, "8.3.36")), matrix) == (PATCHED, LOW)
    assert grade(asset(ev(HOST, "8.3.36")), matrix) == (PATCHED, HIGH)


@pytest.mark.parametrize("version, verdict", [
    ("7.4.33", EXPOSED), ("8.3.35", EXPOSED), ("8.4.26", EXPOSED),
    ("8.3.36", PATCHED), ("8.4.27", PATCHED), ("8.5.12", PATCHED)])
def test_a_network_read_that_settles_the_verdict_is_never_above_low(matrix, version, verdict):
    assert grade(asset(ev(NETWORK, version)), matrix) == (verdict, LOW)


def test_a_hidden_version_is_indeterminate_at_medium(matrix):
    hidden = ev(NETWORK, None, {"php_present": "true"})
    assert grade(asset(hidden), matrix) == (INDETERMINATE, MEDIUM)


def test_confidence_comes_from_the_deciding_evidence(matrix):
    assert grade(asset(ev(NETWORK, "8.3.35"), ev(HOST, "8.3.36")), matrix) == (PATCHED, HIGH)


def test_an_unplaced_package_build_is_indeterminate_at_medium(matrix):
    # PHP is there on a package the matrix does not list, whichever distro it names.
    assert grade(asset(UNPLACED), matrix) == (INDETERMINATE, MEDIUM)
    assert grade(packaged("8.9.9", "centos", "8.9.9-1.el9"), matrix) == (INDETERMINATE, MEDIUM)


def test_an_asset_where_every_read_was_silent_is_indeterminate_at_low(matrix):
    assert grade(asset(*SILENCES), matrix) == (INDETERMINATE, LOW)


def test_one_read_that_saw_php_lifts_an_unsettled_asset_to_medium(matrix):
    assert grade(asset(*SILENCES, GARBLED), matrix) == (INDETERMINATE, MEDIUM)


# Precedence and ties

RANKED = [
    (HOST, CLOUD), (HOST, NETWORK), (HOST, REPO),
    (CLOUD, NETWORK), (CLOUD, REPO), (NETWORK, REPO),
]


def pair(top, top_version, low, low_version, top_first):
    evs = [ev(top, top_version), ev(low, low_version)]
    return asset(*(evs if top_first else reversed(evs)))


@pytest.mark.parametrize("top_first", [True, False])
@pytest.mark.parametrize("top, low", RANKED)
def test_a_patched_top_source_beats_an_exposed_lower_one(matrix, top, low, top_first):
    assert grade(pair(top, "8.3.36", low, "8.3.35", top_first), matrix)[0] is PATCHED


@pytest.mark.parametrize("top_first", [True, False])
@pytest.mark.parametrize("top, low", RANKED)
def test_an_exposed_top_source_beats_a_patched_lower_one(matrix, top, low, top_first):
    assert grade(pair(top, "8.3.35", low, "8.3.36", top_first), matrix)[0] is EXPOSED


def test_lower_ranked_evidence_is_ignored_once_a_top_rank_settles_it(matrix):
    a = asset(ev(HOST, "8.3.36"), ev(NETWORK, "8.3.35"), ev(REPO, "8.3.35"))
    assert grade(a, matrix) == (PATCHED, HIGH)


SAMPLES = {
    EXPOSED: ev(HOST, "8.3.35"),
    INDETERMINATE: GARBLED,
    PATCHED: ev(HOST, "8.3.36"),
    NOT_PHP: NO_PHP,
}
WORST_FIRST = [EXPOSED, INDETERMINATE, PATCHED, NOT_PHP]
ALONE = {
    EXPOSED: (EXPOSED, HIGH),
    INDETERMINATE: (INDETERMINATE, MEDIUM),
    PATCHED: (PATCHED, HIGH),
    NOT_PHP: (NOT_PHP, HIGH),
}


@pytest.mark.parametrize("worse, better", list(itertools.combinations(WORST_FIRST, 2)))
def test_tied_evidence_resolves_to_the_worst_verdict(matrix, worse, better):
    for order in ((worse, better), (better, worse)):
        assert grade(asset(*(SAMPLES[v] for v in order)), matrix)[0] is worse


def test_the_worst_verdict_wins_in_every_order_of_six_reads(matrix):
    # The four kinds of read that say something, and two that say nothing.
    reads = [*SAMPLES.values(), *SILENCES]
    for order in itertools.permutations(reads):
        assert grade(asset(*order), matrix) == (EXPOSED, HIGH)


@pytest.mark.parametrize("verdict", WORST_FIRST)
def test_silent_reads_never_decide_beside_a_read_that_saw_php(matrix, verdict):
    for order in itertools.permutations([SAMPLES[verdict], *SILENCES]):
        assert grade(asset(*order), matrix) == ALONE[verdict]


CASES = [
    pytest.param([SILENT, ev(NETWORK, "7.4.33")], (EXPOSED, LOW),
                 id="silent host and a network exposure"),
    pytest.param([ev(HOST, "8.3.36"), ev(NETWORK, "8.3.35")], (PATCHED, HIGH),
                 id="host patched over a stale network exposure"),
    pytest.param([UNPLACED, ev(NETWORK, "8.3.36")], (INDETERMINATE, MEDIUM),
                 id="unplaced host and a network patched read"),
    pytest.param([UNPLACED, ev(NETWORK, "7.4.33")], (EXPOSED, LOW),
                 id="unplaced host and a network exposure"),
    pytest.param([NO_PHP, ev(NETWORK, "7.4.33")], (EXPOSED, LOW),
                 id="host that found no php and a network exposure"),
    pytest.param([ev(HOST, "8.3.35"), ev(HOST, "8.3.36")], (EXPOSED, HIGH),
                 id="fused pair of host reads, exposed and patched"),
]


@pytest.mark.parametrize("reads, want", CASES)
def test_these_mixes_of_reads_grade_the_same_in_either_order(matrix, reads, want):
    for order in (reads, list(reversed(reads))):
        assert grade(asset(*order), matrix) == want


@pytest.mark.parametrize(
    "read", [SILENT, FAILED, GARBLED, UNPLACED, ev(HOST, None, {"php_present": "true"})],
    ids=["silent", "failed", "garbled", "unplaced", "php-present"])
def test_a_host_that_settles_nothing_does_not_hide_a_network_lead(matrix, read):
    lead = ev(NETWORK, "7.4.33")
    for order in ((read, lead), (lead, read)):
        assert grade(asset(*order), matrix) == (EXPOSED, LOW)


def test_a_silent_host_beside_a_network_lead_surfaces_the_lead(matrix):
    verdict, confidence = grade(asset(ev(HOST, None), ev(NETWORK, "7.4.33")), matrix)
    assert verdict is EXPOSED
    assert verdict is not NOT_PHP
    assert confidence is LOW


def test_a_host_read_that_settles_it_still_beats_a_network_lead(matrix):
    # Ground truth wins: a patched host over a stale network exposure, in either order.
    patched, stale = ev(HOST, "8.3.36"), ev(NETWORK, "8.3.35")
    for order in ((patched, stale), (stale, patched)):
        assert grade(asset(*order), matrix) == (PATCHED, HIGH)


SAW_PHP = [
    pytest.param(UNPLACED, id="unplaced package"),
    pytest.param(ev(HOST, "8.6.0"), id="unknown branch"),
    pytest.param(ev(HOST, "8.3.36RC1"), id="pre-release"),
    pytest.param(GARBLED, id="garbled version"),
    pytest.param(ev(HOST, None, {"php_present": "true"}), id="php-present"),
]


@pytest.mark.parametrize("lower", [ev(CLOUD, "8.3.36"), ev(NETWORK, "8.3.36"), ev(REPO, "8.3.36")],
                         ids=["cloud", "network", "repo"])
@pytest.mark.parametrize("higher", SAW_PHP)
def test_a_patched_read_cannot_clear_a_higher_read_that_saw_php(matrix, higher, lower):
    for order in ((higher, lower), (lower, higher)):
        assert grade(asset(*order), matrix) == (INDETERMINATE, MEDIUM)


def test_the_confidence_comes_from_the_highest_exposure(matrix):
    # The network exposure is a lead at LOW. The repo's HIGH sits below it and does not lift it.
    reads = [ev(NETWORK, "7.4.33"), ev(REPO, "8.3.35", {"confidence": "HIGH"})]
    for order in (reads, list(reversed(reads))):
        assert grade(asset(*order), matrix) == (EXPOSED, LOW)


def test_a_patched_read_clears_an_exposure_but_not_the_unplaced_read_above_it(matrix):
    # The cloud's patched read outranks the network exposure, and the unplaced host outranks both.
    reads = [UNPLACED, ev(CLOUD, "8.3.36"), ev(NETWORK, "8.3.35")]
    for order in itertools.permutations(reads):
        assert grade(asset(*order), matrix) == (INDETERMINATE, MEDIUM)


def test_a_patched_read_on_a_lower_source_does_not_clear_a_higher_exposure(matrix):
    assert grade(asset(ev(HOST, "8.3.35"), ev(CLOUD, "8.3.36")), matrix) == (EXPOSED, HIGH)


def test_a_higher_patched_read_stands_over_a_lower_unplaced_read(matrix):
    hidden = ev(NETWORK, None, {"php_present": "true"})
    for order in ((ev(HOST, "8.3.36"), hidden), (hidden, ev(HOST, "8.3.36"))):
        assert grade(asset(*order), matrix) == (PATCHED, HIGH)


def test_a_host_that_found_no_php_stands_over_a_lower_unplaced_read(matrix):
    hidden = ev(NETWORK, None, {"php_present": "true"})
    for order in ((NO_PHP, hidden), (hidden, NO_PHP)):
        assert grade(asset(*order), matrix) == (NOT_PHP, HIGH)


def test_exposures_on_two_ranks_report_the_higher_rank(matrix):
    for order in itertools.permutations([ev(HOST, "8.3.35"), ev(NETWORK, "7.4.33")]):
        assert grade(asset(*order), matrix) == (EXPOSED, HIGH)


def test_a_mixed_asset_grades_the_same_in_every_order(matrix):
    reads = [UNPLACED, ev(CLOUD, "8.3.36"), ev(NETWORK, "8.3.35"), ev(REPO, "8.3.35"), SILENT]
    for order in itertools.permutations(reads):
        assert grade(asset(*order), matrix) == (INDETERMINATE, MEDIUM)


def test_a_patched_sibling_never_hides_an_exposed_machine(matrix):
    # Two machines behind one hostname merge into one asset with two host reads at the same rank.
    patched = ev(HOST, "8.3.36", {"hostname": "web"})
    exposed = ev(HOST, "8.3.35", {"hostname": "web"})
    for order in itertools.permutations([patched, patched, exposed]):
        assert grade(asset(*order), matrix) == (EXPOSED, HIGH)


def test_an_unplaced_sibling_keeps_a_patched_machine_indeterminate(matrix):
    patched = ev(HOST, "8.3.36", {"hostname": "web"})
    unplaced = ev(HOST, "8.6.0", {"hostname": "web"})
    for order in itertools.permutations([patched, unplaced]):
        assert grade(asset(*order), matrix) == (INDETERMINATE, MEDIUM)


def test_ports_80_and_443_of_one_name_tie_on_the_worst_verdict(matrix):
    assert grade(asset(ev(NETWORK, "8.3.36"), ev(NETWORK, "8.3.35")), matrix) == (EXPOSED, LOW)


def test_ties_below_a_host_that_read_nothing_resolve_the_same_way(matrix):
    a = asset(SILENT, ev(NETWORK, "8.3.36"), ev(NETWORK, "8.3.35"))
    assert grade(a, matrix) == (EXPOSED, LOW)


def test_an_exposed_tie_keeps_the_strongest_confidence(matrix):
    pins = [ev(REPO, "8.3.35", {"confidence": c}) for c in ("LOW", "HIGH", "MEDIUM")]
    for order in itertools.permutations(pins):
        assert grade(asset(*order), matrix) == (EXPOSED, HIGH)


def test_a_milder_tie_keeps_the_weakest_confidence(matrix):
    pins = [ev(REPO, "8.3.36", {"confidence": c}) for c in ("HIGH", "MEDIUM", "LOW")]
    for order in itertools.permutations(pins):
        assert grade(asset(*order), matrix) == (PATCHED, LOW)


def test_the_confidence_belongs_to_the_winning_verdict_alone(matrix):
    # A sure patched read does not lend its confidence to the exposure that outranks it.
    reads = [
        ev(REPO, "8.3.35", {"confidence": "MEDIUM"}),
        ev(REPO, "8.3.35", {"confidence": "LOW"}),
        ev(REPO, "8.3.36", {"confidence": "HIGH"}),
    ]
    for order in itertools.permutations(reads):
        assert grade(asset(*order), matrix) == (EXPOSED, MEDIUM)


def test_an_asset_with_no_evidence_is_indeterminate(matrix):
    assert grade(Asset("web1", "host", []), matrix) == (INDETERMINATE, LOW)


def test_grading_leaves_the_asset_untouched(matrix):
    a = asset(ev(NETWORK, "8.3.35"), ev(HOST, "8.3.36", {"distro": "ubuntu"}))
    before = copy.deepcopy(a)
    grade(a, matrix)
    assert a == before


def test_grade_evidence_grades_one_evidence_without_the_precedence_rule(matrix):
    assert grade_evidence(ev(NETWORK, "8.3.35"), matrix) == (EXPOSED, LOW)
    assert grade_evidence(ev(HOST, "8.3.36"), matrix) == (PATCHED, HIGH)


def test_grade_evidence_tells_an_unplaced_read_from_a_silent_one(matrix):
    assert grade_evidence(UNPLACED, matrix) == (INDETERMINATE, MEDIUM)
    assert grade_evidence(SILENT, matrix) == (INDETERMINATE, LOW)


# Distro builds

SEEDED = [
    ("ubuntu", "8.1.2-1ubuntu2.28"),
    ("debian", "8.4.27-1~deb13u1"),
    ("debian", "8.2.35-1~deb12u1"),
    ("alpine", "8.3.36-r0"),
    ("alpine", "8.4.27-r0"),
    ("alpine", "8.5.12-r0"),
    ("suse", "8.3.36"),
]

LATER = [
    ("ubuntu", "8.1.2-1ubuntu2.29"),
    ("ubuntu", "8.1.2-1ubuntu2.100"),
    ("debian", "8.4.27-1~deb13u2"),
    ("debian", "8.2.35-1~deb12u3"),
    ("alpine", "8.3.36-r1"),
    ("alpine", "8.4.27-r12"),
    ("alpine", "8.5.12-r1"),
    ("suse", "8.3.36-150700.3.24.1"),
    ("suse", "8.3.36-150700.3.30.2"),
    ("suse", "8.3.36+git1"),
    ("suse", "8.3.37"),
]

UNRECOGNIZED = [
    ("ubuntu", "8.1.2-1ubuntu2.27"),
    ("ubuntu", "8.1.2-1ubuntu2.5"),
    ("ubuntu", "8.1.2-1ubuntu2.28.1"),
    ("ubuntu", "8.1.2-1ubuntu2.28~esm1"),
    ("ubuntu", "8.3.6-0ubuntu0.24.04.13"),
    ("ubuntu", "8.4.27-r0"),
    ("debian", "8.4.26-1"),
    ("debian", "8.4.28-1~deb13u1"),
    ("debian", "8.4.27-1~deb12u1"),
    ("debian", "8.2.35-1~deb12u1+b1"),
    ("alpine", "8.3.35-r0"),
    ("alpine", "8.3.36"),
    ("alpine", "8.3.36-r"),
    ("suse", "8.2.29-150700.1.1"),
    ("suse", "8.3.35-150700.3.1.1"),
    ("suse", "8.3.36x"),
    # The micro of a bare upstream version keeps the width the matrix gives it. 8.3.360 has a digit
    # more, 8.3.351 is 8.3.35 with a release number glued on, and 8.3.100 is out of the range.
    ("suse", "8.3.360"),
    ("suse", "8.3.351"),
    ("suse", "8.3.100"),
    ("centos", "8.3.36-1.el9"),
    ("", "8.1.2-1ubuntu2.28"),
]

# Builds that carry a distro revision, so detected_version can stand in for package_version.
CARRIED = [
    ("ubuntu", "8.1.2-1ubuntu2.28"),
    ("ubuntu", "8.1.2-1ubuntu2.29"),
    ("debian", "8.4.27-1~deb13u1"),
    ("debian", "8.4.27-1~deb13u2"),
    ("debian", "8.2.35-1~deb12u1"),
    ("alpine", "8.3.36-r0"),
    ("alpine", "8.4.27-r0"),
    ("alpine", "8.5.12-r0"),
    ("alpine", "8.3.36-r1"),
    ("suse", "8.3.36-150700.3.24.1"),
]


@pytest.mark.parametrize("distro, build", SEEDED)
def test_every_seeded_build_is_likely_patched(matrix, distro, build):
    assert matrix.backport_verdict(distro, build) is PATCHED
    # The package decides, whether php -v gave its upstream number, nothing, or garbage.
    for reported in (upstream(build), None, "garbage"):
        assert grade(packaged(reported, distro, build), matrix) == (PATCHED, HIGH)


@pytest.mark.parametrize("distro, build", LATER)
def test_a_later_revision_of_a_known_build_is_likely_patched(matrix, distro, build):
    assert matrix.backport_verdict(distro, build) is PATCHED
    assert grade(packaged(upstream(build), distro, build), matrix) == (PATCHED, HIGH)


@pytest.mark.parametrize("distro, build", CARRIED)
def test_a_build_carried_in_detected_version_is_looked_up_without_a_package_version(
        matrix, distro, build):
    assert grade(host(build, distro=distro), matrix) == (PATCHED, HIGH)


@pytest.mark.parametrize("distro, build", UNRECOGNIZED)
def test_an_unrecognized_package_build_is_indeterminate(matrix, distro, build):
    assert matrix.backport_verdict(distro, build) is None
    # Below the fix, at it, above it, matching the build or not: the number proves nothing.
    for reported in (upstream(build), None, "8.3.35", "8.3.36", "8.4.99", "7.4.3"):
        assert grade(packaged(reported, distro, build), matrix) == (INDETERMINATE, MEDIUM)


def test_backport_lookup_ignores_case_and_padding_in_the_distro_and_padding_in_the_build(matrix):
    assert matrix.backport_verdict(" Ubuntu ", " 8.1.2-1ubuntu2.28 ") is PATCHED


def test_backport_lookup_refuses_blank_and_oversized_input(matrix):
    assert matrix.backport_verdict("", "8.1.2-1ubuntu2.28") is None
    assert matrix.backport_verdict("ubuntu", "") is None
    assert matrix.backport_verdict("ubuntu", "8.1.2-1ubuntu2." + "9" * 5000) is None


@pytest.mark.parametrize("known, got, want", [
    # The build itself, and a later one of the same series.
    ("8.3.36", "8.3.36", True),
    ("8.3.36", "8.3.37", True),
    ("8.3.36", "8.3.99", True),
    ("8.3.36", "8.3.36-150700.3.24.1", True),
    ("8.3.36", "8.3.36+git1", True),
    ("8.1.2-1ubuntu2.28", "8.1.2-1ubuntu2.29", True),
    ("8.4.27-1~deb13u1", "8.4.27-1~deb13u2", True),
    ("8.4.27-r0", "8.4.27-r1", True),
    # A revision after a distro tag is a counter. A longer run is still a higher number.
    ("8.1.2-1ubuntu2.28", "8.1.2-1ubuntu2.100", True),
    ("8.4.27-r0", "8.4.27-r12", True),
    # An earlier build, and another series.
    ("8.3.36", "8.3.35", False),
    ("8.3.36", "8.4.40", False),
    ("8.3.36", "8.30.40", False),
    ("8.1.2-1ubuntu2.28", "8.1.2-1ubuntu2.27", False),
    ("8.1.2-1ubuntu2.28", "8.1.2-1ubuntu2.5", False),
    ("8.4.27-1~deb13u1", "8.4.28-1~deb13u1", False),
    ("8.4.27-r0", "8.4.26-r9", False),
    # The micro of a bare version is not a counter. A longer run is not a later micro, whether a
    # digit was added (360, 361), a release number was glued on (351 is 35 and release 1,
    # 36150700 is 36 and the SUSE release), or zeros were padded in (036).
    ("8.3.36", "8.3.360", False),
    ("8.3.36", "8.3.361", False),
    ("8.3.36", "8.3.351", False),
    ("8.3.36", "8.3.36150700", False),
    ("8.3.36", "8.3.036", False),
    ("8.3.36", "8.3.100", False),
])
def test_a_build_counts_as_a_later_one_only_in_its_own_series(known, got, want):
    assert _at_or_after(known, got) is want


def test_the_shipped_suse_row_does_not_clear_a_micro_with_a_release_glued_on(matrix):
    # 8.3.35 is below the fix. With release 1 glued on it reads 8.3.351, which as one number is
    # past 8.3.36.
    assert matrix.backport_verdict("suse", "8.3.351") is None
    assert grade(packaged(None, "suse", "8.3.351"), matrix) == (INDETERMINATE, MEDIUM)
    assert matrix.backport_verdict("suse", "8.3.37") is PATCHED


def test_a_package_version_without_a_distro_is_indeterminate(matrix):
    assert grade(host("8.3.35", package_version="8.3.35-1"), matrix) == (INDETERMINATE, MEDIUM)


@pytest.mark.parametrize("distro", ["ubuntu", "debian", "alpine", "suse"])
@pytest.mark.parametrize("version, verdict", [
    # End of life has no upstream fix, and a distro name does not imply a backport.
    ("8.1.2", EXPOSED), ("8.0.30", EXPOSED), ("7.4.33", EXPOSED),
    ("8.3.35", EXPOSED), ("8.4.26", EXPOSED),
    ("8.3.36", PATCHED), ("8.4.27", PATCHED), ("8.4.99", PATCHED), ("8.2.35", PATCHED),
    ("8.6.0", INDETERMINATE),
])
def test_a_distro_name_alone_is_no_package_evidence(matrix, version, verdict, distro):
    # The bare version still grades against the fixed micros, as it does for PHP built from
    # source on a distro host. Package evidence is a build string or a revision in the version.
    want = MEDIUM if verdict is INDETERMINATE else HIGH
    assert grade(host(version, distro=distro), matrix) == (verdict, want)


def test_the_seeded_ubuntu_build_in_detected_version_is_patched(matrix):
    assert grade(host("8.1.2-1ubuntu2.28", distro="ubuntu"), matrix) == (PATCHED, HIGH)


@pytest.mark.parametrize("version", ["8.4.28-1~deb13u1", "8.4.26-1~deb13u1"])
def test_an_unlisted_debian_build_is_indeterminate_on_either_side_of_the_fix(matrix, version):
    assert grade(host(version, distro="debian"), matrix) == (INDETERMINATE, MEDIUM)


def test_a_variant_suffix_is_no_package_evidence(matrix):
    # The bare number decides, with or without a distro name beside it.
    for signals in ({}, {"distro": "ubuntu"}, {"distro": "suse"}):
        assert grade(host("8.3.36-fpm", **signals), matrix) == (PATCHED, HIGH)
        assert grade(host("8.3.35-fpm", **signals), matrix) == (EXPOSED, HIGH)


@pytest.mark.parametrize("suffix", [
    "-1", "+1", "~1", "-1ubuntu2.28", "-1~deb13u1", "-r0", "-r12", "-150700.3.24.1",
])
def test_these_suffixes_are_distro_revisions(matrix, suffix):
    # A revision is package evidence even with no distro signal, and without a distro the matrix
    # cannot place the build.
    assert grade(host("8.3.36" + suffix), matrix) == (INDETERMINATE, MEDIUM)


@pytest.mark.parametrize("suffix", [
    "-r", "-", "-x", "-fpm", "-zts", "-nts", "-cli", "-apache", "+dfsg", "_1", "-alpine3.19",
    "-fpm-alpine3.19",
])
def test_these_suffixes_are_no_distro_revision(matrix, suffix):
    # No revision number follows, so the bare number decides.
    assert grade(host("8.3.36" + suffix), matrix) == (PATCHED, HIGH)
    assert grade(host("8.3.35" + suffix), matrix) == (EXPOSED, HIGH)


@pytest.mark.parametrize("version", [
    "8.1.2-1ubuntu2.5", "8.1.2-1ubuntu2.28", "8.3.36-r0", "8.4.27-1~deb13u1",
    "8.3.36-150700.3.24.1",
])
def test_a_distro_revision_without_a_distro_signal_is_never_graded_bare(matrix, version):
    # Ubuntu's php -v prints the revision, so a probe can see one with no distro signal. Graded
    # bare, 8.1.2-1ubuntu2.28 would read as exposed by the end-of-life rule.
    assert grade(host(version), matrix) == (INDETERMINATE, MEDIUM)


@pytest.mark.parametrize("reported", ["8.3.35", "8.1.1", "8.1.20"])
def test_a_detected_version_that_disagrees_with_the_build_is_indeterminate(matrix, reported):
    got = grade(packaged(reported, "ubuntu", "8.1.2-1ubuntu2.28"), matrix)
    assert got == (INDETERMINATE, MEDIUM)


def test_a_longer_micro_is_not_the_same_php(matrix):
    assert grade(packaged("8.3.3", "alpine", "8.3.36-r0"), matrix) == (INDETERMINATE, MEDIUM)


def test_a_detected_version_that_is_the_whole_build_agrees_with_it(matrix):
    build = "8.1.2-1ubuntu2.28"
    assert grade(packaged(build, "ubuntu", build), matrix) == (PATCHED, HIGH)


def test_blank_package_signals_count_as_absent(matrix):
    assert grade(host("8.3.35", distro="", package_version="  "), matrix) == (EXPOSED, HIGH)


def test_a_packaged_build_seen_from_the_network_is_a_low_confidence_lead(matrix):
    signals = {"distro": "ubuntu", "package_version": "8.1.2-1ubuntu2.28"}
    assert grade(asset(ev(NETWORK, "8.1.2", signals)), matrix) == (PATCHED, LOW)


# Nothing to grade

@pytest.mark.parametrize("flag", ["false", "False", " FALSE "])
@pytest.mark.parametrize("version", [None, "", "   "])
def test_a_host_read_that_says_there_is_no_php_is_not_php(matrix, version, flag):
    assert grade(asset(ev(HOST, version, {"php_present": flag})), matrix) == (NOT_PHP, HIGH)


def test_a_distro_name_beside_a_no_php_flag_still_clears(matrix):
    assert grade(host(None, php_present="false", distro="ubuntu"), matrix) == (NOT_PHP, HIGH)


@pytest.mark.parametrize("version", [None, "", "   "])
def test_a_silent_host_read_is_indeterminate(matrix, version):
    assert grade(asset(ev(HOST, version)), matrix) == (INDETERMINATE, LOW)


def test_a_note_on_a_host_read_blocks_a_no_php_claim(matrix):
    a = asset(ev(HOST, None, {"php_present": "false"}, note="php.ini unreadable"))
    assert grade(a, matrix) == (INDETERMINATE, LOW)


def test_a_version_outweighs_a_contradicting_no_php_flag(matrix):
    assert grade(asset(ev(HOST, "8.3.35", {"php_present": "false"})), matrix) == (EXPOSED, HIGH)
    assert grade(asset(ev(HOST, "garbage", {"php_present": "false"})), matrix) == (
        INDETERMINATE, MEDIUM)


@pytest.mark.parametrize("present", ["true", "True", " TRUE "])
@pytest.mark.parametrize("source", [HOST, CLOUD, NETWORK, REPO])
def test_php_present_without_a_version_is_indeterminate(matrix, source, present):
    want = LOW if source is REPO else MEDIUM
    got = grade(asset(ev(source, None, {"php_present": present})), matrix)
    assert got == (INDETERMINATE, want)


def test_php_present_true_still_counts_beside_a_note(matrix):
    a = asset(ev(HOST, None, {"php_present": "true"}, note="php.ini unreadable"))
    assert grade(a, matrix) == (INDETERMINATE, MEDIUM)


@pytest.mark.parametrize("signals", [{}, {"php_present": "false"}])
@pytest.mark.parametrize("source", [CLOUD, NETWORK, REPO])
def test_only_a_host_read_can_say_php_is_absent(matrix, source, signals):
    # Hidden headers, an empty cloud record, or a repo with no pin leave PHP unproven absent.
    assert grade(asset(ev(source, None, signals)), matrix) == (INDETERMINATE, LOW)


@pytest.mark.parametrize("source", [HOST, CLOUD, NETWORK, REPO])
def test_a_failed_read_degrades_to_indeterminate(matrix, source):
    failed = ev(source, None, note="connection timed out")
    assert grade(asset(failed), matrix) == (INDETERMINATE, LOW)


def test_a_note_does_not_override_a_parseable_version(matrix):
    assert grade(asset(ev(HOST, "8.3.35", note="php.ini unreadable")), matrix) == (EXPOSED, HIGH)


# Signals that are not tidy strings

@pytest.mark.parametrize("signals", [
    {"distro": None}, {"package_version": None}, {"php_present": None}, {"kind": None},
    {"confidence": None}, {"distro": 5}, {"package_version": 7}, {"php_present": 0},
    {"kind": ["composer-constraint"]}, {"confidence": 3.5}, {"distro": ["ubuntu"]},
])
@pytest.mark.parametrize("source", [HOST, NETWORK, REPO])
def test_a_none_or_non_string_signal_cannot_crash_grading(matrix, source, signals):
    verdict, confidence = grade(asset(ev(source, "8.3.35", signals)), matrix)
    assert isinstance(verdict, Verdict)
    assert isinstance(confidence, Confidence)


def test_none_signals_read_as_absent(matrix):
    none = {k: None for k in ("distro", "package_version", "php_present", "kind", "confidence")}
    assert grade(asset(ev(HOST, "8.3.35", none)), matrix) == (EXPOSED, HIGH)
    assert grade(asset(ev(REPO, "8.3.35", none)), matrix) == (EXPOSED, LOW)


def test_a_none_note_and_a_non_string_version_cannot_crash_grading(matrix):
    noteless = Evidence(HOST, "loc", None, Sapi.FPM, {"php_present": "false"}, None)
    assert grade(asset(noteless), matrix) == (NOT_PHP, HIGH)
    assert grade(asset(ev(HOST, 8)), matrix) == (INDETERMINATE, MEDIUM)


# Repository pins

@pytest.mark.parametrize("tag", ["8.3", "8.3-apache", "8-fpm", "latest", "${PHP_VERSION}-fpm"])
def test_a_floating_repo_tag_grades_indeterminate_at_low(matrix, tag):
    assert grade(asset(ev(REPO, tag, {"confidence": "LOW"})), matrix) == (INDETERMINATE, LOW)


@pytest.mark.parametrize("declared, want", [
    ("HIGH", HIGH), ("MEDIUM", MEDIUM), ("LOW", LOW), ("high", HIGH), (" High ", HIGH),
    ("", LOW), ("bogus", LOW), ("1", LOW),
])
def test_a_repo_pin_takes_the_scanners_own_confidence(matrix, declared, want):
    assert grade(asset(ev(REPO, "8.3.35", {"confidence": declared})), matrix) == (EXPOSED, want)


def test_a_repo_pin_with_no_declared_confidence_is_low(matrix):
    assert grade(asset(ev(REPO, "8.3.35")), matrix) == (EXPOSED, LOW)


@pytest.mark.parametrize(
    "kind", ["composer-constraint", "Composer-Constraint", " COMPOSER-CONSTRAINT "])
@pytest.mark.parametrize("version", ["8.3.0", "8.3.35", "8.3.36", "8.4.99", "7.4.0"])
def test_a_composer_constraint_never_grades_as_a_build(matrix, version, kind):
    signals = {"kind": kind, "confidence": "LOW"}
    assert grade(asset(ev(REPO, version, signals)), matrix) == (INDETERMINATE, LOW)


def test_a_repo_pin_that_cannot_be_graded_is_low_however_exact_the_scanner_thinks_it_is(matrix):
    digest = ev(REPO, "sha256:" + "ab" * 32, {"confidence": "HIGH"})
    assert grade(asset(digest), matrix) == (INDETERMINATE, LOW)


FLOOR = ev(REPO, "8.1.0", {"kind": "composer-constraint", "confidence": "LOW"})
FLOATING = ev(REPO, "8.3-apache", {"confidence": "LOW"})
PATCHED_PIN = ev(REPO, "8.3.36", {"confidence": "HIGH"})
EXPOSED_PIN = ev(REPO, "8.3.35", {"confidence": "HIGH"})


def test_a_composer_floor_beside_an_exact_pin_does_not_unsettle_the_repo(matrix):
    # A floor declares what the app needs and says nothing about what runs.
    for order in ((FLOOR, PATCHED_PIN), (PATCHED_PIN, FLOOR)):
        assert grade(asset(*order), matrix) == (PATCHED, HIGH)
    for order in ((FLOOR, EXPOSED_PIN), (EXPOSED_PIN, FLOOR)):
        assert grade(asset(*order), matrix) == (EXPOSED, HIGH)


def test_a_floating_tag_beside_a_patched_pin_leaves_the_repo_indeterminate(matrix):
    # A floating tag declares a runtime and does not place it, so the exact pin cannot clear it.
    for order in ((FLOATING, PATCHED_PIN), (PATCHED_PIN, FLOATING)):
        assert grade(asset(*order), matrix) == (INDETERMINATE, LOW)


def test_a_floating_tag_beside_an_exposed_pin_is_exposed(matrix):
    for order in ((FLOATING, EXPOSED_PIN), (EXPOSED_PIN, FLOATING)):
        assert grade(asset(*order), matrix) == (EXPOSED, HIGH)


def test_a_floor_alone_is_indeterminate_at_low(matrix):
    assert grade(asset(FLOOR), matrix) == (INDETERMINATE, LOW)


# Loading a matrix

GOOD = {
    "fixed": {"8.3": {"micro": 36, "notes": "n"}},
    "eol": {"through": "8.1", "notes": "n"},
    "backports": [],
}


def changed(**over):
    return {**GOOD, **over}


def without(key):
    return {k: v for k, v in GOOD.items() if k != key}


def entry(**over):
    return {"distro": "ubuntu", "build": "8.1.2-1ubuntu2.28", "verdict": "LIKELY_PATCHED", **over}


def write(tmp_path, data):
    path = tmp_path / "matrix.json"
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return str(path)


def test_loader_reads_a_minimal_matrix(tmp_path):
    m = load_matrix(write(tmp_path, GOOD))
    assert m.fixed_micro("8.3") == 36
    assert m.is_eol("8.1")
    assert not m.is_eol("8.2")
    assert m.backport_verdict("ubuntu", "8.1.2-1ubuntu2.28") is None


BAD = {
    "empty file": "",
    "not json": "{",
    "top level list": [],
    "no fixed": without("fixed"),
    "no eol": without("eol"),
    "no backports": without("backports"),
    "fixed a list": changed(fixed=[]),
    "fixed branch not a branch": changed(fixed={"eight": {"micro": 1}}),
    "fixed branch with a micro": changed(fixed={"8.3.1": {"micro": 1}}),
    "fixed entry not an object": changed(fixed={"8.3": 36}),
    "micro a string": changed(fixed={"8.3": {"micro": "36"}}),
    "micro a float": changed(fixed={"8.3": {"micro": 36.0}}),
    "micro a bool": changed(fixed={"8.3": {"micro": True}}),
    "micro negative": changed(fixed={"8.3": {"micro": -1}}),
    "micro missing": changed(fixed={"8.3": {"notes": "n"}}),
    "same branch twice": (
        '{"fixed": {"8.3": {"micro": 36}, "8.3": {"micro": 35}},'
        ' "eol": {"through": "8.1"}, "backports": []}'
    ),
    "same branch spelled twice": changed(fixed={"8.3": {"micro": 36}, "8.03": {"micro": 35}}),
    "eol a list": changed(eol=["8.1"]),
    "eol without through": changed(eol={"notes": "n"}),
    "eol through not a branch": changed(eol={"through": "old"}),
    "fixed branch inside the eol range": changed(fixed={"8.1": {"micro": 5}}),
    "backports an object": changed(backports={}),
    "backport not an object": changed(backports=["ubuntu"]),
    "backport without a distro": changed(
        backports=[{"build": "8.1.2-1", "verdict": "LIKELY_PATCHED"}]),
    "backport blank distro": changed(backports=[entry(distro="  ")]),
    "backport without a build": changed(
        backports=[{"distro": "ubuntu", "verdict": "LIKELY_PATCHED"}]),
    "backport build not a string": changed(backports=[entry(build=8)]),
    "backport build absurdly long": changed(backports=[entry(build="8" * 500)]),
    "backport without a verdict": changed(backports=[{"distro": "ubuntu", "build": "8.1.2-1"}]),
    "backport verdict unknown": changed(backports=[entry(verdict="SAFE")]),
    "backport verdict indeterminate": changed(backports=[entry(verdict="INDETERMINATE")]),
    "backport verdict not a string": changed(backports=[entry(verdict=["LIKELY_PATCHED"])]),
}


@pytest.mark.parametrize("data", list(BAD.values()), ids=list(BAD))
def test_loader_rejects_a_malformed_matrix_and_names_the_file(tmp_path, data):
    path = write(tmp_path, data)
    with pytest.raises(MatrixError) as err:
        load_matrix(path)
    assert path in str(err.value)


def test_loader_names_a_missing_file(tmp_path):
    with pytest.raises(MatrixError, match="nope.json"):
        load_matrix(str(tmp_path / "nope.json"))


def test_loader_rejects_a_file_that_is_not_utf8(tmp_path):
    path = tmp_path / "matrix.json"
    path.write_bytes(b'{"fixed": "\xff"}')
    with pytest.raises(MatrixError):
        load_matrix(str(path))


def custom(tmp_path, *entries):
    return load_matrix(write(tmp_path, changed(backports=list(entries))))


def test_a_known_vulnerable_build_matches_exactly_and_only_exactly(tmp_path):
    m = custom(tmp_path, entry(distro="debian", build="8.4.26-1", verdict="EXPOSED"))
    assert m.backport_verdict("debian", "8.4.26-1") is EXPOSED
    assert m.backport_verdict("debian", "8.4.26-2") is None
    assert grade(packaged("8.4.26", "debian", "8.4.26-1"), m) == (EXPOSED, HIGH)


@pytest.mark.parametrize("flip", [False, True])
def test_a_known_vulnerable_build_outranks_a_patched_series_that_covers_it(tmp_path, flip):
    rows = [
        entry(distro="debian", build="8.4.27-1~deb13u1"),
        entry(distro="debian", build="8.4.27-1~deb13u2", verdict="EXPOSED"),
    ]
    m = custom(tmp_path, *(reversed(rows) if flip else rows))
    assert m.backport_verdict("debian", "8.4.27-1~deb13u2") is EXPOSED
    assert m.backport_verdict("debian", "8.4.27-1~deb13u3") is PATCHED


def test_a_known_build_without_a_revision_number_matches_only_itself(tmp_path):
    # Nothing to compare a later revision against, and int() must never see an empty string.
    m = custom(tmp_path, entry(distro="debian", build="8.4.27-1~deb13u"))
    assert m.backport_verdict("debian", "8.4.27-1~deb13u") is PATCHED
    assert m.backport_verdict("debian", "8.4.27-1~deb13u2") is None
