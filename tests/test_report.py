import copy
import json
import time

import pytest

from php_radar.knowledge import DATA_PATH, grade, load_matrix
from php_radar.model import Asset, AssetInventory, Evidence, Sapi, Source
from php_radar.report import redact, render_console, render_json, render_sarif


def asset_exposed():
    return Asset("web1", "host", [Evidence(Source.HOST, "web1", "8.3.35", Sapi.FPM, {})])


def test_json_has_verdict_and_confidence():
    data = json.loads(render_json([asset_exposed()], load_matrix(DATA_PATH)))
    assert data["assets"][0]["verdict"] == "EXPOSED"
    assert data["assets"][0]["confidence"] == "HIGH"

def test_sarif_is_valid_shape():
    doc = json.loads(render_sarif([asset_exposed()], load_matrix(DATA_PATH)))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]

def test_no_credentials_in_any_output():
    # A signal named like a secret reaches none of the three outputs.
    a = Asset("web1", "host", [Evidence(Source.CLOUD, "arn:...:web1", "8.3.35", Sapi.FPM,
             {"aws_secret_access_key": "AKIA_SECRET_SHOULD_NOT_APPEAR"})])
    m = load_matrix(DATA_PATH)
    for text in (render_console([a], m), render_json([a], m), render_sarif([a], m)):
        assert "AKIA_SECRET_SHOULD_NOT_APPEAR" not in text


HOST, CLOUD, NETWORK, REPO = Source.HOST, Source.CLOUD, Source.NETWORK, Source.REPO
MASK = "[REDACTED]"

# Non-ASCII and control characters are built with chr() so the source stays plain ASCII.
ESC = chr(27)
CYRILLIC_A = chr(0x430)
E_ACUTE = chr(0xE9)
GRINNING = chr(0x1F600)

# Made-up credentials in the shapes real ones take. They are split so no literal in this file
# is a whole token. The AWS pair is the documentation example from AWS.
GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
AWS_ID = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
HEX_40 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
HEX_64 = "0123456789abcdef" * 4

# An armored PGP key is a header, armor headers, a blank line, base64, a checksum, and a footer.
PGP_OPEN = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n"
PGP_BODY = "lQVYBGJxExampleBodyLineZq9xAAAA"
PGP_CLOSE = "\n=ab1C\n-----END PGP PRIVATE KEY BLOCK-----"
PGP_BLOCK = PGP_OPEN + PGP_BODY + PGP_CLOSE


@pytest.fixture(scope="module")
def matrix():
    return load_matrix(DATA_PATH)


def ev(source, location, version, sapi=Sapi.UNKNOWN, note="", **signals):
    return Evidence(source, location, version, sapi, signals, note)


def asset(key, *evidence, kind="host"):
    return Asset(key, kind, list(evidence))


def exposed(key="web1"):
    return asset(key, ev(HOST, key, "8.3.35", Sapi.FPM))


def patched(key="web2"):
    return asset(key, ev(HOST, key, "8.3.36", Sapi.FPM))


def indeterminate(key="web3"):
    return asset(key, ev(NETWORK, "https://" + key, None, php_present="true"))


def clear(key="web4"):
    return asset(key, ev(HOST, key, None, php_present="false"))


ALL_FOUR = [exposed, patched, indeterminate, clear]


def as_json(assets, matrix):
    return json.loads(render_json(assets, matrix))


def as_sarif(assets, matrix):
    return json.loads(render_sarif(assets, matrix))


# JSON

def test_json_summary_counts_every_verdict(matrix):
    data = as_json([f() for f in ALL_FOUR] + [exposed("web5")], matrix)
    assert data["tool"] == "php-radar"
    assert data["summary"] == {
        "total": 5,
        "by_verdict": {"EXPOSED": 2, "INDETERMINATE": 1, "LIKELY_PATCHED": 1, "NOT_PHP": 1},
    }


def test_json_asset_shape(matrix):
    row = as_json([exposed()], matrix)["assets"][0]
    assert {k: row[k] for k in ("key", "kind", "verdict", "confidence", "sapi", "version")} == {
        "key": "web1", "kind": "host", "verdict": "EXPOSED", "confidence": "HIGH",
        "sapi": "FPM", "version": "8.3.35",
    }
    assert row["evidence"] == [{
        "source": "HOST", "location": "web1", "detected_version": "8.3.35", "sapi": "FPM",
        "verdict": "EXPOSED", "confidence": "HIGH", "signals": {}, "note": "",
    }]


def test_json_asset_grade_is_what_grade_returns(matrix):
    mixed = asset("web1", ev(HOST, "web1", "8.3.36"), ev(NETWORK, "https://web1", "8.3.35"))
    assets = [f() for f in ALL_FOUR] + [mixed]
    for a, row in zip(assets, as_json(assets, matrix)["assets"]):
        verdict, confidence = grade(a, matrix)
        assert (row["verdict"], row["confidence"]) == (verdict.name, confidence.name)


def test_json_keeps_input_order_and_never_merges_equal_keys(matrix):
    rows = as_json([exposed("web1"), patched("web1")], matrix)["assets"]
    assert [(r["key"], r["verdict"]) for r in rows] == [
        ("web1", "EXPOSED"), ("web1", "LIKELY_PATCHED")]


def test_json_of_nothing(matrix):
    data = as_json([], matrix)
    assert data["assets"] == []
    assert data["summary"]["total"] == 0


def test_each_read_keeps_its_own_grade_under_the_asset_grade(matrix):
    host = ev(HOST, "web1", "8.3.36", Sapi.FPM)
    net = ev(NETWORK, "https://web1", "8.3.35")
    for order in ([host, net], [net, host]):
        row = as_json([asset("web1", *order)], matrix)["assets"][0]
        assert (row["verdict"], row["confidence"]) == ("LIKELY_PATCHED", "HIGH")
        assert [(e["source"], e["verdict"], e["confidence"]) for e in row["evidence"]] == [
            ("HOST", "LIKELY_PATCHED", "HIGH"), ("NETWORK", "EXPOSED", "LOW")]


def test_the_read_that_decided_the_verdict_comes_first(matrix):
    # The host said nothing, so the network lead made this asset EXPOSED.
    silent = ev(HOST, "web1", None)
    lead = ev(NETWORK, "https://web1", "7.4.33")
    row = as_json([asset("web1", silent, lead)], matrix)["assets"][0]
    assert (row["verdict"], row["confidence"]) == ("EXPOSED", "LOW")
    assert [e["source"] for e in row["evidence"]] == ["NETWORK", "HOST"]


@pytest.mark.parametrize("reads, sapi", [
    ([(HOST, Sapi.FPM), (NETWORK, Sapi.UNKNOWN)], "FPM"),
    ([(CLOUD, Sapi.UNKNOWN), (NETWORK, Sapi.CGI)], "CGI"),
    ([(HOST, Sapi.FPM), (NETWORK, Sapi.MOD_PHP)], "FPM"),
    ([(HOST, Sapi.UNKNOWN), (NETWORK, Sapi.UNKNOWN)], "UNKNOWN"),
    ([], "UNKNOWN"),
])
def test_sapi_comes_from_the_most_authoritative_read_that_knows_it(matrix, reads, sapi):
    a = asset("web1", *[ev(source, "loc", "8.3.35", s) for source, s in reads])
    assert as_json([a], matrix)["assets"][0]["sapi"] == sapi


def test_version_is_the_package_build_when_there_is_one(matrix):
    pkg = ev(HOST, "web1", "8.1.2", Sapi.FPM, distro="ubuntu", package_version="8.1.2-1ubuntu2.28")
    row = as_json([asset("web1", pkg)], matrix)["assets"][0]
    assert (row["verdict"], row["confidence"]) == ("LIKELY_PATCHED", "HIGH")
    assert row["version"] == "8.1.2-1ubuntu2.28"
    assert row["evidence"][0]["detected_version"] == "8.1.2"


def test_version_is_null_when_no_read_has_one(matrix):
    row = as_json([indeterminate()], matrix)["assets"][0]
    assert row["version"] is None
    assert row["evidence"][0]["detected_version"] is None


def test_a_no_php_asset_takes_no_version_from_a_disagreeing_banner(matrix):
    banner = ev(NETWORK, "https://web4", "8.3.36")
    row = as_json([asset("web4", ev(HOST, "web4", None, php_present="false"), banner)],
                  matrix)["assets"][0]
    assert (row["verdict"], row["confidence"]) == ("NOT_PHP", "HIGH")
    assert row["version"] is None
    assert [(e["source"], e["detected_version"]) for e in row["evidence"]] == [
        ("HOST", None), ("NETWORK", "8.3.36")]


def test_an_asset_with_no_evidence_still_renders(matrix):
    ghost = asset("ghost")
    row = as_json([ghost], matrix)["assets"][0]
    assert (row["verdict"], row["confidence"], row["evidence"]) == ("INDETERMINATE", "LOW", [])
    assert as_sarif([ghost], matrix)["runs"][0]["results"][0]["locations"] == []
    assert "  ghost (host): LOW confidence, no PHP version found" in render_console(
        [ghost], matrix).splitlines()


def test_plain_signals_come_through_unchanged(matrix):
    signals = {"distro": "ubuntu", "package_version": "8.1.2-1ubuntu2.28",
               "memory_limit": "128M", "session.upload_progress.enabled": "0"}
    a = asset("web1", ev(HOST, "web1", "8.1.2", Sapi.FPM, **signals))
    assert as_json([a], matrix)["assets"][0]["evidence"][0]["signals"] == signals


def test_odd_signal_values_come_out_as_text(matrix):
    a = asset("web1", ev(HOST, "web1", "8.3.35", Sapi.FPM, port=443, gone=None))
    signals = as_json([a], matrix)["assets"][0]["evidence"][0]["signals"]
    assert signals == {"port": "443", "gone": ""}


@pytest.mark.parametrize("name", [
    "aws_secret_access_key", "AWS_SESSION_TOKEN", "GITHUB_TOKEN", "Password", "db_passwd",
    "apiKey", "X-Api-Key", "private_key", "client_secret", "Authorization", "credentials_file",
    "ssh_passphrase", "DB_PWD", "oauth_state", "Bearer",
    "db_pass", "PASS", "pw", "PW", "mysql-pw", "user.pass", "pass_hash",
])
def test_signal_names_holding_a_secret_word_are_dropped(matrix, name):
    a = asset("web1", ev(HOST, "web1", "8.3.35", Sapi.FPM, **{name: "hunter2", "distro": "x"}))
    assert as_json([a], matrix)["assets"][0]["evidence"][0]["signals"] == {"distro": "x"}


@pytest.mark.parametrize("name", ["passthru", "bypass", "compass", "passenger", "pwned", "swp"])
def test_signal_names_that_only_contain_pass_or_pw_are_kept(matrix, name):
    a = asset("web1", ev(HOST, "web1", "8.3.35", Sapi.FPM, **{name: "1"}))
    assert as_json([a], matrix)["assets"][0]["evidence"][0]["signals"] == {name: "1"}


# A name is read as words, so a capital after a lowercase letter or a digit starts a new one
# (dbPass), and so does a capitalized word after a run of capitals (DBPass). Joined in one case,
# dbpass or DBPASS, a name cannot be told from bypass and compass, and these tests leave it out.

CAMEL_CREDENTIALS = ["dbPass", "userPw", "apiKey", "authToken", "DBPass", "SMTPPass", "smtpPW",
                     "dbPassHash", "db2Pass", "dbPASS", "rootPw"]
CAMEL_PLAIN = ["Passenger", "PASSENGER", "BYPASS", "COMPASS", "PWNED", "Pwned", "userPwned",
               "byPassenger", "Compass", "compassPoint", "PassportNumber"]


@pytest.mark.parametrize("name", CAMEL_CREDENTIALS)
def test_camel_case_signal_names_holding_a_secret_word_are_dropped(matrix, name):
    a = asset("web1", ev(HOST, "web1", "8.3.35", Sapi.FPM, **{name: "hunter2", "distro": "x"}))
    assert as_json([a], matrix)["assets"][0]["evidence"][0]["signals"] == {"distro": "x"}


@pytest.mark.parametrize("name", CAMEL_PLAIN)
def test_camel_case_signal_names_that_only_contain_pass_or_pw_are_kept(matrix, name):
    a = asset("web1", ev(HOST, "web1", "8.3.35", Sapi.FPM, **{name: "1"}))
    assert as_json([a], matrix)["assets"][0]["evidence"][0]["signals"] == {name: "1"}


@pytest.mark.parametrize("name", CAMEL_CREDENTIALS + CAMEL_PLAIN + [
    "db_pass", "PASS", "mysql-pw", "user.pw", "token", "passthru", "bypass", "pwned"])
def test_the_signal_screen_and_the_value_rule_agree_on_a_name(matrix, name):
    # One definition of a name decides both, so a name cannot be masked in text and still be
    # printed as a signal, or the other way round.
    a = asset("web1", ev(HOST, "web1", "8.3.35", Sapi.FPM, **{name: "hunter2"}))
    dropped = name not in as_json([a], matrix)["assets"][0]["evidence"][0]["signals"]
    assert dropped == ("hunter2" not in redact(name + "=hunter2"))


def test_secret_shapes_inside_a_plain_signal_are_masked(matrix):
    a = asset("web1", ev(HOST, "web1", "8.3.35", Sapi.FPM, banner="cloned with " + GH_TOKEN))
    signals = as_json([a], matrix)["assets"][0]["evidence"][0]["signals"]
    assert signals == {"banner": "cloned with " + MASK}


def test_a_credential_used_as_a_signal_name_is_masked(matrix):
    a = asset("web1", ev(HOST, "web1", "8.3.35", Sapi.FPM, **{GH_TOKEN: "x"}))
    signals = as_json([a], matrix)["assets"][0]["evidence"][0]["signals"]
    assert signals == {MASK: "x"}


def test_rendering_leaves_the_input_alone(matrix):
    a = asset("web1", ev(HOST, "web1", "8.3.35", Sapi.FPM, aws_secret_access_key="hunter2",
                         banner="token=abc123"), ev(NETWORK, "https://web1", "8.3.35"))
    before = copy.deepcopy(a)
    for render in (render_console, render_json, render_sarif):
        render([a], matrix)
    assert a == before


# SARIF

def test_sarif_envelope(matrix):
    doc = as_sarif([exposed()], matrix)
    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "php-radar"
    assert [r["id"] for r in driver["rules"]] == [
        "PHP2SHELL-EXPOSED", "PHP2SHELL-INDETERMINATE",
        "PHP2SHELL-LIKELY_PATCHED", "PHP2SHELL-NOT_PHP"]


def test_sarif_has_one_result_per_asset_in_order_even_with_equal_keys(matrix):
    results = as_sarif([patched("web1"), exposed("web1"), clear()], matrix)["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == [
        "PHP2SHELL-LIKELY_PATCHED", "PHP2SHELL-EXPOSED", "PHP2SHELL-NOT_PHP"]


def test_sarif_rule_index_points_at_its_rule(matrix):
    run = as_sarif([f() for f in ALL_FOUR], matrix)["runs"][0]
    assert len(run["results"]) == 4
    for result in run["results"]:
        assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]


@pytest.mark.parametrize("make, level, kind", [
    (exposed, "error", None),
    (indeterminate, "warning", None),
    (patched, "none", "pass"),
    (clear, "none", "notApplicable"),
])
def test_sarif_level_and_kind_follow_the_verdict(matrix, make, level, kind):
    run = as_sarif([make()], matrix)["runs"][0]
    result = run["results"][0]
    assert result["level"] == level
    assert result.get("kind") == kind
    assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["defaultConfiguration"] == {
        "level": level}


def test_sarif_message_names_the_asset_and_its_grade(matrix):
    result = as_sarif([exposed()], matrix)["runs"][0]["results"][0]
    assert result["message"]["text"] == "EXPOSED: web1 (host), HIGH confidence, PHP 8.3.35, FPM"


def test_sarif_repo_read_is_a_file_location(matrix):
    pin = ev(REPO, "docker\\app dir\\Dockerfile", "7.4.33", repo="acme/site")
    result = as_sarif([asset("acme/site", pin, kind="repo")], matrix)["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "docker/app%20dir/Dockerfile"}, "region": {"startLine": 1}}


def test_sarif_file_uri_is_percent_encoded_ascii(matrix):
    pin = ev(REPO, "caf" + E_ACUTE + "/Dockerfile", "7.4.33", repo="acme/site")
    result = as_sarif([asset("acme/site", pin, kind="repo")], matrix)["runs"][0]["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "caf%C3%A9/Dockerfile"


def test_sarif_survives_a_file_name_with_an_undecodable_byte(matrix):
    # os.walk hands back such a name as a lone surrogate.
    pin = ev(REPO, "bad" + chr(0xDC80) + "/Dockerfile", "7.4.33", repo="acme/site")
    doc = as_sarif([asset("acme/site", pin, kind="repo")], matrix)
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert uri["uri"] == "bad%5Cudc80/Dockerfile"


def test_sarif_other_reads_are_named_resources(matrix):
    loc = as_sarif([exposed()], matrix)["runs"][0]["results"][0]["locations"][0]
    assert loc["logicalLocations"] == [{"name": "web1", "kind": "resource"}]
    assert "physicalLocation" not in loc


def test_sarif_first_location_is_the_lead_and_the_rest_are_related(matrix):
    host = ev(HOST, "web1", "8.3.36", Sapi.FPM)
    net = ev(NETWORK, "https://web1", "8.3.35")
    result = as_sarif([asset("web1", net, host)], matrix)["runs"][0]["results"][0]
    assert len(result["locations"]) == 1
    assert result["locations"][0]["logicalLocations"][0]["name"] == "web1"
    assert result["locations"][0]["message"]["text"] == "HOST: LIKELY_PATCHED, HIGH confidence"
    (related,) = result["relatedLocations"]
    assert related["id"] == 0
    assert related["logicalLocations"][0]["name"] == "https://web1"
    assert related["message"]["text"] == "NETWORK: EXPOSED, LOW confidence"


def test_sarif_numbers_each_related_location(matrix):
    reads = [ev(HOST, "web1", "8.3.36"), ev(CLOUD, "arn:web1", "8.3.36"),
             ev(NETWORK, "https://web1", "8.3.36")]
    result = as_sarif([asset("web1", *reads)], matrix)["runs"][0]["results"][0]
    assert [r["id"] for r in result["relatedLocations"]] == [0, 1]
    assert [r["logicalLocations"][0]["name"] for r in result["relatedLocations"]] == [
        "arn:web1", "https://web1"]


def test_sarif_properties_carry_the_triage_fields(matrix):
    props = as_sarif([exposed()], matrix)["runs"][0]["results"][0]["properties"]
    assert props == {"verdict": "EXPOSED", "confidence": "HIGH", "sapi": "FPM",
                     "version": "8.3.35"}


def test_sarif_of_nothing_is_still_a_valid_document(matrix):
    doc = as_sarif([], matrix)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


# Console

HEADER = "php-radar: {n} (EXPOSED {a}, INDETERMINATE {b}, LIKELY_PATCHED {c}, NOT_PHP {d})"


def test_console_pins_the_whole_layout(matrix):
    host = ev(HOST, "web1", "8.3.36", Sapi.FPM)
    net = ev(NETWORK, "https://web1", "8.3.35", note="redirected")
    assert render_console([asset("web1", net, host)], matrix).splitlines() == [
        HEADER.format(n="1 asset", a=0, b=0, c=1, d=0),
        "",
        "LIKELY_PATCHED (1)",
        "  web1 (host): HIGH confidence, PHP 8.3.36, FPM",
        "    HOST     LIKELY_PATCHED  HIGH    web1  PHP 8.3.36",
        "    NETWORK  EXPOSED         LOW     https://web1  PHP 8.3.35  (redirected)",
    ]


def test_console_groups_by_verdict_with_exposed_first(matrix):
    text = render_console([patched(), clear(), indeterminate(), exposed()], matrix)
    heads = [text.index(h) for h in (
        "EXPOSED (1)", "INDETERMINATE (1)", "LIKELY_PATCHED (1)", "NOT_PHP (1)")]
    assert heads == sorted(heads)
    keys = [text.index(k + " (host)") for k in ("web1", "web3", "web2", "web4")]
    assert keys == sorted(keys)


def test_console_lines_carry_no_trailing_space(matrix):
    bare = asset("web1", ev(HOST, "", None, php_present="true"))
    text = render_console([bare, exposed(), indeterminate()], matrix)
    assert all(line == line.rstrip() for line in text.splitlines())


def test_console_leads_with_the_count(matrix):
    assert render_console([], matrix) == HEADER.format(n="0 assets", a=0, b=0, c=0, d=0)
    two = render_console([exposed(), patched()], matrix)
    assert two.startswith(HEADER.format(n="2 assets", a=1, b=0, c=1, d=0))


def test_console_omits_the_sapi_when_unknown(matrix):
    lines = render_console([asset("web1", ev(HOST, "web1", "8.3.35"))], matrix).splitlines()
    assert "  web1 (host): HIGH confidence, PHP 8.3.35" in lines
    assert "UNKNOWN" not in "\n".join(lines)


def test_console_says_what_is_true_when_there_is_no_version(matrix):
    # A hidden version and a failed read both land here, so the wording cannot claim PHP is there.
    refused = asset("web5", ev(NETWORK, "https://web5", None, note="connection refused"))
    lines = render_console([indeterminate(), refused, clear()], matrix).splitlines()
    assert "  web3 (host): MEDIUM confidence, no PHP version found" in lines
    assert "  web5 (host): LOW confidence, no PHP version found" in lines
    assert "  web4 (host): HIGH confidence, no PHP found" in lines


def test_console_lists_assets_with_equal_keys_separately(matrix):
    text = render_console([exposed("web1"), patched("web1")], matrix)
    assert text.count("web1 (host)") == 2
    assert "EXPOSED (1)" in text
    assert "LIKELY_PATCHED (1)" in text


def test_console_puts_the_surer_finding_first_within_a_group(matrix):
    lead = asset("lead", ev(NETWORK, "https://lead", "8.3.35"))
    sure = asset("sure", ev(HOST, "sure", "8.3.35"))
    text = render_console([lead, sure], matrix)
    assert text.index("sure (host)") < text.index("lead (host)")


def test_console_keeps_input_order_among_equal_findings(matrix):
    text = render_console([exposed("b"), exposed("a"), exposed("c")], matrix)
    spots = [text.index(k + " (host)") for k in "bac"]
    assert spots == sorted(spots)


def test_console_cannot_be_driven_by_a_hostile_banner(matrix):
    banner = "ok" + ESC + "[2J\nEXPOSED (9)"
    a = asset("web1", ev(NETWORK, "https://web1", None, note=banner, php_present="true"))
    text = render_console([a], matrix)
    assert ESC not in text
    assert not any(line.startswith("EXPOSED") for line in text.splitlines())
    assert "ok\\x1b[2J\\nEXPOSED (9)" in text


def test_console_spells_out_lookalike_characters(matrix):
    text = render_console([asset("web" + CYRILLIC_A + "1", ev(HOST, "web1", "8.3.35"))], matrix)
    assert text.isascii()
    assert "web\\u04301 (host)" in text


def test_every_renderer_emits_plain_ascii(matrix):
    a = asset("caf" + E_ACUTE, ev(HOST, "web1", "8.3.35", Sapi.FPM, x=GRINNING, note=ESC))
    for render in (render_console, render_json, render_sarif):
        assert render([a], matrix).isascii()
    assert as_json([a], matrix)["assets"][0]["key"] == "caf" + E_ACUTE


# Redaction

@pytest.mark.parametrize("text, secret", [
    ("cloned with " + GH_TOKEN + " ok", GH_TOKEN),
    ("pat github_pat_" + "11ABCDEFG0abcdefghijklmnopqrstuvwxyz0123456789", "11ABCDEFG0"),
    ("id " + AWS_ID + " here", AWS_ID),
    ("placeholder AKIA_EXAMPLE_KEY_ID", "AKIA_EXAMPLE_KEY_ID"),
    ("glued to a word: tokenx" + GH_TOKEN, GH_TOKEN),
    ("glued to a word: idx" + AWS_ID, AWS_ID),
    ("glued to a word: xBearer abcdefghij0123456789", "abcdefghij0123456789"),
    ("temporary ASIA" + "ABCDEFGHIJ012345 here", "ABCDEFGHIJ012345"),
    ("value " + AWS_SECRET + " end", AWS_SECRET),
    ("sent Bearer abcdefghij0123456789 to", "abcdefghij0123456789"),
    ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA"),
    ("jwt eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".dozjgNryP4J3jVmNHl0w5N_Xg",
     "eyJzdWIiOiIxMjM0NTY3ODkwIn0"),
    ("slack xoxb-" + "123456789012-abcdefghijklmnop", "123456789012-abcdefghijklmnop"),
    ("google AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q", "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"),
    ("stripe sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc", "4eC39HqLyjWDarjtT1zdp7dc"),
    ("openai sk-" + "proj-abcdefghijklmnopqrstuvwxyz0123", "abcdefghijklmnopqrstuvwxyz0123"),
    ("gitlab glpat-" + "abcdefghij0123456789", "abcdefghij0123456789"),
    ("npm npm_" + "abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghijklmnopqrstuvwxyz0123456789"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
     "MIIEowIBAAKCAQEA"),
    ("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq", "MIIEvQIBADANBgkq"),
    ("clone https://deploy:hunter2@git.example.com/acme/site.git", "hunter2"),
    ("password=hunter2", "hunter2"),
    ("TOKEN: abc123def456", "abc123def456"),
    ('{"api_key": "k3y-value-here"}', "k3y-value-here"),
    ("aws_secret_access_key = " + AWS_SECRET, AWS_SECRET),
    ("GET /login?client_secret=s3cr3t&grant=x", "s3cr3t"),
    ('passphrase="correct horse battery staple"', "battery"),
    ("passphrase='correct horse battery staple'", "battery"),
    ('password="never closed with spaces', "spaces"),
    ("password='never closed with spaces", "spaces"),
    ('password = "a,b;c&d"', "c&d"),
    ("X-Auth: abcdefgh", "abcdefgh"),
])
def test_redact_masks_what_looks_like_a_credential(text, secret):
    out = redact(text)
    assert secret not in out
    assert MASK in out


@pytest.mark.parametrize("text, masked", [
    ("https://deploy:p@ss@git.example.com/x", "https://" + MASK + "@git.example.com/x"),
    ("client_secret=s3cr3t&grant=x", "client_secret=" + MASK + "&grant=x"),
    ("Authorization: Bearer abc", "Authorization: " + MASK),
    ('{"api_key": "k3y"}', '{"api_key": "' + MASK + '"}'),
    ('{"api_key":"k3y","port":8443}', '{"api_key":"' + MASK + '","port":8443}'),
    ("passphrase='two words' next", "passphrase='" + MASK + "' next"),
    ("x " + AWS_SECRET + " y", "x " + MASK + " y"),
    ("password:hunter2", "password:" + MASK),
    ("login failed, password:hunter2 rejected", "login failed, password:" + MASK + " rejected"),
    ("https://deploy:pa/ss@db.example/app", "https://" + MASK + "@db.example/app"),
    ("failed to dial deploy:hunter2@db.internal:5432: refused",
     "failed to dial " + MASK + "@db.internal:5432: refused"),
    ("root:p@ss@db1 unreachable", MASK + "@db1 unreachable"),
])
def test_redact_keeps_the_context_around_the_mask(text, masked):
    assert redact(text) == masked


# Three forms of credential that are easy to miss: a name and a colon with no space, URL userinfo
# in odd shapes, and a PGP private key block.

# 1. A credential name, a colon, and no space after it.

@pytest.mark.parametrize("text, secret", [
    ("password:hunter2", "hunter2"),
    ("PASSWORD:hunter2", "hunter2"),
    ("api_key:ABCD1234efgh5678", "ABCD1234efgh5678"),
    ("X-Api-Key:abc123def456", "abc123def456"),
    ("db.password:hunter2", "hunter2"),
    ("login failed, password:hunter2 rejected", "hunter2"),
    ("password :hunter2", "hunter2"),
    ("password: hunter2", "hunter2"),
    ("Authorization:Bearer abc", "abc"),
    ('password:"two words"', "words"),
    ('{"password":"hunter2"}', "hunter2"),
    # repr and JSON print a newline as a backslash and an n.
    ("login failed\\npassword:hunter2", "hunter2"),
    ("<b>password:hunter2</b>", "hunter2"),
    ("password:1234!abcd", "1234!abcd"),
    ("token:123abc", "123abc"),
    ("key:12.ab", "12.ab"),
])
def test_a_secret_after_a_colon_with_no_space_is_masked(text, secret):
    out = redact(text)
    assert secret not in out
    assert MASK in out


# A value is masked whatever it looks like. Only the name can spare it, and only a name that counts
# something. A lookahead on the value made the colon forms and the = form disagree.

@pytest.mark.parametrize("text, secret", [
    ("password: 123456", "123456"),
    ("password=123456", "123456"),
    ("password:123456", "123456"),
    ("password :123456", "123456"),
    ('{"password": 123456}', "123456"),
    ('{"password":123456}', "123456"),
    ("token: 3600", "3600"),
    ("token=3600", "3600"),
    ("api_key:493817265", "493817265"),
    ("secret: 42", "42"),
    ("passphrase: 1234", "1234"),
    ("Authorization: 12345678", "12345678"),
    ("db_pass=1234", "1234"),
])
def test_a_numeric_secret_is_masked_in_every_form(text, secret):
    assert secret not in redact(text)


@pytest.mark.parametrize("text", [
    "token_ttl=3600", "token_ttl:3600", "token_ttl: 3600", "token_ttl : 3600", "TOKEN_TTL=3600",
    "key_size: 2048", "key-size=2048", "auth_port:389", "password_timeout: 30",
    "secret_rotation_days:90", "token_timeout: 2.5", "api_key_count=3", "retry-token-limit=5",
    "key_rotation: 90", "SECRET_ROTATION=30",
    '{"token_ttl": 3600}', '{"token_ttl":3600,"port":8443}', "token_ttl => 3600 => 3600",
    "access_token_ttl=3600&grant=x",
])
def test_a_name_that_counts_something_is_left_alone(text):
    # The last segment of the name says it is a lifetime, a port, or a size, and not a credential.
    assert redact(text) == text


@pytest.mark.parametrize("text, secret", [
    ("account_key=abc123", "abc123"),
    ("transport_secret=abc123", "abc123"),
    ("portal_password=abc123", "abc123"),
    ("token_ttls=abc123", "abc123"),
    ("tokenttl=abc123", "abc123"),
    ("token_ttl_x=abc123", "abc123"),
    ("key_sized: abc123", "abc123"),
    ("api_key_port2=abc123", "abc123"),
    ("count_token=abc123", "abc123"),
    ("port_secret: abc123", "abc123"),
    ("ttl-key=abc123", "abc123"),
    ("ttl_password:abc123", "abc123"),
])
def test_only_a_whole_last_segment_spares_a_name(text, secret):
    assert secret not in redact(text)


@pytest.mark.parametrize("text", [
    "Password::defaults()", "Hash::password::make", "token::new", "$user->key::class",
])
def test_a_scope_operator_is_not_a_name_value_pair(text):
    assert redact(text) == text


def test_a_url_keeps_its_port_and_a_bare_host_and_port_may_lose_it():
    assert redact("https://keycloak:8443/auth/realms/master") == (
        "https://keycloak:8443/auth/realms/master")
    # Cosmetic and accepted: with no URL around it, keycloak:8443 reads as name:value, and so does
    # an image and its tag.
    assert redact("keycloak:8443") == "keycloak:" + MASK
    assert redact("token-service:1.2.3") == "token-service:" + MASK
    assert redact("ghcr.io/acme/token-service:1.2.3") == "ghcr.io/acme/token-service:1.2.3"


@pytest.mark.parametrize("text", [
    "arn:aws:lambda:us-east-1:111122223333:function:auth-service:prod",
    "arn:aws:lambda:us-east-1:111122223333:function:auth-service:12",
    "arn:aws:secretsmanager:us-east-1:111122223333:secret:MySecret-AbCdEf",
    "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
    "111122223333.dkr.ecr.us-east-1.amazonaws.com/auth-service:v1.2",
    "registry.example.com/key-vault-api:8.3.35-fpm",
])
def test_the_segments_of_an_arn_or_an_image_reference_are_not_name_value_pairs(text):
    assert redact(text) == text


# PHP prints name => value, and Go and Ansible write name := value.

@pytest.mark.parametrize("text, masked", [
    ("DB_PASSWORD => Zq9hunter2", "DB_PASSWORD => " + MASK),
    ("DB_PASSWORD => Zq9hunter2 => Zq9hunter2", "DB_PASSWORD => " + MASK),
    ('$_SERVER["DB_PASSWORD"] => Zq9hunter2', '$_SERVER["DB_PASSWORD"] => ' + MASK),
    ("$_ENV['API_TOKEN'] => Zq9hunter2", "$_ENV['API_TOKEN'] => " + MASK),
    ("[password] => Zq9hunter2", "[password] => " + MASK),
    ("'password' => 'Zq9hunter2'", "'password' => '" + MASK + "'"),
    ('"password" => "Zq9hunter2",', '"password" => "' + MASK + '",'),
    ("password := Zq9hunter2", "password := " + MASK),
    ("password:=Zq9hunter2", "password:=" + MASK),
    # A quote or a closing bracket may come before a plain =, as in a PHP assignment.
    ("$cfg['password'] = 'Zq9hunter2';", "$cfg['password'] = '" + MASK + "';"),
    ('$_ENV["API_TOKEN"]=Zq9hunter2;', '$_ENV["API_TOKEN"]=' + MASK + ";"),
    ("$db[pass] = Zq9hunter2", "$db[pass] = " + MASK),
])
def test_php_and_go_style_pairs_are_masked_whole(text, masked):
    assert redact(text) == masked


@pytest.mark.parametrize("text", [
    "memory_limit => 128M => 128M", "session.upload_progress.enabled => 0 => 0",
    "mysqli.default_port => 3306 => 3306", "session.cookie_secure => Off => Off",
    "[user] => bob", "Array\n(\n    [host] => db1\n)",
    # An empty value does not reach over to the next line.
    "[password] => \n[user] => bob", "password => \n",
])
def test_php_pairs_with_nothing_to_hide_are_left_alone(text):
    assert redact(text) == text


# A backslash escapes a quote inside a quoted value, so the span does not end there.

@pytest.mark.parametrize("text, masked", [
    ('password => "ab\\"cd"', 'password => "' + MASK + '"'),
    ("'password' => 'a\\'b'", "'password' => '" + MASK + "'"),
    ('{"password": "ab\\"cd"}', '{"password": "' + MASK + '"}'),
    ('password="ab\\"cd" next', 'password="' + MASK + '" next'),
    ("passphrase='it\\'s a phrase' next", "passphrase='" + MASK + "' next"),
    ('api_key: "k\\"3y" tail', 'api_key: "' + MASK + '" tail'),
    # An escaped backslash does not escape the quote after it.
    ('password => "ab\\\\" next', 'password => "' + MASK + '" next'),
    ('password => "a\\\\\\"b" next', 'password => "' + MASK + '" next'),
    # A backslash can escape a line break as well.
    ('password="ab\\\ncd" next', 'password="' + MASK + '" next'),
    ("password='ab\\\ncd' next", "password='" + MASK + "' next"),
])
def test_a_quoted_value_steps_over_an_escaped_quote(text, masked):
    assert redact(text) == masked


# var_dump puts the value on the line after the key, as string(N) "value". It does not escape a
# quote, and an object adds the visibility to the key.

VAR_DUMP = (
    "array(3) {\n"
    '  ["user"]=>\n'
    '  string(3) "bob"\n'
    '  ["password"]=>\n'
    '  string(7) "Zq9hunt"\n'
    '  ["port"]=>\n'
    "  int(3306)\n"
    "}"
)


def test_a_var_dump_block_masks_the_password_and_nothing_else():
    assert redact(VAR_DUMP) == VAR_DUMP.replace('"Zq9hunt"', '"' + MASK + '"')


@pytest.mark.parametrize("text, masked", [
    ('["password":protected]=>\n  string(7) "Zq9hunt"',
     '["password":protected]=>\n  string(7) "' + MASK + '"'),
    ('["secret":"Config":private]=>\n  string(7) "Zq9hunt"',
     '["secret":"Config":private]=>\n  string(7) "' + MASK + '"'),
    ('["secret":"App\\Config":private]=>\n  string(7) "Zq9hunt"',
     '["secret":"App\\Config":private]=>\n  string(7) "' + MASK + '"'),
    ('["password"]=>\n  string(9) "ab"cd"ef"', '["password"]=>\n  string(9) "' + MASK + '"'),
    ('["password"]=>\n  int(123456)', '["password"]=>\n  ' + MASK),
    ('["db_pass"]=>\n  float(1.5)', '["db_pass"]=>\n  ' + MASK),
    ('["db_pass"]=>\n  bool(false)', '["db_pass"]=>\n  ' + MASK),
    ('["password"]=> string(7) "Zq9hunt"', '["password"]=> ' + MASK),
])
def test_var_dump_forms_are_masked(text, masked):
    assert redact(text) == masked


@pytest.mark.parametrize("text", [
    '["user"]=>\n  string(3) "bob"', '["token_ttl"]=>\n  int(3600)', '["password"]=>\n  NULL',
    '["password"]=>\n  [user]',
])
def test_var_dump_entries_with_nothing_to_hide_are_left_alone(text):
    assert redact(text) == text


# A password is whatever a person typed, so with a space after the separator it runs to the end of
# the line. An Authorization value is a scheme and its parameters. Written inline, with no space
# after the separator, a value still ends at its delimiter.

NEGOTIATE = "YIIChwYGKwYBBQUCoIICezCCAnegJDAiBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYKKwYBBAGCNwICCqKCAkUE"
NTLM = "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


@pytest.mark.parametrize("text, masked", [
    ("password: a long passphrase with spaces", "password: " + MASK),
    ("password = a long passphrase with spaces", "password = " + MASK),
    ("Authorization: Negotiate " + NEGOTIATE, "Authorization: " + MASK),
    ('Authorization: Digest username="bob", realm="x", response="deadbeef"',
     "Authorization: " + MASK),
    ("note: password: correct horse\nnext line", "note: password: " + MASK + "\nnext line"),
    ("password=hunter2 rejected", "password=" + MASK + " rejected"),
    ("password=hunter2&next=/home", "password=" + MASK + "&next=/home"),
    ("pass: correct horse battery staple", "pass: " + MASK),
    ("PW = a b c", "PW = " + MASK),
])
def test_a_spaced_password_or_authorization_runs_to_the_end_of_the_line(text, masked):
    assert redact(text) == masked


def test_a_token_stops_at_its_delimiter_even_with_a_space_after_the_separator():
    # Only a password or an Authorization header can hold spaces. A token is one run of characters.
    assert redact("token: abc123 next") == "token: " + MASK + " next"
    assert redact("api_key = k3y next") == "api_key = " + MASK + " next"


@pytest.mark.parametrize("text, secret", [
    ("Authorization:Negotiate " + NEGOTIATE, NEGOTIATE),
    ("X-Auth:Negotiate " + NEGOTIATE, NEGOTIATE),
    ("X-Auth: NTLM " + NTLM, NTLM),
    ("X-Auth:NTLM " + NTLM, NTLM),
    ("Authorization:Digest abcdef0123456789", "abcdef0123456789"),
    ("Authorization:Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA"),
    ("X-Auth: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA"),
    ("X-Auth: Bearer abcdef0123", "abcdef0123"),
])
def test_an_auth_scheme_word_goes_with_its_value(text, secret):
    assert secret not in redact(text)


# pass and pw mark a credential only as a whole segment.

@pytest.mark.parametrize("text, secret", [
    ("db_pass=Zq9hunter2", "Zq9hunter2"),
    ("pass: Zq9hunter2", "Zq9hunter2"),
    ("PASS=Zq9hunter2", "Zq9hunter2"),
    ("PW=Zq9hunter2", "Zq9hunter2"),
    ("mysql-pw: Zq9hunter2", "Zq9hunter2"),
    ("pw:Zq9hunter2", "Zq9hunter2"),
    ("[db_pass] => Zq9hunter2", "Zq9hunter2"),
    # repr and JSON print a newline or a tab as a backslash and a letter.
    ("line one\\npass: Zq9hunter2", "Zq9hunter2"),
    ("line one\\nPW=Zq9hunter2", "Zq9hunter2"),
    ("line one\\npw:Zq9hunter2", "Zq9hunter2"),
    ("col\\tpass=Zq9hunter2", "Zq9hunter2"),
])
def test_pass_and_pw_name_a_credential(text, secret):
    assert secret not in redact(text)


@pytest.mark.parametrize("text", [
    "passthru=disabled", "bypass: true", "compass=north", "passenger: 3", "pwned=1", "bypass=1",
    "line one\\nbypass: true", "line one\\npassenger=3",
])
def test_words_that_only_contain_pass_or_pw_are_left_alone(text):
    assert redact(text) == text


# The same names written in camelCase. NAME stands for the name under test.

CAMEL_FORMS = [
    "NAME=Zq9hunter2", "NAME: Zq9hunter2", "NAME:Zq9hunter2", '{"NAME":"Zq9hunter2"}',
    "NAME => Zq9hunter2", "$cfg['NAME'] = 'Zq9hunter2';", '["NAME"]=>\n  string(10) "Zq9hunter2"',
]


@pytest.mark.parametrize("form", CAMEL_FORMS)
@pytest.mark.parametrize("name", CAMEL_CREDENTIALS)
def test_a_camel_case_credential_name_masks_its_value_in_every_form(name, form):
    assert "Zq9hunter2" not in redact(form.replace("NAME", name))


@pytest.mark.parametrize("form", ["NAME=1", "NAME: 1", "NAME:1", '{"NAME":"1"}', "NAME => 1"])
@pytest.mark.parametrize("name", CAMEL_PLAIN)
def test_camel_case_words_that_only_contain_pass_or_pw_are_left_alone(name, form):
    text = form.replace("NAME", name)
    assert redact(text) == text


@pytest.mark.parametrize("text, masked", [
    ("dbPass=Zq9hunter2", "dbPass=" + MASK),
    ("userPw: Zq9hunter2", "userPw: " + MASK),
    ("userPw:Zq9hunter2 next", "userPw:" + MASK + " next"),
    ('{"dbPass":"Zq9hunter2","port":3306}', '{"dbPass":"' + MASK + '","port":3306}'),
    ("$cfg['userPw'] = 'Zq9hunter2';", "$cfg['userPw'] = '" + MASK + "';"),
    ("SMTPPass: Zq9 hunter2", "SMTPPass: " + MASK),
    ("dbPassHash=Zq9hunter2", "dbPassHash=" + MASK),
    ("db2Pass=Zq9hunter2", "db2Pass=" + MASK),
    ("dbPASS=Zq9hunter2", "dbPASS=" + MASK),
    # A counting suffix spares a camelCase name the same way it spares a snake_case one.
    ("dbPass_ttl=3600", "dbPass_ttl=3600"),
    ("dbPass_ttl_x=Zq9hunter2", "dbPass_ttl_x=" + MASK),
])
def test_camel_case_pairs_keep_their_name_and_lose_their_value(text, masked):
    assert redact(text) == masked


# 2. Credentials in a URL, with an odd authority or none.

@pytest.mark.parametrize("text, secret", [
    ("https://deploy:S3cr3t@Pass@db.example/app", "S3cr3t"),
    ("https://deploy:S3cr3t@Pass@db.example/app", "Pass@db"),
    ("ftp://a:b@c:d@host/path", "c:d"),
    ("https://deploy:pa/ss-Zq9@db.example/app", "pa/ss-Zq9"),
    ("https://deploy:pa?ss-Zq9@db.example/app", "pa?ss-Zq9"),
    ("https://deploy:pa#ss-Zq9@db.example/app", "pa#ss-Zq9"),
    ("redis://:hunter2@cache:6379/0", "hunter2"),
    ("see https://deploy:wJalr/K7MDENG+bPx==@s3.example/b ok", "wJalr/K7MDENG+bPx=="),
])
def test_url_credentials_are_masked_in_unusual_shapes(text, secret):
    assert secret not in redact(text)


def test_a_url_stops_at_its_authority_when_it_can():
    # The exact rule runs first, so an @ further along is left as it was.
    assert redact("https://u:pw@host/path?email=bob@example.com") == (
        "https://" + MASK + "@host/path?email=bob@example.com")


@pytest.mark.parametrize("text, secret", [
    ("failed to dial deploy:hunter2@db.internal:5432: refused", "hunter2"),
    ("root:p@ss@db1 unreachable", "p@ss"),
    ("user:pass@host", "pass"),
    ("(deploy:hunter2@db1)", "hunter2"),
    ("dsn=deploy:hunter2@db1", "hunter2"),
    ("a,deploy:hunter2@db1;b", "hunter2"),
    ("deploy:hunter2@db.internal:5432/app", "hunter2"),
    ("failed\\ndeploy:hunter2@db1", "hunter2"),
    ("<td>deploy:hunter2@db1</td>", "hunter2"),
    ("|deploy:hunter2@db1", "hunter2"),
    ("!deploy:hunter2@db1", "hunter2"),
    ("?deploy:hunter2@db1", "hunter2"),
])
def test_a_userinfo_with_no_scheme_is_masked(text, secret):
    out = redact(text)
    assert secret not in out
    assert MASK + "@" in out


@pytest.mark.parametrize("text", [
    "git@github.com:acme/site.git", "bob@example.com", "mailto:bob@example.com",
    "email:admin@corp.example", "DNS:web1.corp.example, IP Address:10.0.0.5",
    "uses:actions/checkout@v4",
    "arn:aws:iam::123456789012:user/bob@example.com",
    "php:8.3.35-fpm@sha256:" + HEX_64,
    "composer require vendor/pkg:1.2.3@dev",
    # A name after a . : or @ continues a host, an ARN, or an address, so it starts nothing.
    "https://host/path.file:xyz@abc",
    "arn:aws:sns:us-east-1:111122223333:oncall:bob@corp.example",
    "bob@corp.example:cache@v2",
    "docker://registry.example.com:5000/php@sha256:" + HEX_64,
    "C:\\Users\\bob@corp.example\\site\\Dockerfile",
    "https://medium.com/@user/post", "https://registry.npmjs.org/@babel/core",
    "https://host.example/path?email=bob@example.com",
])
def test_addresses_and_pins_that_only_look_like_userinfo_stay(text):
    assert redact(text) == text


# An @ in a secret-named value belongs to the value. The name rules run before the bare userinfo
# rule, so password:P@ssw0rd is masked whole and keeps its name, and a userinfo whose user is a
# plain name still reaches the bare rule.

@pytest.mark.parametrize("text, masked", [
    ("password:P@ssw0rd", "password:" + MASK),
    ("token:abc@def", "token:" + MASK),
    ("api_key:a@b", "api_key:" + MASK),
    ("pw:x@y", "pw:" + MASK),
    ("PASSWORD:P@ssw0rd", "PASSWORD:" + MASK),
    ("db.password:P@ssw0rd", "db.password:" + MASK),
    ("X-Api-Key:ab@cd", "X-Api-Key:" + MASK),
    ("pass:x@y", "pass:" + MASK),
    ("secret:s3@cret", "secret:" + MASK),
    ("passphrase:a@b", "passphrase:" + MASK),
    ("login failed, password:P@ssw0rd rejected", "login failed, password:" + MASK + " rejected"),
    ("dsn token:abc@def end", "dsn token:" + MASK + " end"),
    ('password:"P@ssw0rd"', 'password:"' + MASK + '"'),
    ("password:P@ss@word", "password:" + MASK),
    ("password:@x", "password:" + MASK),
    ("password:x@", "password:" + MASK),
    ("dbPass:P@ssw0rd", "dbPass:" + MASK),
    ("userPw:x@y", "userPw:" + MASK),
    # The same pairs written with the other separators already kept their name.
    ("password=P@ssw0rd", "password=" + MASK),
    ("password: P@ssw0rd", "password: " + MASK),
])
def test_an_at_sign_in_a_secret_named_value_is_part_of_the_value(text, masked):
    assert redact(text) == masked


@pytest.mark.parametrize("text, masked", [
    ("deploy:pw@host", MASK + "@host"),
    ("the dsn deploy:pw@host is wrong", "the dsn " + MASK + "@host is wrong"),
    ("deploy:password@host", MASK + "@host"),
    ("deploy:token@host", MASK + "@host"),
    ("deploy:Zq9@x@host", MASK + "@host"),
    ("user:pass@host", MASK + "@host"),
    ("failed to dial deploy:hunter2@db.internal:5432: refused",
     "failed to dial " + MASK + "@db.internal:5432: refused"),
])
def test_a_userinfo_with_a_plain_user_is_still_masked_as_one(text, masked):
    assert redact(text) == masked


# 3. A PGP private key block, whose header has a BLOCK suffix.

def test_a_pgp_private_key_block_is_masked_whole():
    out = redact("note: " + PGP_BLOCK + " after")
    assert out == "note: " + MASK + " after"


def test_a_pgp_private_key_block_that_never_closes_is_masked_to_the_end():
    out = redact("note: " + PGP_OPEN + PGP_BODY)
    assert out == "note: " + MASK
    assert PGP_BODY not in out


@pytest.mark.parametrize("label", ["RSA ", "EC ", "OPENSSH ", "ENCRYPTED ", "DSA ", ""],
                         ids=["rsa", "ec", "openssh", "encrypted", "dsa", "plain"])
def test_the_other_private_key_blocks_are_still_masked(label):
    head = "-----BEGIN " + label + "PRIVATE KEY-----"
    foot = "-----END " + label + "PRIVATE KEY-----"
    assert redact(head + "\nb3BlbnNzaC1rZXk\n" + foot) == MASK


@pytest.mark.parametrize("text", [
    "", "8.3.35", "8.3.35-1ubuntu2.28", "8.4.27-1~deb13u1", "PHP/8.3.35", "Apache/2.4.58 (Ubuntu)",
    "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc123def4567890",
    "arn:aws:lambda:us-east-1:111122223333:function:billing-export-worker",
    "https://web1.corp.example:8443/login",
    "https://keycloak.corp.example:8443/realms/master",
    "http://token-service:9000/health",
    "ghcr.io/acme/token-service:1.2.3",
    "docker.io/library/php@sha256:" + "0123456789abcdef" * 4,
    HEX_40,
    "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMn",
    "disk-images-backup-for-php-servers",
    "connection refused", "timed out after 2.0s", "HTTP 403 Forbidden",
    "keep-alive: timeout=5, max=100",
    "session.upload_progress.enabled => 0 => 0",
    "memory_limit => 128M => 128M",
    "C:\\Users\\dev\\keys\\site\\Dockerfile",
    "/home/dev/.aws/credentials",
    "Dockerfile", "composer.json", "10.0.0.5:443",
    "Basic authentication required",
    "https://auth.corp.example:8443/oauth/authorize",
    "pinned the author of the build",
])
def test_redact_leaves_ordinary_output_alone(text):
    assert redact(text) == text


@pytest.mark.parametrize("text", [
    GH_TOKEN, AWS_ID, "x " + AWS_SECRET, "Authorization: Bearer abcdefghij0123456789",
    "https://deploy:hunter2@git.example.com/x", "password=hunter2",
    "-----BEGIN PRIVATE KEY-----\nMIIEvQ", '{"api_key": "k3y"}', 'passphrase="two words"',
    "password:hunter2", "https://deploy:pa/ss@db.example/app", "root:p@ss@db1 unreachable",
    PGP_BLOCK, "note: " + PGP_OPEN + PGP_BODY, 'password:"two words"', "token_ttl:3600",
    'password => "ab\\"cd"', "'password' => 'a\\'b'", VAR_DUMP,
    '["password":protected]=>\n  string(7) "Zq9hunt"', '["password"]=>\n  int(123456)',
    "DB_PASSWORD => Zq9hunter2 => Zq9hunter2", "password: a long phrase with spaces",
    "Authorization: Negotiate " + NEGOTIATE, "db_pass=1234", "password := Zq9hunter2",
    "'password' => 'Zq9hunter2'", "password: 123456", "token_ttl => 3600",
    "password:P@ssw0rd", "token:abc@def", "deploy:pw@host", "dbPass=Zq9hunter2",
    "SMTPPass: Zq9 hunter2", "userPw:x@y", '["dbPass"]=>\n  string(10) "Zq9hunter2"',
])
def test_redact_is_idempotent(text):
    once = redact(text)
    assert redact(once) == once


# A banner comes from whoever runs the server, so each pattern must stay linear on hostile text.
HOSTILE = {
    "repeated fragment": "key" * 60_000,
    "dotted run": "a.a." * 60_000,
    "unclosed key blocks": "-----BEGIN PRIVATE KEY-----" * 6_000,
    "long userinfo span": "://" + "a" * 300_000,
    "many userinfo spans": "://a@" * 60_000,
    "name then spaces": "token" + " " * 300_000 + "x",
    "repeated assignment": "token=" * 60_000,
    "unclosed quotes": 'password="' * 30_000,
    "unclosed single quotes": "auth='" * 40_000,
    "quote then long text": 'key="' + "x y " * 80_000,
    "repeated scheme": "Bearer " * 40_000,
    "repeated prefix": "ghp_" * 80_000,
    "one long run": "A" * 300_000,
    "slashes": "/" * 300_000,
    "many 40-char runs": ("A1" * 20 + " ") * 8_000,
    "repeated bare colon": "key:" * 80_000,
    "bare colon after commas": ",key:" * 60_000,
    "name then spaces then colon": "password" + " " * 300_000 + ":",
    "long name run": "token_" * 40_000,
    "repeated counting suffix": "token_ttl=" * 40_000,
    "name run then ttl": "token" + "_x" * 100_000 + "_ttl",
    "repeated php pair": "password =>" * 40_000,
    "php pair lines": "[password] => x\n" * 30_000,
    "spaced password": "password: " * 40_000,
    "repeated pass": "pass " * 100_000,
    "repeated pw": "pw=" * 100_000,
    "arrows": "=>" * 150_000,
    "escaped quotes": 'password => "' + 'a\\"' * 100_000,
    "escape pairs": '"' + "\\a" * 150_000,
    "escaped single quotes": "key='" + "\\'" * 100_000,
    "var_dump entries": '["password"]=>\n  string(1) "x"\n' * 20_000,
    "var_dump keys alone": '["password"]=>\n' * 40_000,
    "var_dump visibility": '["password":"A\\B":private]=>\n  int(1)\n' * 15_000,
    "userinfo run": "a:" * 150_000,
    "userinfo after commas": ",a:" * 100_000,
    "userinfo with many at signs": "a:b@" * 80_000,
    "loose url colons": "://a:" * 60_000,
    "loose url long password": "://a:" + "b" * 300_000,
    "unclosed pgp blocks": ("-----BEGIN PGP " + "PRIVATE KEY BLOCK-----") * 5_000,
    "begin with spaces": "-----BEGIN " + " " * 300_000,
    "camel run": "dbPass" * 60_000,
    "acronym camel run": "DBPass" * 40_000,
    "camel run with colons": "aPw:" * 100_000,
    "camel pw run": "Pw" * 40_000,
    "password colon at signs": "password:a@" * 60_000,
    "token colon long at run": "token:" + "a@" * 150_000,
    "name colon at signs after commas": ",pw:a@" * 60_000,
}


@pytest.mark.parametrize("text", HOSTILE.values(), ids=HOSTILE.keys())
def test_redact_stays_linear_on_hostile_text(text):
    # The slowest input takes under a second. A pattern that backtracks takes minutes.
    start = time.perf_counter()
    redact(text)
    assert time.perf_counter() - start < 10


# Credentials never reach any output

PLAIN = "hunter2-correct-horse"  # no shape, so only a signal name can catch it
NUMERIC = "493817265"
URL_PASSWORD = "hunter2"
PLANTS = {
    "secret-named signal": (PLAIN, lambda s: ev(HOST, "web1", "8.3.35", client_secret=s)),
    "token-named signal": (PLAIN, lambda s: ev(HOST, "web1", "8.3.35", GITHUB_TOKEN=s)),
    "key-named signal": (PLAIN, lambda s: ev(HOST, "web1", "8.3.35", api_key=s)),
    "password-named signal": (PLAIN, lambda s: ev(HOST, "web1", "8.3.35", db_password=s)),
    "shaped value under a plain name": (
        GH_TOKEN, lambda s: ev(HOST, "web1", "8.3.35", banner=s)),
    "shaped value in a sentence": (
        GH_TOKEN, lambda s: ev(HOST, "web1", "8.3.35", banner="cloned with " + s + " ok")),
    "shaped value in the note": (
        GH_TOKEN, lambda s: ev(HOST, "web1", "8.3.35", note="clone failed for " + s)),
    "shaped value in the location": (
        GH_TOKEN, lambda s: ev(HOST, "https://" + s + "@github.com/acme/site.git", "8.3.35")),
    "shaped value as the version": (GH_TOKEN, lambda s: ev(HOST, "web1", s)),
    "aws id in the note": (AWS_ID, lambda s: ev(HOST, "web1", "8.3.35", note="using " + s)),
    "aws secret in the note": (AWS_SECRET, lambda s: ev(HOST, "web1", "8.3.35", note=s)),
    "password in a url": (URL_PASSWORD, lambda s: ev(
        HOST, "https://deploy:" + s + "@git.example.com/acme/site.git", "8.3.35")),
    # A colon with no space after it, and the spaced form beside it.
    "bare-colon secret in a signal value": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", banner="api_key:" + s)),
    "bare-colon secret in the note": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", note="login failed, password:" + s)),
    "spaced-colon secret in a signal value": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", banner="password: " + s)),
    # URL credentials with an odd authority, or with none.
    "url password with two at signs": (
        "S3cr3t@Pass", lambda s: ev(HOST, "https://deploy:" + s + "@db.example/app", "8.3.35")),
    "tail of a url password with two at signs": (
        "Pass@db.example", lambda s: ev(
            HOST, "web1", "8.3.35", note="https://deploy:S3cr3t@" + s + "/app")),
    "url password with a slash": (
        "pa/ss-Zq9", lambda s: ev(HOST, "https://deploy:" + s + "@db.example/app", "8.3.35")),
    "url password with a question mark in a signal value": (
        "pa?ss-Zq9", lambda s: ev(
            HOST, "web1", "8.3.35", banner="https://deploy:" + s + "@db.example/app")),
    "url password with a hash in the note": (
        "pa#ss-Zq9", lambda s: ev(
            HOST, "web1", "8.3.35", note="https://deploy:" + s + "@db.example/app")),
    "userinfo with no scheme in the note": (
        PLAIN, lambda s: ev(
            HOST, "web1", "8.3.35", note="failed to dial deploy:" + s + "@db.internal:5432")),
    "userinfo with no scheme in a signal value": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", banner="deploy:" + s + "@db.internal")),
    # A secret that is all digits, after each separator, in a note, a signal value, and a location.
    "numeric secret after a colon in the note": (
        NUMERIC, lambda s: ev(HOST, "web1", "8.3.35", note="login failed, password: " + s)),
    "numeric secret after a bare colon in the note": (
        NUMERIC, lambda s: ev(HOST, "web1", "8.3.35", note="login failed, password:" + s)),
    "numeric secret after an equals sign in a signal value": (
        NUMERIC, lambda s: ev(HOST, "web1", "8.3.35", banner="api_key=" + s)),
    "numeric secret in a json value": (
        NUMERIC, lambda s: ev(HOST, "web1", "8.3.35", banner='{"password": ' + s + '}')),
    "numeric secret in the location": (
        NUMERIC, lambda s: ev(HOST, "https://db.example/login?token=" + s, "8.3.35")),
    # The location and the resource signal skip two shape rules, and every other rule still runs.
    "token shape in the location outside userinfo": (
        GH_TOKEN, lambda s: ev(HOST, "https://git.example.com/" + s + "/site.git", "8.3.35")),
    "name=value secret in the resource signal": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", resource="arn:aws:lambda:us-east-1:"
                            "111122223333:function:fn?api_key=" + s)),
    "userinfo in the resource signal": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", resource="https://deploy:" + s + "@host/fn")),
    "token shape in the resource signal": (
        GH_TOKEN, lambda s: ev(HOST, "web1", "8.3.35", resource="arn:aws:lambda:us-east-1:"
                               "111122223333:function:" + s)),
    # PHP's name => value, and a passphrase with spaces.
    "php -i pair in the note": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", note="DB_PASSWORD => " + s + " => " + s)),
    "php array pair in a signal value": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", banner="$_ENV['API_TOKEN'] => " + s)),
    "print_r pair in the note": (
        PLAIN, lambda s: ev(
            HOST, "web1", "8.3.35", note="Array\n(\n    [password] => " + s + "\n)")),
    "var_export pair in a signal value": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", banner="'password' => '" + s + "',")),
    "spaced passphrase in the note": (
        "battery staple", lambda s: ev(
            HOST, "web1", "8.3.35", note="password: correct horse " + s + " ok")),
    "negotiate blob in a signal value": (
        NEGOTIATE, lambda s: ev(HOST, "web1", "8.3.35", banner="Authorization: Negotiate " + s)),
    "ntlm blob in the note": (
        NTLM, lambda s: ev(HOST, "web1", "8.3.35", note="X-Auth:NTLM " + s)),
    "pass named value in the note": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", note="db_pass=" + s)),
    # A quoted value with an escaped quote in it, and var_dump's value on the next line.
    "escaped quote in the note": (
        "tail-secret", lambda s: ev(HOST, "web1", "8.3.35", note='password => "ab\\"' + s + '"')),
    "escaped quote in a signal value": (
        "tail-secret", lambda s: ev(
            HOST, "web1", "8.3.35", banner="'password' => 'a\\'" + s + "'")),
    "var_dump block in the note": (
        PLAIN, lambda s: ev(
            HOST, "web1", "8.3.35",
            note='array(1) {\n  ["password"]=>\n  string(%d) "%s"\n}' % (len(s), s))),
    "var_dump property in a signal value": (
        PLAIN, lambda s: ev(
            HOST, "web1", "8.3.35",
            banner='["secret":"Config":private]=>\n  string(%d) "%s"' % (len(s), s))),
    "var_dump number in the note": (
        NUMERIC, lambda s: ev(HOST, "web1", "8.3.35", note='["password"]=>\n  int(%s)' % s)),
    # An @ inside a secret-named value, and a camelCase credential name.
    "at sign in a bare-colon password in the note": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", note="login failed, password:Zq9@" + s)),
    "at sign in a bare-colon token in a signal value": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", banner="token:abc@" + s)),
    "at sign in a bare-colon pw in the note": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", note="pw:x@" + s)),
    "camel case pass signal": (PLAIN, lambda s: ev(HOST, "web1", "8.3.35", dbPass=s)),
    "camel case pw signal": (PLAIN, lambda s: ev(HOST, "web1", "8.3.35", userPw=s)),
    "camel case api key signal": (PLAIN, lambda s: ev(HOST, "web1", "8.3.35", apiKey=s)),
    "camel case pair in the note": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", note="dbPass=" + s)),
    "camel case json pair in a signal value": (
        PLAIN, lambda s: ev(HOST, "web1", "8.3.35", banner='{"userPw": "' + s + '"}')),
    # A PGP private key block.
    "pgp block in the note": (
        PGP_BODY, lambda s: ev(HOST, "web1", "8.3.35", note="key follows " + PGP_OPEN + s
                               + PGP_CLOSE)),
    "pgp block in a signal value": (
        PGP_BODY, lambda s: ev(HOST, "web1", "8.3.35", banner=PGP_OPEN + s + PGP_CLOSE)),
    "pgp block that never closes": (
        PGP_BODY, lambda s: ev(HOST, "web1", "8.3.35", note=PGP_OPEN + s)),
}
RENDERERS = {"console": render_console, "json": render_json, "sarif": render_sarif}


@pytest.mark.parametrize("render", RENDERERS.values(), ids=RENDERERS.keys())
@pytest.mark.parametrize("secret, build", PLANTS.values(), ids=PLANTS.keys())
def test_a_planted_credential_reaches_no_output(matrix, render, secret, build):
    assert secret not in render([asset("web1", build(secret))], matrix)


@pytest.mark.parametrize("render", RENDERERS.values(), ids=RENDERERS.keys())
@pytest.mark.parametrize("make", [
    lambda s: asset(s, ev(HOST, "web1", "8.3.35")),
    lambda s: asset("web1", ev(HOST, "web1", "8.3.35"), kind=s),
], ids=["asset key", "asset kind"])
def test_a_credential_in_an_asset_field_reaches_no_output(matrix, render, make):
    assert GH_TOKEN not in render([make(GH_TOKEN)], matrix)


# A location and the resource signal name a thing, so they skip the two rules that read a value by
# its shape alone. A key that is a resource signal does too, and a cloud asset's key always is one.
# Every other rule still runs on them. Every other key is scanned in full.

RUN_40 = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"  # 40 base64 characters, mixed case and digits
FUNCTION_ARN = "arn:aws:lambda:us-east-1:111122223333:function:" + RUN_40
# Elastic Beanstalk allows spaces in an application name, so an ARN can hold a word and a long run.
SPACED_ARN = ("arn:aws:elasticbeanstalk:us-east-1:111122223333:environment/Bearer "
              + "x" * 20 + "/Prod")
HOST_URL = "https://web-" + RUN_40 + ".example.com:8443/"
IDENTIFIERS = [FUNCTION_ARN, SPACED_ARN, HOST_URL]


@pytest.mark.parametrize("text", IDENTIFIERS)
def test_an_identifier_skips_the_two_rules_that_read_shape_alone(text):
    assert redact(text) != text
    assert redact(text, identifier=True) == text


@pytest.mark.parametrize("text", IDENTIFIERS)
def test_a_location_prints_as_given_in_every_renderer(matrix, text):
    a = asset("web1", ev(CLOUD, text, "8.3.35"))
    assert as_json([a], matrix)["assets"][0]["evidence"][0]["location"] == text
    assert text in render_console([a], matrix)
    where = as_sarif([a], matrix)["runs"][0]["results"][0]["locations"][0]["logicalLocations"]
    assert where[0]["name"] == text


@pytest.mark.parametrize("text", [FUNCTION_ARN, SPACED_ARN])
def test_the_resource_signal_prints_as_given(matrix, text):
    a = asset("web1", ev(CLOUD, "web1", "8.3.35", resource=text, service="lambda"))
    signals = as_json([a], matrix)["assets"][0]["evidence"][0]["signals"]
    assert signals == {"resource": text, "service": "lambda"}


def inventoried(arn):
    # How a run builds a cloud asset. Its key comes out as the resource signal.
    inventory = AssetInventory()
    inventory.add(ev(CLOUD, arn, None, resource=arn, service="lambda", php_present="true"))
    return inventory.assets()


@pytest.mark.parametrize("arn", [FUNCTION_ARN, SPACED_ARN])
def test_the_key_of_a_cloud_asset_prints_as_its_arn_in_every_renderer(matrix, arn):
    assets = inventoried(arn)
    assert assets[0].key == arn
    assert as_json(assets, matrix)["assets"][0]["key"] == arn
    assert f"  {arn} (host): " in render_console(assets, matrix)
    message = as_sarif(assets, matrix)["runs"][0]["results"][0]["message"]["text"]
    assert f": {arn} (host), " in message


OTHER_FIELDS = {
    "a note": lambda s: asset("web1", ev(HOST, "web1", "8.3.35", note="id " + s)),
    "a plain signal": lambda s: asset("web1", ev(HOST, "web1", "8.3.35", banner="id " + s)),
    "the hostname signal": lambda s: asset("web1", ev(HOST, "web1", "8.3.35", hostname=s)),
    "the repo signal": lambda s: asset("web1", ev(REPO, "Dockerfile", "8.3.35", repo=s)),
    "an asset key": lambda s: asset("id " + s, ev(HOST, "web1", "8.3.35")),
    "an asset kind": lambda s: asset("web1", ev(HOST, "web1", "8.3.35"), kind="id " + s),
}


@pytest.mark.parametrize("render", RENDERERS.values(), ids=RENDERERS.keys())
@pytest.mark.parametrize("make", OTHER_FIELDS.values(), ids=OTHER_FIELDS.keys())
def test_every_other_field_still_masks_a_bare_40_character_run(matrix, render, make):
    assert RUN_40 not in render([make(RUN_40)], matrix)


@pytest.mark.parametrize("render", RENDERERS.values(), ids=RENDERERS.keys())
def test_every_other_field_still_masks_a_bearer_run(matrix, render):
    bearer = "Bearer " + "x" * 20
    a = asset("id " + bearer, ev(HOST, "web1", "8.3.35", banner=bearer, note=bearer))
    assert "x" * 20 not in render([a], matrix)


# A run builds the key of an asset from its first read. Only a resource signal makes it an
# identifier. A key from a host name, an ip, or a repo id is scanned in full.

SCANNED_KEYS = {
    "a repo id": (ev(REPO, "Dockerfile", "8.3.35", repo="acme/web-" + RUN_40), RUN_40),
    "a repo id with a Bearer run": (
        ev(REPO, "Dockerfile", "8.3.35", repo="Bearer " + "x" * 20 + "~20c3d9ad"), "x" * 20),
    "a host name with a Bearer run": (
        ev(HOST, "web1", "8.3.35", hostname="Bearer " + "x" * 20), "x" * 20),
    "an ip with a 40-character run": (
        ev(NETWORK, "http://web1/", "8.3.35", ip="host-" + RUN_40), RUN_40),
}


@pytest.mark.parametrize("render", RENDERERS.values(), ids=RENDERERS.keys())
@pytest.mark.parametrize("read, secret", SCANNED_KEYS.values(), ids=SCANNED_KEYS.keys())
def test_a_key_made_from_another_signal_is_scanned_in_full(matrix, render, read, secret):
    inventory = AssetInventory()
    inventory.add(read)
    (a,) = inventory.assets()
    assert secret.lower() in a.key.lower()  # the key holds it, so the check below is not empty
    assert secret not in render([a], matrix)


def test_a_host_name_key_stays_scanned_when_a_later_read_has_a_resource(matrix):
    bearer = "Bearer " + "x" * 20
    inventory = AssetInventory()
    inventory.add(ev(HOST, "web1", "8.3.35", hostname=bearer))
    inventory.add(ev(CLOUD, FUNCTION_ARN, None, hostname=bearer, resource=FUNCTION_ARN,
                     php_present="true"))
    (a,) = inventory.assets()
    assert a.key == bearer.lower()  # the host name made the key, and the ARN did not
    for render in RENDERERS.values():
        assert "x" * 20 not in render([a], matrix)


@pytest.mark.parametrize("render", RENDERERS.values(), ids=RENDERERS.keys())
@pytest.mark.parametrize("as_resource", [False, True], ids=["plain key", "resource key"])
@pytest.mark.parametrize("key, secret", [
    ("https://deploy:" + PLAIN + "@git.example.com/acme/site.git", PLAIN),
    ("arn:aws:lambda:us-east-1:111122223333:function:fn?api_key=" + PLAIN, PLAIN),
    ("web1?token=" + NUMERIC, NUMERIC),
    ("arn:aws:lambda:us-east-1:111122223333:function:" + GH_TOKEN, GH_TOKEN),
], ids=["userinfo", "name=value", "numeric query", "token shape"])
def test_the_asset_key_keeps_the_credential_rules(matrix, render, as_resource, key, secret):
    signals = {"resource": key} if as_resource else {}
    a = asset(key, ev(HOST, "web1", "8.3.35", **signals))
    assert secret not in render([a], matrix)


def test_secret_fields_stay_masked_in_the_same_entry_as_two_printed_identifiers(matrix):
    a = asset("web1", ev(CLOUD, HOST_URL, "8.3.35", resource=FUNCTION_ARN, api_key=PLAIN,
                         banner="password=" + PLAIN, note="using " + AWS_ID))
    entry = as_json([a], matrix)["assets"][0]["evidence"][0]
    assert entry["location"] == HOST_URL
    assert entry["signals"] == {"resource": FUNCTION_ARN, "banner": "password=" + MASK}
    assert entry["note"] == "using " + MASK
