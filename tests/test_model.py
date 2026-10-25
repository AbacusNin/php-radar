import itertools

import pytest

from php_radar.model import (
    SOURCE_PRECEDENCE,
    Asset,
    AssetInventory,
    Confidence,
    Evidence,
    Sapi,
    Source,
    Verdict,
    asset_identity,
    normalize_hostname,
)

ARN = "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc"


def make(source, location="loc", **signals):
    return Evidence(source, location, "8.3.35", Sapi.UNKNOWN, signals)


def assets_of(*evs):
    inv = AssetInventory()
    for e in evs:
        inv.add(e)
    return inv.assets()


def test_inventory_merges_same_host_across_sources():
    inv = AssetInventory()
    inv.add(Evidence(Source.NETWORK, "https://web1", "8.3.35", Sapi.UNKNOWN, {"hostname": "web1"}))
    inv.add(Evidence(Source.HOST, "web1", "8.3.35", Sapi.FPM, {"hostname": "web1"}))
    assets = inv.assets()
    assert len(assets) == 1
    assert len(assets[0].evidence) == 2


def test_repo_and_host_do_not_merge():
    inv = AssetInventory()
    inv.add(Evidence(Source.REPO, "repo:acme/site", None, Sapi.UNKNOWN, {"repo": "acme/site"}))
    inv.add(Evidence(Source.HOST, "web1", "8.3.35", Sapi.FPM, {"hostname": "web1"}))
    assert len(inv.assets()) == 2


def test_one_machine_seen_by_cloud_network_and_host_is_one_asset():
    cloud = make(Source.CLOUD, ARN, resource=ARN, hostname="web1")
    net = make(Source.NETWORK, "https://web1", hostname="web1")
    host = make(Source.HOST, "web1", hostname="web1")
    assets = assets_of(cloud, net, host)
    assert len(assets) == 1
    assert assets[0].evidence == [cloud, net, host]


def test_cloud_resource_and_host_hostname_with_nothing_shared_stay_apart():
    cloud = make(Source.CLOUD, ARN, resource=ARN)
    host = make(Source.HOST, "web1", hostname="web1")
    assert len(assets_of(cloud, host)) == 2


@pytest.mark.parametrize("a, b", [("Web1", "web1"), ("web1.", "web1"), ("WEB1.", "Web1")])
def test_hostname_case_and_one_trailing_dot_do_not_split_a_host(a, b):
    assert len(assets_of(make(Source.NETWORK, hostname=a), make(Source.HOST, hostname=b))) == 1


def test_fqdn_and_short_name_stay_distinct():
    short = make(Source.HOST, hostname="web1")
    full = make(Source.HOST, hostname="web1.corp.example")
    assert len(assets_of(short, full)) == 2


def test_resource_matches_case_sensitively():
    lower = make(Source.CLOUD, resource=ARN)
    upper = make(Source.CLOUD, resource=ARN.upper())
    assert len(assets_of(lower, upper)) == 2


@pytest.mark.parametrize("a, b", [
    ({"ip": "10.0.0.5"}, {"ip": "10.0.0.5"}),
    ({"hostname": "web1", "ip": "10.0.0.5"}, {"ip": "10.0.0.5"}),
    ({"hostname": "web1", "ip": "10.0.0.5"}, {"hostname": "web2", "ip": "10.0.0.5"}),
])
def test_a_shared_ip_never_merges(a, b):
    assert len(assets_of(make(Source.HOST, **a), make(Source.NETWORK, **b))) == 2


def test_repo_evidence_from_different_repos_stays_apart_at_the_same_path():
    a = make(Source.REPO, "Dockerfile", repo="acme/a")
    b = make(Source.REPO, "Dockerfile", repo="acme/b")
    assert len(assets_of(a, b)) == 2


@pytest.mark.parametrize("where", ["Dockerfile", "compose.yml"])
def test_repo_evidence_merges_on_the_repo_signal(where):
    a = make(Source.REPO, "Dockerfile", repo="acme/a")
    b = make(Source.REPO, where, repo="acme/a")
    assets = assets_of(a, b)
    assert len(assets) == 1
    assert assets[0].evidence == [a, b]


def test_repo_evidence_ignores_host_identifiers():
    pin = make(Source.REPO, "Dockerfile", hostname="web1", resource=ARN)
    host = make(Source.HOST, "web1", hostname="web1", resource=ARN)
    assert len(assets_of(pin, host)) == 2


def test_host_evidence_ignores_the_repo_signal():
    pin = make(Source.REPO, "Dockerfile", repo="acme/site")
    host = make(Source.HOST, "web1", repo="acme/site")
    assert len(assets_of(pin, host)) == 2


@pytest.mark.parametrize("source, signals", [
    (Source.HOST, {"hostname": "   "}),
    (Source.HOST, {"hostname": ""}),
    (Source.HOST, {"hostname": "."}),
    (Source.HOST, {"resource": "  "}),
    (Source.REPO, {"repo": "  "}),
    (Source.REPO, {"repo": ""}),
])
def test_blank_identifiers_never_merge(source, signals):
    # Different locations, so only the blank value itself could have joined them.
    assert len(assets_of(make(source, "a", **signals), make(source, "b", **signals))) == 2


def test_matching_locations_alone_never_merge():
    # Location is a display fallback and nothing more.
    assert len(assets_of(make(Source.HOST, "web1"), make(Source.HOST, "web1"))) == 2


def test_a_record_carrying_both_identifiers_joins_assets_created_earlier():
    by_arn = make(Source.CLOUD, ARN, resource=ARN)
    by_name = make(Source.HOST, "web1", hostname="web1")
    both = make(Source.CLOUD, ARN, resource=ARN, hostname="web1")
    for order in itertools.permutations([by_arn, by_name, both]):
        assets = assets_of(*order)
        assert len(assets) == 1
        assert assets[0].evidence == list(order)


def test_a_bridged_asset_keeps_the_place_of_its_earliest_evidence():
    a = make(Source.HOST, "a", hostname="a")
    b = make(Source.HOST, "b", hostname="b")
    c = make(Source.CLOUD, "c", resource="rc")
    d = make(Source.CLOUD, "d", hostname="a", resource="rc")
    assert [x.evidence for x in assets_of(a, b, c, d)] == [[a, c, d], [b]]


def test_the_earliest_evidence_names_a_merged_asset():
    net = make(Source.NETWORK, hostname="Web1.")
    cloud = make(Source.CLOUD, resource=ARN, hostname="web1")
    assert [a.key for a in assets_of(net, cloud)] == ["web1"]
    assert [a.key for a in assets_of(cloud, net)] == [ARN]


@pytest.mark.parametrize("raw, normal", [
    ("web1", "web1"),
    ("Web1", "web1"),
    ("web1.", "web1"),
    ("WEB1.Corp.Example.", "web1.corp.example"),
    ("web1..", "web1."),
    ("  Web1.  ", "web1"),
    ("", ""),
    ("   ", ""),
    (".", ""),
])
def test_normalize_hostname(raw, normal):
    assert normalize_hostname(raw) == normal


@pytest.mark.parametrize("signals, key", [
    ({"resource": ARN, "hostname": "web1", "ip": "10.0.0.5"}, ARN),
    ({"resource": "arn:aws:s3:::MixedCase"}, "arn:aws:s3:::MixedCase"),
    ({"hostname": "Web1.", "ip": "10.0.0.5"}, "web1"),
    ({"ip": "10.0.0.5"}, "10.0.0.5"),
    ({}, "loc"),
    ({"resource": "  ", "hostname": " ", "ip": "10.0.0.5"}, "10.0.0.5"),
    ({"hostname": "", "ip": ""}, "loc"),
])
def test_display_key_order(signals, key):
    ev = Evidence(Source.NETWORK, "loc", None, Sapi.UNKNOWN, signals)
    assert asset_identity(ev) == ("host", key)


@pytest.mark.parametrize("signals, key", [
    ({"repo": "acme/site"}, "acme/site"),
    ({"repo": "  "}, "Dockerfile"),
    ({}, "Dockerfile"),
    ({"hostname": "web1", "resource": ARN, "ip": "10.0.0.5"}, "Dockerfile"),
])
def test_repo_display_key_is_the_repo_signal_else_location(signals, key):
    ev = Evidence(Source.REPO, "Dockerfile", None, Sapi.UNKNOWN, signals)
    assert asset_identity(ev) == ("repo", key)


@pytest.mark.parametrize("source, kind", [
    (Source.REPO, "repo"),
    (Source.HOST, "host"),
    (Source.CLOUD, "host"),
    (Source.NETWORK, "host"),
])
def test_identity_kind_follows_source(source, kind):
    ev = Evidence(source, "loc", None, Sapi.UNKNOWN, {})
    assert asset_identity(ev)[0] == kind


def test_precedence_is_the_literal_mapping():
    assert SOURCE_PRECEDENCE == {Source.HOST: 3, Source.CLOUD: 2, Source.NETWORK: 1, Source.REPO: 0}


def test_precedence_orders_host_over_network():
    assert SOURCE_PRECEDENCE[Source.HOST] > SOURCE_PRECEDENCE[Source.NETWORK]


def test_evidence_note_defaults_to_empty():
    assert Evidence(Source.HOST, "web1", None, Sapi.UNKNOWN, {}).note == ""


def test_asset_add_appends_evidence():
    asset = Asset("web1", "host", [])
    ev = Evidence(Source.HOST, "web1", "8.3.35", Sapi.FPM, {})
    asset.add(ev)
    assert asset.evidence == [ev]


def test_inventory_returns_assets_in_first_seen_order():
    inv = AssetInventory()
    for name in ("b", "a", "b", "c"):
        inv.add(Evidence(Source.HOST, name, "8.3.35", Sapi.FPM, {"hostname": name}))
    assets = inv.assets()
    assert [a.key for a in assets] == ["b", "a", "c"]
    assert [len(a.evidence) for a in assets] == [2, 1, 1]


@pytest.mark.parametrize("enum, names", [
    (Verdict, ["EXPOSED", "INDETERMINATE", "LIKELY_PATCHED", "NOT_PHP"]),
    (Confidence, ["HIGH", "MEDIUM", "LOW"]),
    (Sapi, ["MOD_PHP", "FPM", "CGI", "CLI", "UNKNOWN"]),
    (Source, ["REPO", "CLOUD", "NETWORK", "HOST"]),
], ids=["Verdict", "Confidence", "Sapi", "Source"])
def test_enum_members_in_order_with_name_values(enum, names):
    assert [m.name for m in enum] == names
    assert [m.value for m in enum] == names
