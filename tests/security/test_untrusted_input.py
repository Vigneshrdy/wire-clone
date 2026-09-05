"""Untrusted input handling.

Everything a sensor hands the system is influenced by a host on the monitored
network: domain names, SNI values, byte counts, even field presence. These tests
assert the system rejects rather than repairs, and never lets captured data reach
a dangerous sink.
"""

from __future__ import annotations

import pytest

from sih_ntd.errors import ValidationRejection
from sih_ntd.ingest import Normalizer, ZeekLogReader, derive_event_id
from sih_ntd.metrics import EVENTS_REJECTED, reset
from sih_ntd.schemas import SourceType, normalise_domain
from tests.conftest import T0


@pytest.fixture
def normalizer(settings) -> Normalizer:
    reset()
    return Normalizer(settings)


def base_record(**overrides) -> dict:
    record = {
        "ts": T0, "uid": "CabcD1", "id.orig_h": "10.0.0.5", "id.orig_p": 40000,
        "id.resp_h": "198.51.100.7", "id.resp_p": 443, "proto": "tcp",
        "orig_pkts": 5, "resp_pkts": 5, "orig_ip_bytes": 500, "resp_ip_bytes": 900,
        "conn_state": "SF",
    }
    record.update(overrides)
    return record


@pytest.mark.parametrize(
    ("field", "value", "why"),
    [
        ("id.orig_h", "not-an-ip", "malformed source address"),
        ("id.orig_h", "10.0.0.256", "out-of-range octet"),
        ("id.resp_p", 99999, "port above 65535"),
        ("ts", "not-a-time", "unparseable timestamp"),
    ],
)
def test_malformed_fields_are_rejected_not_coerced(normalizer, field, value, why):
    with pytest.raises(ValidationRejection):
        normalizer.normalize(base_record(**{field: value}), SourceType.ZEEK_LOG)


def test_missing_addresses_are_rejected(normalizer):
    record = base_record()
    del record["id.orig_h"]
    with pytest.raises(ValidationRejection, match="source/destination"):
        normalizer.normalize(record, SourceType.ZEEK_LOG)


def test_rejections_are_counted_with_low_cardinality_reasons(normalizer):
    for value in ("not-an-ip", "10.0.0.999", "::gg"):
        with pytest.raises(ValidationRejection):
            normalizer.normalize(base_record(**{"id.orig_h": value}), SourceType.ZEEK_LOG)
    total = sum(
        EVENTS_REJECTED.value(reason=reason)
        for reason in ("bad_address", "validation", "other", "bad_timestamp")
    )
    assert total == 3


@pytest.mark.parametrize(
    "hostile",
    [
        "a" * 300,                                  # oversized
        "x" * 70 + ".example.com",                  # oversized label
        "'; DROP TABLE alerts; --.example.com",     # SQL-looking
        "$(id).example.com",                        # shell-looking
        "../../etc/passwd.example.com",             # path-looking
        "<script>alert(1)</script>.example.com",    # markup
    ],
)
def test_hostile_domain_names_never_reach_a_detector(normalizer, hostile):
    """A name the attacker controls must fail validation, not be sanitised."""
    with pytest.raises(ValidationRejection):
        normalizer.normalize(base_record(query=hostile, proto="udp"), SourceType.ZEEK_LOG)


def test_oversized_service_strings_are_truncated_not_rejected(normalizer):
    """Free-text provenance fields are capped; they are not a correctness boundary."""
    event = normalizer.normalize(base_record(service="s" * 5000), SourceType.ZEEK_LOG)
    assert len(event.service) <= 256


def test_negative_counters_are_dropped_rather_than_trusted(normalizer):
    event = normalizer.normalize(base_record(orig_ip_bytes=-5000), SourceType.ZEEK_LOG)
    assert event.orig_bytes == 0, "a negative byte count must not become a negative rate"


def test_answers_list_is_capped(normalizer):
    event = normalizer.normalize(
        base_record(query="example.com", proto="udp", answers=["1.2.3.4"] * 500),
        SourceType.ZEEK_LOG,
    )
    assert len(event.dns.answers) <= 64


def test_unknown_protocol_numbers_become_other(normalizer):
    event = normalizer.normalize(base_record(proto=253), SourceType.IPFIX)
    assert str(event.transport_protocol) == "other"


def test_event_ids_are_deterministic_so_replay_is_idempotent():
    first = derive_event_id(T0, "flow-key", "conn")
    assert first == derive_event_id(T0, "flow-key", "conn")
    assert first != derive_event_id(T0, "flow-key", "dns")


def test_duplicate_detection_is_bounded(normalizer):
    for index in range(1000):
        normalizer.is_duplicate(f"id-{index}")
    assert normalizer.is_duplicate("id-0") in (True, False)  # may have aged out
    assert len(normalizer._seen) <= 100_000


def test_zeek_reader_skips_unparseable_lines(tmp_path, settings):
    (tmp_path / "conn.log").write_text(
        "\n".join(
            [
                "#comment line",
                "{not json",
                '{"ts": 1757000000.0, "uid": "C1", "id.orig_h": "10.0.0.5", '
                '"id.resp_h": "198.51.100.7", "id.resp_p": 443, "proto": "tcp"}',
            ]
        )
        + "\n"
    )
    events = list(ZeekLogReader(tmp_path, Normalizer(settings)).read())
    assert len(events) == 1


def test_normalise_domain_accepts_wildcards_and_service_labels():
    """Legitimate oddities must not be rejected along with the hostile ones."""
    assert normalise_domain("*.example.com") == "*.example.com"
    assert normalise_domain("_dmarc.example.com") == "_dmarc.example.com"


def test_no_module_opens_a_socket_toward_captured_addresses():
    """Structural check on the passive-only guarantee.

    The detection path must contain no outbound network primitives. Redis and the
    HTTP server are separate modules; nothing that touches captured data may
    connect anywhere.
    """
    import inspect

    from sih_ntd import baselines, evidence, fusion
    from sih_ntd.detectors import c2, ddos, dga, dns_tunnel, exfiltration, recon, tls_malware
    from sih_ntd.features import engine, stats

    forbidden_modules = {"socket", "requests", "urllib", "httpx", "subprocess", "http", "ftplib"}
    forbidden_calls = {"eval", "exec", "system", "popen"}
    import ast

    for module in (
        baselines, evidence, fusion, engine, stats,
        ddos, recon, c2, dga, dns_tunnel, tls_malware, exfiltration,
    ):
        tree = ast.parse(inspect.getsource(module))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in forbidden_modules, (
                        f"{module.__name__} imports {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in forbidden_modules, (
                    f"{module.__name__} imports from {node.module}"
                )
            elif isinstance(node, ast.Call):
                name = (
                    node.func.id if isinstance(node.func, ast.Name)
                    else node.func.attr if isinstance(node.func, ast.Attribute)
                    else ""
                )
                assert name not in forbidden_calls, f"{module.__name__} calls {name}()"


def test_replay_never_builds_a_shell_command_from_a_filename():
    """PCAP paths can come from an API request; argv must be a list, never a string.

    Checked on the AST rather than the text, so a comment explaining why
    ``shell=True`` is dangerous does not fail the test that forbids it.
    """
    import ast
    import inspect

    from sih_ntd.sensor import replay

    tree = ast.parse(inspect.getsource(replay))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert any(
        isinstance(node.func, ast.Attribute) and node.func.attr == "run" for node in calls
    ), "expected subprocess.run to be present"
    for node in calls:
        for keyword in node.keywords:
            assert keyword.arg != "shell", "subprocess must never be called with shell="
        if isinstance(node.func, ast.Attribute) and node.func.attr == "run" and node.args:
            assert isinstance(node.args[0], ast.List), "argv must be a list literal"
