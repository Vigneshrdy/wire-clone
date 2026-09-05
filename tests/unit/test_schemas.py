"""Schema validation is the trust boundary; these tests are about rejection."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sih_ntd.schemas import (
    EVENT_SCHEMA_VERSION,
    Alert,
    AnalystFeedback,
    DnsMetadata,
    Evidence,
    FeatureVector,
    FeedbackLabel,
    NormalizedEvent,
    normalise_domain,
)
from tests.conftest import T0, flow


def test_event_derives_flow_id_and_epoch_from_epoch_seconds():
    event = flow()
    assert event.flow_id and len(event.flow_id) == 16
    assert event.epoch == T0
    assert event.timestamp.tzinfo is not None, "timestamps must be timezone-aware UTC"


def test_flow_id_is_direction_sensitive():
    """A->B and B->A are different flows; collapsing them would merge conversations."""
    forward = flow(src="10.0.0.1", dst="10.0.0.2")
    reverse = flow(src="10.0.0.2", dst="10.0.0.1")
    assert forward.flow_id != reverse.flow_id


def test_syn_only_and_failed_detection():
    syn = flow(state="S0", flags="S", resp_packets=0, resp_bytes=0)
    assert syn.is_syn_only and syn.failed
    established = flow(state="SF", flags="ShADadFf")
    assert not established.is_syn_only and not established.failed


def test_udp_flow_is_never_syn_only():
    """SYN is a TCP concept; a UDP flow reporting syn_only would corrupt DDoS rates."""
    assert not flow(proto="udp", state="SF", flags=None).is_syn_only


def test_unknown_event_schema_version_is_rejected():
    with pytest.raises(ValidationError, match="unsupported event schema_version"):
        NormalizedEvent(
            schema_version="9.9.9", timestamp=T0, source_type="SYNTHETIC",
            src_ip="10.0.0.1", dst_ip="10.0.0.2", transport_protocol="tcp",
        )
    assert EVENT_SCHEMA_VERSION == "1.0.0"


def test_mixed_ip_versions_are_rejected():
    with pytest.raises(ValidationError, match="different IP versions"):
        NormalizedEvent(
            timestamp=T0, source_type="SYNTHETIC", src_ip="10.0.0.1", dst_ip="2001:db8::1",
            transport_protocol="tcp",
        )


def test_events_are_immutable():
    event = flow()
    with pytest.raises(ValidationError):
        event.src_ip = "10.0.0.99"


@pytest.mark.parametrize(
    "bad",
    [
        "a" * 254,                      # over the 253-char DNS limit
        "x" * 64 + ".example.com",      # label over 63 chars
        "bad_char$.example.com",        # outside LDH
        "",                             # empty
        "double..dot.example.com",      # empty label
    ],
)
def test_malformed_domains_are_rejected(bad):
    with pytest.raises(ValueError):
        normalise_domain(bad)


def test_domain_is_canonicalised():
    assert normalise_domain("WWW.Example.COM.") == "www.example.com"


def test_dns_metadata_derives_structure():
    dns = DnsMetadata(query="a.b.c.example.com", qtype="TXT")
    assert dns.subdomain_depth == 3
    assert dns.query_length == len("a.b.c.example.com")


def test_feature_vector_rejects_non_finite_values():
    with pytest.raises(ValidationError, match="not finite"):
        FeatureVector(
            timestamp=T0, entity_kind="HOST", entity_id="10.0.0.1", window_seconds=1.0,
            values={"rate": float("inf")},
        )


def test_feature_require_raises_instead_of_defaulting_to_zero():
    """A missing feature must be loud: silently zero-filling hides a broken engine."""
    vector = FeatureVector(
        timestamp=T0, entity_kind="HOST", entity_id="10.0.0.1", window_seconds=1.0,
        values={"present": 1.0},
    )
    assert vector.require("present") == (1.0,)
    with pytest.raises(KeyError, match="missing"):
        vector.require("present", "absent")
    assert vector.get("absent", -1.0) == -1.0


def test_false_negative_feedback_requires_a_corrected_class():
    with pytest.raises(ValidationError, match="corrected_threat_class"):
        AnalystFeedback(alert_id="a1", label=FeedbackLabel.FALSE_NEGATIVE)
    ok = AnalystFeedback(
        alert_id="a1", label=FeedbackLabel.FALSE_NEGATIVE, corrected_threat_class="DGA"
    )
    assert ok.corrected_threat_class == "DGA"


def test_alert_requires_evidence():
    with pytest.raises(ValidationError):
        Alert(
            timestamp=T0, first_seen=T0, last_seen=T0, threat_class="DDOS", confidence=0.9,
            confidence_basis="RULE_EVIDENCE", severity="HIGH", entity_kind="DESTINATION",
            entity_id="10.0.0.9", detector_name="ddos", detector_version="1.0.0",
            technique="HYBRID",
        )


def test_confidence_is_bounded():
    with pytest.raises(ValidationError):
        Alert(
            timestamp=T0, first_seen=T0, last_seen=T0, threat_class="DDOS", confidence=1.5,
            confidence_basis="RULE_EVIDENCE", severity="HIGH", entity_kind="DESTINATION",
            entity_id="10.0.0.9", detector_name="ddos", detector_version="1.0.0",
            technique="HYBRID", evidence=Evidence(summary="x"),
        )
