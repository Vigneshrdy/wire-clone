"""Per-detector behaviour: positives, benign traffic, and boundary conditions.

These run through the real feature engine rather than hand-built feature dicts, so
a change that breaks the engine/detector contract fails here instead of in
production.
"""

from __future__ import annotations

import pytest

from sih_ntd.features.engine import FeatureEngine
from sih_ntd.schemas import DetectorState, ThreatClass, TlsMetadata
from sih_ntd.sensor.synthetic import generate
from tests.conftest import T0, flow, syn_flood_events


def run(engine: FeatureEngine, detectors, events):
    """Feed events through the engine and collect every detector result."""
    results = []
    for event in events:
        for vector in engine.process(event):
            results.extend(detectors.evaluate(vector))
    for vector in engine.flush():
        results.extend(detectors.evaluate(vector))
    return results


def classes(results) -> set[ThreatClass]:
    return {r.threat_class for r in results}


# --- DDoS ------------------------------------------------------------------
def test_ddos_fires_on_a_distributed_syn_flood(engine, detectors):
    results = run(engine, detectors, syn_flood_events(3000))
    ddos = [r for r in results if r.threat_class is ThreatClass.DDOS]
    assert ddos, "a 2000/s SYN flood from 250 sources must be detected"
    top = max(ddos, key=lambda r: r.confidence)
    assert "SYN_FLOOD_RATE" in top.reason_codes
    assert "DISTRIBUTED_SOURCES" in top.reason_codes
    assert top.supporting_features["syn_rate_1s"] > 500
    assert top.supporting_features["unique_src_ips_5s"] > 50


def test_ddos_reports_a_cold_baseline_instead_of_claiming_abnormality(engine, detectors):
    results = [r for r in run(engine, detectors, syn_flood_events(3000))
               if r.threat_class is ThreatClass.DDOS]
    assert any("BASELINE_COLD" in r.reason_codes for r in results)


def test_ddos_ignores_a_tiny_burst_below_the_flow_floor(engine, detectors):
    """Ten SYNs is not a flood; rates from near-empty windows must be ignored."""
    results = run(engine, detectors, syn_flood_events(10))
    assert ThreatClass.DDOS not in classes(results)


def test_ddos_ignores_high_volume_established_traffic(engine, detectors):
    """Volume alone is not an attack: these connections all complete."""
    events = [
        flow(ts=T0 + i * 0.0005, src=f"203.0.113.{i % 250}", dst="10.0.0.9",
             dst_port=443, orig_bytes=800, resp_bytes=4000, orig_packets=8,
             resp_packets=10, duration=0.4, state="SF", flags="ShADadFf")
        for i in range(3000)
    ]
    results = [r for r in run(engine, detectors, events) if r.threat_class is ThreatClass.DDOS]
    # A genuine 2000 flows/sec still trips the volumetric rule, but it must not be
    # reported as a SYN flood.
    assert all("SYN_FLOOD_RATE" not in r.reason_codes for r in results)


def test_ddos_detects_amplification(engine, detectors):
    results = run(engine, detectors, generate("ddos_udp_amp", count=4000, seed=5))
    ddos = [r for r in results if r.threat_class is ThreatClass.DDOS]
    assert ddos
    assert any("AMPLIFICATION_RATIO" in r.reason_codes or "UDP_FLOOD_RATE" in r.reason_codes
               for r in ddos)


# --- Recon -----------------------------------------------------------------
def test_recon_detects_a_vertical_port_scan(engine, detectors):
    results = run(engine, detectors, generate("scan_vertical", count=400, seed=5))
    recon = [r for r in results if r.threat_class is ThreatClass.RECON]
    assert recon
    assert "VERTICAL_PORT_SCAN" in max(recon, key=lambda r: r.confidence).reason_codes


def test_recon_detects_a_horizontal_sweep(engine, detectors):
    results = run(engine, detectors, generate("scan_horizontal", count=400, seed=5))
    recon = [r for r in results if r.threat_class is ThreatClass.RECON]
    assert recon
    assert any("HORIZONTAL_HOST_SCAN" in r.reason_codes or "NETWORK_SWEEP" in r.reason_codes
               for r in recon)


def test_recon_ignores_a_busy_client_whose_connections_succeed(engine, detectors):
    """Wide fan-out with successful connections is a proxy or backup agent, not a scan."""
    events = [
        flow(ts=T0 + i * 0.1, src="10.0.0.30", dst=f"198.51.100.{i % 60}", dst_port=443,
             orig_bytes=2000, resp_bytes=40_000, orig_packets=12, resp_packets=30,
             duration=3.0, state="SF", flags="ShADadFf")
        for i in range(300)
    ]
    assert ThreatClass.RECON not in classes(run(engine, detectors, events))


def test_recon_ignores_too_few_flows(engine, detectors):
    events = [
        flow(ts=T0 + i, src="203.0.113.77", dst="10.0.0.5", dst_port=1000 + i,
             orig_bytes=60, resp_bytes=0, orig_packets=1, resp_packets=0, duration=0.0,
             state="S0", flags="S")
        for i in range(5)
    ]
    assert ThreatClass.RECON not in classes(run(engine, detectors, events))


# --- C2 beaconing ----------------------------------------------------------
def test_c2_detects_a_fixed_interval_beacon(engine, detectors):
    results = run(engine, detectors, generate("c2_beacon", count=40, seed=5))
    c2 = [r for r in results if r.threat_class is ThreatClass.C2_BEACON]
    assert c2
    top = max(c2, key=lambda r: r.confidence)
    assert "PERIODIC_INTERVALS" in top.reason_codes
    assert top.supporting_features["periodicity_score"] > 0.7
    assert top.supporting_features["interarrival_cv"] < 0.25
    assert len(top.reason_codes) >= 3, "periodicity alone must not be enough to fire"


def test_c2_ignores_irregular_traffic(engine, detectors):
    import random

    rng = random.Random(11)
    ts = T0
    events = []
    for _ in range(40):
        ts += rng.uniform(1.0, 120.0)
        events.append(flow(ts=ts, src="10.0.0.42", dst="192.0.2.66", dst_port=443,
                           orig_bytes=rng.randint(500, 90_000), state="SF"))
    assert ThreatClass.C2_BEACON not in classes(run(engine, detectors, events))


def test_c2_ignores_sub_second_polling(engine, detectors):
    """1s-interval keepalives are regular but are not beacons."""
    events = [
        flow(ts=T0 + i * 1.0, src="10.0.0.42", dst="192.0.2.66", dst_port=443,
             orig_bytes=512, resp_bytes=512, duration=0.5, state="SF")
        for i in range(40)
    ]
    assert ThreatClass.C2_BEACON not in classes(run(engine, detectors, events))


# --- DNS tunnelling --------------------------------------------------------
def test_dns_tunnel_detects_encoded_subdomains(engine, detectors):
    results = run(engine, detectors, generate("dns_tunnel", count=200, seed=5))
    tunnel = [r for r in results if r.threat_class is ThreatClass.DNS_TUNNEL]
    assert tunnel
    top = max(tunnel, key=lambda r: r.confidence)
    assert top.supporting_features["dns_domain_length"] >= 60
    assert any(code.startswith(("OVERSIZED", "HIGH_QUERY", "HEX_")) for code in top.reason_codes)


def test_dns_tunnel_ignores_ordinary_lookups(engine, detectors, dns_event_factory):
    events = [
        dns_event_factory(name, ts=T0 + i * 0.5)
        for i, name in enumerate(
            ["cdn.example.com", "api.example.net", "mail.example.org"] * 40
        )
    ]
    assert ThreatClass.DNS_TUNNEL not in classes(run(engine, detectors, events))


def test_dns_tunnel_needs_behaviour_as_well_as_a_long_name(engine, detectors, dns_event_factory):
    """One long high-entropy name is a CDN asset lookup, not a tunnel."""
    long_name = "a1b2c3d4e5f60718293a4b5c6d7e8f90.assets.example.net"
    assert ThreatClass.DNS_TUNNEL not in classes(
        run(engine, detectors, [dns_event_factory(long_name)])
    )


# --- Exfiltration ----------------------------------------------------------
def test_exfiltration_detects_sustained_outbound_upload(engine, detectors):
    results = run(engine, detectors, generate("exfil", count=60, seed=5))
    exfil = [r for r in results if r.threat_class is ThreatClass.EXFILTRATION]
    assert exfil
    top = max(exfil, key=lambda r: r.confidence)
    assert "HIGH_OUTBOUND_VOLUME" in top.reason_codes
    assert len(top.reason_codes) >= 2, "volume alone must never be reported as exfiltration"


def test_exfiltration_ignores_large_inbound_downloads(engine, detectors):
    events = [
        flow(ts=T0 + i * 2.0, src="10.0.0.31", dst="198.51.100.9", dst_port=443,
             orig_bytes=5_000, resp_bytes=20_000_000, orig_packets=100,
             resp_packets=9000, duration=30.0, state="SF")
        for i in range(60)
    ]
    assert ThreatClass.EXFILTRATION not in classes(run(engine, detectors, events))


def test_exfiltration_ignores_internal_transfers(engine, detectors):
    """Inside-to-inside bulk copy is a backup, not egress."""
    events = [
        flow(ts=T0 + i * 2.0, src="10.0.0.31", dst="10.0.0.40", dst_port=445,
             orig_bytes=20_000_000, resp_bytes=5_000, orig_packets=9000,
             resp_packets=100, duration=60.0, state="SF")
        for i in range(60)
    ]
    assert ThreatClass.EXFILTRATION not in classes(run(engine, detectors, events))


# --- unavailable detectors -------------------------------------------------
def test_unavailable_detectors_report_state_and_never_score(engine, detectors):
    """An honest gap: no model, no output, and a reason an operator can read."""
    for name in ("dga", "tls_malware"):
        detector = detectors.get(name)
        assert detector is not None
        assert detector.state() is DetectorState.UNAVAILABLE
        assert detector.state_reason()
        assert detector not in detectors.ready()

    tls_flow = flow(
        tls=TlsMetadata(version="TLSv13", sni="rare.example.org", ja4="t13d1234h2_abc_def",
                        cert_self_signed=True, established=True)
    )
    results = run(engine, detectors, [tls_flow])
    assert ThreatClass.TLS_MALWARE not in classes(results)
    assert ThreatClass.DGA not in classes(results)


# --- false-positive budget -------------------------------------------------
def test_benign_traffic_produces_no_detections(engine, detectors):
    """The single most important detector test: 3000 benign flows, zero alerts."""
    results = run(engine, detectors, generate("benign", count=3000, seed=5))
    assert results == [], f"false positives on benign traffic: {classes(results)}"
