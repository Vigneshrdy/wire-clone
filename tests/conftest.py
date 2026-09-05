"""Shared fixtures.

Everything is deterministic: fixed timestamps, seeded generators, in-memory
stores. No test reads the wall clock or the developer's real database, because a
detector suite that depends on "now" fails at midnight and nowhere else.
"""

from __future__ import annotations

import pytest

from sih_ntd.baselines import BaselineStore
from sih_ntd.config import Settings, get_settings
from sih_ntd.detectors import build_default_registry
from sih_ntd.features.engine import FeatureEngine
from sih_ntd.fusion import ThreatFusion
from sih_ntd.pipeline import Pipeline
from sih_ntd.schemas import DnsMetadata, NormalizedEvent, TlsMetadata
from sih_ntd.store import Store

#: Fixed reference time for every fixture (2025-09-04T15:33:20Z).
T0 = 1_757_000_000.0


@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path, monkeypatch):
    """Point the store and model registry at a temp dir for every test."""
    get_settings.cache_clear()
    monkeypatch.setenv("SIH_STORE__PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("SIH_REGISTRY__ROOT", str(tmp_path / "ml_artifacts"))
    yield
    get_settings.cache_clear()


@pytest.fixture
def settings() -> Settings:
    return get_settings()


@pytest.fixture
def store(settings) -> Store:
    store = Store(":memory:", settings=settings)
    yield store
    store.close()


@pytest.fixture
def engine(settings) -> FeatureEngine:
    return FeatureEngine(settings, baselines=BaselineStore())


@pytest.fixture
def detectors(settings):
    return build_default_registry(settings)


@pytest.fixture
def fusion(settings) -> ThreatFusion:
    return ThreatFusion(settings, pipeline_run_id="test-run")


@pytest.fixture
def pipeline(settings, store, detectors, engine, fusion) -> Pipeline:
    return Pipeline(
        settings, store=store, detectors=detectors, engine=engine, fusion=fusion,
        publish_alerts=False, run_id="test-run",
    )


def flow(
    ts: float = T0,
    src: str = "10.0.0.5",
    dst: str = "198.51.100.7",
    *,
    src_port: int = 40000,
    dst_port: int = 443,
    proto: str = "tcp",
    orig_bytes: int = 1000,
    resp_bytes: int | None = 2000,
    orig_packets: int = 10,
    resp_packets: int | None = 12,
    duration: float | None = 1.0,
    state: str = "SF",
    flags: str | None = "ShADadFf",
    service: str | None = None,
    dns: DnsMetadata | None = None,
    tls: TlsMetadata | None = None,
) -> NormalizedEvent:
    """Build one normalized event. Keyword-only so call sites read as English."""
    return NormalizedEvent(
        timestamp=ts, source_type="SYNTHETIC", src_ip=src, dst_ip=dst, src_port=src_port,
        dst_port=dst_port, transport_protocol=proto, orig_bytes=orig_bytes,
        resp_bytes=resp_bytes, orig_packets=orig_packets, resp_packets=resp_packets,
        duration=duration, connection_state=state, tcp_flags=flags, service=service,
        dns=dns, tls=tls,
    )


def syn_flood_events(count: int = 3000, target: str = "10.0.0.9", start: float = T0):
    """A distributed SYN flood: many sources, one target, nothing established."""
    return [
        flow(
            ts=start + i * 0.0005, src=f"203.0.113.{i % 250}", dst=target,
            src_port=1024 + (i % 60000), dst_port=80, orig_bytes=60, resp_bytes=0,
            orig_packets=1, resp_packets=0, duration=0.0, state="S0", flags="S",
        )
        for i in range(count)
    ]


@pytest.fixture
def dns_event_factory():
    """Build DNS query events with controllable name/qtype/rcode."""

    def build(name: str, ts: float = T0, *, qtype: str = "A", rcode: str = "NOERROR",
              response_bytes: int = 120, src: str = "10.0.0.5") -> NormalizedEvent:
        return flow(
            ts=ts, src=src, dst="10.0.0.53", dst_port=53, proto="udp", service="dns",
            orig_bytes=60 + len(name), resp_bytes=response_bytes, orig_packets=1,
            resp_packets=1, duration=0.01,
            dns=DnsMetadata(query=name, qtype=qtype, rcode=rcode, response_bytes=response_bytes),
        )

    return build
