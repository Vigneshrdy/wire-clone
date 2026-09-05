"""Seeded synthetic traffic metadata generator.

Purpose: deterministic, offline, safe test and demo data. It emits *metadata*
(flow records with DNS/TLS fields), never packets, and it never touches a network
interface -- so it cannot be repurposed into an attack tool.

Every scenario is seeded, so the same seed produces the same events, which is what
makes detector tests assertable and benchmarks comparable. All addresses come from
documentation/test ranges (RFC 5737 ``203.0.113.0/24``, ``198.51.100.0/24``,
``192.0.2.0/24``) and RFC 1918 space for the "inside" hosts.

Scenarios: ``benign``, ``ddos_syn``, ``ddos_udp_amp``, ``scan_vertical``,
``scan_horizontal``, ``c2_beacon``, ``dga``, ``dns_tunnel``, ``exfil``, ``mixed``.
"""

from __future__ import annotations

import random
import string
import zlib
from typing import Callable, Iterator

from ..ingest import derive_event_id
from ..schemas import DnsMetadata, NormalizedEvent, SourceType, TlsMetadata

INSIDE_HOSTS = [f"10.0.0.{i}" for i in range(5, 60)]
OUTSIDE_HOSTS = [f"198.51.100.{i}" for i in range(2, 60)]
BOTNET_SOURCES = [f"203.0.113.{i}" for i in range(1, 255)]
TARGET = "10.0.0.9"
RESOLVER = "10.0.0.53"

BENIGN_DOMAINS = [
    "cdn.example.com", "api.example.net", "mail.example.org", "updates.example.com",
    "images.example.net", "login.example.org", "search.example.com", "static.example.net",
    "docs.example.org", "chat.example.com", "maps.example.net", "video.example.org",
]
BENIGN_SERVICES = [("https", 443, "tcp"), ("http", 80, "tcp"), ("dns", 53, "udp"),
                   ("ssh", 22, "tcp"), ("smtp", 25, "tcp")]
BENIGN_JA4 = ["t13d1516h2_8daaf6152771_02713d6af862", "t13d1517h2_8daaf6152771_b0da82dd1658"]


def _rand_label(rng: random.Random, length: int, alphabet: str = string.ascii_lowercase + string.digits) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _event(**kwargs) -> NormalizedEvent:
    kwargs.setdefault("source_type", SourceType.SYNTHETIC)
    kwargs.setdefault("sensor_id", "synthetic")
    # Deterministic event_id (the schema default is a random uuid4): the same seed
    # must produce byte-identical events so replays are idempotent and benchmark
    # runs are comparable.
    dns = kwargs.get("dns")
    flow_key = (
        f"{kwargs['src_ip']}:{kwargs.get('src_port')}>{kwargs['dst_ip']}:"
        f"{kwargs.get('dst_port')}/{kwargs['transport_protocol']}"
        f"|{dns.query if dns else ''}"
    )
    kwargs.setdefault("event_id", derive_event_id(float(kwargs["timestamp"]), flow_key, "synthetic"))
    return NormalizedEvent(**kwargs)


def benign(rng: random.Random, start: float, count: int) -> Iterator[NormalizedEvent]:
    """Ordinary traffic: established connections, cached DNS, low fan-out.

    Deliberately includes some failed connections and some DNS, because a
    "benign" fixture with zero noise is not a real false-positive test.
    """
    ts = start
    for _ in range(count):
        ts += rng.expovariate(4.0)  # ~4 flows/sec, Poisson arrivals
        host = rng.choice(INSIDE_HOSTS)
        service, port, proto = rng.choice(BENIGN_SERVICES)
        if service == "dns":
            yield _event(
                timestamp=ts, src_ip=host, dst_ip=RESOLVER, src_port=rng.randint(32768, 60999),
                dst_port=53, transport_protocol="udp", service="dns", orig_packets=1,
                resp_packets=1, orig_bytes=rng.randint(60, 90), resp_bytes=rng.randint(90, 300),
                duration=round(rng.uniform(0.001, 0.05), 4), connection_state="SF",
                dns=DnsMetadata(
                    query=rng.choice(BENIGN_DOMAINS), qtype="A", rcode="NOERROR",
                    answers=["93.184.216.34"], response_bytes=rng.randint(90, 300),
                ),
            )
            continue
        orig_bytes = rng.randint(400, 20_000)
        tls = None
        if port == 443:
            tls = TlsMetadata(
                version="TLSv13", sni=rng.choice(BENIGN_DOMAINS), ja4=rng.choice(BENIGN_JA4),
                cipher="TLS_AES_128_GCM_SHA256", cert_validity_days=90,
                cert_self_signed=False, established=True,
            )
        failed = rng.random() < 0.05
        yield _event(
            timestamp=ts, src_ip=host, dst_ip=rng.choice(OUTSIDE_HOSTS),
            src_port=rng.randint(32768, 60999), dst_port=port, transport_protocol=proto,
            service=service, orig_packets=0 if failed else rng.randint(5, 60),
            resp_packets=0 if failed else rng.randint(5, 80),
            orig_bytes=0 if failed else orig_bytes,
            resp_bytes=0 if failed else rng.randint(400, 200_000),
            duration=None if failed else round(rng.uniform(0.05, 30.0), 3),
            connection_state="S0" if failed else "SF", tcp_flags="S" if failed else "ShADadFf",
            tls=tls,
        )


def ddos_syn(rng: random.Random, start: float, count: int) -> Iterator[NormalizedEvent]:
    """Distributed SYN flood: many spoofed-looking sources, one target, no replies."""
    ts = start
    for i in range(count):
        ts += rng.uniform(0.0002, 0.0008)  # ~2000 flows/sec
        yield _event(
            timestamp=ts, src_ip=BOTNET_SOURCES[i % len(BOTNET_SOURCES)], dst_ip=TARGET,
            src_port=rng.randint(1024, 65535), dst_port=80, transport_protocol="tcp",
            service="http", orig_packets=1, resp_packets=0, orig_bytes=60, resp_bytes=0,
            duration=0.0, connection_state="S0", tcp_flags="S",
        )


def ddos_udp_amp(rng: random.Random, start: float, count: int) -> Iterator[NormalizedEvent]:
    """Reflection/amplification: small requests, large responses toward the victim."""
    ts = start
    for i in range(count):
        ts += rng.uniform(0.0003, 0.001)
        request = rng.randint(60, 80)
        yield _event(
            timestamp=ts, src_ip=BOTNET_SOURCES[i % len(BOTNET_SOURCES)], dst_ip=TARGET,
            src_port=53, dst_port=rng.randint(1024, 65535), transport_protocol="udp",
            service="dns", orig_packets=1, resp_packets=1, orig_bytes=request,
            resp_bytes=request * rng.randint(20, 50), duration=0.001,
            connection_state="SF",
        )


def scan_vertical(rng: random.Random, start: float, count: int) -> Iterator[NormalizedEvent]:
    """One attacker enumerating many ports on a few hosts."""
    ts = start
    attacker = "203.0.113.77"
    targets = INSIDE_HOSTS[:3]
    for i in range(count):
        ts += rng.uniform(0.01, 0.05)
        yield _event(
            timestamp=ts, src_ip=attacker, dst_ip=targets[i % len(targets)],
            src_port=rng.randint(40000, 60000), dst_port=1 + (i * 7) % 9000,
            transport_protocol="tcp", orig_packets=1, resp_packets=0, orig_bytes=60,
            resp_bytes=0, duration=0.0, connection_state="S0", tcp_flags="S",
        )


def scan_horizontal(rng: random.Random, start: float, count: int) -> Iterator[NormalizedEvent]:
    """One attacker probing one service across the whole subnet."""
    ts = start
    attacker = "203.0.113.88"
    for i in range(count):
        ts += rng.uniform(0.005, 0.02)
        yield _event(
            timestamp=ts, src_ip=attacker, dst_ip=f"10.0.{(i // 254) % 4}.{1 + i % 254}",
            src_port=rng.randint(40000, 60000), dst_port=445, transport_protocol="tcp",
            service="smb", orig_packets=1, resp_packets=0, orig_bytes=60, resp_bytes=0,
            duration=0.0, connection_state="REJ", tcp_flags="S",
        )


def c2_beacon(rng: random.Random, start: float, count: int) -> Iterator[NormalizedEvent]:
    """Fixed-interval check-ins with stable payload size to a rare destination."""
    ts = start
    host, c2 = "10.0.0.42", "192.0.2.66"
    interval = 30.0
    for _ in range(count):
        ts += interval + rng.uniform(-0.4, 0.4)  # small jitter, CV well under 0.25
        payload = 512 + rng.randint(-8, 8)
        yield _event(
            timestamp=ts, src_ip=host, dst_ip=c2, src_port=rng.randint(32768, 60999),
            dst_port=443, transport_protocol="tcp", service="ssl", orig_packets=6,
            resp_packets=5, orig_bytes=payload, resp_bytes=payload + rng.randint(-16, 16),
            duration=round(rng.uniform(0.4, 0.6), 3), connection_state="SF",
            tcp_flags="ShADadFf",
            tls=TlsMetadata(
                version="TLSv12", sni=None, ja4="t12d0708h1_c867ba2a4e4c_9f1f2c1a0b33",
                cipher="TLS_RSA_WITH_AES_128_CBC_SHA", cert_validity_days=365,
                cert_self_signed=True, established=True,
            ),
        )


def dga(rng: random.Random, start: float, count: int) -> Iterator[NormalizedEvent]:
    """Malware walking a generated-domain list; most lookups NXDOMAIN."""
    ts = start
    host = "10.0.0.42"
    for i in range(count):
        ts += rng.uniform(0.2, 1.5)
        name = f"{_rand_label(rng, rng.randint(12, 22))}.{rng.choice(['com', 'net', 'info'])}"
        resolved = i % 12 == 0
        yield _event(
            timestamp=ts, src_ip=host, dst_ip=RESOLVER, src_port=rng.randint(32768, 60999),
            dst_port=53, transport_protocol="udp", service="dns", orig_packets=1,
            resp_packets=1, orig_bytes=60 + len(name), resp_bytes=90 if resolved else 60,
            duration=0.01, connection_state="SF",
            dns=DnsMetadata(
                query=name, qtype="A", rcode="NOERROR" if resolved else "NXDOMAIN",
                answers=["192.0.2.77"] if resolved else [],
                response_bytes=90 if resolved else 60,
            ),
        )


def dns_tunnel(rng: random.Random, start: float, count: int) -> Iterator[NormalizedEvent]:
    """Data carried in long, unique, hex-encoded subdomains under one zone."""
    ts = start
    host = "10.0.0.51"
    for _ in range(count):
        ts += rng.uniform(0.05, 0.15)  # sustained ~10 queries/sec
        chunk = _rand_label(rng, 48, "0123456789abcdef")
        name = f"{chunk[:24]}.{chunk[24:]}.tunnel.example.net"
        yield _event(
            timestamp=ts, src_ip=host, dst_ip=RESOLVER, src_port=rng.randint(32768, 60999),
            dst_port=53, transport_protocol="udp", service="dns", orig_packets=1,
            resp_packets=1, orig_bytes=60 + len(name), resp_bytes=rng.randint(400, 900),
            duration=0.01, connection_state="SF",
            dns=DnsMetadata(
                query=name, qtype="TXT", rcode="NOERROR",
                answers=[_rand_label(rng, 60)], response_bytes=rng.randint(400, 900),
            ),
        )


def exfil(rng: random.Random, start: float, count: int) -> Iterator[NormalizedEvent]:
    """Sustained outbound bulk upload to a destination the host never uses.

    Preceded by a baseline-warming phase, because the detector must not fire on a
    cold baseline and a fixture that skips the warm-up tests nothing.
    """
    ts = start
    host, sink = "10.0.0.31", "192.0.2.130"
    for _ in range(max(40, count // 2)):
        ts += rng.uniform(0.5, 1.5)
        yield _event(
            timestamp=ts, src_ip=host, dst_ip=rng.choice(OUTSIDE_HOSTS),
            src_port=rng.randint(32768, 60999), dst_port=443, transport_protocol="tcp",
            service="ssl", orig_packets=20, resp_packets=40,
            orig_bytes=rng.randint(2_000, 20_000), resp_bytes=rng.randint(20_000, 200_000),
            duration=round(rng.uniform(0.5, 5.0), 3), connection_state="SF",
        )
    for _ in range(count):
        ts += rng.uniform(0.5, 2.0)
        yield _event(
            timestamp=ts, src_ip=host, dst_ip=sink, src_port=rng.randint(32768, 60999),
            dst_port=443, transport_protocol="tcp", service="ssl",
            orig_packets=rng.randint(4000, 9000), resp_packets=rng.randint(80, 200),
            orig_bytes=rng.randint(6_000_000, 12_000_000), resp_bytes=rng.randint(4_000, 20_000),
            duration=round(rng.uniform(60.0, 180.0), 2), connection_state="SF",
        )


SCENARIOS: dict[str, Callable[[random.Random, float, int], Iterator[NormalizedEvent]]] = {
    "benign": benign,
    "ddos_syn": ddos_syn,
    "ddos_udp_amp": ddos_udp_amp,
    "scan_vertical": scan_vertical,
    "scan_horizontal": scan_horizontal,
    "c2_beacon": c2_beacon,
    "dga": dga,
    "dns_tunnel": dns_tunnel,
    "exfil": exfil,
}


def generate(
    scenario: str = "mixed", count: int = 1000, seed: int = 1337, start: float = 1_757_000_000.0
) -> list[NormalizedEvent]:
    """Deterministic event list for one scenario, sorted by timestamp.

    ``mixed`` overlays benign traffic with every attack pattern, which is the
    realistic case: detectors must find the needle while the haystack is present.
    """
    rng = random.Random(seed)
    if scenario == "mixed":
        events: list[NormalizedEvent] = list(benign(rng, start, count))
        for name, builder in SCENARIOS.items():
            if name == "benign":
                continue
            # crc32, not hash(): str hashing is salted per process, which would
            # make "mixed" non-reproducible across runs.
            offset = zlib.crc32(name.encode()) % 1000
            # Rate-based scenarios need enough flows for a per-second threshold to
            # be reachable; behavioural ones do not.
            volume = max(2000, count * 2) if name.startswith("ddos") else max(60, count // 6)
            events.extend(
                builder(random.Random(seed + offset), start + 5.0, volume)
            )
        events.sort(key=lambda e: e.epoch)
        return events
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}; choose from {sorted(SCENARIOS) + ['mixed']}")
    events = list(SCENARIOS[scenario](rng, start, count))
    events.sort(key=lambda e: e.epoch)
    return events
