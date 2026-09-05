"""Stateful streaming feature engine.

Turns a stream of :class:`~sih_ntd.schemas.NormalizedEvent` into
:class:`~sih_ntd.schemas.FeatureVector` objects. This module is the *only* place
features are computed, for both streaming inference and offline dataset
construction, so a model can never be trained on a different definition of
``syn_rate_5s`` than the one production computes.

Three entity perspectives are tracked, because the same flow is evidence of
different things depending on which end you look from:

* ``HOST``        keyed by source IP -- fan-out, scanning, DNS behaviour, exfil
* ``DESTINATION`` keyed by destination IP -- inbound flood concentration
* ``PAIR``        keyed by ``src->dst`` -- beacon periodicity and payload stability

Emission
--------
Windowed vectors are rate-limited to one per entity per
``windows.emit_interval_seconds`` and carry *every* window size at once
(``flows_per_sec_1s`` ... ``flows_per_sec_300s``). One vector with suffixed names
beats five vectors per entity: fewer objects on the hot path, and a detector can
compare a 1s burst against a 300s baseline without joining anything.

Protocol vectors (DNS, TLS) are emitted per event with ``window_seconds == 0.0``
because a DGA verdict on a single query must not wait for the next window tick.
They still include the host's windowed DNS behaviour so the DNS-tunnelling
detector can combine lexical and behavioural evidence from one input.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..baselines import BaselineStore
from ..config import Settings, get_settings
from ..schemas import (
    Direction,
    EntityKind,
    FeatureVector,
    NormalizedEvent,
    TransportProtocol,
)
from ..windows import (
    IntervalTracker,
    LruStateMap,
    SlidingWindow,
    UniqueTracker,
    window_suffix,
)
from . import stats

# Metrics that get a behavioural baseline. Kept short and explicit: every entry
# costs one EWMA series per entity, and a baseline nobody reads is pure memory.
BASELINED_METRICS: tuple[str, ...] = (
    "flows_per_sec_60s",
    "bytes_out_per_sec_60s",
    "syn_rate_5s",
    "unique_dst_ports_60s",
    "unique_dst_ips_60s",
    "dns_queries_per_sec_60s",
)


@dataclass
class WindowBundle:
    """All counters for one entity at one window size.

    Names are *absolute* (``src_``/``dst_`` refer to the flow, not to the entity),
    so the same bundle serves every perspective and detectors cannot mix up whose
    fan-out they are reading.
    """

    size: float

    def __post_init__(self) -> None:
        w = self.size
        self.flows = SlidingWindow(w)
        self.packets = SlidingWindow(w)
        self.orig_bytes = SlidingWindow(w)
        self.resp_bytes = SlidingWindow(w)
        self.orig_packets = SlidingWindow(w)
        self.resp_packets = SlidingWindow(w)
        self.syn_only = SlidingWindow(w)
        self.failed = SlidingWindow(w)
        self.duration = SlidingWindow(w)
        self.tcp = SlidingWindow(w)
        self.udp = SlidingWindow(w)
        self.icmp = SlidingWindow(w)
        self.src_ips = UniqueTracker(w)
        self.dst_ips = UniqueTracker(w)
        self.dst_ports = UniqueTracker(w)
        self.services = UniqueTracker(w)
        self.ja4 = UniqueTracker(w)
        self.dns_queries = SlidingWindow(w)
        self.dns_txt = SlidingWindow(w)
        self.dns_nxdomain = SlidingWindow(w)
        self.dns_response_bytes = SlidingWindow(w)
        self.dns_names = UniqueTracker(w)
        self._all = (
            self.flows, self.packets, self.orig_bytes, self.resp_bytes,
            self.orig_packets, self.resp_packets, self.syn_only, self.failed,
            self.duration, self.tcp, self.udp, self.icmp, self.dns_queries,
            self.dns_txt, self.dns_nxdomain, self.dns_response_bytes,
        )
        self._trackers = (
            self.src_ips, self.dst_ips, self.dst_ports, self.services,
            self.ja4, self.dns_names,
        )

    def observe(self, event: NormalizedEvent) -> None:
        ts = event.epoch
        self.flows.add(ts)
        self.packets.add(ts, event.total_packets)
        self.orig_bytes.add(ts, event.orig_bytes)
        self.resp_bytes.add(ts, event.resp_bytes or 0)
        self.orig_packets.add(ts, event.orig_packets)
        self.resp_packets.add(ts, event.resp_packets or 0)
        if event.is_syn_only:
            self.syn_only.add(ts)
        if event.failed:
            self.failed.add(ts)
        if event.duration is not None:
            self.duration.add(ts, event.duration)
        proto = event.transport_protocol
        if proto is TransportProtocol.TCP:
            self.tcp.add(ts)
        elif proto is TransportProtocol.UDP:
            self.udp.add(ts)
        elif proto is TransportProtocol.ICMP:
            self.icmp.add(ts)
        self.src_ips.add(ts, str(event.src_ip))
        self.dst_ips.add(ts, str(event.dst_ip))
        if event.dst_port is not None:
            self.dst_ports.add(ts, event.dst_port)
        if event.service:
            self.services.add(ts, event.service)
        if event.tls and event.tls.ja4:
            self.ja4.add(ts, event.tls.ja4)
        if event.dns is not None:
            self.dns_queries.add(ts)
            if event.dns.query:
                self.dns_names.add(ts, event.dns.query)
            if (event.dns.qtype or "").upper() in {"TXT", "NULL", "CNAME"}:
                self.dns_txt.add(ts)
            if (event.dns.rcode or "").upper() in {"NXDOMAIN", "3"}:
                self.dns_nxdomain.add(ts)
            if event.dns.response_bytes:
                self.dns_response_bytes.add(ts, event.dns.response_bytes)

    def expire(self, now: float) -> None:
        for window in self._all:
            window.expire(now)
        for tracker in self._trackers:
            tracker.expire(now)

    def features(self, now: float) -> dict[str, float]:
        s = window_suffix(self.size)
        flows = self.flows.count
        out_bytes = self.orig_bytes.total
        in_bytes = self.resp_bytes.total
        return {
            f"flows_per_sec_{s}": self.flows.count_rate(),
            f"flow_count_{s}": float(flows),
            f"packets_per_sec_{s}": self.packets.rate(),
            f"bytes_per_sec_{s}": (out_bytes + in_bytes) / self.size,
            f"bytes_out_per_sec_{s}": out_bytes / self.size,
            f"bytes_in_per_sec_{s}": in_bytes / self.size,
            f"bytes_out_total_{s}": out_bytes,
            f"bytes_in_total_{s}": in_bytes,
            f"mean_packet_size_{s}": stats.ratio(out_bytes + in_bytes, self.packets.total),
            f"mean_duration_{s}": self.duration.mean,
            f"syn_rate_{s}": self.syn_only.count_rate(),
            f"syn_count_{s}": float(self.syn_only.count),
            f"syn_ratio_{s}": stats.ratio(self.syn_only.count, flows, cap=1.0),
            f"failed_ratio_{s}": stats.ratio(self.failed.count, flows, cap=1.0),
            f"tcp_ratio_{s}": stats.ratio(self.tcp.count, flows, cap=1.0),
            f"udp_ratio_{s}": stats.ratio(self.udp.count, flows, cap=1.0),
            f"icmp_ratio_{s}": stats.ratio(self.icmp.count, flows, cap=1.0),
            f"udp_rate_{s}": self.udp.count_rate(),
            f"orig_resp_byte_ratio_{s}": stats.ratio(out_bytes, in_bytes),
            f"orig_resp_packet_ratio_{s}": stats.ratio(
                self.orig_packets.total, self.resp_packets.total
            ),
            f"amplification_ratio_{s}": stats.ratio(in_bytes, out_bytes),
            f"unique_src_ips_{s}": float(self.src_ips.cardinality),
            f"unique_dst_ips_{s}": float(self.dst_ips.cardinality),
            f"unique_dst_ports_{s}": float(self.dst_ports.cardinality),
            f"unique_services_{s}": float(self.services.cardinality),
            f"unique_ja4_{s}": float(self.ja4.cardinality),
            f"src_ip_entropy_{s}": stats.shannon_entropy(self.src_ips.counts()),
            f"dst_ip_entropy_{s}": stats.shannon_entropy(self.dst_ips.counts()),
            f"dst_port_entropy_{s}": stats.shannon_entropy(self.dst_ports.counts()),
            f"src_ip_entropy_norm_{s}": stats.normalised_entropy(self.src_ips.counts()),
            f"dst_concentration_{s}": self.dst_ips.top_share(),
            f"src_concentration_{s}": self.src_ips.top_share(),
            f"fanout_{s}": stats.ratio(self.dst_ips.cardinality, flows, cap=1.0),
            f"dns_queries_per_sec_{s}": self.dns_queries.count_rate(),
            f"dns_query_count_{s}": float(self.dns_queries.count),
            f"dns_unique_name_ratio_{s}": stats.ratio(
                self.dns_names.cardinality, self.dns_queries.count, cap=1.0
            ),
            f"dns_txt_ratio_{s}": stats.ratio(self.dns_txt.count, self.dns_queries.count, cap=1.0),
            f"dns_nxdomain_ratio_{s}": stats.ratio(
                self.dns_nxdomain.count, self.dns_queries.count, cap=1.0
            ),
            f"dns_mean_response_bytes_{s}": self.dns_response_bytes.mean,
            f"coverage_{s}": self.flows.coverage(now),
        }


@dataclass
class EntityState:
    """Per-entity streaming state across every configured window size."""

    kind: EntityKind
    entity_id: str
    sizes: tuple[float, ...]
    bundles: dict[float, WindowBundle] = field(default_factory=dict, repr=False)
    intervals: IntervalTracker = field(default_factory=IntervalTracker, repr=False)
    byte_samples: list[float] = field(default_factory=list, repr=False)
    duration_samples: list[float] = field(default_factory=list, repr=False)
    last_emit: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0
    event_count: int = 0
    recent_flow_ids: list[str] = field(default_factory=list, repr=False)
    recent_pcaps: list[str] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self.bundles = {size: WindowBundle(size) for size in self.sizes}

    def observe(self, event: NormalizedEvent) -> None:
        ts = event.epoch
        if self.first_seen == 0.0:
            self.first_seen = ts
        self.last_seen = ts
        self.event_count += 1
        for bundle in self.bundles.values():
            bundle.expire(ts)
            bundle.observe(event)
        self.intervals.add(ts)
        # Bounded payload-stability samples for beacon scoring.
        self.byte_samples.append(float(event.total_bytes))
        if len(self.byte_samples) > 64:
            del self.byte_samples[0]
        if event.duration is not None:
            self.duration_samples.append(event.duration)
            if len(self.duration_samples) > 64:
                del self.duration_samples[0]
        if event.flow_id:
            self.recent_flow_ids.append(event.flow_id)
            if len(self.recent_flow_ids) > 64:
                del self.recent_flow_ids[0]
        if event.pcap_reference and event.pcap_reference not in self.recent_pcaps:
            self.recent_pcaps.append(event.pcap_reference)
            if len(self.recent_pcaps) > 8:
                del self.recent_pcaps[0]

    def timing_features(self) -> dict[str, float]:
        intervals = self.intervals.intervals()
        return {
            "interarrival_mean": stats.mean(intervals),
            "interarrival_stdev": stats.stdev(intervals),
            "interarrival_cv": stats.coefficient_of_variation(intervals),
            "interarrival_count": float(len(intervals)),
            "periodicity_score": stats.periodicity_score(intervals),
            "burstiness": stats.burstiness(intervals),
            "byte_stability_cv": stats.coefficient_of_variation(self.byte_samples),
            "duration_stability_cv": stats.coefficient_of_variation(self.duration_samples),
            "mean_flow_bytes": stats.mean(self.byte_samples),
            "observed_span": max(0.0, self.last_seen - self.first_seen),
            "entity_event_count": float(self.event_count),
        }

    def features(self, now: float) -> dict[str, float]:
        values: dict[str, float] = {}
        for bundle in self.bundles.values():
            values.update(bundle.features(now))
        values.update(self.timing_features())
        return values


class FeatureEngine:
    """Event -> feature vectors. Single-threaded and deterministic by design."""

    def __init__(
        self,
        settings: Settings | None = None,
        baselines: BaselineStore | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.sizes = tuple(self.settings.windows.sizes)
        self.emit_interval = self.settings.windows.emit_interval_seconds
        self.baselines = baselines if baselines is not None else BaselineStore()
        self._states: LruStateMap = LruStateMap(self.settings.windows.max_tracked_entities)
        self._home_networks = [
            ipaddress.ip_network(net) for net in self.settings.sensor.home_networks
        ]

    # --- entity state ----------------------------------------------------
    def _state(self, kind: EntityKind, entity_id: str) -> EntityState:
        return self._states.touch(
            (kind, entity_id),
            lambda: EntityState(kind=kind, entity_id=entity_id, sizes=self.sizes),
        )

    def is_internal(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip in net for net in self._home_networks)

    def classify_direction(self, event: NormalizedEvent) -> Direction:
        """Direction relative to the configured home networks.

        Only used to describe the flow; nothing is ever sent anywhere.
        """
        src_internal = self.is_internal(str(event.src_ip))
        dst_internal = self.is_internal(str(event.dst_ip))
        if src_internal and dst_internal:
            return Direction.INTERNAL
        if src_internal:
            return Direction.OUTBOUND
        if dst_internal:
            return Direction.INBOUND
        return Direction.EXTERNAL

    # --- main entry point ------------------------------------------------
    def process(self, event: NormalizedEvent) -> list[FeatureVector]:
        """Fold one event into state and return whatever vectors are now due."""
        ts = event.epoch
        src, dst = str(event.src_ip), str(event.dst_ip)
        pair_id = f"{src}->{dst}"

        host = self._state(EntityKind.HOST, src)
        destination = self._state(EntityKind.DESTINATION, dst)
        pair = self._state(EntityKind.PAIR, pair_id)
        for state in (host, destination, pair):
            state.observe(event)

        vectors: list[FeatureVector] = []
        for state in (host, destination, pair):
            if ts - state.last_emit >= self.emit_interval:
                vectors.append(self._build(state, ts, event))
                state.last_emit = ts

        # Protocol vectors: emitted per event, window_seconds == 0.0.
        if event.dns is not None and event.dns.query:
            vectors.append(self._dns_vector(host, event, ts))
        if event.tls is not None and (event.tls.ja4 or event.tls.sni):
            vectors.append(self._tls_vector(pair, event, ts))

        # Destination rarity is maintained after feature construction so a first
        # contact is still reported as rare in the vector describing it.
        self.baselines.note_destination(src, dst)
        return vectors

    def _build(self, state: EntityState, ts: float, event: NormalizedEvent) -> FeatureVector:
        values = state.features(ts)
        values["is_internal_source"] = 1.0 if self.is_internal(str(event.src_ip)) else 0.0
        values["is_internal_destination"] = 1.0 if self.is_internal(str(event.dst_ip)) else 0.0
        values["destination_rarity"] = self.baselines.destination_rarity(
            str(event.src_ip), str(event.dst_ip)
        )
        values.update(self._baseline_features(state, values))
        return FeatureVector(
            timestamp=ts,
            entity_kind=state.kind,
            entity_id=state.entity_id,
            window_seconds=max(self.sizes),
            values=values,
            labels=self._labels(event, state),
            event_count=state.event_count,
            flow_ids=list(state.recent_flow_ids[-64:]),
            pcap_references=list(state.recent_pcaps[-8:]),
        )

    def _baseline_features(self, state: EntityState, values: dict[str, float]) -> dict[str, float]:
        """Compare selected metrics to their EWMA baseline.

        ``*_baseline_warm`` is emitted explicitly so a detector can distinguish
        "within baseline" from "no baseline yet"; the z-score is 0.0 in the cold
        case, never a large number.
        """
        out: dict[str, float] = {}
        for metric in BASELINED_METRICS:
            if metric not in values:
                continue
            deviation = self.baselines.observe(state.kind, state.entity_id, metric, values[metric])
            if deviation is None:
                out[f"{metric}_zscore"] = 0.0
                out[f"{metric}_baseline_mean"] = 0.0
                out[f"{metric}_baseline_p95"] = 0.0
                out[f"{metric}_baseline_warm"] = 0.0
            else:
                out[f"{metric}_zscore"] = deviation.zscore
                out[f"{metric}_baseline_mean"] = deviation.baseline_mean
                out[f"{metric}_baseline_p95"] = (
                    0.0 if deviation.p95 != deviation.p95 else deviation.p95
                )
                out[f"{metric}_baseline_warm"] = 1.0
        return out

    @staticmethod
    def _labels(event: NormalizedEvent, state: EntityState) -> dict[str, str]:
        labels = {
            "src_ip": str(event.src_ip),
            "dst_ip": str(event.dst_ip),
            "transport": str(event.transport_protocol),
            "direction": str(event.direction),
        }
        if event.service:
            labels["service"] = event.service
        if event.dst_port is not None:
            labels["dst_port"] = str(event.dst_port)
        return labels

    def _dns_vector(self, host: EntityState, event: NormalizedEvent, ts: float) -> FeatureVector:
        """Per-query vector: lexical features plus the host's DNS behaviour."""
        assert event.dns is not None and event.dns.query is not None
        dns = event.dns
        values = stats.dns_lexical_features(dns.query)
        values["dns_event"] = 1.0
        values["dns_answer_count"] = float(dns.answer_count)
        values["dns_response_bytes"] = float(dns.response_bytes or 0)
        values["dns_is_txt"] = 1.0 if (dns.qtype or "").upper() in {"TXT", "NULL"} else 0.0
        values["dns_is_nxdomain"] = 1.0 if (dns.rcode or "").upper() in {"NXDOMAIN", "3"} else 0.0
        values["dns_request_response_asymmetry"] = stats.ratio(
            float(dns.response_bytes or 0), float(len(dns.query))
        )
        # Behavioural context from the host's windows, so one input carries both
        # lexical and behavioural evidence.
        for bundle in host.bundles.values():
            s = window_suffix(bundle.size)
            bundle_features = bundle.features(ts)
            for name in (
                f"dns_queries_per_sec_{s}",
                f"dns_query_count_{s}",
                f"dns_unique_name_ratio_{s}",
                f"dns_txt_ratio_{s}",
                f"dns_nxdomain_ratio_{s}",
                f"dns_mean_response_bytes_{s}",
            ):
                values[name] = bundle_features[name]
        return FeatureVector(
            timestamp=ts,
            entity_kind=EntityKind.HOST,
            entity_id=str(event.src_ip),
            window_seconds=0.0,
            values=values,
            labels={
                "dns_query": dns.query,
                "dns_qtype": dns.qtype or "",
                "dns_rcode": dns.rcode or "",
                "src_ip": str(event.src_ip),
                "dst_ip": str(event.dst_ip),
            },
            event_count=1,
            flow_ids=[event.flow_id] if event.flow_id else [],
            pcap_references=[event.pcap_reference] if event.pcap_reference else [],
        )

    def _tls_vector(self, pair: EntityState, event: NormalizedEvent, ts: float) -> FeatureVector:
        """Per-handshake vector. Metadata only -- no decryption anywhere."""
        assert event.tls is not None
        tls = event.tls
        timing = pair.timing_features()
        values = {
            "tls_event": 1.0,
            "tls_session_bytes": float(event.total_bytes),
            "tls_session_packets": float(event.total_packets),
            "tls_session_duration": float(event.duration or 0.0),
            "tls_mean_packet_size": stats.ratio(event.total_bytes, event.total_packets),
            "tls_orig_resp_byte_ratio": stats.ratio(event.orig_bytes, event.resp_bytes or 0),
            "tls_cert_validity_days": float(tls.cert_validity_days or 0),
            "tls_self_signed": 1.0 if tls.cert_self_signed else 0.0,
            "tls_established": 1.0 if tls.established else 0.0,
            "tls_sni_present": 1.0 if tls.sni else 0.0,
            "tls_sni_length": float(len(tls.sni or "")),
            "tls_sni_entropy": stats.char_entropy(tls.sni or ""),
            "destination_rarity": self.baselines.destination_rarity(
                str(event.src_ip), str(event.dst_ip)
            ),
            "interarrival_cv": timing["interarrival_cv"],
            "periodicity_score": timing["periodicity_score"],
        }
        labels = {
            "src_ip": str(event.src_ip),
            "dst_ip": str(event.dst_ip),
            "tls_version": tls.version or "",
            "tls_cipher": tls.cipher or "",
        }
        if tls.ja4:
            labels["ja4"] = tls.ja4
        if tls.ja4s:
            labels["ja4s"] = tls.ja4s
        if tls.sni:
            labels["sni"] = tls.sni
        return FeatureVector(
            timestamp=ts,
            entity_kind=EntityKind.PAIR,
            entity_id=pair.entity_id,
            window_seconds=0.0,
            values=values,
            labels=labels,
            event_count=1,
            flow_ids=[event.flow_id] if event.flow_id else [],
        )

    def flush(self, now: float | None = None) -> list[FeatureVector]:
        """Emit a vector for every tracked entity, ignoring the emit interval.

        Needed at the end of a bounded PCAP replay: a 600 ms capture would
        otherwise only ever produce the (empty) vectors emitted on each entity's
        first event, and the burst it contains would never reach a detector.
        """
        vectors: list[FeatureVector] = []
        for (kind, entity_id), state in list(self._states.items()):
            if state.event_count == 0:
                continue
            ts = now if now is not None else state.last_seen
            for bundle in state.bundles.values():
                bundle.expire(ts)
            values = state.features(ts)
            values["destination_rarity"] = 0.0
            values.update(self._baseline_features(state, values))
            vectors.append(
                FeatureVector(
                    timestamp=ts,
                    entity_kind=kind,
                    entity_id=entity_id,
                    window_seconds=max(self.sizes),
                    values=values,
                    labels={"flushed": "1"},
                    event_count=state.event_count,
                    flow_ids=list(state.recent_flow_ids[-64:]),
                    pcap_references=list(state.recent_pcaps[-8:]),
                )
            )
            state.last_emit = ts
        return vectors

    # --- introspection ---------------------------------------------------
    @property
    def tracked_entities(self) -> int:
        return len(self._states)

    @property
    def evictions(self) -> int:
        return self._states.evictions


def windowed_feature_names(sizes: tuple[float, ...] | None = None) -> tuple[str, ...]:
    """Every feature name a windowed vector can contain, for docs and datasets."""
    sizes = sizes or tuple(get_settings().windows.sizes)
    names: list[str] = []
    for size in sizes:
        names.extend(WindowBundle(size).features(0.0).keys())
    names.extend(EntityState(EntityKind.HOST, "x", sizes).timing_features().keys())
    names.extend(["is_internal_source", "is_internal_destination", "destination_rarity"])
    for metric in BASELINED_METRICS:
        names.extend(
            [f"{metric}_zscore", f"{metric}_baseline_mean",
             f"{metric}_baseline_p95", f"{metric}_baseline_warm"]
        )
    return tuple(dict.fromkeys(names))
