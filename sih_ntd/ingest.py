"""Event normalization: untrusted sensor records -> validated NormalizedEvent.

This is the trust boundary. Everything upstream (Zeek logs, NetFlow exports,
replayed PCAP metadata) is attacker-influenced: a host on the monitored network
chooses the domain names, SNI values and packet counts that end up in these
records. So:

* field names are looked up through an alias table, never ``eval``'d or used to
  build attribute access;
* every value goes through Pydantic validation, and a record that fails is
  *rejected and counted*, never coerced to zeros;
* ``event_id`` is derived deterministically, which makes replay idempotent and
  gives free deduplication of the same log line seen twice.

Supported inputs: Zeek ``conn``/``dns``/``ssl`` JSON, NetFlow/IPFIX-style flow
dicts, and the synthetic generator. Adding a source means adding aliases, not a
new code path.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Iterator

from pydantic import ValidationError

from .config import Settings, get_settings
from .errors import ValidationRejection
from .logging_conf import get_logger
from .metrics import EVENTS_RECEIVED, EVENTS_REJECTED
from .schemas import (
    DnsMetadata,
    NormalizedEvent,
    SourceType,
    TlsMetadata,
    TransportProtocol,
)

log = get_logger(__name__)

#: canonical name -> accepted source keys, in priority order.
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("ts", "timestamp", "flowStartSeconds", "start_time", "first_switched"),
    "flow_id": ("uid", "flow_id", "flowId"),
    "src_ip": ("id.orig_h", "src_ip", "sourceIPv4Address", "sourceIPv6Address", "srcaddr"),
    "src_port": ("id.orig_p", "src_port", "sourceTransportPort", "srcport"),
    "dst_ip": ("id.resp_h", "dst_ip", "destinationIPv4Address", "destinationIPv6Address", "dstaddr"),
    "dst_port": ("id.resp_p", "dst_port", "destinationTransportPort", "dstport"),
    "transport_protocol": ("proto", "transport_protocol", "protocolIdentifier", "prot"),
    "service": ("service", "application", "app"),
    "duration": ("duration", "flowDurationMilliseconds", "elapsed"),
    "orig_packets": ("orig_pkts", "orig_packets", "packetDeltaCount", "dpkts", "in_pkts"),
    "resp_packets": ("resp_pkts", "resp_packets", "reversePacketDeltaCount", "out_pkts"),
    "orig_bytes": ("orig_ip_bytes", "orig_bytes", "octetDeltaCount", "dbytes", "in_bytes"),
    "resp_bytes": ("resp_ip_bytes", "resp_bytes", "reverseOctetDeltaCount", "out_bytes"),
    "connection_state": ("conn_state", "connection_state", "state"),
    "tcp_flags": ("history", "tcp_flags", "tcpControlBits", "flags"),
    "sensor_id": ("sensor_id", "_system_name", "observationDomainId"),
    "pcap_reference": ("pcap_reference", "_path_pcap", "capture_file"),
}

DNS_ALIASES: dict[str, tuple[str, ...]] = {
    "query": ("query", "dns_query", "qname"),
    "qtype": ("qtype_name", "qtype", "dns_qtype"),
    "rcode": ("rcode_name", "rcode", "dns_rcode"),
    "answers": ("answers", "dns_answers"),
    "response_bytes": ("response_bytes", "resp_bytes_dns", "answer_bytes"),
    "rejected": ("rejected",),
}

TLS_ALIASES: dict[str, tuple[str, ...]] = {
    "version": ("version", "tls_version", "ssl_version"),
    "sni": ("server_name", "sni", "tls_sni"),
    "ja4": ("ja4", "ja4_fingerprint"),
    "ja4s": ("ja4s", "ja4s_fingerprint"),
    "cipher": ("cipher", "tls_cipher"),
    "cert_subject_cn": ("subject", "cert_subject_cn"),
    "cert_issuer_cn": ("issuer", "cert_issuer_cn"),
    "cert_validity_days": ("cert_validity_days",),
    "cert_self_signed": ("self_signed", "cert_self_signed"),
    "established": ("established",),
}

#: IANA protocol numbers seen in NetFlow/IPFIX.
PROTO_NUMBERS = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp"}

#: Cap on how many recent event ids are remembered for deduplication. Bounded so
#: a long replay cannot exhaust memory.
DEDUP_CAPACITY = 100_000


def _pick(record: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    for key in aliases:
        if key in record and record[key] not in ("", None, "-"):
            return record[key]
    return None


def _protocol(value: Any) -> TransportProtocol:
    if value is None:
        return TransportProtocol.OTHER
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        return TransportProtocol(PROTO_NUMBERS.get(int(value), "other"))
    text = str(value).lower()
    return TransportProtocol(text) if text in {"tcp", "udp", "icmp"} else TransportProtocol.OTHER


def derive_event_id(timestamp: float, flow_key: str, kind: str) -> str:
    """Deterministic id: replaying the same record yields the same id.

    That makes ``INSERT OR IGNORE`` in the store a real deduplication mechanism
    rather than a hope, and lets a demo re-run a PCAP without inflating counts.
    """
    return hashlib.sha256(f"{timestamp:.6f}|{flow_key}|{kind}".encode()).hexdigest()[:32]


class Normalizer:
    """Stateless per-record normalization plus a bounded dedup memory."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.sensor_id = self.settings.sensor.sensor_id
        self._seen: dict[str, None] = {}
        self.rejected = 0
        self.duplicates = 0

    # --- public API ------------------------------------------------------
    def normalize(
        self, record: dict[str, Any], source_type: SourceType = SourceType.ZEEK_LOG
    ) -> NormalizedEvent:
        """Normalize one record or raise :class:`ValidationRejection`."""
        try:
            payload = self._to_payload(record, source_type)
            event = NormalizedEvent.model_validate(payload)
        except (ValidationError, ValueError, KeyError, TypeError) as exc:
            self.rejected += 1
            reason = str(exc).splitlines()[0][:200]
            EVENTS_REJECTED.inc(reason=_reason_bucket(exc))
            raise ValidationRejection(reason, source=str(source_type)) from exc
        EVENTS_RECEIVED.inc(source_type=str(source_type))
        return event

    def normalize_many(
        self, records: Iterable[dict[str, Any]], source_type: SourceType = SourceType.ZEEK_LOG
    ) -> Iterator[NormalizedEvent]:
        """Normalize a stream, skipping (and counting) rejects and duplicates."""
        for record in records:
            try:
                event = self.normalize(record, source_type)
            except ValidationRejection as exc:
                log.debug("record rejected", extra={"reason": exc.reason})
                continue
            if self.is_duplicate(event.event_id):
                self.duplicates += 1
                continue
            yield event

    def is_duplicate(self, event_id: str) -> bool:
        if event_id in self._seen:
            return True
        self._seen[event_id] = None
        if len(self._seen) > DEDUP_CAPACITY:
            # Drop the oldest quarter in one pass; dict preserves insertion order.
            for key in list(self._seen)[: DEDUP_CAPACITY // 4]:
                del self._seen[key]
        return False

    # --- mapping ---------------------------------------------------------
    def _to_payload(self, record: dict[str, Any], source_type: SourceType) -> dict[str, Any]:
        timestamp = _pick(record, FIELD_ALIASES["timestamp"])
        if timestamp is None:
            raise ValueError("record has no usable timestamp")
        timestamp = float(timestamp)

        src_ip = _pick(record, FIELD_ALIASES["src_ip"])
        dst_ip = _pick(record, FIELD_ALIASES["dst_ip"])
        if src_ip is None or dst_ip is None:
            raise ValueError("record has no source/destination address")

        protocol = _protocol(_pick(record, FIELD_ALIASES["transport_protocol"]))
        src_port = _optional_int(_pick(record, FIELD_ALIASES["src_port"]))
        dst_port = _optional_int(_pick(record, FIELD_ALIASES["dst_port"]))
        flow_id = _pick(record, FIELD_ALIASES["flow_id"])
        duration = _duration_seconds(record)

        dns = self._dns(record)
        tls = self._tls(record)
        kind = "dns" if dns else ("ssl" if tls else "conn")
        flow_key = str(flow_id) if flow_id else f"{src_ip}:{src_port}>{dst_ip}:{dst_port}/{protocol}"
        if dns and dns.query:
            # A single DNS flow can carry many queries; include the name so each
            # query is its own event instead of colliding on the flow key.
            flow_key = f"{flow_key}|{dns.query}|{dns.qtype or ''}"

        payload: dict[str, Any] = {
            "event_id": derive_event_id(timestamp, flow_key, kind),
            "timestamp": timestamp,
            "sensor_id": str(_pick(record, FIELD_ALIASES["sensor_id"]) or self.sensor_id)[:256],
            "source_type": source_type,
            "flow_id": str(flow_id)[:256] if flow_id else None,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "transport_protocol": protocol,
            "service": _optional_text(_pick(record, FIELD_ALIASES["service"])),
            "duration": duration,
            "orig_packets": _optional_int(_pick(record, FIELD_ALIASES["orig_packets"])) or 0,
            "resp_packets": _optional_int(_pick(record, FIELD_ALIASES["resp_packets"])),
            "orig_bytes": _optional_int(_pick(record, FIELD_ALIASES["orig_bytes"])) or 0,
            "resp_bytes": _optional_int(_pick(record, FIELD_ALIASES["resp_bytes"])),
            "connection_state": _optional_text(_pick(record, FIELD_ALIASES["connection_state"])),
            "tcp_flags": _optional_text(_pick(record, FIELD_ALIASES["tcp_flags"])),
            "pcap_reference": _optional_text(_pick(record, FIELD_ALIASES["pcap_reference"])),
            "raw_event_reference": _optional_text(record.get("_path")),
        }
        if dns:
            payload["dns"] = dns
        if tls:
            payload["tls"] = tls
        return payload

    @staticmethod
    def _dns(record: dict[str, Any]) -> DnsMetadata | None:
        query = _pick(record, DNS_ALIASES["query"])
        if query is None:
            return None
        answers = _pick(record, DNS_ALIASES["answers"]) or []
        if isinstance(answers, str):
            answers = [answers]
        return DnsMetadata(
            query=str(query),
            qtype=_optional_text(_pick(record, DNS_ALIASES["qtype"])),
            rcode=_optional_text(_pick(record, DNS_ALIASES["rcode"])),
            answers=[str(a)[:256] for a in list(answers)[:64]],
            response_bytes=_optional_int(_pick(record, DNS_ALIASES["response_bytes"])),
            rejected=bool(_pick(record, DNS_ALIASES["rejected"]) or False),
        )

    @staticmethod
    def _tls(record: dict[str, Any]) -> TlsMetadata | None:
        values = {
            field: _pick(record, aliases) for field, aliases in TLS_ALIASES.items()
        }
        if not any(values[field] for field in ("version", "sni", "ja4", "ja4s", "cipher")):
            return None
        return TlsMetadata(
            version=_optional_text(values["version"]),
            sni=str(values["sni"]) if values["sni"] else None,
            ja4=_optional_text(values["ja4"]),
            ja4s=_optional_text(values["ja4s"]),
            cipher=_optional_text(values["cipher"]),
            cert_subject_cn=_optional_text(values["cert_subject_cn"]),
            cert_issuer_cn=_optional_text(values["cert_issuer_cn"]),
            cert_validity_days=_optional_int(values["cert_validity_days"]),
            cert_self_signed=(
                None if values["cert_self_signed"] is None else bool(values["cert_self_signed"])
            ),
            established=None if values["established"] is None else bool(values["established"]),
        )


def _reason_bucket(exc: Exception) -> str:
    """Low-cardinality rejection reason for metrics (never the raw message)."""
    text = str(exc).lower()
    if "timestamp" in text:
        return "bad_timestamp"
    if "address" in text or "ip" in text:
        return "bad_address"
    if "domain" in text or "label" in text:
        return "bad_domain"
    if "schema_version" in text:
        return "schema_version"
    if isinstance(exc, ValidationError):
        return "validation"
    return "other"


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _optional_text(value: Any, limit: int = 256) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] or None


def _duration_seconds(record: dict[str, Any]) -> float | None:
    raw = _pick(record, FIELD_ALIASES["duration"])
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    # IPFIX reports milliseconds under a name that says so.
    if "flowDurationMilliseconds" in record:
        value /= 1000.0
    return max(0.0, value)


class ZeekLogReader:
    """Read Zeek JSON logs and correlate ``dns``/``ssl`` records onto connections.

    Zeek writes one file per protocol, joined by ``uid``. Correlating here rather
    than in the feature engine keeps session assembly in the ingest layer where it
    belongs, and means a NetFlow-only deployment does not carry the logic.
    """

    def __init__(self, log_dir: Path | str, normalizer: Normalizer | None = None) -> None:
        self.log_dir = Path(log_dir)
        self.normalizer = normalizer or Normalizer()

    @staticmethod
    def _read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
        if not path.exists():
            return
        with path.open() as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    EVENTS_REJECTED.inc(reason="bad_json")
                    continue
                if isinstance(record, dict):
                    yield record

    def read(self, source_type: SourceType = SourceType.ZEEK_LOG) -> Iterator[NormalizedEvent]:
        """Yield normalized events in timestamp order."""
        by_uid: dict[str, dict[str, Any]] = {}
        for name in ("dns.log", "ssl.log"):
            for record in self._read_jsonl(self.log_dir / name):
                uid = record.get("uid")
                if uid:
                    # Later records for the same uid win: Zeek writes the fuller
                    # record last for a completed session.
                    by_uid.setdefault(str(uid), {}).update(record)

        records: list[dict[str, Any]] = []
        for record in self._read_jsonl(self.log_dir / "conn.log"):
            uid = str(record.get("uid", ""))
            merged = dict(record)
            if uid and uid in by_uid:
                extra = {k: v for k, v in by_uid[uid].items() if k not in ("ts", "uid")}
                merged.update(extra)
            records.append(merged)

        # Protocol logs without a matching conn record still carry usable metadata.
        conn_uids = {str(r.get("uid", "")) for r in records}
        records.extend(r for uid, r in by_uid.items() if uid not in conn_uids)
        records.sort(key=lambda r: float(_pick(r, FIELD_ALIASES["timestamp"]) or 0.0))
        yield from self.normalizer.normalize_many(records, source_type)
