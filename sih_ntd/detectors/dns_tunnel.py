"""DNS tunnelling detection: lexical evidence plus query behaviour.

Runs on per-query vectors (``window_seconds == 0.0``), which also carry the
querying host's windowed DNS behaviour, so one input has both halves of the
evidence. That matters because either half alone is weak: long high-entropy names
appear in CDN and antivirus lookups, and a high query rate is normal for a
resolver.

Requires a lexical trigger *and* at least one behavioural trigger before firing.
"""

from __future__ import annotations

from ..features import stats
from ..schemas import (
    ConfidenceBasis,
    DetectorInput,
    DetectorResult,
    EntityKind,
    Severity,
    Technique,
    ThreatClass,
)
from .base import Detector

#: Below this many queries in 60s there is not enough behaviour to judge.
BEHAVIOUR_WINDOW = "60s"


class DnsTunnelDetector(Detector):
    name = "dns_tunnel"
    version = "1.0.0"
    threat_class = ThreatClass.DNS_TUNNEL
    technique = Technique.HYBRID
    confidence_basis = ConfidenceBasis.RULE_EVIDENCE
    entity_kinds = (EntityKind.HOST,)
    per_event = True

    def accepts(self, features) -> bool:  # type: ignore[override]
        return super().accepts(features) and features.get("dns_event") == 1.0

    def evaluate(self, payload: DetectorInput) -> DetectorResult | None:
        f = payload.features
        t = self.thresholds

        query_length = f.get("dns_domain_length")
        payload_length = f.get("dns_payload_length")
        entropy = f.get("dns_char_entropy")
        hex_ratio = f.get("dns_hex_ratio")
        depth = f.get("dns_subdomain_depth")

        lexical: list[str] = []
        if query_length >= t.tunnel_query_length:
            lexical.append("OVERSIZED_QUERY_NAME")
        # 24 characters is roughly the shortest base32/hex chunk worth tunnelling;
        # below that, high entropy is just a short random-looking CDN label.
        if entropy >= t.tunnel_entropy and payload_length >= 24:
            lexical.append("HIGH_QUERY_ENTROPY")
        if hex_ratio >= 0.9 and payload_length >= 24:
            lexical.append("HEX_ENCODED_SUBDOMAIN")
        if depth >= 3 and payload_length >= 30:
            lexical.append("DEEP_ENCODED_SUBDOMAIN")
        if not lexical:
            return None

        query_rate = f.get(f"dns_queries_per_sec_{BEHAVIOUR_WINDOW}")
        query_count = f.get(f"dns_query_count_{BEHAVIOUR_WINDOW}")
        unique_ratio = f.get(f"dns_unique_name_ratio_{BEHAVIOUR_WINDOW}")
        txt_ratio = f.get(f"dns_txt_ratio_{BEHAVIOUR_WINDOW}")
        asymmetry = f.get("dns_request_response_asymmetry")

        behavioural: list[str] = []
        if query_count >= t.tunnel_min_queries and unique_ratio >= t.tunnel_unique_subdomain_ratio:
            # Every query a different name: a cache would make this pointless for
            # legitimate traffic, so it indicates data being carried in the name.
            behavioural.append("UNIQUE_SUBDOMAIN_PER_QUERY")
        if txt_ratio >= t.tunnel_txt_ratio and query_count >= t.tunnel_min_queries:
            behavioural.append("EXCESSIVE_TXT_QUERIES")
        if query_count >= t.tunnel_min_queries and query_rate >= 5.0:
            behavioural.append("SUSTAINED_QUERY_RATE")
        # An ordinary A-record answer is already several times the query name's
        # length, so ratio alone flags all normal DNS. Downstream tunnel data needs
        # a genuinely large response as well.
        if asymmetry >= 6.0 and f.get("dns_response_bytes") >= 300:
            behavioural.append("RESPONSE_LARGER_THAN_QUERY")
        if not behavioural:
            return None

        lexical_strength = max(
            stats.normalise_exceedance(query_length, t.tunnel_query_length),
            stats.normalise_exceedance(entropy, t.tunnel_entropy, saturation=1.4),
        )
        confidence = min(
            0.96,
            0.4 * lexical_strength + 0.15 * len(lexical) + 0.15 * len(behavioural),
        )
        supporting = {
            "dns_domain_length": query_length,
            "dns_payload_length": payload_length,
            "dns_char_entropy": entropy,
            "dns_hex_ratio": hex_ratio,
            "dns_subdomain_depth": depth,
            f"dns_query_count_{BEHAVIOUR_WINDOW}": query_count,
            f"dns_queries_per_sec_{BEHAVIOUR_WINDOW}": query_rate,
            f"dns_unique_name_ratio_{BEHAVIOUR_WINDOW}": unique_ratio,
            f"dns_txt_ratio_{BEHAVIOUR_WINDOW}": txt_ratio,
            "dns_request_response_asymmetry": asymmetry,
            "length_threshold": float(t.tunnel_query_length),
            "entropy_threshold": t.tunnel_entropy,
        }
        return self.build_result(
            f,
            score=lexical_strength,
            confidence=confidence,
            severity=self._severity(len(lexical), len(behavioural), query_count),
            reason_codes=[*lexical, *behavioural],
            supporting=supporting,
        )

    def _severity(self, lexical: int, behavioural: int, query_count: float) -> Severity:
        """Sustained tunnelling is an active channel; a single odd name is not."""
        if lexical >= 2 and behavioural >= 2 and query_count >= 100:
            return Severity.HIGH
        if lexical >= 2 or behavioural >= 2:
            return Severity.MEDIUM
        return Severity.LOW
