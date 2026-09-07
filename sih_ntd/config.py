"""Explicit configuration with local-development defaults and env overrides.

Every knob is settable through the environment with the ``SIH_`` prefix and
``__`` as the nesting delimiter, e.g. ``SIH_REDIS__URL``,
``SIH_THRESHOLDS__DDOS_SYN_RATE``. Defaults are chosen so that
``uv run sih-ntd api`` works on a laptop with only redis running.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parent.parent


class RedisSettings(BaseModel):
    url: str = "redis://localhost:6379/0"
    consumer_group: str = "sih-ntd"
    consumer_name: str = "worker-1"
    # Approximate MAXLEN trimming: bounded memory without O(n) exact trims.
    stream_maxlen: int = Field(default=100_000, ge=1000)
    block_ms: int = Field(default=2000, ge=1)
    batch_size: int = Field(default=256, ge=1, le=10_000)
    # Deliveries of the same entry before it is treated as poison and DLQ'd.
    max_deliveries: int = Field(default=5, ge=1, le=100)
    claim_idle_ms: int = Field(default=60_000, ge=1000)
    socket_timeout_seconds: float = Field(default=5.0, gt=0)
    connect_retries: int = Field(default=3, ge=0, le=20)


class StoreSettings(BaseModel):
    """Analytical store. SQLite today; see docs/ARCHITECTURE.md for the ClickHouse seam."""

    path: Path = REPO_ROOT / "data" / "sih_ntd.db"
    busy_timeout_ms: int = Field(default=5000, ge=100)
    retention_days: int = Field(default=30, ge=1)
    persist_features: bool = True


class SensorSettings(BaseModel):
    sensor_id: str = "sensor-local"
    # CIDRs considered "inside" the monitored network, used for direction tagging
    # and for exfiltration's inbound/outbound reasoning.
    home_networks: list[str] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    zeek_log_dir: Path = REPO_ROOT / "zeek_logs"
    pcap_dir: Path = REPO_ROOT / "data" / "pcap"


class WindowSettings(BaseModel):
    """Sliding-window sizes in seconds. Order matters only for reporting."""

    sizes: list[float] = [1.0, 5.0, 30.0, 60.0, 300.0]
    # Feature vectors are emitted at most this often per (entity, window).
    emit_interval_seconds: float = Field(default=1.0, gt=0)
    max_tracked_entities: int = Field(default=50_000, ge=100)

    @field_validator("sizes")
    @classmethod
    def _sorted_positive(cls, v: list[float]) -> list[float]:
        if not v or any(x <= 0 for x in v):
            raise ValueError("window sizes must be positive and non-empty")
        return sorted(set(float(x) for x in v))


class ThresholdSettings(BaseModel):
    """Detector thresholds in ONE place -- never scattered as literals in detectors."""

    # --- DDoS ---
    ddos_syn_rate: float = 500.0            # SYN-only flows/sec toward one destination
    ddos_flow_rate: float = 1000.0          # flows/sec toward one destination
    ddos_packet_rate: float = 20_000.0
    ddos_min_unique_sources: int = 50
    ddos_source_entropy: float = 4.0        # bits; high == distributed/spoofed
    ddos_baseline_multiplier: float = 10.0  # observed / EWMA baseline
    ddos_amplification_ratio: float = 5.0

    # --- Recon ---
    recon_unique_ports: int = 20            # vertical scan
    recon_unique_hosts: int = 25            # horizontal scan
    recon_failed_ratio: float = 0.8
    recon_min_flows: int = 20
    recon_max_mean_duration: float = 1.0

    # --- C2 beaconing ---
    c2_min_intervals: int = 6               # need >=7 connections to judge periodicity
    c2_max_cv: float = 0.25                 # coefficient of variation of inter-arrivals
    c2_periodicity_score: float = 0.7
    c2_max_jitter_seconds: float = 30.0
    c2_byte_stability_cv: float = 0.3

    # --- DGA ---
    dga_probability: float = 0.85           # calibrated champion probability
    dga_min_domain_length: int = 8

    # --- DNS tunnelling ---
    tunnel_query_length: int = 60
    tunnel_entropy: float = 3.6             # bits/char over the subdomain
    tunnel_unique_subdomain_ratio: float = 0.8
    tunnel_min_queries: int = 20
    tunnel_txt_ratio: float = 0.3

    # --- TLS/QUIC ---
    tls_rare_ja4_max_count: int = 3

    # --- Exfiltration ---
    exfil_min_outbound_bytes: int = 10_000_000
    exfil_outbound_inbound_ratio: float = 20.0
    exfil_baseline_zscore: float = 4.0
    exfil_destination_rarity: float = 0.9

    # --- Baselines ---
    baseline_ewma_alpha: float = Field(default=0.05, gt=0, le=1)
    baseline_min_observations: int = Field(default=30, ge=1)


class FusionSettings(BaseModel):
    correlation_window_seconds: float = Field(default=300.0, gt=0)
    dedup_window_seconds: float = Field(default=60.0, gt=0)
    # Confidence uplift applied per additional corroborating detector.
    corroboration_bonus: float = Field(default=0.08, ge=0, le=0.5)
    max_confidence: float = Field(default=0.99, gt=0, le=1.0)
    min_alert_confidence: float = Field(default=0.5, ge=0, le=1.0)
    incident_idle_seconds: float = Field(default=900.0, gt=0)


class RegistrySettings(BaseModel):
    root: Path = REPO_ROOT / "ml_artifacts"
    # Governance gates. A candidate must clear all of these AND be promoted
    # explicitly; nothing here promotes anything on its own.
    min_precision: float = Field(default=0.90, ge=0, le=1)
    min_recall: float = Field(default=0.80, ge=0, le=1)
    max_false_positive_rate: float = Field(default=0.02, ge=0, le=1)
    max_inference_latency_ms: float = Field(default=5.0, gt=0)
    require_dataset: bool = True
    require_champion_improvement: bool = True
    #: Minimum share of out-of-corpus probe names a model must still detect. Guards
    #: against a model that memorised its training generators -- see
    #: `sih_ntd.ml.training.transfer_check`.
    min_transfer_recall: float = Field(default=0.5, ge=0, le=1)


class DriftSettings(BaseModel):
    psi_threshold: float = 0.2
    ks_threshold: float = 0.15
    js_threshold: float = 0.1
    min_samples: int = Field(default=200, ge=20)
    bins: int = Field(default=10, ge=2, le=100)


class ApiSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    prefix: str = "/api/v1"
    default_page_size: int = Field(default=50, ge=1, le=1000)
    max_page_size: int = Field(default=500, ge=1, le=5000)
    ws_queue_size: int = Field(default=256, ge=1)
    # Optional bearer/X-API-key token for mutating management routes. When unset,
    # those routes are allowed only while the API is bound to loopback.
    admin_token: str | None = Field(default=None, min_length=16, max_length=4096)
    # Prototype default binds to loopback only. Anything wider needs an auth
    # layer first -- see docs/SECURITY_MODEL.md.
    allow_replay_trigger: bool = True


class LoggingSettings(BaseModel):
    level: str = "INFO"
    json_output: bool = True


class ReplaySettings(BaseModel):
    zeek_binary: str = "zeek"
    speed: float = Field(default=0.0, ge=0)  # 0 == as fast as possible
    max_events: int = Field(default=0, ge=0)  # 0 == unlimited


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SIH_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    redis: RedisSettings = RedisSettings()
    store: StoreSettings = StoreSettings()
    sensor: SensorSettings = SensorSettings()
    windows: WindowSettings = WindowSettings()
    thresholds: ThresholdSettings = ThresholdSettings()
    fusion: FusionSettings = FusionSettings()
    registry: RegistrySettings = RegistrySettings()
    drift: DriftSettings = DriftSettings()
    api: ApiSettings = ApiSettings()
    logging: LoggingSettings = LoggingSettings()
    replay: ReplaySettings = ReplaySettings()


@lru_cache
def get_settings() -> Settings:
    """Process-wide settings. Cached; call ``get_settings.cache_clear()`` in tests."""
    return Settings()


class Streams:
    """Redis stream names. Single source of truth so producers/consumers agree."""

    RAW = "network.raw"
    NORMALIZED = "network.normalized"
    FEATURES = "network.features"
    ALERTS = "network.alerts"
    FEEDBACK = "network.feedback"
    MODEL_EVENTS = "model.events"

    @staticmethod
    def dlq(stream: str) -> str:
        return f"{stream}.dlq"
