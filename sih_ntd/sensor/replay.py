"""Offline replay: PCAP or synthetic metadata into the pipeline.

The demo path, and the reason the whole system can be shown without touching a
production network. Two modes:

* :func:`replay_synthetic` -- seeded generator, always available, no dependencies.
* :func:`replay_pcap` -- runs Zeek over a capture file and ingests the JSON logs.
  Zeek is a *host* dependency and is not installed in this environment
  (``which zeek`` -> not found), so this function reports that clearly instead of
  pretending; it never silently substitutes synthetic data for a capture the
  operator asked to analyse.

Both are read-only with respect to the monitored network: one reads a file, the
other generates local metadata. Nothing is transmitted anywhere.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ..config import Settings, get_settings
from ..errors import ConfigError
from ..ingest import ZeekLogReader
from ..logging_conf import get_logger
from ..pipeline import Pipeline, publish_events
from ..schemas import SourceType
from ..store import Store
from ..streaming import StreamClient
from .synthetic import generate

log = get_logger(__name__)

#: Zeek scripts that produce the logs the reader needs. json-streaming-logs gives
#: one JSON object per line, which is what ZeekLogReader parses.
ZEEK_ARGS = ("LogAscii::use_json=T",)


def zeek_available(binary: str = "zeek") -> bool:
    return shutil.which(binary) is not None


def replay_synthetic(
    *,
    scenario: str = "mixed",
    count: int = 2000,
    seed: int = 1337,
    settings: Settings | None = None,
    to_stream: bool = False,
    persist: bool = True,
) -> dict[str, Any]:
    """Generate a scenario and run it through the pipeline (or publish it).

    ``to_stream=True`` publishes onto ``network.normalized`` for a separate worker
    process to consume, which is how the distributed path is demonstrated;
    otherwise the pipeline runs in-process, which is what tests and benchmarks use.
    """
    settings = settings or get_settings()
    events = generate(scenario, count=count, seed=seed)
    if to_stream:
        published = publish_events(events, StreamClient(settings))
        return {
            "mode": "stream", "scenario": scenario, "events": published,
            "stream": "network.normalized",
        }
    pipeline = Pipeline(settings, store=Store(settings=settings), publish_alerts=False)
    stats = pipeline.handle_events(events, persist=persist)
    return {
        "mode": "in_process",
        "scenario": scenario,
        "events": stats.events,
        "features": stats.features,
        "detector_results": stats.detector_results,
        "alerts": stats.alerts,
        "suppressed_duplicates": stats.suppressed,
        "incidents": stats.incidents,
    }


def run_zeek(pcap_path: Path, output_dir: Path, binary: str = "zeek") -> list[Path]:
    """Run Zeek over a PCAP and return the JSON logs it produced.

    The PCAP path is passed as an argv element, never interpolated into a shell
    string: the filename may come from an API request, and ``shell=True`` there
    would be a command-injection hole.
    """
    if not zeek_available(binary):
        raise ConfigError(
            f"{binary!r} not found on PATH. Install Zeek to analyse PCAP files, or use "
            "`sih-ntd synth` for synthetic metadata. This build does not substitute "
            "synthetic data for a capture you asked to analyse."
        )
    if not pcap_path.is_file():
        raise ConfigError(f"capture file not found: {pcap_path}")
    output_dir.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(  # noqa: S603 -- argv list, no shell
        [binary, "-r", str(pcap_path), *ZEEK_ARGS],
        cwd=str(output_dir),
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    if completed.returncode != 0:
        raise ConfigError(
            f"zeek exited {completed.returncode}: {completed.stderr.strip()[:500]}"
        )
    return sorted(output_dir.glob("*.log"))


def replay_pcap(
    *,
    pcap_path: str | Path,
    settings: Settings | None = None,
    to_stream: bool = False,
    keep_logs: bool = False,
) -> dict[str, Any]:
    """PCAP -> Zeek -> normalized events -> pipeline (or Redis)."""
    settings = settings or get_settings()
    pcap = Path(pcap_path)
    workdir = Path(tempfile.mkdtemp(prefix="sih-zeek-"))
    try:
        logs = run_zeek(pcap, workdir, settings.replay.zeek_binary)
        reader = ZeekLogReader(workdir)
        events = list(reader.read(SourceType.PCAP_REPLAY))
        # Tag every event with the capture it came from so alerts can reference it
        # for evidence without storing packets.
        events = [e.model_copy(update={"pcap_reference": pcap.name}) for e in events]
        if to_stream:
            published = publish_events(events, StreamClient(settings))
            return {
                "mode": "stream", "pcap": str(pcap), "zeek_logs": [p.name for p in logs],
                "events": published,
            }
        pipeline = Pipeline(settings, store=Store(settings=settings), publish_alerts=False)
        stats = pipeline.handle_events(events)
        return {
            "mode": "in_process",
            "pcap": str(pcap),
            "zeek_logs": [p.name for p in logs],
            "events": stats.events,
            "rejected": reader.normalizer.rejected,
            "duplicates": reader.normalizer.duplicates,
            "alerts": stats.alerts,
            "incidents": stats.incidents,
        }
    finally:
        if not keep_logs:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            log.info("zeek logs kept", extra={"path": str(workdir)})
