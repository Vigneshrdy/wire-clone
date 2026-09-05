"""Command-line entry points.

``sih-ntd <command>``. Deliberately argparse rather than a CLI framework: the
commands are a handful of flat verbs and a dependency buys nothing here.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import Streams, get_settings
from .logging_conf import configure_logging, get_logger

log = get_logger("sih_ntd.cli")


def _print(payload: object) -> None:
    print(json.dumps(payload, indent=2, default=str))


def cmd_api(args: argparse.Namespace) -> int:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "sih_ntd.api:app",
        host=args.host or settings.api.host,
        port=args.port or settings.api.port,
        reload=args.reload,
        log_config=None,
    )
    return 0


def cmd_worker(args: argparse.Namespace) -> int:
    """Consume ``network.normalized`` and produce alerts."""
    from .pipeline import Pipeline
    from .store import Store
    from .streaming import StreamClient

    settings = get_settings()
    if args.consumer:
        settings.redis.consumer_name = args.consumer
    pipeline = Pipeline(settings, store=Store(settings=settings), stream=StreamClient(settings))
    log.info("worker starting", extra={"stream": Streams.NORMALIZED, "run_id": pipeline.run_id})
    stats = pipeline.run_worker(max_batches=args.max_batches, idle_exit=args.idle_exit)
    _print(
        {
            "events": stats.events, "rejected": stats.rejected, "features": stats.features,
            "detector_results": stats.detector_results, "alerts": stats.alerts,
            "suppressed": stats.suppressed, "incidents": stats.incidents,
        }
    )
    return 0


def cmd_synth(args: argparse.Namespace) -> int:
    from .sensor.replay import replay_synthetic

    _print(
        replay_synthetic(
            scenario=args.scenario, count=args.count, seed=args.seed, to_stream=args.stream
        )
    )
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    from .errors import ConfigError
    from .sensor.replay import replay_pcap

    try:
        _print(replay_pcap(pcap_path=args.pcap, to_stream=args.stream, keep_logs=args.keep_logs))
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_train_dga(args: argparse.Namespace) -> int:
    from .ml.training import train_dga

    metadata, validation, test, dataset = train_dga(
        per_family=args.per_family, benign_count=args.benign, seed=args.seed,
        register=not args.no_register,
    )
    _print(
        {
            "dataset": dataset.metadata.model_dump(mode="json"),
            "validation": validation.metrics,
            "test": test.metrics,
            "test_confusion": test.confusion,
            "model": metadata.model_dump(mode="json") if metadata else None,
            "next_step": (
                "review metrics, then `sih-ntd models evaluate dga` and "
                "`sih-ntd models promote dga --model-version ...`"
            ),
        }
    )
    return 0


def cmd_models(args: argparse.Namespace) -> int:
    from .ml.governance import PromotionGate
    from .ml.registry import ModelRegistry
    from .ml.shadow import compare
    from .schemas import ModelStatus
    from .store import Store

    registry = ModelRegistry()
    if args.action == "list":
        _print(registry.summary() if not args.detector else
               {
                   "models": [m.model_dump(mode="json") for m in registry.list_models(args.detector)],
                   "promotion_history": [
                       r.model_dump(mode="json") for r in registry.promotion_history(args.detector)
                   ],
               })
        return 0
    if not args.detector:
        print("error: --detector is required for this action", file=sys.stderr)
        return 2
    if args.action == "evaluate":
        candidates = [
            m for m in registry.list_models(args.detector)
            if args.model_version in (None, m.model_version)
        ]
        if not candidates:
            print("error: no such model", file=sys.stderr)
            return 2
        report = PromotionGate().evaluate(
            candidates[0], registry.champion(args.detector), acknowledge=set(args.acknowledge or [])
        )
        _print(
            {
                "model": candidates[0].model_dump(mode="json"),
                "gate": report.as_dict(),
                "shadow": compare(args.detector, Store(), registry).as_dict(),
            }
        )
        return 0 if report.passed else 1
    if args.action == "promote":
        model = registry.get(args.detector, args.model_version)
        if model is None:
            print("error: model not registered", file=sys.stderr)
            return 2
        report = PromotionGate().evaluate(
            model, registry.champion(args.detector), acknowledge=set(args.acknowledge or [])
        )
        if not report.passed:
            _print({"promoted": False, "blocked_by": report.failures})
            return 1
        if report.acknowledged and not args.reason:
            print(
                "error: --reason is required when acknowledging failed gates "
                f"({sorted(report.acknowledged)})",
                file=sys.stderr,
            )
            return 2
        updated = registry.set_status(
            args.detector, args.model_version, ModelStatus(args.to_status),
            actor=args.actor, reason=args.reason,
            gate_results={
                **report.results,
                **{f"acknowledged:{k}": False for k in report.acknowledged},
            },
        )
        _print(
            {
                "promoted": True, "model": updated.model_dump(mode="json"),
                "acknowledged_gates": report.acknowledged,
                "note": "restart workers to load the new champion",
            }
        )
        return 0
    if args.action == "rollback":
        _print({"champion": registry.rollback(args.detector, actor=args.actor).model_dump(mode="json")})
        return 0
    return 2


def cmd_drift(args: argparse.Namespace) -> int:
    """Compare two windows of stored feature vectors and record drift signals."""
    from .ml.drift import DriftMonitor, feature_matrix
    from .store import Store

    store = Store()
    rows = store.feature_rows(entity_kind=args.entity_kind, limit=args.limit)
    if len(rows) < 2 * get_settings().drift.min_samples:
        _print(
            {
                "drift_events": 0,
                "reason": (
                    f"only {len(rows)} stored feature vectors; need at least "
                    f"{2 * get_settings().drift.min_samples} to split into reference "
                    "and current windows"
                ),
            }
        )
        return 0
    midpoint = len(rows) // 2
    # rows come back newest-first, so the second half is the older reference window.
    current = feature_matrix(r["values"] for r in rows[:midpoint])
    reference = feature_matrix(r["values"] for r in rows[midpoint:])
    events = DriftMonitor().feature_drift(
        args.detector, reference, current, window=f"{midpoint} vs {len(rows) - midpoint} vectors"
    )
    store.insert_drift_events(events)
    _print(
        {
            "drift_events": len(events),
            "events": [e.model_dump(mode="json") for e in events[:20]],
            "note": "signals only; nothing was retrained or promoted",
        }
    )
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    from benchmarks.harness import run_benchmark

    _print(run_benchmark(scenario=args.scenario, count=args.count, seed=args.seed,
                         persist=not args.no_persist).model_dump(mode="json"))
    return 0


def cmd_store(args: argparse.Namespace) -> int:
    from .store import Store

    store = Store()
    if args.action == "health":
        _print(store.health())
    elif args.action == "prune":
        import time

        cutoff = time.time() - args.days * 86400
        _print({"deleted": store.prune(cutoff), "older_than_days": args.days})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sih-ntd",
        description="SIH 26145 -- passive AI-based cyber threat detection (backend)",
    )
    parser.add_argument("--log-level", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    api = sub.add_parser("api", help="run the FastAPI backend")
    api.add_argument("--host", default=None)
    api.add_argument("--port", type=int, default=None)
    api.add_argument("--reload", action="store_true")
    api.set_defaults(func=cmd_api)

    worker = sub.add_parser("worker", help="run a detection worker against Redis Streams")
    worker.add_argument("--consumer", default=None, help="consumer name within the group")
    worker.add_argument("--max-batches", type=int, default=None)
    worker.add_argument("--idle-exit", action="store_true", help="exit once the stream is drained")
    worker.set_defaults(func=cmd_worker)

    synth = sub.add_parser("synth", help="generate synthetic traffic metadata")
    synth.add_argument("--scenario", default="mixed")
    synth.add_argument("--count", type=int, default=2000)
    synth.add_argument("--seed", type=int, default=1337)
    synth.add_argument("--stream", action="store_true", help="publish to Redis instead of running inline")
    synth.set_defaults(func=cmd_synth)

    replay = sub.add_parser("replay", help="replay a PCAP through Zeek into the pipeline")
    replay.add_argument("pcap")
    replay.add_argument("--stream", action="store_true")
    replay.add_argument("--keep-logs", action="store_true")
    replay.set_defaults(func=cmd_replay)

    train = sub.add_parser("train-dga", help="train + evaluate a DGA candidate (never promotes)")
    train.add_argument("--per-family", type=int, default=3000)
    train.add_argument("--benign", type=int, default=12000)
    train.add_argument("--seed", type=int, default=20260905)
    train.add_argument("--no-register", action="store_true")
    train.set_defaults(func=cmd_train_dga)

    models = sub.add_parser("models", help="inspect / evaluate / promote / rollback models")
    models.add_argument("action", choices=["list", "evaluate", "promote", "rollback"])
    models.add_argument("detector", nargs="?", default=None)
    models.add_argument("--model-version", default=None)
    models.add_argument("--to-status", default="CHAMPION")
    models.add_argument("--actor", default="cli")
    models.add_argument("--reason", default="")
    models.add_argument(
        "--acknowledge", action="append", default=None,
        help="gate name to accept as failing (recorded in the promotion history)",
    )
    models.set_defaults(func=cmd_models)

    drift = sub.add_parser("drift", help="compute drift between stored feature windows")
    drift.add_argument("--detector", default="pipeline")
    drift.add_argument("--entity-kind", default="HOST")
    drift.add_argument("--limit", type=int, default=20000)
    drift.set_defaults(func=cmd_drift)

    bench = sub.add_parser("bench", help="measure throughput and latency")
    bench.add_argument("--scenario", default="mixed")
    bench.add_argument("--count", type=int, default=20000)
    bench.add_argument("--seed", type=int, default=1337)
    bench.add_argument("--no-persist", action="store_true")
    bench.set_defaults(func=cmd_bench)

    store = sub.add_parser("store", help="store maintenance")
    store.add_argument("action", choices=["health", "prune"])
    store.add_argument("--days", type=int, default=30)
    store.set_defaults(func=cmd_store)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level)
    # Make `benchmarks` importable when running from a source checkout.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
