"""Structured errors. Every pipeline stage fails with one of these, never a bare Exception."""

from __future__ import annotations


class SihNtdError(Exception):
    """Base for every error raised by this package."""


class ConfigError(SihNtdError):
    """Configuration is missing or self-contradictory."""


class ValidationRejection(SihNtdError):
    """An untrusted record failed validation and was quarantined, not repaired."""

    def __init__(self, reason: str, *, source: str = "unknown", raw_ref: str | None = None) -> None:
        super().__init__(f"rejected record from {source}: {reason}")
        self.reason = reason
        self.source = source
        self.raw_ref = raw_ref


class StreamUnavailable(SihNtdError):
    """The event fabric (Redis) could not be reached within the retry budget."""


class StoreUnavailable(SihNtdError):
    """The analytical store could not be reached within the retry budget."""


class DetectorUnavailable(SihNtdError):
    """A detector cannot run: missing model, missing corpus, unmet schema version.

    This is a normal, reportable state -- not a crash. The pipeline records it and
    keeps every other detector running.
    """

    def __init__(self, detector: str, reason: str) -> None:
        super().__init__(f"detector {detector} unavailable: {reason}")
        self.detector = detector
        self.reason = reason


class ArtifactIntegrityError(SihNtdError):
    """A model artefact's hash or estimator class does not match its registry entry."""


class PromotionBlocked(SihNtdError):
    """A governance gate refused a model promotion."""

    def __init__(self, detector: str, model_version: str, failures: dict[str, str]) -> None:
        detail = "; ".join(f"{k}: {v}" for k, v in failures.items())
        super().__init__(f"promotion of {detector}/{model_version} blocked -- {detail}")
        self.detector = detector
        self.model_version = model_version
        self.failures = failures


class SchemaVersionMismatch(SihNtdError):
    """A record or artefact was produced under an incompatible schema version."""
