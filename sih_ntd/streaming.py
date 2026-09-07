"""Redis Streams event fabric.

Consumer groups give at-least-once delivery with acknowledgement, which is what
the pipeline needs: a worker that dies mid-window must not lose the events it had
claimed. Kafka would give the same guarantee plus partitioning nobody here needs,
at the cost of an operationally heavy dependency -- revisit only if a measured
benchmark demands it.

Failure handling
----------------
* **Retry**: unacked entries are reclaimed with ``XAUTOCLAIM`` after
  ``claim_idle_ms``, so a crashed consumer's work is picked up.
* **Poison events**: an entry that has been delivered more than
  ``max_deliveries`` times is moved to ``<stream>.dlq`` and acknowledged, then
  never retried. Without this, one malformed record blocks the group forever.
* **Retention**: ``XADD MAXLEN ~`` caps each stream; approximate trimming is O(1)
  per call where exact trimming is not.
* **Unavailability**: connection is checked at startup and surfaced as
  :class:`~sih_ntd.errors.StreamUnavailable` rather than retried forever.
"""

from __future__ import annotations

import json
import time
from typing import Any, Iterator

import redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError

from .config import Settings, Streams, get_settings
from .errors import StreamUnavailable
from .logging_conf import get_logger
from .metrics import DLQ_MESSAGES, STREAM_LAG, STREAM_MESSAGES

log = get_logger(__name__)

#: Field name used for the JSON body of every stream entry.
PAYLOAD_FIELD = "payload"


def _is_nogroup(exc: Exception) -> bool:
    """True for Redis' NOGROUP error (stream or consumer group no longer exists)."""
    return "NOGROUP" in str(exc)


class StreamClient:
    """Thin wrapper over redis-py with the group/ack/DLQ policy baked in."""

    def __init__(self, settings: Settings | None = None, client: redis.Redis | None = None) -> None:
        self.settings = settings or get_settings()
        self.config = self.settings.redis
        self._client = client or redis.Redis.from_url(
            self.config.url,
            decode_responses=True,
            socket_timeout=self.config.socket_timeout_seconds,
            socket_connect_timeout=self.config.socket_timeout_seconds,
        )

    @property
    def raw(self) -> redis.Redis:
        return self._client

    def ping(self) -> bool:
        """True when the fabric is reachable. Bounded retries, then give up."""
        for attempt in range(self.config.connect_retries + 1):
            try:
                return bool(self._client.ping())
            except RedisConnectionError:
                if attempt == self.config.connect_retries:
                    return False
                time.sleep(0.2 * (attempt + 1))
        return False

    def require(self) -> None:
        if not self.ping():
            raise StreamUnavailable(f"redis not reachable at {self.config.url}")

    # --- publishing ------------------------------------------------------
    def publish(self, stream: str, payload: dict[str, Any] | str) -> str:
        body = payload if isinstance(payload, str) else json.dumps(payload, default=str)
        try:
            message_id = self._client.xadd(
                stream,
                {PAYLOAD_FIELD: body},
                maxlen=self.config.stream_maxlen,
                approximate=True,
            )
        except RedisConnectionError as exc:
            raise StreamUnavailable(f"publish to {stream} failed: {exc}") from exc
        STREAM_MESSAGES.inc(stream=stream, outcome="published")
        return message_id

    def publish_many(self, stream: str, payloads: list[dict[str, Any] | str]) -> int:
        if not payloads:
            return 0
        pipe = self._client.pipeline(transaction=False)
        for payload in payloads:
            body = payload if isinstance(payload, str) else json.dumps(payload, default=str)
            pipe.xadd(stream, {PAYLOAD_FIELD: body},
                      maxlen=self.config.stream_maxlen, approximate=True)
        try:
            pipe.execute()
        except RedisConnectionError as exc:
            raise StreamUnavailable(f"publish to {stream} failed: {exc}") from exc
        STREAM_MESSAGES.inc(len(payloads), stream=stream, outcome="published")
        return len(payloads)

    # --- consuming -------------------------------------------------------
    def ensure_group(self, stream: str, group: str | None = None) -> None:
        group = group or self.config.consumer_group
        try:
            # mkstream so a consumer can start before any producer exists.
            self._client.xgroup_create(stream, group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
        except RedisConnectionError as exc:
            raise StreamUnavailable(f"cannot create group on {stream}: {exc}") from exc

    def read(
        self, stream: str, *, group: str | None = None, consumer: str | None = None,
        count: int | None = None, block_ms: int | None = None,
    ) -> list[tuple[str, dict[str, Any]]]:
        """Read new entries for this consumer. Returns ``[(message_id, payload)]``."""
        group = group or self.config.consumer_group
        consumer = consumer or self.config.consumer_name
        try:
            response = self._client.xreadgroup(
                group, consumer, {stream: ">"},
                count=count or self.config.batch_size,
                block=self.config.block_ms if block_ms is None else block_ms,
            )
        except RedisConnectionError as exc:
            raise StreamUnavailable(f"read from {stream} failed: {exc}") from exc
        except ResponseError as exc:
            # The stream (and with it the group) can vanish under a running
            # consumer: a retention wipe, an operator DEL, or a restarted Redis.
            # That is an operational event, not a fatal one -- recreate the group
            # and let the next poll continue. Without this, any of the above kills
            # every worker.
            if not _is_nogroup(exc):
                raise
            log.warning("consumer group missing, recreating", extra={"stream": stream})
            self.ensure_group(stream, group)
            return []
        return self._decode(stream, response)

    def _decode(self, stream: str, response: Any) -> list[tuple[str, dict[str, Any]]]:
        out: list[tuple[str, dict[str, Any]]] = []
        for _stream_name, entries in response or []:
            for message_id, fields in entries:
                body = fields.get(PAYLOAD_FIELD)
                if body is None:
                    self.dead_letter(stream, message_id, {"raw": fields}, "missing payload field")
                    continue
                try:
                    out.append((message_id, json.loads(body)))
                except json.JSONDecodeError as exc:
                    # Undecodable entry: DLQ immediately rather than retry 5 times.
                    self.dead_letter(stream, message_id, {"raw": body[:2048]}, f"bad json: {exc}")
        return out

    def reclaim(
        self, stream: str, *, group: str | None = None, consumer: str | None = None,
        count: int = 64,
    ) -> list[tuple[str, dict[str, Any]]]:
        """Take over entries abandoned by a dead consumer, DLQ-ing poison ones.

        An entry whose delivery count exceeds ``max_deliveries`` is treated as
        poison: something about it makes a consumer die, so retrying it forever
        would stall the group.
        """
        group = group or self.config.consumer_group
        consumer = consumer or self.config.consumer_name
        try:
            pending = self._client.xpending_range(
                stream, group, min="-", max="+", count=count
            )
        except ResponseError as exc:
            if _is_nogroup(exc):
                self.ensure_group(stream, group)
            return []
        except RedisConnectionError:
            return []
        poison = [
            entry["message_id"]
            for entry in pending
            if entry["times_delivered"] > self.config.max_deliveries
        ]
        for message_id in poison:
            entries = self._client.xrange(stream, min=message_id, max=message_id)
            body = entries[0][1] if entries else {}
            self.dead_letter(
                stream, message_id, {"raw": body},
                f"exceeded {self.config.max_deliveries} delivery attempts",
            )
        try:
            _next, claimed, _deleted = self._client.xautoclaim(
                stream, group, consumer, min_idle_time=self.config.claim_idle_ms, count=count
            )
        except (ResponseError, RedisConnectionError):
            return []
        return self._decode(stream, [(stream, claimed)])

    def ack(self, stream: str, message_ids: list[str], group: str | None = None) -> int:
        if not message_ids:
            return 0
        try:
            acked = int(self._client.xack(stream, group or self.config.consumer_group, *message_ids))
        except ResponseError as exc:
            # Group gone (see read()). The entries are gone with it, so there is
            # nothing left to acknowledge.
            if not _is_nogroup(exc):
                raise
            return 0
        STREAM_MESSAGES.inc(acked, stream=stream, outcome="acked")
        return acked

    def dead_letter(self, stream: str, message_id: str, payload: dict[str, Any], reason: str) -> None:
        """Park an unprocessable entry and acknowledge it so the group moves on."""
        dlq = Streams.dlq(stream)
        self._client.xadd(
            dlq,
            {
                PAYLOAD_FIELD: json.dumps(
                    {"source_stream": stream, "message_id": message_id,
                     "reason": reason, "payload": payload},
                    default=str,
                )
            },
            maxlen=self.config.stream_maxlen,
            approximate=True,
        )
        try:
            self._client.xack(stream, self.config.consumer_group, message_id)
        except ResponseError:
            pass
        DLQ_MESSAGES.inc(stream=stream)
        log.warning("event dead-lettered", extra={"stream": stream, "reason": reason})

    def lag(self, stream: str, group: str | None = None) -> int:
        """Pending (delivered, unacked) entries -- the backpressure signal."""
        try:
            info = self._client.xpending(stream, group or self.config.consumer_group)
        except ResponseError:
            return 0
        pending = int(info.get("pending", 0)) if isinstance(info, dict) else int(info[0] or 0)
        STREAM_LAG.set(pending, stream=stream)
        return pending

    def stream_info(self, stream: str) -> dict[str, Any]:
        try:
            info = self._client.xinfo_stream(stream)
        except ResponseError:
            return {"length": 0, "groups": 0}
        return {"length": info.get("length", 0), "groups": info.get("groups", 0)}

    def consume(
        self, stream: str, *, group: str | None = None, consumer: str | None = None,
        idle_reclaim: bool = True,
    ) -> Iterator[list[tuple[str, dict[str, Any]]]]:
        """Blocking batch iterator: yields batches until the caller stops."""
        self.ensure_group(stream, group)
        while True:
            batch = self.read(stream, group=group, consumer=consumer)
            if not batch and idle_reclaim:
                batch = self.reclaim(stream, group=group, consumer=consumer)
            yield batch

    def trim(self, stream: str, maxlen: int | None = None) -> int:
        return int(
            self._client.xtrim(stream, maxlen=maxlen or self.config.stream_maxlen, approximate=True)
        )

    def delete_stream(self, stream: str) -> None:
        """Test/dev helper: remove a stream and its DLQ entirely."""
        self._client.delete(stream, Streams.dlq(stream))
