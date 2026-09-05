"""Redis Streams behaviour: consumer groups, ack, reclaim, DLQ, worker round-trip.

Marked ``redis``; skipped automatically when no server is reachable so the rest of
the suite stays runnable offline.
"""

from __future__ import annotations

import uuid

import pytest

from sih_ntd.config import Streams
from sih_ntd.pipeline import Pipeline, publish_events
from sih_ntd.streaming import StreamClient
from tests.conftest import syn_flood_events

pytestmark = pytest.mark.redis


@pytest.fixture
def stream(settings):
    client = StreamClient(settings)
    if not client.ping():
        pytest.skip("redis not reachable")
    name = f"test.sih.{uuid.uuid4().hex[:8]}"
    client.delete_stream(name)
    yield client, name
    client.delete_stream(name)


def test_publish_read_ack_cycle(stream):
    client, name = stream
    client.ensure_group(name)
    client.publish(name, {"n": 1})
    client.publish_many(name, [{"n": 2}, {"n": 3}])
    batch = client.read(name, block_ms=100)
    assert [payload["n"] for _, payload in batch] == [1, 2, 3]
    assert client.lag(name) == 3, "unacked entries are the backpressure signal"
    client.ack(name, [message_id for message_id, _ in batch])
    assert client.lag(name) == 0


def test_ensure_group_is_idempotent(stream):
    client, name = stream
    client.ensure_group(name)
    client.ensure_group(name)  # BUSYGROUP must be swallowed


def test_undecodable_entry_goes_to_the_dead_letter_stream(stream):
    """One malformed entry must not block the group forever."""
    client, name = stream
    client.ensure_group(name)
    client.raw.xadd(name, {"payload": "{not json"})
    client.publish(name, {"n": 42})
    batch = client.read(name, block_ms=100)
    assert [payload["n"] for _, payload in batch] == [42]
    assert client.stream_info(Streams.dlq(name))["length"] == 1


def test_entry_without_a_payload_field_is_dead_lettered(stream):
    client, name = stream
    client.ensure_group(name)
    client.raw.xadd(name, {"unexpected": "shape"})
    assert client.read(name, block_ms=100) == []
    assert client.stream_info(Streams.dlq(name))["length"] == 1


def test_abandoned_entries_are_reclaimed(stream):
    """A crashed consumer's work must be picked up by another."""
    client, name = stream
    client.ensure_group(name)
    client.publish(name, {"n": 7})
    client.read(name, consumer="dead-worker", block_ms=100)
    client.config.claim_idle_ms = 0  # simulate the idle threshold having passed
    reclaimed = client.reclaim(name, consumer="live-worker")
    assert [payload["n"] for _, payload in reclaimed] == [7]


def test_worker_consumes_published_events_and_stores_alerts(settings, store):
    client = StreamClient(settings)
    if not client.ping():
        pytest.skip("redis not reachable")
    settings.redis.consumer_group = f"test-{uuid.uuid4().hex[:8]}"
    client.delete_stream(Streams.NORMALIZED)
    published = publish_events(syn_flood_events(2000), client)
    assert published == 2000

    pipeline = Pipeline(settings, store=store, stream=client, publish_alerts=True)
    stats = pipeline.run_worker(idle_exit=True)
    assert stats.events == 2000
    assert stats.alerts >= 1
    assert store.query_alerts(threat_class="DDOS")
    assert client.stream_info(Streams.ALERTS)["length"] >= 1, "alerts must be republished for /ws"
    client.delete_stream(Streams.NORMALIZED)


def test_worker_dead_letters_an_invalid_event(settings, store):
    client = StreamClient(settings)
    if not client.ping():
        pytest.skip("redis not reachable")
    settings.redis.consumer_group = f"test-{uuid.uuid4().hex[:8]}"
    client.delete_stream(Streams.NORMALIZED)
    client.publish(Streams.NORMALIZED, {"not": "an event"})
    pipeline = Pipeline(settings, store=store, stream=client, publish_alerts=False)
    stats = pipeline.run_worker(idle_exit=True)
    assert stats.rejected == 1
    assert client.stream_info(Streams.dlq(Streams.NORMALIZED))["length"] >= 1
    client.delete_stream(Streams.NORMALIZED)
