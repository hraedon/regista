from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor

from regista._in_memory import InMemoryRegista, TransportResult

KEY_PATH = os.path.join(os.path.dirname(__file__), "test_keys.json")

WF_YAML = """
name: test
version: 1
regista_version: "0.1.0"

states:
  - name: open
    initial: true
  - name: closed
    terminal: true

transitions:
  - name: close
    from: open
    to: closed
    allowed_roles: []

work_item_types:
  - name: task
    custom_fields: []

roles: []
"""


def _make_sub(transport=None) -> InMemoryRegista:
    sub = InMemoryRegista(hmac_key_path=KEY_PATH, witness_transport=transport)
    sub.register_workflow(WF_YAML)
    return sub


class TestDeliverNoTransport:
    def test_no_transport_returns_zero(self):
        sub = _make_sub()
        assert sub.deliver_pending_witness_receipts() == 0

    def test_no_transport_with_receipts_returns_zero(self):
        sub = _make_sub()
        sub.register_witness("https://example.com/hook")
        sub.create_work_item("test", "task", "actor-1")
        assert sub.deliver_pending_witness_receipts() == 0
        receipts = sub.list_witness_receipts()
        assert len(receipts) == 1
        assert receipts[0]["status"] == "pending"


class TestDeliverSuccess:
    def test_successful_delivery_confirms_receipt(self):
        calls: list[tuple[str, dict, dict]] = []

        def transport(url, headers, payload):
            calls.append((url, headers, payload))
            return TransportResult(status_code=200, body={"ok": True})

        sub = _make_sub(transport)
        wid = sub.register_witness("https://example.com/hook")
        _wi, evt = sub.create_work_item("test", "task", "actor-1")

        count = sub.deliver_pending_witness_receipts()
        assert count == 1

        receipts = sub.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 1
        assert receipts[0]["status"] == "confirmed"
        assert receipts[0]["confirmed_at"] is not None
        assert receipts[0]["witness_response"] == {"ok": True}
        assert receipts[0]["error_message"] is None
        assert receipts[0]["submitted_at"] is not None

        assert len(calls) == 1
        url, headers, payload = calls[0]
        assert url == "https://example.com/hook"
        assert headers["Content-Type"] == "application/json"
        assert headers["User-Agent"] == "regista-delivery/0"
        assert payload["receipt_id"] == receipts[0]["receipt_id"]
        assert payload["witness_id"] == str(wid)
        assert "event" in payload
        assert payload["event"]["event_id"] == str(evt.event_id)

    def test_successful_delivery_stores_witness_signature(self):
        def transport(url, headers, payload):
            return TransportResult(
                status_code=200,
                body={"witness_signature": "deadbeef"},
            )

        sub = _make_sub(transport)
        sub.register_witness("https://example.com/hook")
        _wi, evt = sub.create_work_item("test", "task", "actor-1")

        sub.deliver_pending_witness_receipts()

        receipts = sub.list_witness_receipts(event_id=evt.event_id)
        assert receipts[0]["status"] == "confirmed"
        assert receipts[0]["witness_signature"] == "deadbeef"

    def test_delivery_resets_consecutive_failures(self):
        state = {"calls": 0}

        def transport(url, headers, payload):
            state["calls"] += 1
            if state["calls"] < 3:
                return TransportResult(status_code=500, error="boom")
            return TransportResult(status_code=200, body={"ok": True})

        sub = _make_sub(transport)
        sub.register_witness(
            "https://example.com/hook",
            max_failures=10,
            max_retries=5,
        )
        sub.create_work_item("test", "task", "actor-1")

        sub.deliver_pending_witness_receipts()
        assert sub.list_witnesses()[0]["consecutive_failures"] == 1

        sub.deliver_pending_witness_receipts()
        assert sub.list_witnesses()[0]["consecutive_failures"] == 2

        sub.deliver_pending_witness_receipts()
        assert sub.list_witnesses()[0]["consecutive_failures"] == 0
        assert sub.list_witnesses()[0]["status"] == "active"

    def test_multiple_receipts_delivered(self):
        def transport(url, headers, payload):
            return TransportResult(status_code=200, body={"ok": True})

        sub = _make_sub(transport)
        sub.register_witness("https://example.com/hook")
        sub.create_work_item("test", "task", "actor-1")
        sub.create_work_item("test", "task", "actor-2")
        sub.create_work_item("test", "task", "actor-3")

        count = sub.deliver_pending_witness_receipts()
        assert count == 3
        assert len(sub.list_witness_receipts(status="confirmed")) == 3


class TestDeliverFailure:
    def test_failure_increments_retry_count(self):
        def transport(url, headers, payload):
            return TransportResult(status_code=500, error="server error")

        sub = _make_sub(transport)
        sub.register_witness(
            "https://example.com/hook",
            max_retries=3,
            max_failures=10,
        )
        _wi, evt = sub.create_work_item("test", "task", "actor-1")

        sub.deliver_pending_witness_receipts()
        receipts = sub.list_witness_receipts(event_id=evt.event_id)
        assert receipts[0]["status"] == "pending"
        assert receipts[0]["retry_count"] == 1
        assert receipts[0]["error_message"] == "server error"

        sub.deliver_pending_witness_receipts()
        receipts = sub.list_witness_receipts(event_id=evt.event_id)
        assert receipts[0]["status"] == "pending"
        assert receipts[0]["retry_count"] == 2

    def test_receipt_paused_after_max_retries(self):
        def transport(url, headers, payload):
            return TransportResult(status_code=500, error="server error")

        sub = _make_sub(transport)
        sub.register_witness(
            "https://example.com/hook",
            max_retries=2,
            max_failures=10,
        )
        _wi, evt = sub.create_work_item("test", "task", "actor-1")

        sub.deliver_pending_witness_receipts()
        assert sub.list_witness_receipts(event_id=evt.event_id)[0]["status"] == "pending"

        sub.deliver_pending_witness_receipts()
        receipt = sub.list_witness_receipts(event_id=evt.event_id)[0]
        assert receipt["status"] == "paused"
        assert receipt["retry_count"] == 2

    def test_paused_receipt_not_redelivered(self):
        def transport(url, headers, payload):
            return TransportResult(status_code=500, error="server error")

        sub = _make_sub(transport)
        sub.register_witness(
            "https://example.com/hook",
            max_retries=1,
            max_failures=10,
        )
        _wi, evt = sub.create_work_item("test", "task", "actor-1")

        sub.deliver_pending_witness_receipts()
        assert sub.list_witness_receipts(event_id=evt.event_id)[0]["status"] == "paused"

        count = sub.deliver_pending_witness_receipts()
        assert count == 0

    def test_transport_exception_treated_as_failure(self):
        def transport(url, headers, payload):
            raise ConnectionError("network unreachable")

        sub = _make_sub(transport)
        sub.register_witness(
            "https://example.com/hook",
            max_retries=3,
            max_failures=10,
        )
        _wi, evt = sub.create_work_item("test", "task", "actor-1")

        count = sub.deliver_pending_witness_receipts()
        assert count == 0
        receipt = sub.list_witness_receipts(event_id=evt.event_id)[0]
        assert receipt["status"] == "pending"
        assert receipt["retry_count"] == 1
        assert "network unreachable" in receipt["error_message"]

    def test_http_error_code_without_error_field(self):
        def transport(url, headers, payload):
            return TransportResult(status_code=503)

        sub = _make_sub(transport)
        sub.register_witness(
            "https://example.com/hook",
            max_retries=5,
            max_failures=10,
        )
        _wi, evt = sub.create_work_item("test", "task", "actor-1")

        sub.deliver_pending_witness_receipts()
        receipt = sub.list_witness_receipts(event_id=evt.event_id)[0]
        assert receipt["status"] == "pending"
        assert receipt["error_message"] == "HTTP 503"


class TestAutoPause:
    def test_witness_auto_paused_after_max_failures(self):
        def transport(url, headers, payload):
            return TransportResult(status_code=500, error="server error")

        sub = _make_sub(transport)
        sub.register_witness(
            "https://example.com/hook",
            max_failures=3,
            max_retries=10,
        )
        sub.create_work_item("test", "task", "actor-1")
        sub.create_work_item("test", "task", "actor-2")
        sub.create_work_item("test", "task", "actor-3")

        sub.deliver_pending_witness_receipts()
        witnesses = sub.list_witnesses()
        assert witnesses[0]["status"] == "paused"
        assert witnesses[0]["consecutive_failures"] == 3

    def test_paused_witness_not_processed(self):
        call_count = 0

        def transport(url, headers, payload):
            nonlocal call_count
            call_count += 1
            return TransportResult(status_code=500, error="server error")

        sub = _make_sub(transport)
        sub.register_witness(
            "https://example.com/hook",
            max_failures=1,
            max_retries=10,
        )
        sub.create_work_item("test", "task", "actor-1")
        sub.create_work_item("test", "task", "actor-2")

        sub.deliver_pending_witness_receipts()
        assert sub.list_witnesses()[0]["status"] == "paused"

        sub.create_work_item("test", "task", "actor-3")
        count = sub.deliver_pending_witness_receipts()
        assert count == 0


class TestSignSecret:
    def test_signature_header_set_when_sign_secret_provided(self):
        captured_headers: dict = {}

        def transport(url, headers, payload):
            captured_headers.update(headers)
            return TransportResult(status_code=200, body={"ok": True})

        sub = _make_sub(transport)
        secret = b"super-secret-key"
        sub.register_witness(
            "https://example.com/hook",
            sign_secret=secret,
        )
        sub.create_work_item("test", "task", "actor-1")

        sub.deliver_pending_witness_receipts()

        assert "X-Regista-Signature" in captured_headers
        sig_header = captured_headers["X-Regista-Signature"]
        assert sig_header.startswith("sha256=")

    def test_no_signature_header_without_sign_secret(self):
        captured_headers: dict = {}

        def transport(url, headers, payload):
            captured_headers.update(headers)
            return TransportResult(status_code=200, body={"ok": True})

        sub = _make_sub(transport)
        sub.register_witness("https://example.com/hook")
        sub.create_work_item("test", "task", "actor-1")

        sub.deliver_pending_witness_receipts()
        assert "X-Regista-Signature" not in captured_headers

    def test_custom_headers_passed_through(self):
        captured_headers: dict = {}

        def transport(url, headers, payload):
            captured_headers.update(headers)
            return TransportResult(status_code=200, body={"ok": True})

        sub = _make_sub(transport)
        sub.register_witness(
            "https://example.com/hook",
            headers={"Authorization": "Bearer token123"},
        )
        sub.create_work_item("test", "task", "actor-1")

        sub.deliver_pending_witness_receipts()
        assert captured_headers["Authorization"] == "Bearer token123"


class TestEventPayload:
    def test_payload_contains_event_data(self):
        captured_payload: dict = {}

        def transport(url, headers, payload):
            captured_payload.update(payload)
            return TransportResult(status_code=200, body={"ok": True})

        sub = _make_sub(transport)
        sub.register_witness("https://example.com/hook")
        _wi, evt = sub.create_work_item("test", "task", "actor-1")

        sub.deliver_pending_witness_receipts()

        event = captured_payload["event"]
        assert event["event_id"] == str(evt.event_id)
        assert event["work_item_id"] == str(_wi.work_item_id)
        assert event["workflow_name"] == "test"
        assert event["transition"] == "created"
        assert "payload_canonical_hash" in event
        assert "signature" in event
        assert "timestamp" in event

    def test_witness_scheme_stored_on_receipt(self):
        def transport(url, headers, payload):
            return TransportResult(status_code=200, body={"ok": True})

        sub = _make_sub(transport)
        sub.register_witness(
            "https://example.com/hook",
            key_scheme="hmac-sha256",
        )
        _wi, evt = sub.create_work_item("test", "task", "actor-1")

        sub.deliver_pending_witness_receipts()
        receipt = sub.list_witness_receipts(event_id=evt.event_id)[0]
        assert receipt["witness_scheme"] == "hmac-sha256"


class TestCreateProjectWithTransport:
    def test_create_project_accepts_witness_transport(self):
        def transport(url, headers, payload):
            return TransportResult(status_code=200, body={"ok": True})

        sub = InMemoryRegista.create_project(
            hmac_key_path=KEY_PATH,
            witness_transport=transport,
        )
        sub.register_workflow(WF_YAML)
        sub.register_witness("https://example.com/hook")
        sub.create_work_item("test", "task", "actor-1")

        count = sub.deliver_pending_witness_receipts()
        assert count == 1


class TestConcurrentDelivery:
    def test_concurrent_delivery_no_double_delivery(self):
        import time

        delivery_count = 0
        counter_lock = threading.Lock()

        def transport(url, headers, payload):
            time.sleep(0.05)
            with counter_lock:
                nonlocal delivery_count
                delivery_count += 1
            return TransportResult(status_code=200, body={"ok": True})

        sub = _make_sub(transport)
        sub.register_witness("https://example.com/hook")
        sub.create_work_item("test", "task", "actor-1")

        errors: list[Exception] = []

        def deliver():
            try:
                sub.deliver_pending_witness_receipts()
            except Exception as exc:
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(deliver) for _ in range(2)]
            for f in futures:
                f.result(timeout=10)

        assert not errors, f"Errors during concurrent delivery: {errors}"
        assert delivery_count == 1, (
            f"Expected exactly 1 transport call, got {delivery_count}"
        )
        receipts = sub.list_witness_receipts()
        assert len(receipts) == 1
        assert receipts[0]["status"] == "confirmed"

    def test_concurrent_delivery_multiple_receipts_no_double(self):
        import time

        delivered_payloads: list[str] = []
        counter_lock = threading.Lock()

        def transport(url, headers, payload):
            time.sleep(0.05)
            with counter_lock:
                delivered_payloads.append(payload["receipt_id"])
            return TransportResult(status_code=200, body={"ok": True})

        sub = _make_sub(transport)
        sub.register_witness("https://example.com/hook")
        for i in range(5):
            sub.create_work_item("test", "task", f"actor-{i}")

        errors: list[Exception] = []

        def deliver():
            try:
                sub.deliver_pending_witness_receipts()
            except Exception as exc:
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(deliver) for _ in range(2)]
            for f in futures:
                f.result(timeout=10)

        assert not errors, f"Errors during concurrent delivery: {errors}"
        assert len(delivered_payloads) == 5, (
            f"Expected exactly 5 transport calls, got {len(delivered_payloads)}"
        )
        assert len(set(delivered_payloads)) == 5, (
            f"Duplicate receipt IDs delivered: {delivered_payloads}"
        )
        confirmed = sub.list_witness_receipts(status="confirmed")
        assert len(confirmed) == 5
