from __future__ import annotations

import threading

import structlog

from ._observability import Metrics

log = structlog.get_logger()


class MaintenanceThread:
    def __init__(
        self,
        regista,
        *,
        sweep_interval: float = 30.0,
        recurrence_interval: float = 10.0,
        hook_poll_interval: float = 2.0,
        partition_interval: float = 3600.0,
        timestamp_interval: float = 3600.0,
        tsa_config=None,
        witness_interval: float = 30.0,
    ) -> None:
        self._regista = regista
        self._sweep_interval = sweep_interval
        self._recurrence_interval = recurrence_interval
        self._hook_poll_interval = hook_poll_interval
        self._partition_interval = partition_interval
        self._timestamp_interval = timestamp_interval
        self._tsa_config = tsa_config
        self._witness_interval = witness_interval
        self._next_timestamp = 0.0
        self._next_witness = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_cycle_ok: bool = True
        self._project: str = getattr(regista, "_project", "unknown")
        self._metrics: Metrics | None = getattr(regista, "_metrics", None)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._next_timestamp = 0.0
        self._next_witness = 0.0
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info("maintenance.thread_started", project=self._project)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None
        log.info("maintenance.thread_stopped", project=self._project)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def last_cycle_ok(self) -> bool:
        return self._last_cycle_ok

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._regista.sweep_expired_claims()

                self._regista.sweep_expired_hook_leases()

                self._fire_due_recurrences()

                self._regista.ensure_event_partitions(3)

                self._regista.refresh_hook_queue_metrics()

                self._maybe_timestamp_events()

                self._maybe_deliver_witness_receipts()

                self._last_cycle_ok = True
            except Exception as e:
                log.error("maintenance.cycle_error", error=str(e))
                if self._metrics:
                    self._metrics.inc("maintenance_errors", self._project)
                self._last_cycle_ok = False

            if self._metrics:
                self._metrics.inc("maintenance_cycles", self._project)

            self._stop.wait(timeout=self._sweep_interval)

    def _maybe_timestamp_events(self) -> None:
        import time

        if self._tsa_config is None or self._timestamp_interval <= 0:
            return
        now = time.monotonic()
        if now < self._next_timestamp:
            return
        self._next_timestamp = now + self._timestamp_interval
        try:
            ts_ops = getattr(self._regista, "timestamping", None)
            if ts_ops is not None:
                ts_ops.trigger()
                log.info("maintenance.timestamping_triggered", project=self._project)
        except Exception as e:
            log.error("maintenance.timestamping_error", error=str(e))
            if self._metrics:
                self._metrics.inc("timestamping_errors", self._project)

    def _maybe_deliver_witness_receipts(self) -> None:
        import time

        now = time.monotonic()
        if now < self._next_witness:
            return
        self._next_witness = now + self._witness_interval
        try:
            witness_ops = getattr(self._regista, "witnesses", None)
            if witness_ops is not None:
                count = witness_ops.deliver()
                if count > 0:
                    log.info(
                        "maintenance.witness_receipts_delivered",
                        project=self._project,
                        count=count,
                    )
        except Exception as e:
            log.error("maintenance.witness_delivery_error", error=str(e))
            if self._metrics:
                self._metrics.inc("maintenance_errors", self._project)

    def _fire_due_recurrences(self) -> None:
        try:
            due = self._regista.due_recurrences()
        except Exception:
            log.warning("maintenance.due_recurrences_error", exc_info=True)
            return
        for rule in due:
            try:
                self._regista.fire_recurrence(rule["rule_id"])
                if self._metrics:
                    self._metrics.inc("maintenance_recurrences_fired", self._project)
            except Exception as e:
                log.warning(
                    "maintenance.recurrence_fire_error",
                    rule_id=str(rule["rule_id"]),
                    error=str(e),
                )
