from __future__ import annotations

import threading

import structlog

from ._observability import Metrics

log = structlog.get_logger()


class MaintenanceThread:
    def __init__(
        self,
        substrate,
        *,
        sweep_interval: float = 30.0,
        recurrence_interval: float = 10.0,
        hook_poll_interval: float = 2.0,
        partition_interval: float = 3600.0,
    ) -> None:
        self._substrate = substrate
        self._sweep_interval = sweep_interval
        self._recurrence_interval = recurrence_interval
        self._hook_poll_interval = hook_poll_interval
        self._partition_interval = partition_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_cycle_ok: bool = True
        self._project: str = getattr(substrate, "_project", "unknown")
        self._metrics: Metrics | None = getattr(substrate, "_metrics", None)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info("maintenance.thread_started", project=self._project)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._sweep_interval + 5)
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
                swept_claims = self._substrate.sweep_expired_claims()
                if swept_claims > 0 and self._metrics:
                    self._metrics.inc(
                        "maintenance_claims_swept",
                        self._project,
                        amount=swept_claims,
                    )

                swept_hooks = self._substrate.sweep_expired_hook_leases()
                if swept_hooks > 0 and self._metrics:
                    self._metrics.inc(
                        "maintenance_hook_leases_swept",
                        self._project,
                        amount=swept_hooks,
                    )

                self._fire_due_recurrences()

                self._substrate.ensure_event_partitions(3)

                self._substrate.refresh_hook_queue_metrics()

                self._last_cycle_ok = True
            except Exception as e:
                log.error("maintenance.cycle_error", error=str(e))
                if self._metrics:
                    self._metrics.inc("maintenance_errors", self._project)
                self._last_cycle_ok = False

            if self._metrics:
                self._metrics.inc("maintenance_cycles", self._project)

            self._stop.wait(timeout=self._sweep_interval)

    def _fire_due_recurrences(self) -> None:
        try:
            due = self._substrate.due_recurrences()
        except Exception:
            log.warning("maintenance.due_recurrences_error")
            return
        for rule in due:
            try:
                self._substrate.fire_recurrence(rule["rule_id"])
                if self._metrics:
                    self._metrics.inc("maintenance_recurrences_fired", self._project)
            except Exception as e:
                log.warning(
                    "maintenance.recurrence_fire_error",
                    rule_id=str(rule["rule_id"]),
                    error=str(e),
                )
