"""The in-memory v6 epoch API — ``InMemoryRegista``'s half of D2 (WI-287).

Mirrors :class:`~regista._api_genesis.GenesisApiMixin` method for method, but the
mirroring is only in the *method names*: the bodies call the same
``_genesis.append_v6_genesis`` / ``_genesis.read_genesis_from_connection`` the
Postgres backend calls, handed
:class:`~regista._in_memory_v6.InMemoryV6Connection` instead of a pooled
``DictConn``. So genesis envelope validation, the bootstrap-acceptance checks,
signing, the ``project_identity`` singleton, chain-head advancement and the whole
recovery path are shared code, not a second implementation.

``_mgr`` and ``_keys`` exist here for the same reason: the shared conformance
suite (``tests/test_p17_v6_writer.py::TestSemanticConformance``) is written
against ``project._mgr.transaction()`` and ``project._keys``, and
``SUITE-RECONCILIATION.md`` §2.3(a) wants *one* suite over both backends rather
than a backend-shaped fork of the assertions.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, cast

from ._errors import ErrorCode, RegistaError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ._connection import DictConn
    from ._genesis import GenesisRecovery, V6GenesisWrite
    from ._in_memory_v6 import InMemoryV6Connection, InMemoryV6ConnectionManager
    from ._keys import KeySet


def _as_conn(conn: InMemoryV6Connection) -> DictConn:
    """Hand the facade to the shared v6 paths, which are annotated ``DictConn``.

    ``DictConn`` is a concrete ``psycopg.Connection[dict[str, Any]]`` alias, not a
    Protocol, so a structurally-compatible facade cannot satisfy it nominally.
    The cast is confined to this one function on purpose: it is the exact place
    the parity seam crosses the type boundary, and narrowing ``DictConn`` to a
    Protocol on the P1.7 branch would remove the need for it entirely (worth
    doing — see NOTES-WI287.md §5).
    """

    return cast("DictConn", conn)


class InMemGenesisMixin:
    """v6 genesis for the in-memory backend."""

    _key_set: KeySet | None
    _store: Any
    _v6_mgr: InMemoryV6ConnectionManager | None = None

    @property
    def _keys(self) -> KeySet | None:
        """``Regista``'s spelling for the keyset, so one suite reads both backends.

        **Deliberately non-raising, and this is load-bearing.** An earlier revision
        refused here when no keyset was configured; that broke
        ``tests/test_in_memory_conformance.py``'s
        ``getattr(sub, "_key_set", None) or getattr(sub, "_keys", None)`` — a
        property that raises is not absent, so ``getattr``'s default never
        applies and the exception escapes. Caught by the full-suite run, not by
        review. The refusal belongs to the operations that actually need a key
        (:meth:`_require_keys`), not to the accessor.
        """
        return self._key_set

    def _require_keys(self) -> KeySet:
        """The keyset, or a refusal — every v6 event must be signed.

        A keyless in-memory instance has nothing to open an epoch with: the
        legacy backend's "``key_set is None`` means emit unsigned dummy bytes"
        shortcut is precisely what the clean epoch removes, so it is refused by
        name rather than degraded.
        """
        if self._key_set is None:
            raise RegistaError(
                ErrorCode.GENESIS_INVALID,
                "this InMemoryRegista has no keyset; a v6 epoch cannot be opened "
                "without an Ed25519 actor-role key bound to the genesis principal "
                "(construct it with a key path — tests/_v6_fixtures.make_v6_keyset)",
            )
        return self._key_set

    @property
    def _mgr(self) -> InMemoryV6ConnectionManager:
        from ._in_memory_v6 import InMemoryV6ConnectionManager

        manager: InMemoryV6ConnectionManager | None = getattr(self, "_v6_mgr", None)
        if manager is None:
            manager = InMemoryV6ConnectionManager(self._store.v6_rows)
            self._v6_mgr = manager
        return manager

    def initialize_epoch(
        self,
        envelope: Mapping[str, Any],
        *,
        gate_passed: bool = False,
    ) -> V6GenesisWrite:
        """Open the clean v6 epoch with its single project genesis event."""
        from ._genesis import append_v6_genesis

        key_set = self._require_keys()
        with self._mgr.transaction() as conn:
            return append_v6_genesis(_as_conn(conn), key_set, envelope, gate_passed=gate_passed)

    def write_genesis(
        self,
        envelope: Mapping[str, Any],
        *,
        gate_passed: bool = False,
    ) -> V6GenesisWrite:
        """Compatibility spelling for :meth:`initialize_epoch`."""
        return self.initialize_epoch(envelope, gate_passed=gate_passed)

    def read_genesis(self) -> GenesisRecovery | None:
        """Recover and verify the in-memory project's v6 genesis without writing.

        The read-only connection is a real refusal surface, not a label: an
        attempted write through it raises ``PARITY_BOUNDARY_POSTGRES_ONLY``. The
        Postgres path gets the same guarantee from ``SET TRANSACTION READ ONLY``,
        which the in-memory facade cannot execute and therefore enforces itself.
        """
        from ._genesis import read_genesis_from_connection

        key_set = self._require_keys()
        with self._mgr.read_only_transaction() as conn:
            return read_genesis_from_connection(_as_conn(conn), key_set)

    def recover_genesis(self) -> GenesisRecovery | None:
        """Alias for the read-side genesis recovery operation."""
        return self.read_genesis()

    @property
    def v6_epoch_open(self) -> bool:
        """Whether this instance has an open v6 epoch.

        A property on the *handle* and a method on the *store*: the store member is
        part of the ``EventStore`` protocol the legacy funnel calls through, while the
        handle member mirrors ``Regista.v6_epoch_open``. ``bool(...)`` around a bound
        method would be unconditionally true, which is how the shapes were caught.
        """
        open_: bool = self._store.v6_epoch_open()
        return open_


__all__ = ["InMemGenesisMixin"]
