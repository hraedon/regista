from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._api_base import _RegistaBase
from ._errors import ErrorCode, RegistaError
from ._genesis import (
    GenesisRecovery,
    V6GenesisWrite,
    append_v6_genesis,
    read_genesis_from_connection,
)


class GenesisApiMixin(_RegistaBase):
    def initialize_epoch(
        self,
        envelope: Mapping[str, Any],
        *,
        gate_passed: bool = False,
    ) -> V6GenesisWrite:
        """Open the clean v6 epoch with its single project genesis event."""
        self._require_open()
        if self._read_only:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "cannot initialize a v6 epoch through a read-only Regista connection",
            )
        with self._mgr.transaction() as conn:
            return append_v6_genesis(
                conn,
                self._keys,
                envelope,
                gate_passed=gate_passed,
            )

    def write_genesis(
        self,
        envelope: Mapping[str, Any],
        *,
        gate_passed: bool = False,
    ) -> V6GenesisWrite:
        """Compatibility spelling for :meth:`initialize_epoch`."""
        return self.initialize_epoch(envelope, gate_passed=gate_passed)

    def read_genesis(self) -> GenesisRecovery | None:
        """Recover and verify the project's v6 genesis without writing."""
        self._require_open()
        with self._mgr.transaction() as conn:
            conn.execute("SET TRANSACTION READ ONLY")
            return read_genesis_from_connection(conn, self._keys)

    def recover_genesis(self) -> GenesisRecovery | None:
        """Alias for the read-side genesis recovery operation."""
        return self.read_genesis()


__all__ = ["GenesisApiMixin"]
