"""Public secret-provider facade.

This module is the stable import boundary for consumers that need Regista's
secret resolution and provider discovery.  Backend implementations remain in
``regista._secrets``; this facade deliberately contains no duplicate backend
logic.
"""

from __future__ import annotations

from ._errors import ErrorCode as ErrorCode
from ._errors import RegistaError as RegistaError
from ._secrets import DeleteOutcome as DeleteOutcome
from ._secrets import SecretProvider as SecretProvider
from ._secrets import StoreNewOutcome as StoreNewOutcome
from ._secrets import available_providers as available_providers
from ._secrets import delete as delete
from ._secrets import is_provider_available as is_provider_available
from ._secrets import known_providers as known_providers
from ._secrets import protect_windows_secret as protect_windows_secret
from ._secrets import reference_provider as reference_provider
from ._secrets import register_provider as register_provider
from ._secrets import resolve as resolve
from ._secrets import resolve_str as resolve_str
from ._secrets import store as store
from ._secrets import store_new as store_new
from ._secrets import supports_delete as supports_delete
from ._secrets import supports_write as supports_write
from ._secrets import unregister_provider as unregister_provider
from ._secrets import vault_auth_status as vault_auth_status

API_VERSION = 1

__all__ = [
    "API_VERSION",
    "DeleteOutcome",
    "ErrorCode",
    "RegistaError",
    "SecretProvider",
    "StoreNewOutcome",
    "available_providers",
    "delete",
    "is_provider_available",
    "known_providers",
    "protect_windows_secret",
    "reference_provider",
    "register_provider",
    "resolve",
    "resolve_str",
    "store",
    "store_new",
    "supports_delete",
    "supports_write",
    "unregister_provider",
    "vault_auth_status",
]
