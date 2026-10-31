"""Asynchronous PyronixCloud client for Pyronix alarm panels.

A session opens only when the caller asks for it. Each arm or disarm request is
sent once and never repeated. Connection fields and wire payloads are never logged.
"""

from .client import (
    OPTIONAL_AUTH,
    REQUIRED_AUTH,
    STATUS,
    AreaState,
    AuthenticationError,
    CommandUnconfirmedError,
    ConnectionState,
    PanelBusyError,
    PanelClient,
    Snapshot,
    empty_snapshot,
    validate_auth,
)
from .protocol import ProtocolError

__all__ = [
    "OPTIONAL_AUTH",
    "REQUIRED_AUTH",
    "STATUS",
    "AreaState",
    "AuthenticationError",
    "CommandUnconfirmedError",
    "ConnectionState",
    "PanelBusyError",
    "PanelClient",
    "ProtocolError",
    "Snapshot",
    "empty_snapshot",
    "validate_auth",
]
