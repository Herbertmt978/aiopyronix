"""Explicit Pyronix sessions. Never log connection fields or wire payloads."""

import asyncio
from collections.abc import Callable, Coroutine, Mapping
import contextlib
import copy
import json
import time
from typing import Any, Literal, NotRequired, TypedDict

import aiohttp

from .protocol import (
    FrameBuffer,
    PanelSession,
    ProtocolError,
    cloud_command,
    cloud_message,
)

ENDPOINT = "wss://app.pyronixcloud.com:443"
STATUS = {
    0: "Unset",
    1: "Set",
    2: "Alarmed",
    3: "Setting",
    4: "Cannot Set",
    5: "Can Override",
    6: "Set Cancelled",
}
REQUIRED_AUTH = (
    "AppUser",
    "PushId",
    "DeviceId",
    "PanelId",
    "SystemName",
    "PanelPwd",
    "UserCode",
)
OPTIONAL_AUTH = (
    "AppVersion",
    "AppType",
    "OSName",
    "OSVersion",
    "NetworkType",
    "AppLang",
)

type ConnectionState = Literal["disconnected", "connecting", "connected", "error"]


class AreaState(TypedDict):
    """The last reported state of one panel area."""

    name: str
    value: int | None
    status: str


class Snapshot(TypedDict):
    """Area states, permissions and firmware retained from panel records."""

    areas: dict[int, AreaState]
    can_arm: set[int]
    can_disarm: set[int]
    permissions_received: bool
    observed_at: float | None
    firmware: NotRequired[str]


class AuthenticationError(ProtocolError):
    """A confirmed rejection; caller must not repeatedly retry credentials."""


class PanelBusyError(ProtocolError):
    """A local operation owns the connection; this is not a panel outage."""


class CommandUnconfirmedError(ProtocolError):
    """The command was attempted, but its outcome remains uncertain."""

    def __init__(self, snapshot: Snapshot | None = None) -> None:
        """Keep the latest state, if any, for the caller to inspect."""
        super().__init__(
            "Command attempted, but the requested state is not confirmed. "
            "Check the panel before trying again; the command was not repeated."
        )
        self.snapshot = snapshot


def empty_snapshot() -> Snapshot:
    """Return a snapshot with no areas and no permissions."""
    return {
        "areas": {},
        "can_arm": set(),
        "can_disarm": set(),
        "permissions_received": False,
        "observed_at": None,
    }


def operation_confirmed(operation: str, value: int | None) -> bool:
    """Setting confirms an arm request, without claiming the area is fully armed."""
    return value in (1, 3) if operation == "arm" else value == 0


def validate_auth(auth: object) -> dict[str, str]:
    """Return only the connection fields the session needs."""
    if not isinstance(auth, Mapping) or not all(
        isinstance(auth.get(k), str) and auth[k] for k in REQUIRED_AUTH
    ):
        raise ProtocolError("Missing connection details")
    if (
        len(auth["PanelId"]) != 8
        or not auth["UserCode"].isascii()
        or not auth["UserCode"].isdigit()
        or not 4 <= len(auth["UserCode"]) <= 8
    ):
        raise ProtocolError("Invalid panel connection details")
    allowed = {*REQUIRED_AUTH, *OPTIONAL_AUTH}
    return {k: str(v) for k, v in auth.items() if k in allowed}


def ingest(snapshot: Snapshot, record: Mapping[str, Any]) -> None:
    """Retain only area state, allowed operations and firmware; drop raw user data."""
    kind = record.get("type")
    if kind == "area":
        for index, row in _area_rows(record).items():
            snapshot["areas"][index] = {
                "name": str(row.get("N", "Area"))[:80],
                "value": row["V"],
                "status": STATUS.get(row["V"], "Unknown"),
            }
    elif kind == "user":
        # Check both before keeping either, so a malformed record changes nothing.
        can_arm = _permitted_areas(record, "SetAreas")
        can_disarm = _permitted_areas(record, "UnsetAreas")
        snapshot["can_arm"], snapshot["can_disarm"] = can_arm, can_disarm
        snapshot["permissions_received"] = True
    elif kind == "panel":
        hi, lo = record.get("VersionHi"), record.get("VersionLo")
        if type(hi) is int and type(lo) is int:
            snapshot["firmware"] = f"{hi}.{lo}"


def _area_rows(record: Mapping[str, Any]) -> dict[int, dict[str, Any]]:
    """Return the usable rows of an area record by area; reject a malformed record."""
    rows = record.get("Detail", [])
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ProtocolError("Invalid panel status")
    return {
        row["R"]: row
        for row in rows
        if type(row.get("R")) is int
        and 0 <= row["R"] <= 255
        and type(row.get("V")) is int
    }


def _permitted_areas(record: Mapping[str, Any], source: str) -> set[int]:
    areas = record.get(source, {})
    values = areas.get("R", []) if isinstance(areas, dict) else None
    if not isinstance(values, list) or any(
        type(v) is not int or not 0 <= v <= 255 for v in values
    ):
        raise ProtocolError("Invalid panel permissions")
    return set(values)


def complete(snapshot: Snapshot) -> bool:
    """Whether every permitted area has reported its state."""
    permitted = snapshot["can_arm"] | snapshot["can_disarm"]
    return (
        snapshot["permissions_received"]
        and bool(permitted)
        and permitted <= snapshot["areas"].keys()
    )


def validate_control(operation: str, area: int, snapshot: Snapshot) -> None:
    """Exactly one area, no forced omissions or output/installer operations."""
    if (
        operation not in ("arm", "disarm")
        or type(area) is not int
        or not 0 <= area <= 255
    ):
        raise ProtocolError("Unsupported alarm operation")
    allowed = snapshot["can_arm"] if operation == "arm" else snapshot["can_disarm"]
    if not complete(snapshot) or area not in allowed:
        raise ProtocolError("Panel user cannot control this area")
    if operation == "arm" and snapshot["areas"][area]["value"] in (4, 5):
        raise ProtocolError("Panel reports the area cannot be set without intervention")


def control_frame(
    session: PanelSession, operation: str, area: int, snapshot: Snapshot
) -> str:
    """Build the single-area arm or disarm frame after validating it."""
    validate_control(operation, area, snapshot)
    if session.phase != "data":
        raise ProtocolError("Panel session is not ready")
    # Installed HomeControl SDK sendArmAreas / sendUnArmAreas: 45 / 47.
    return session.frame("D", bytes([45 if operation == "arm" else 47, 1, area]))


class PanelClient:
    """One explicitly opened session; commands and incoming status share its socket."""

    CONNECT_TIMEOUT = 50
    COMMAND_TIMEOUT = 25
    HEARTBEAT_INTERVAL = 10
    SILENCE_TIMEOUT = 40
    IDLE_TIMEOUT = 300

    def __init__(
        self,
        http: aiohttp.ClientSession,
        auth: Mapping[str, Any],
        on_update: Callable[[Snapshot], None] | None = None,
        on_state: Callable[[], None] | None = None,
        create_task: Callable[[Coroutine[Any, Any, None]], asyncio.Task[None]]
        | None = None,
    ) -> None:
        """Validate the connection details without connecting."""
        self.http = http
        self.auth = validate_auth(auth)
        self.on_update = on_update
        self.on_state = on_state
        self.create_task = create_task or asyncio.create_task
        self.state: ConnectionState = "disconnected"
        self.detail: str | None = None
        self.idle_deadline: float | None = None
        self.idle_expires_at: float | None = None
        self.last_received: float | None = None
        self.data = empty_snapshot()
        self._reader: asyncio.Task[None] | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._session: PanelSession | None = None
        self._ready: asyncio.Future[Snapshot] | None = None
        self._pending: tuple[str, int, asyncio.Future[Snapshot]] | None = None
        self._phase = "cloud"
        self._password_requested = self._connect_requested = False
        self._write_lock = asyncio.Lock()
        self._command_lock = asyncio.Lock()
        self._stop_requested = False

    @property
    def connected(self) -> bool:
        """Whether a live, authenticated session is open."""
        return self.state == "connected" and self._ws is not None

    def snapshot(self) -> Snapshot:
        """Return an independent copy of the current state."""
        return copy.deepcopy(self.data)

    def _set_state(self, state: ConnectionState, detail: str | None = None) -> None:
        self.state, self.detail = state, detail
        if self.on_state:
            self.on_state()

    def _touch(self) -> None:
        self.idle_deadline = time.monotonic() + self.IDLE_TIMEOUT
        self.idle_expires_at = time.time() + self.IDLE_TIMEOUT
        if self.on_state:
            self.on_state()

    @staticmethod
    def _future() -> asyncio.Future[Snapshot]:
        future: asyncio.Future[Snapshot] = asyncio.get_running_loop().create_future()
        # Disconnect can settle a request whose caller has already been cancelled.
        future.add_done_callback(lambda f: None if f.cancelled() else f.exception())
        return future

    async def connect(self) -> Snapshot:
        """Open a session, or extend an open one, and return the panel state."""
        if self.connected:
            self._touch()
            return self.snapshot()
        if (
            self._reader is not None
            and not self._reader.done()
            and self.state != "connecting"
        ):
            await self.disconnect()
        if self._reader is None or self._reader.done():
            self.data = empty_snapshot()
            self._stop_requested = False
            self._ready = self._future()
            self._set_state("connecting")
            self._reader = self.create_task(self._run())
        ready = self._ready
        if ready is None:
            raise ProtocolError("Connection was disconnected.")
        try:
            # Unlike wait_for(shield()), this leaves the shared future untouched, so
            # failing it after a timeout or cancellation is not logged as unhandled.
            done, _ = await asyncio.wait({ready}, timeout=self.CONNECT_TIMEOUT)
        except asyncio.CancelledError:
            await self.disconnect()
            raise
        if not done:
            await self.disconnect()
            error = ProtocolError("Connection timed out. Press Connect to try again.")
            self._set_state("error", str(error))
            raise error
        return ready.result()

    async def disconnect(self) -> None:
        """Close the session. This never sends an alarm command."""
        self._stop_requested = True
        self._set_state("disconnected")
        reader = self._reader
        if reader is not None and not reader.done():
            reader.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reader
        self._reader = None
        if self._ready is not None and not self._ready.done():
            self._ready.set_exception(ProtocolError("Connection was disconnected."))
        self.idle_deadline = None
        self.idle_expires_at = None
        self._set_state("disconnected")

    async def control(self, operation: str, area: int) -> Snapshot:
        """Send one arm or disarm request and wait for the panel to confirm it."""
        if self._command_lock.locked():
            raise PanelBusyError(
                "Another panel command is in progress; wait for its result"
            )
        async with self._command_lock:
            if not self.connected:
                raise ProtocolError(
                    "Disconnected. Press Connect before choosing an alarm action."
                )
            self._touch()
            future = None
            try:
                async with asyncio.timeout(self.COMMAND_TIMEOUT):
                    async with self._write_lock:
                        ws, session = self._ws, self._session
                        if not self.connected or ws is None or session is None:
                            raise ProtocolError(
                                "Disconnected. Press Connect before choosing an alarm action."
                            )
                        validate_control(operation, area, self.data)
                        if operation_confirmed(
                            operation, self.data["areas"][area]["value"]
                        ):
                            return self.snapshot()
                        frame = control_frame(session, operation, area, self.data)
                        future = self._future()
                        self._pending = (operation, area, future)
                        # Set pending before writing: a failed write may still reach the panel.
                        await ws.send_str(frame)
                    return await asyncio.shield(future)
            except TimeoutError:
                raise CommandUnconfirmedError(
                    self.snapshot() if self.connected else None
                ) from None
            except aiohttp.ClientError, OSError, ConnectionError:
                await self.disconnect()
                raise CommandUnconfirmedError from None
            finally:
                if future is not None and self._pending and self._pending[2] is future:
                    self._pending = None
                if future is not None and not future.done():
                    future.cancel()

    async def _send(self, build_frame: Callable[[], str]) -> None:
        async with self._write_lock:
            if self._ws is None:
                raise ConnectionError("Panel connection closed")
            await self._ws.send_str(build_frame())

    async def _run(self) -> None:
        error = None
        self._phase = "cloud"
        self._password_requested = self._connect_requested = False
        framing = FrameBuffer()
        try:
            session = self._session = PanelSession(
                self.auth["PanelId"], self.auth["PanelPwd"]
            )
            async with self.http.ws_connect(
                ENDPOINT,
                timeout=aiohttp.ClientWSTimeout(ws_close=3),
                heartbeat=None,
                max_msg_size=1000000,
            ) as ws:
                self._ws = ws
                await self._send(lambda: cloud_message(self.auth, "subscription"))
                try:
                    await self._receive(ws, session, framing)
                finally:
                    if self._phase in ("handshake", "data"):
                        with contextlib.suppress(
                            TimeoutError, aiohttp.ClientError, OSError, RuntimeError
                        ):
                            await asyncio.wait_for(self._send(session.close), 2)
        except asyncio.CancelledError:
            pass
        except ProtocolError as exc:
            error = exc
        except TimeoutError, aiohttp.ClientError, OSError, ValueError, UnicodeError:
            error = ProtocolError(
                "Panel connection failed or closed. Press Connect to try again."
            )
        finally:
            self._ws = None
            self.idle_deadline = None
            self.idle_expires_at = None
            if self._pending and not self._pending[2].done():
                self._pending[2].set_exception(CommandUnconfirmedError())
            if self._ready is not None and not self._ready.done():
                self._ready.set_exception(
                    error or ProtocolError("Connection was disconnected.")
                )
            if error and not self._stop_requested:
                self._set_state("error", str(error))
            else:
                self._set_state("disconnected")

    async def _receive(
        self,
        ws: aiohttp.ClientWebSocketResponse,
        session: PanelSession,
        framing: FrameBuffer,
    ) -> None:
        while True:
            if (
                self.connected
                and self._pending is None
                and self.idle_deadline is not None
                and time.monotonic() >= self.idle_deadline
            ):
                return
            try:
                message = await asyncio.wait_for(
                    ws.receive(), self.HEARTBEAT_INTERVAL if self.connected else 20
                )
            except TimeoutError:
                if (
                    not self.connected
                    or self.last_received is None
                    or time.monotonic() - self.last_received >= self.SILENCE_TIMEOUT
                ):
                    raise ConnectionError("Panel stopped responding") from None
                await self._send(session.heartbeat)
                continue
            if message.type not in (aiohttp.WSMsgType.TEXT, aiohttp.WSMsgType.BINARY):
                raise ConnectionError("Panel connection closed")
            self.last_received = time.monotonic()
            if not message.data.strip():
                if self._phase == "data":
                    await self._send(session.heartbeat)
                continue
            for raw in framing.feed(message.data):
                await self._handle_frame(raw, session)

    async def _handle_frame(self, raw: str, session: PanelSession) -> None:
        command = cloud_command(raw)
        if command:
            await self._handle_cloud_command(command, session)
        elif self._phase == "handshake":
            reply = session.handshake(raw)
            if reply:
                await self._send(lambda: reply)
            else:
                await self._send(lambda: session.login(self.auth["UserCode"]))
                self._phase = "data"
        elif self._phase == "data":
            await self._handle_panel_data(raw, session)
        else:
            raise ProtocolError("Unexpected panel session state")

    async def _handle_cloud_command(self, command: str, session: PanelSession) -> None:
        if command in ("w", "m") and not self._password_requested:
            self._password_requested = True
            await self._send(lambda: cloud_message(self.auth, "password"))
        elif command == "j" and not self._connect_requested:
            self._connect_requested = True
            await self._send(lambda: cloud_message(self.auth, "connect"))
        elif command == "u" and self._phase == "cloud":
            await self._send(lambda: cloud_message(self.auth, "connect", encoded=False))
            await self._send(session.announce)
            self._phase = "handshake"
        elif command == "a":
            raise AuthenticationError(
                "Panel access was denied; reconfigure credentials"
            )
        else:
            raise ProtocolError(
                {
                    "b": "Panel is busy. Disconnect the other app and press Connect again.",
                    "n": "Panel is not polling its cloud service. Press Connect to try again.",
                    "i": "Panel subscription has expired",
                }.get(command, "Unexpected cloud response")
            )

    async def _handle_panel_data(self, raw: str, session: PanelSession) -> None:
        try:
            header, body = session.receive(raw)
        except ProtocolError as exc:
            if not self.data["areas"] and str(exc) == "Panel integrity check failed":
                raise AuthenticationError(
                    "Panel login integrity failed; verify credentials"
                ) from None
            raise
        if header in ("e", "f", "c") and not self.data["areas"]:
            raise AuthenticationError("Panel login rejected; reconfigure credentials")
        if header == "g":
            return  # Authenticated photo data; this integration only consumes area state.
        if header != "d":
            raise ProtocolError(
                "Panel closed or rejected the session. Press Connect again."
            )
        if not body.strip():
            return
        try:
            record = json.loads(body)
        except ValueError, RecursionError:
            record = None  # Undecodable, or nested too deeply to decode.
        if not isinstance(record, dict):
            raise ProtocolError("Invalid panel status")
        ingest(self.data, record)
        if not complete(self.data):
            return
        if record.get("type") == "area" or self.data["observed_at"] is None:
            self.data["observed_at"] = time.time()
        if not self.connected:
            self._set_state("connected")
            self._touch()
        snapshot = self.snapshot()
        if self.on_update:
            self.on_update(snapshot)
        if self._ready is not None and not self._ready.done():
            self._ready.set_result(snapshot)
        if self._pending and record.get("type") == "area":
            self._settle_pending(record, snapshot)

    def _settle_pending(self, record: Mapping[str, Any], snapshot: Snapshot) -> None:
        if self._pending is None:
            return
        operation, area, future = self._pending
        if future.done() or area not in _area_rows(record):
            return
        value = self.data["areas"][area]["value"]
        if operation_confirmed(operation, value):
            future.set_result(snapshot)
        elif value in (4, 5, 6):
            future.set_exception(
                ProtocolError("Panel could not complete the requested operation")
            )
