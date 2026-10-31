import asyncio
from collections import deque
import copy
import hashlib
import json
import logging
import time
from types import SimpleNamespace

import aiohttp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from aiopyronix import (
    AuthenticationError,
    CommandUnconfirmedError,
    PanelBusyError,
    PanelClient,
    ProtocolError,
)
from aiopyronix.client import control_frame, ingest, validate_auth
from aiopyronix.protocol import PanelSession, crypt_body, fixed_key, unwrap, wrap
from tests.const import AUTH
from tests.test_protocol import panel_frame


class FakeSocket:
    def __init__(self, mode="normal", initial_value=0, cloud_reply="j never-log-this"):
        self.mode = mode
        self.cloud_reply = cloud_reply
        self.password = (
            "other-password" if mode == "wrong_password" else AUTH["PanelPwd"]
        )
        self.replies = asyncio.Queue()
        self.closed = False
        self.subscribed = asyncio.Event()
        self.announced = asyncio.Event()
        self.command_sent = asyncio.Event()
        self.heartbeat_seen = asyncio.Event()
        self.commands = []
        self.password_requests = self.connect_requests = 0
        self.login_reply = "e"
        self.sent = []
        self.seq = 0
        self.value = initial_value
        self.key = None
        self.private = ec.derive_private_key(987654321, ec.SECP256R1())

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.closed = True

    def packet(self, header, body):
        self.seq += 1
        return panel_frame(
            header, self.seq, body, self.key if header in "deg" else None
        )

    def area(self):
        return self.packet(
            "d",
            json.dumps(
                {"type": "area", "Detail": [{"R": 0, "N": "Day Set", "V": self.value}]}
            ).encode(),
        )

    async def send_str(self, text):
        self.sent.append(text)
        if text.startswith("(<p>"):
            return
        raw = unwrap(text)
        if raw.startswith(b"<p>"):
            if b"<w>" in raw:
                self.subscribed.set()
                if self.mode == "cloud_silent":
                    return
                if self.mode == "early_frame":
                    self.replies.put_nowait(self.packet("a", b"\x01\x20" + b"12345678"))
                    return
                if self.mode == "keepalive":
                    self.replies.put_nowait(" \r\n")
                self.replies.put_nowait(f"<e>{self.cloud_reply}</e>")
            elif b"<j>" in raw:
                self.password_requests += 1
                self.replies.put_nowait(
                    "<e>w </e>" if self.mode == "password_loop" else "<e>j </e>"
                )
            elif b"<a>" in raw:
                self.connect_requests += 1
                self.replies.put_nowait(
                    {"busy": "<e>b </e>", "connect_loop": "<e>j </e>"}.get(
                        self.mode, "<e>u </e>"
                    )
                )
        elif raw[:1] == b"A":
            self.announced.set()
            if self.mode == "handshake_timeout":
                return
            self.replies.put_nowait(self.packet("a", b"\x01\x20" + b"12345678"))
        elif raw[:1] == b"B":
            public = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), raw[6:-16]
            )
            shared = self.private.exchange(ec.ECDH(), public)
            panel_public = self.private.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
            )
            self.replies.put_nowait(self.packet("b", b"\x01" + panel_public))
            self.key = hashlib.sha256(
                fixed_key(self.password, AUTH["PanelId"]) + shared
            ).digest()[:16]
        elif raw[:1] == b"D":
            if self.mode == "wrong_password":
                # The client cannot read anything sent under the panel's real key.
                self.replies.put_nowait(self.area())
                return
            body = crypt_body(
                self.key,
                ord("D"),
                len(raw) - 21,
                int.from_bytes(raw[1:3], "little"),
                raw[5:],
                decrypt=True,
            )[:-16]
            if body.startswith(b","):
                assert body == b",9876\n"
                if self.mode == "bad_login":
                    self.replies.put_nowait(self.packet(self.login_reply, b""))
                    return
                first = self.area()
                user = self.packet(
                    "d", b'{"type":"user","SetAreas":{"R":[0]},"UnsetAreas":{"R":[0]}}'
                )
                # Fragmentation and coalescing occur across real WebSocket messages.
                self.replies.put_nowait("\n" + first[:9])
                self.replies.put_nowait(first[9:] + user)
            elif body[:1] in (b"-", b"/"):
                self.commands.append(body)
                self.command_sent.set()
                self.value = 1 if body[:1] == b"-" else 0
                if self.mode == "send_failure":
                    raise ConnectionError
                if self.mode == "setting_ack":
                    self.value = 3
                if self.mode == "closed_ack":
                    self.replies.put_nowait(None)
                if self.mode not in ("lost_ack", "closed_ack"):
                    self.replies.put_nowait(self.area())

            elif body == b" ":
                self.heartbeat_seen.set()
                if self.mode != "silent":
                    self.replies.put_nowait(self.packet("d", b" "))

    async def receive(self):
        await asyncio.sleep(0)  # A real socket yields even when data is waiting.
        reply = await self.replies.get()
        return SimpleNamespace(
            type=aiohttp.WSMsgType.CLOSED if reply is None else aiohttp.WSMsgType.TEXT,
            data=reply,
        )

    def push_area(self, value):
        self.value = value
        self.replies.put_nowait(self.area())

    def push_record(self, record, header="d"):
        self.replies.put_nowait(self.packet(header, json.dumps(record).encode()))


class FakeHTTP:
    def __init__(self, socket):
        self.socket = socket
        self.connections = 0

    def ws_connect(self, *args, **kwargs):
        self.connections += 1
        return self.socket


class SequencedHTTP:
    def __init__(self, *sockets):
        self.sockets = deque(sockets)
        self.connections = 0

    def ws_connect(self, *args, **kwargs):
        self.connections += 1
        return self.sockets.popleft()


@pytest.fixture
async def make_client():
    clients = []

    def create(mode="normal", initial=0, cloud_reply="j never-log-this", **kwargs):
        wire = FakeSocket(mode, initial, cloud_reply)
        http = FakeHTTP(wire)
        client = PanelClient(http, AUTH, **kwargs)
        clients.append(client)
        return client, wire, http

    yield create
    for client in clients:
        await client.disconnect()


async def test_connect_controls_and_live_push_share_one_socket(make_client):
    updated = asyncio.Event()
    client, wire, http = make_client(on_update=lambda data: updated.set())
    result = await client.connect()
    assert result["areas"][0]["value"] == 0 and wire.commands == []
    assert client.connected and not wire.closed
    assert (await client.control("arm", 0))["areas"][0]["value"] == 1
    assert (await client.control("disarm", 0))["areas"][0]["value"] == 0
    updated.clear()
    wire.push_area(2)
    await asyncio.wait_for(updated.wait(), 1)
    assert client.snapshot()["areas"][0]["value"] == 2
    assert http.connections == 1 and wire.commands == [b"-\x01\x00", b"/\x01\x00"]
    await client.disconnect()
    assert not client.connected and wire.closed
    assert unwrap(wire.sent[-1])[:1] == b"E"


async def test_offline_control_never_opens_a_connection(make_client):
    client, wire, http = make_client()
    with pytest.raises(ProtocolError, match="Press Connect"):
        await client.control("disarm", 0)
    assert http.connections == 0 and wire.commands == []


@pytest.mark.parametrize(
    ("mode", "error"), [("busy", ProtocolError), ("bad_login", AuthenticationError)]
)
async def test_failed_connect_does_not_retry_and_can_be_disconnected(
    make_client, mode, error
):
    client, wire, http = make_client(mode)
    with pytest.raises(error):
        await client.connect()
    assert client.state == "error" and http.connections == 1 and wire.commands == []
    await client.disconnect()
    assert client.state == "disconnected" and wire.closed


async def test_failed_connection_can_be_explicitly_retried():
    first, second = FakeSocket("busy"), FakeSocket()
    http = SequencedHTTP(first, second)
    client = PanelClient(http, AUTH)
    try:
        with pytest.raises(ProtocolError):
            await client.connect()
        await client.connect()
        assert client.connected and http.connections == 2
        assert first.commands == second.commands == []
    finally:
        await client.disconnect()


async def test_connect_timeout_is_bounded_and_releases_socket(make_client):
    client, wire, http = make_client("handshake_timeout")
    client.CONNECT_TIMEOUT = 0.02
    with pytest.raises(ProtocolError, match="timed out"):
        await client.connect()
    assert client.state == "error" and wire.closed and http.connections == 1


async def test_timed_out_or_cancelled_connect_reports_nothing_unhandled(make_client):
    loop = asyncio.get_running_loop()
    reports = []
    previous = loop.get_exception_handler()
    loop.set_exception_handler(
        lambda _loop, context: reports.append(context["message"])
    )
    try:
        timed_out, _wire, _http = make_client("handshake_timeout")
        timed_out.CONNECT_TIMEOUT = 0.02
        with pytest.raises(ProtocolError, match="timed out"):
            await timed_out.connect()
        cancelled, _wire, _http = make_client("handshake_timeout")
        pending = asyncio.create_task(cancelled.connect())
        await asyncio.sleep(0.01)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        for _ in range(3):
            await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(previous)
    assert reports == []
    assert cancelled.state == "disconnected"


async def test_disconnect_cancels_connect_promptly(make_client):
    connecting = asyncio.Event()
    client, _wire, _http = make_client(
        "handshake_timeout", on_state=lambda: connecting.set()
    )
    request = asyncio.create_task(client.connect())
    await connecting.wait()
    await client.disconnect()
    with pytest.raises(ProtocolError, match="disconnected"):
        await asyncio.wait_for(request, 1)
    assert client.state == "disconnected" and not client.connected


async def test_duplicate_connect_uses_existing_session(make_client):
    client, wire, http = make_client()
    await asyncio.gather(client.connect(), client.connect())
    await client.connect()
    assert http.connections == 1 and client.connected and wire.commands == []


@pytest.mark.parametrize("mode", ["closed_ack", "send_failure"])
async def test_lost_connection_after_write_never_reconnects_or_retries(
    make_client, mode
):
    client, wire, http = make_client(mode)
    await client.connect()
    with pytest.raises(CommandUnconfirmedError):
        await client.control("arm", 0)
    assert len(wire.commands) == 1 and http.connections == 1 and not client.connected


async def test_late_confirmation_updates_live_state_without_resending(make_client):
    updated = asyncio.Event()
    client, wire, http = make_client("lost_ack", on_update=lambda data: updated.set())
    await client.connect()
    client.COMMAND_TIMEOUT = 0.02
    with pytest.raises(CommandUnconfirmedError) as error:
        await client.control("arm", 0)
    assert error.value.snapshot["areas"][0]["value"] == 0 and client.connected
    updated.clear()
    wire.push_area(1)
    await asyncio.wait_for(updated.wait(), 1)
    assert client.snapshot()["areas"][0]["value"] == 1
    assert len(wire.commands) == 1 and http.connections == 1


async def test_stalled_write_is_bounded_and_never_repeated(make_client):
    client, wire, http = make_client()
    await client.connect()
    client.COMMAND_TIMEOUT = 0.02
    original_send = wire.send_str

    async def stalled_send(text):
        if unwrap(text)[:1] == b"D":
            await asyncio.Event().wait()
        await original_send(text)

    wire.send_str = stalled_send
    with pytest.raises(CommandUnconfirmedError):
        await asyncio.wait_for(client.control("arm", 0), 1)
    assert http.connections == 1 and client._pending is None


async def test_setting_is_confirmed_before_exit_delay(make_client):
    client, wire, _http = make_client("setting_ack")
    await client.connect()
    assert (await client.control("arm", 0))["areas"][0]["value"] == 3
    sequence = client._session.tx_sequence
    await client.control("arm", 0)
    assert client._session.tx_sequence == sequence and len(wire.commands) == 1


async def test_disconnect_during_pending_command_reports_uncertainty(make_client):
    client, wire, http = make_client("lost_ack")
    await client.connect()
    request = asyncio.create_task(client.control("arm", 0))
    await wire.command_sent.wait()
    with pytest.raises(PanelBusyError):
        await client.control("disarm", 0)
    assert client.connected
    await client.disconnect()
    with pytest.raises(CommandUnconfirmedError):
        await request
    assert len(wire.commands) == 1 and wire.closed and http.connections == 1


async def test_cancelled_command_does_not_cancel_live_reader_or_resend(make_client):
    client, wire, http = make_client("lost_ack")
    await client.connect()
    request = asyncio.create_task(client.control("arm", 0))
    await wire.command_sent.wait()
    request.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request
    assert client.connected and client._pending is None
    assert len(wire.commands) == 1 and http.connections == 1


async def test_heartbeat_keeps_session_without_refreshing_user_idle_deadline(
    make_client,
):
    client, wire, _http = make_client()
    client.HEARTBEAT_INTERVAL = 0.01
    await client.connect()
    deadline = client.idle_deadline
    await asyncio.wait_for(wire.heartbeat_seen.wait(), 1)
    assert client.connected and client.idle_deadline == deadline and wire.commands == []


async def test_idle_session_closes_without_changing_alarm(make_client):
    client, wire, _http = make_client()
    client.HEARTBEAT_INTERVAL = 0.01
    client.IDLE_TIMEOUT = 0.02
    await client.connect()
    await asyncio.wait_for(client._reader, 1)
    assert client.state == "disconnected" and wire.closed and wire.commands == []
    assert client.idle_expires_at is None


async def test_unresponsive_live_session_becomes_error(make_client):
    client, wire, http = make_client("silent")
    client.HEARTBEAT_INTERVAL = 0.01
    client.SILENCE_TIMEOUT = 0.02
    await client.connect()
    await asyncio.wait_for(client._reader, 1)
    assert client.state == "error" and wire.closed and http.connections == 1


async def test_disconnect_then_connect_opens_a_new_session():
    first, second = FakeSocket(), FakeSocket(initial_value=1)
    http = SequencedHTTP(first, second)
    client = PanelClient(http, AUTH)
    try:
        await client.connect()
        await client.disconnect()
        assert first.closed
        result = await client.connect()
        assert result["areas"][0]["value"] == 1 and http.connections == 2
        assert first.commands == second.commands == []
    finally:
        await client.disconnect()


@pytest.mark.parametrize(
    ("auth", "message"),
    [
        (None, "Missing"),
        ({k: v for k, v in AUTH.items() if k != "UserCode"}, "Missing"),
        ({**AUTH, "PanelPwd": ""}, "Missing"),
        ({**AUTH, "UserCode": 9876}, "Missing"),
        ({**AUTH, "PanelId": "1234567"}, "Invalid"),
        ({**AUTH, "UserCode": "98a6"}, "Invalid"),
        ({**AUTH, "UserCode": "987"}, "Invalid"),
        ({**AUTH, "UserCode": "987654321"}, "Invalid"),
        ({**AUTH, "UserCode": "９８７６"}, "Invalid"),
    ],
)
def test_invalid_connection_details_are_refused_without_connecting(auth, message):
    http = FakeHTTP(FakeSocket())
    with pytest.raises(ProtocolError, match=message):
        PanelClient(http, auth)
    assert http.connections == 0


def test_only_known_connection_fields_are_kept():
    auth = {**AUTH, "AppVersion": "6.3.0", "Email": "fixture@example.invalid"}
    assert validate_auth(auth) == {**AUTH, "AppVersion": "6.3.0"}


def test_records_keep_only_valid_area_rows_permissions_and_firmware():
    client = PanelClient(FakeHTTP(FakeSocket()), AUTH)
    data = client.data
    rows = [
        {"R": 256, "V": 0},
        {"R": True, "V": 0},
        {"R": 1, "V": "1"},
        {"R": 2, "V": 9, "N": "x" * 100, "UserName": "never-kept"},
    ]
    ingest(data, {"type": "area", "Detail": rows})
    ingest(data, {"type": "panel", "VersionHi": "2", "VersionLo": 11})
    assert "firmware" not in data
    ingest(data, {"type": "panel", "VersionHi": 2, "VersionLo": 11})
    ingest(data, {"type": "user", "SetAreas": {"R": [2]}, "UnsetAreas": {"R": [2]}})
    ingest(data, {"type": "unknown", "Detail": [{"R": 3, "V": 0}]})
    assert data["areas"] == {2: {"name": "x" * 80, "value": 9, "status": "Unknown"}}
    assert data["firmware"] == "2.11" and data["can_arm"] == data["can_disarm"] == {2}


@pytest.mark.parametrize(
    "areas", [{"R": 0}, {"R": [256]}, {"R": [True]}, {"R": ["0"]}, {"R": [-1]}]
)
def test_malformed_permissions_are_rejected(areas):
    client = PanelClient(FakeHTTP(FakeSocket()), AUTH)
    with pytest.raises(ProtocolError, match="permissions"):
        ingest(client.data, {"type": "user", "SetAreas": areas})
    assert client.data["permissions_received"] is False


@pytest.mark.parametrize(
    ("initial", "operation", "area", "message"),
    [
        (0, "bypass", 0, "Unsupported"),
        (0, "arm", True, "Unsupported"),
        (0, "arm", 256, "Unsupported"),
        (0, "arm", 1, "cannot control"),
        (4, "arm", 0, "without intervention"),
        (5, "arm", 0, "without intervention"),
    ],
)
async def test_refused_operations_send_nothing(
    make_client, initial, operation, area, message
):
    client, wire, _http = make_client(initial=initial)
    await client.connect()
    sequence = client._session.tx_sequence
    with pytest.raises(ProtocolError, match=message):
        await client.control(operation, area)
    assert wire.commands == [] and client._session.tx_sequence == sequence
    assert client.connected and client._pending is None


async def test_disarm_is_allowed_while_arming_is_blocked(make_client):
    client, wire, _http = make_client(initial=4)
    await client.connect()
    assert (await client.control("disarm", 0))["areas"][0]["value"] == 0
    assert wire.commands == [b"/\x01\x00"]


def test_control_frame_requires_an_encrypted_session():
    snapshot = {
        "areas": {0: {"name": "Day Set", "value": 0, "status": "Unset"}},
        "can_arm": {0},
        "can_disarm": {0},
        "permissions_received": True,
        "observed_at": None,
    }
    session = PanelSession(AUTH["PanelId"], AUTH["PanelPwd"])
    with pytest.raises(ProtocolError, match="not ready"):
        control_frame(session, "arm", 0, snapshot)
    snapshot["permissions_received"] = False
    with pytest.raises(ProtocolError, match="cannot control"):
        control_frame(session, "arm", 0, snapshot)
    assert session.tx_sequence == 0


async def test_state_changes_and_idle_expiry_are_reported(make_client):
    seen = []
    client, _wire, _http = make_client(
        on_state=lambda: seen.append((client.state, client.idle_expires_at))
    )
    await client.connect()
    assert seen[0] == ("connecting", None)
    assert seen[-1][0] == "connected" and seen[-1][1] is not None
    await client.disconnect()
    assert seen[-1] == ("disconnected", None)


@pytest.mark.parametrize("command", ["w", "m"])
async def test_saved_password_is_requested_once_when_the_cloud_asks(
    make_client, command
):
    client, wire, _http = make_client(cloud_reply=f"{command} ")
    await client.connect()
    assert client.connected and wire.password_requests == 1 and wire.commands == []


@pytest.mark.parametrize(
    ("reply", "error", "message"),
    [
        ("a", AuthenticationError, "denied"),
        ("n", ProtocolError, "not polling"),
        ("i", ProtocolError, "expired"),
        ("x", ProtocolError, "Unexpected cloud response"),
    ],
)
async def test_cloud_refusals_end_the_session_without_retrying(
    make_client, reply, error, message
):
    client, wire, http = make_client(cloud_reply=f"{reply} never-log-this")
    with pytest.raises(error, match=message):
        await client.connect()
    assert client.state == "error" and "never-log-this" not in client.detail
    assert http.connections == 1 and wire.closed and wire.commands == []


@pytest.mark.parametrize(
    ("mode", "cloud_reply", "password_requests", "connect_requests"),
    [("password_loop", "w ", 1, 0), ("connect_loop", "j ", 0, 1)],
)
async def test_repeated_cloud_prompts_are_answered_only_once(
    make_client, mode, cloud_reply, password_requests, connect_requests
):
    client, wire, _http = make_client(mode, cloud_reply=cloud_reply)
    client.CONNECT_TIMEOUT = 1
    with pytest.raises(ProtocolError, match="Unexpected cloud response"):
        await client.connect()
    assert wire.password_requests == password_requests
    assert wire.connect_requests == connect_requests


@pytest.mark.parametrize("header", ["e", "f", "c"])
async def test_rejected_login_asks_for_new_credentials(make_client, header):
    client, wire, http = make_client("bad_login")
    wire.login_reply = header
    with pytest.raises(AuthenticationError, match="rejected"):
        await client.connect()
    assert client.state == "error" and http.connections == 1 and wire.commands == []


async def test_disconnect_during_handshake_closes_the_panel_session(make_client):
    client, wire, _http = make_client("handshake_timeout")
    request = asyncio.create_task(client.connect())
    await wire.announced.wait()
    await client.disconnect()
    with pytest.raises(ProtocolError, match="disconnected"):
        await request
    assert unwrap(wire.sent[-1])[:1] == b"F" and wire.closed


async def test_alarm_command_restarts_the_idle_timer(make_client):
    client, wire, _http = make_client()
    await client.connect()
    deadline = client.idle_deadline
    client.IDLE_TIMEOUT = 600
    await client.control("arm", 0)
    assert client.idle_deadline >= deadline + 300 and len(wire.commands) == 1


async def test_panel_frame_before_cloud_connection_is_rejected(make_client):
    client, wire, _http = make_client("early_frame")
    with pytest.raises(ProtocolError, match="Unexpected panel session state"):
        await client.connect()
    assert client.state == "error" and wire.closed


async def test_wrong_panel_password_is_reported_as_credentials(make_client):
    client, wire, _http = make_client("wrong_password")
    with pytest.raises(AuthenticationError, match="integrity"):
        await client.connect()
    assert client.state == "error" and wire.closed and wire.commands == []


async def test_disconnect_before_panel_handshake_sends_no_panel_frame(make_client):
    client, wire, _http = make_client("cloud_silent")
    request = asyncio.create_task(client.connect())
    await wire.subscribed.wait()
    await client.disconnect()
    with pytest.raises(ProtocolError, match="disconnected"):
        await request
    assert wire.closed and [unwrap(text)[:3] for text in wire.sent] == [b"<p>"]


async def test_reader_ending_before_panel_handshake_sends_no_panel_frame(make_client):
    client, wire, _http = make_client()

    async def end_quietly(*args):
        await wire.subscribed.wait()

    client._receive = end_quietly
    with pytest.raises(ProtocolError, match="disconnected"):
        await client.connect()
    assert client.state == "disconnected" and wire.closed
    assert [unwrap(text)[:3] for text in wire.sent] == [b"<p>"]


async def test_blank_messages_are_ignored_or_answered_with_a_heartbeat(make_client):
    client, wire, _http = make_client("keepalive")
    await client.connect()
    assert not wire.heartbeat_seen.is_set()
    wire.replies.put_nowait("  ")
    await asyncio.wait_for(wire.heartbeat_seen.wait(), 1)
    assert client.connected and wire.commands == []


async def test_photo_frames_are_ignored(make_client):
    updated = asyncio.Event()
    client, wire, _http = make_client(on_update=lambda data: updated.set())
    await client.connect()
    updated.clear()
    wire.replies.put_nowait(wire.packet("g", b"\xff\xd8 not decoded"))
    wire.push_area(1)
    await asyncio.wait_for(updated.wait(), 1)
    assert client.connected and client.snapshot()["areas"][0]["value"] == 1


async def test_firmware_report_keeps_the_last_area_observation_time(make_client):
    updated = asyncio.Event()
    client, wire, _http = make_client(on_update=lambda data: updated.set())
    observed = (await client.connect())["observed_at"]
    updated.clear()
    wire.push_record({"type": "panel", "VersionHi": 2, "VersionLo": 11})
    await asyncio.wait_for(updated.wait(), 1)
    snapshot = client.snapshot()
    assert snapshot["firmware"] == "2.11" and snapshot["observed_at"] == observed


def corrupted(packet):
    raw = bytearray(unwrap(packet))
    raw[-1] ^= 1
    return wrap(bytes(raw))


@pytest.mark.parametrize(
    ("reply", "message"),
    [
        (lambda wire: wire.packet("f", b""), "closed or rejected"),
        (lambda wire: wire.packet("e", b""), "closed or rejected"),
        (lambda wire: wire.packet("d", b"[]"), "Invalid panel status"),
        (lambda wire: wire.packet("d", b"{"), "Invalid panel status"),
        # Deeper than the JSON decoder can recurse within the 64 KiB body limit.
        (lambda wire: wire.packet("d", b"[" * 65535), "Invalid panel status"),
        (lambda wire: corrupted(wire.area()), "integrity"),
        (lambda wire: "(not base64!)", "Invalid transport encoding"),
        (lambda wire: "unframed", "transport prefix"),
    ],
)
async def test_invalid_data_after_login_ends_session_without_reauth(
    make_client, reply, message
):
    client, wire, http = make_client()
    await client.connect()
    wire.replies.put_nowait(reply(wire))
    await asyncio.wait_for(client._reader, 1)
    assert client.state == "error" and message in client.detail
    assert wire.closed and http.connections == 1 and wire.commands == []


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ({"type": "user", "SetAreas": [0]}, "Invalid panel permissions"),
        (
            {"type": "user", "SetAreas": {"R": []}, "UnsetAreas": None},
            "Invalid panel permissions",
        ),
        ({"type": "area", "Detail": 5}, "Invalid panel status"),
        ({"type": "area", "Detail": "never-log-this"}, "Invalid panel status"),
        ({"type": "area", "Detail": {"R": 0, "V": 1}}, "Invalid panel status"),
        ({"type": "area", "Detail": [1]}, "Invalid panel status"),
        (
            {"type": "area", "Detail": [{"R": 0, "V": 1}, ["never-log-this"]]},
            "Invalid panel status",
        ),
    ],
)
async def test_malformed_record_ends_session_without_confirming_or_retrying(
    make_client, caplog, record, message
):
    caplog.set_level(logging.DEBUG)
    client, wire, http = make_client("lost_ack")
    await client.connect()
    before = client.snapshot()
    request = asyncio.create_task(client.control("arm", 0))
    await wire.command_sent.wait()
    wire.push_record(record)
    with pytest.raises(CommandUnconfirmedError):
        await request
    # The reader ends by itself, without an exception left for nobody to retrieve.
    await asyncio.wait_for(client._reader, 1)
    assert client.state == "error" and client.detail == message
    assert client.snapshot() == before
    assert wire.closed and http.connections == 1 and len(wire.commands) == 1
    assert caplog.records == []


async def test_unusable_area_row_never_settles_a_command(make_client):
    client, wire, _http = make_client("lost_ack", initial=6)
    await client.connect()
    request = asyncio.create_task(client.control("arm", 0))
    await wire.command_sent.wait()
    # The row names the area, but its value is unusable: the earlier
    # "Set Cancelled" must not be read as the panel refusing this command.
    wire.push_record({"type": "area", "Detail": [{"R": 0, "N": "Day Set", "V": "1"}]})
    wire.push_area(1)
    assert (await request)["areas"][0]["value"] == 1
    assert len(wire.commands) == 1 and client.connected


@pytest.mark.parametrize("value", [4, 5, 6])
async def test_panel_refusal_of_a_command_is_reported_without_resending(
    make_client, value
):
    client, wire, _http = make_client("lost_ack")
    await client.connect()
    request = asyncio.create_task(client.control("arm", 0))
    await wire.command_sent.wait()
    wire.push_area(value)
    with pytest.raises(ProtocolError, match="could not complete"):
        await request
    assert len(wire.commands) == 1 and client.connected and client._pending is None


async def test_unrelated_or_repeated_area_reports_settle_a_command_once(make_client):
    updated = asyncio.Event()
    client, wire, _http = make_client("lost_ack", on_update=lambda data: updated.set())
    await client.connect()
    request = asyncio.create_task(client.control("arm", 0))
    await wire.command_sent.wait()
    updated.clear()
    wire.push_record({"type": "area", "Detail": [{"R": 1, "N": "Garage", "V": 0}]})
    await asyncio.wait_for(updated.wait(), 1)
    updated.clear()
    wire.push_area(2)
    await asyncio.wait_for(updated.wait(), 1)
    assert not request.done()
    # Two confirmations in one message: the second finds the command settled.
    wire.value = 1
    wire.replies.put_nowait(wire.area() + wire.area())
    assert (await request)["areas"][0]["value"] == 1
    assert len(wire.commands) == 1 and client.connected


async def test_connect_while_closing_waits_then_opens_a_new_session():
    first, second = FakeSocket(), FakeSocket(initial_value=1)
    http = SequencedHTTP(first, second)
    client = PanelClient(http, AUTH)
    await client.connect()
    closing, release = asyncio.Event(), asyncio.Event()
    send = first.send_str

    async def slow_close(text):
        if unwrap(text)[:1] == b"E":
            closing.set()
            await release.wait()
        await send(text)

    first.send_str = slow_close
    stop = asyncio.create_task(client.disconnect())
    await closing.wait()
    reopen = asyncio.create_task(client.connect())
    await asyncio.sleep(0)
    release.set()
    try:
        assert (await reopen)["areas"][0]["value"] == 1
        await stop
        assert client.connected and first.closed and http.connections == 2
        assert first.commands == second.commands == []
    finally:
        await client.disconnect()


async def test_disconnect_while_a_command_waits_for_the_socket_sends_nothing(
    make_client,
):
    client, wire, _http = make_client()
    await client.connect()
    async with client._write_lock:
        request = asyncio.create_task(client.control("arm", 0))
        await asyncio.sleep(0)
        stop = asyncio.create_task(client.disconnect())
        await asyncio.sleep(0)
    with pytest.raises(ProtocolError, match="Press Connect"):
        await request
    await stop
    assert wire.commands == [] and wire.closed and not client.connected


async def test_internal_guards_fail_closed(make_client):
    client, wire, http = make_client()
    # Typing guards for states the public methods never leave behind.
    with pytest.raises(ConnectionError):
        await client._send(lambda: "never sent")
    client._settle_pending({"type": "area", "Detail": [{"R": 0, "V": 1}]}, {})
    client._reader = asyncio.create_task(asyncio.Event().wait())
    client.state = "connecting"
    with pytest.raises(ProtocolError, match="disconnected"):
        await client.connect()
    assert http.connections == 0 and wire.sent == []


# Moved from the integration's tests, where they guarded these wire details.
DATA = {
    "areas": {
        0: {"name": "Day Set", "value": 0, "status": "Unset"},
        1: {"name": "Night Set", "value": 0, "status": "Unset"},
        2: {"name": "Garage", "value": 0, "status": "Unset"},
        3: {"name": "Bike Shed", "value": 0, "status": "Unset"},
    },
    "can_arm": {0, 1, 2, 3},
    "can_disarm": {0, 1, 2, 3},
    "permissions_received": True,
    "firmware": "2.11",
    "observed_at": time.time(),
}


def test_command_wire_ids_and_permission_bounds():
    session = PanelSession("12345678", "fixture")
    session.phase = "data"
    session.key = bytes(16)
    for operation, expected in [("arm", b"-\x01\x02"), ("disarm", b"/\x01\x02")]:
        raw = unwrap(control_frame(session, operation, 2, DATA))
        assert (
            crypt_body(
                session.key, ord("D"), 3, session.tx_sequence, raw[5:], decrypt=True
            )[:-16]
            == expected
        )
    for operation, area in [
        ("arm", 4),
        ("disarm", 255),
        ("omit", 0),
        ("arm", -1),
        ("arm", True),
    ]:
        with pytest.raises(ProtocolError):
            control_frame(session, operation, area, DATA)
    snapshot = copy.deepcopy(DATA)
    snapshot["areas"][2]["value"] = 5
    with pytest.raises(ProtocolError):
        control_frame(session, "arm", 2, snapshot)


def test_status_retains_only_needed_fields_and_credentials_are_narrow():
    snapshot = {
        "areas": {},
        "can_arm": set(),
        "can_disarm": set(),
        "permissions_received": False,
    }
    ingest(
        snapshot,
        {
            "type": "area",
            "Detail": [
                {
                    "R": 0,
                    "N": "Day Set",
                    "V": 0,
                    "LastSet": {"U": "private-person"},
                    "S": "arbitrary",
                }
            ],
        },
    )
    assert snapshot["areas"][0] == {"name": "Day Set", "value": 0, "status": "Unset"}
    ingest(
        snapshot,
        {
            "type": "user",
            "U": "private-person",
            "SetAreas": {"R": [0]},
            "UnsetAreas": {"R": [0]},
        },
    )
    assert "private-person" not in repr(snapshot)
    assert "unrelated_secret" not in validate_auth(
        {**AUTH, "unrelated_secret": "never-keep"}
    )
