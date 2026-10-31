import hashlib
import struct
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pytest

from aiopyronix.protocol import (
    BUFFER_LIMIT,
    FrameBuffer,
    PanelSession,
    ProtocolError,
    cloud_message,
    crypt_body,
    fixed_key,
    unwrap,
    wrap,
)


def panel_frame(header, seq, body, key=None):
    head = struct.pack("<BHH", ord(header), seq, len(body))
    tail = body + hashlib.sha256(head + body).digest()[:16]
    if key:
        tail = reference_crypt(key, ord(header), len(body), seq, tail)
    return wrap(head + tail)


def reference_crypt(key, header, length, seq, plain):
    # Independent byte-for-byte transcription of vendor encryptMessage loop.
    def encrypt(block):
        worker = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return worker.update(block) + worker.finalize()

    feedback = bytearray(encrypt(struct.pack("<IIII", header, length, seq, 0)))
    result = bytearray()
    for index, value in enumerate(plain):
        slot = index % 16
        if not slot:
            feedback = bytearray(encrypt(bytes(feedback)))
        ciphertext = value ^ feedback[slot]
        result.append(ciphertext)
        feedback[slot] = ciphertext
    return bytes(result)


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 511])
def test_cipher_matches_vendor_feedback_across_blocks(size):
    key = bytes(range(16))
    payload = bytes(i % 256 for i in range(size))
    actual = crypt_body(key, ord("D"), size, 0x10042, payload)
    assert actual == reference_crypt(key, ord("D"), size, 0x10042, payload)
    assert crypt_body(key, ord("D"), size, 0x10042, actual, decrypt=True) == payload


def test_handshake_login_and_status_with_independent_panel():
    client = PanelSession("12345678", "synthetic-password")
    assert unwrap(client.announce())[:5] == b"A\x01\x00\x00\x00"
    extra = b"test"
    outgoing = client.handshake(
        panel_frame("a", 1, b"\x01\x83" + b"12345678" + extra + bytes(11))
    )
    own_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), unwrap(outgoing)[6:-16]
    )
    panel_private = ec.derive_private_key(123456789, ec.SECP256R1())
    panel_public = panel_private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    shared = panel_private.exchange(ec.ECDH(), own_public)
    expected_key = hashlib.sha256(
        fixed_key("synthetic-password", "12345678") + shared + extra
    ).digest()[:16]
    assert client.handshake(panel_frame("b", 2, b"\x01" + panel_public)) is None
    assert client.key == expected_key
    login = unwrap(client.login("9876"))
    assert (
        crypt_body(expected_key, ord("D"), 6, 3, login[5:], decrypt=True)[:-16]
        == b",9876\n"
    )
    status = panel_frame("d", 3, b'{"type":"status"}', expected_key)
    assert client.receive(status) == ("d", b'{"type":"status"}')
    with pytest.raises(ProtocolError, match="sequence"):
        client.receive(status)


def test_bad_panel_or_corrupted_data_is_rejected():
    client = PanelSession("12345678", "synthetic-password")
    with pytest.raises(ProtocolError, match="mismatch"):
        client.handshake(panel_frame("a", 1, b"\x01\x83" + b"87654321"))
    client = PanelSession("12345678", "synthetic-password")
    raw = bytearray(unwrap(panel_frame("a", 1, b"\x01\x83" + b"12345678")))
    raw[-1] ^= 1
    with pytest.raises(ProtocolError, match="integrity"):
        client.receive(wrap(raw))
    assert client.rx_sequence == 0


def test_vendor_transport_whitespace_is_accepted():
    packet = panel_frame("a", 1, b"\x01\x20" + b"12345678")
    assert unwrap(" \r\n" + packet + "\n") == unwrap(packet)


def test_streaming_transport_split_coalesced_and_cloud_frames():
    packet = panel_frame("a", 1, b"\x01\x20" + b"12345678")
    framing = FrameBuffer()
    received = []
    for character in "\n" + packet + packet + "<e>b </e>":
        received.extend(framing.feed(character))
    assert received == [packet, packet, "<e>b </e>"]
    assert framing.pending == ""
    with pytest.raises(ProtocolError):
        framing.feed("invalid")


def test_cloud_operations_are_narrow_and_xml_escaped():
    auth = {
        "AppUser": "fixture&user",
        "PushId": "test",
        "DeviceId": "test",
        "PanelId": "12345678",
        "SystemName": "A < B",
        "PanelPwd": "fixture",
    }
    doc = ET.fromstring(unwrap(cloud_message(auth, "connect")))  # noqa: S314
    assert doc.findtext("b") == "A < B"
    assert {x.tag for x in doc} == set("nuabziltmv") | {"c", "lang"}
    for operation in ("arm", "disarm", "delete", "output", "save"):
        with pytest.raises(ProtocolError):
            cloud_message(auth, operation)


def test_encrypted_sequence_wrap_and_fixed_password_hash():
    client = PanelSession("12345678", "synthetic-password")
    assert client.fixed == fixed_key(
        hashlib.sha256(b"synthetic-password\x0012345678").hexdigest(), "12345678"
    )
    client.key = bytes(range(16))
    client.rx_sequence = 65535
    head = struct.pack("<BHH", ord("d"), 0, 1)
    tail = b" " + hashlib.sha256(head + b" ").digest()[:16]
    incoming = wrap(head + reference_crypt(client.key, ord("d"), 1, 65536, tail))
    assert client.receive(incoming) == ("d", b" ")
    assert client.rx_sequence == 65536


def established_session():
    session = PanelSession("12345678", "synthetic-password")
    outgoing = session.handshake(panel_frame("a", 1, b"\x01\x20" + b"12345678"))
    own_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), unwrap(outgoing)[6:-16]
    )
    panel_private = ec.derive_private_key(123456789, ec.SECP256R1())
    panel_public = panel_private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    assert session.handshake(panel_frame("b", 2, b"\x01" + panel_public)) is None
    assert session.key is not None and panel_private.exchange(ec.ECDH(), own_public)
    return session


def test_transport_accepts_bytes_and_rejects_malformed_frames():
    packet = panel_frame("a", 1, b"\x01\x20" + b"12345678")
    assert FrameBuffer().feed(packet.encode()) == [packet]
    assert unwrap(packet.encode()) == unwrap(packet)
    with pytest.raises(ProtocolError, match="Unexpected transport frame"):
        unwrap("<e>b </e>")
    with pytest.raises(ProtocolError, match="Invalid transport encoding"):
        unwrap("(not base64!)")


def test_receive_buffer_is_bounded():
    framing = FrameBuffer()
    framing.feed("(" + "A" * (BUFFER_LIMIT - 1))
    with pytest.raises(ProtocolError, match="limit"):
        framing.feed("AA")


@pytest.mark.parametrize("password", ["z" * 32, "00 11 22 33 44 55 66 77 88 99 aa"])
def test_malformed_protected_password_is_rejected(password):
    with pytest.raises(ProtocolError, match="protected credential"):
        fixed_key(password, "12345678")


def test_panel_identifier_must_have_eight_characters():
    with pytest.raises(ProtocolError, match="identifier"):
        PanelSession("1234567", "synthetic-password")


@pytest.mark.parametrize(
    ("frame", "message"),
    [
        (wrap(bytes(20)), "Truncated"),
        (wrap(struct.pack("<BHH", ord("a"), 1, 5) + bytes(16)), "Invalid panel frame"),
        (wrap(struct.pack("<BHH", ord("z"), 1, 0) + bytes(16)), "Invalid panel frame"),
        (panel_frame("d", 1, b"{}", bytes(16)), "before session establishment"),
    ],
)
def test_malformed_panel_frames_are_rejected(frame, message):
    client = PanelSession("12345678", "synthetic-password")
    with pytest.raises(ProtocolError, match=message):
        client.receive(frame)
    assert client.rx_sequence == 0


def test_nothing_but_close_is_sent_before_key_exchange():
    client = PanelSession("12345678", "synthetic-password")
    with pytest.raises(ProtocolError, match="Session key is unavailable"):
        client.frame("D", b" ")
    with pytest.raises(ProtocolError, match="not ready"):
        client.heartbeat()
    with pytest.raises(ProtocolError, match="login"):
        client.login("9876")
    assert unwrap(client.close())[:1] == b"F"


@pytest.mark.parametrize(
    ("header", "body", "message"),
    [
        ("a", b"\x01" + bytes(33), "key exchange rejected"),
        ("b", b"\x01" + bytes(10), "key exchange rejected"),
        ("b", b"\x01\x05" + bytes(32), "public key"),
    ],
)
def test_unexpected_key_exchange_replies_are_rejected(header, body, message):
    client = PanelSession("12345678", "synthetic-password")
    client.handshake(panel_frame("a", 1, b"\x01\x20" + b"12345678"))
    with pytest.raises(ProtocolError, match=message):
        client.handshake(panel_frame(header, 2, body))
    assert client.key is None


def test_established_session_refuses_another_handshake():
    client = established_session()
    with pytest.raises(ProtocolError, match="key exchange rejected"):
        client.handshake(panel_frame("b", 3, b"\x01" + bytes(33)))
    assert unwrap(client.close())[:1] == b"E"


@pytest.mark.parametrize("code", ["987", "987654321", "98a6", "９８７６"])
def test_login_accepts_only_four_to_eight_ascii_digits(code):
    client = established_session()
    sequence = client.tx_sequence
    with pytest.raises(ProtocolError, match="login"):
        client.login(code)
    assert client.tx_sequence == sequence
