"""B4 TLS JA4 — ClientHello parser and fingerprint string."""

from __future__ import annotations

from scanner.fingerprint.tls import _ja4, _parse_client_hello


def _client_hello(version=0x0303, ciphers=(0x1301, 0x1302), exts=(0x0000, 0x000A)) -> bytes:
    body = bytearray()
    body += b"\x01"  # handshake type = ClientHello
    body += b"\x00\x00\x00"  # length placeholder
    body += version.to_bytes(2, "big")
    body += b"\x00" * 32  # random
    body += b"\x00"  # session id length 0
    cs = b"".join(c.to_bytes(2, "big") for c in ciphers)
    body += len(cs).to_bytes(2, "big") + cs
    body += b"\x01\x00"  # compression: len 1, method 0
    ext_block = b"".join(e.to_bytes(2, "big") + b"\x00\x00" for e in exts)
    body += len(ext_block).to_bytes(2, "big") + ext_block
    record = bytearray()
    record += b"\x16"  # content type handshake
    record += b"\x03\x01"  # record version
    record += len(body).to_bytes(2, "big")
    record += body
    return bytes(record)


def test_parse_client_hello_extracts_fields():
    parsed = _parse_client_hello(_client_hello())
    assert parsed is not None
    version, ciphers, exts = parsed
    assert version == 0x0303
    assert ciphers == [0x1301, 0x1302]
    assert exts == [0x0000, 0x000A]


def test_parse_rejects_non_handshake():
    assert _parse_client_hello(b"\x17\x03\x03\x00\x05hello") is None


def test_parse_rejects_short():
    assert _parse_client_hello(b"\x16\x03") is None


def test_ja4_deterministic_and_formatted():
    a = _ja4(0x0303, [0x1301, 0x1302], [0x0000])
    b = _ja4(0x0303, [0x1302, 0x1301], [0x0000])  # order-independent (sorted)
    assert a == b
    assert a.startswith("t12_")  # TLS 1.2 -> "12"
    parts = a.split("_")
    assert parts[1] == "02"  # cipher count
    assert parts[2] == "01"  # extension count


def test_ja4_version_labels():
    assert _ja4(0x0304, [], []).startswith("t13_")
    assert _ja4(0x0301, [], []).startswith("t10_")
