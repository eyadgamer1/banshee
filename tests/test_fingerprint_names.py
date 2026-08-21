"""B6 name-resolution wire codecs — DNS PTR and NetBIOS NBSTAT round-trips."""

from __future__ import annotations

import struct

from scanner.fingerprint.names import (
    build_nbstat_query,
    build_ptr_query,
    decode_name,
    encode_netbios_name,
    encode_qname,
    parse_first_ptr,
    parse_nbstat_reply,
    reverse_ptr_name,
)


def test_encode_qname_basic():
    assert encode_qname("a.bc") == b"\x01a\x02bc\x00"


def test_encode_qname_skips_empty_labels():
    assert encode_qname("a..b.") == b"\x01a\x01b\x00"


def test_decode_name_simple():
    data = b"\x03foo\x03bar\x00"
    name, end = decode_name(data, 0)
    assert name == "foo.bar"
    assert end == len(data)


def test_decode_name_with_compression_pointer():
    # "bar" at offset 0, then a name "foo" + pointer back to offset 0.
    base = b"\x03bar\x00"
    msg = base + b"\x03foo" + struct.pack("!H", 0xC000 | 0)
    name, end = decode_name(msg, len(base))
    assert name == "foo.bar"
    # end points just past the 2-byte pointer (len('\x03foo')=4 + pointer=2)
    assert end == len(base) + 6


def test_reverse_ptr_name():
    assert reverse_ptr_name("10.0.0.5") == "5.0.0.10.in-addr.arpa"


def test_build_ptr_query_structure():
    q = build_ptr_query("5.0.0.10.in-addr.arpa", txid=0x1234)
    txid, _flags, qd, _an, _ns, _ar = struct.unpack_from("!HHHHHH", q, 0)
    assert txid == 0x1234
    assert qd == 1
    # ends with QTYPE=PTR(12), QCLASS=IN(1)
    qtype, qclass = struct.unpack_from("!HH", q, len(q) - 4)
    assert qtype == 12
    assert qclass == 1


def test_parse_first_ptr_roundtrip():
    # Build a minimal DNS response: 1 question, 1 PTR answer pointing to "host.local".
    txid = 0x4150
    header = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    qname = encode_qname("5.0.0.10.in-addr.arpa")
    question = qname + struct.pack("!HH", 12, 1)
    # answer: name pointer to question (0xC00C), type PTR, class IN, ttl, rdata
    target = encode_qname("host.local")
    answer = (
        struct.pack("!H", 0xC00C)
        + struct.pack("!HHIH", 12, 1, 60, len(target))
        + target
    )
    resp = header + question + answer
    assert parse_first_ptr(resp) == "host.local"


def test_parse_first_ptr_returns_none_for_short_input():
    assert parse_first_ptr(b"\x00\x01") is None


def test_parse_first_ptr_returns_none_when_no_answers():
    header = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0)
    resp = header + encode_qname("x") + struct.pack("!HH", 12, 1)
    assert parse_first_ptr(resp) is None


def test_encode_netbios_name_length():
    # Wildcard "*" encodes to 0x20 + 32 nibble bytes + 0x00 terminator = 34 bytes.
    enc = encode_netbios_name("*", suffix=0x00, pad=0x00)
    assert len(enc) == 34
    assert enc[0] == 0x20
    assert enc[-1] == 0x00


def test_build_nbstat_query_structure():
    q = build_nbstat_query()
    qtype, qclass = struct.unpack_from("!HH", q, len(q) - 4)
    assert qtype == 0x0021  # NBSTAT
    assert qclass == 1


def test_parse_nbstat_reply_extracts_unique_name():
    # header(12) + question name(34) + qtype/qclass(4) + answer name ptr(2)
    header = struct.pack("!HHHHHH", 0x4150, 0x8400, 0, 1, 0, 0)
    question = encode_netbios_name("*", suffix=0x00, pad=0x00) + struct.pack("!HH", 0x21, 1)
    ans_name = struct.pack("!H", 0xC00C)  # pointer answer name
    type_class_ttl = struct.pack("!HHI", 0x21, 1, 0)
    workstation = b"WORKSTATION1   "  # 15 bytes
    suffix = bytes([0x00])  # unique workstation suffix
    flags = struct.pack("!H", 0x0400)  # not group
    rdata = bytes([1]) + workstation + suffix + flags  # name count=1 + one entry
    rdlength = struct.pack("!H", len(rdata))
    resp = header + question + ans_name + type_class_ttl + rdlength + rdata
    assert parse_nbstat_reply(resp) == "WORKSTATION1"


def test_parse_nbstat_reply_none_on_truncated():
    assert parse_nbstat_reply(b"\x00" * 10) is None
