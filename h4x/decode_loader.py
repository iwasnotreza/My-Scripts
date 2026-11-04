#!/usr/bin/env python3
"""
Static decoder for the H4xScripts loader wrapper observed at:
    https://h4xscripts.xyz/loader

Version fingerprint:
    header: --[[ 1.0.0 ]]
    wrapper: loadstring or load + getfenv/getgenv/getrenv probe
    container: custom base64 -> 102 framed records -> HMAC-SHA256 / ChaCha20
    stage1: 32-byte key + custom range-coded Lua source (210254 bytes)
    stage2: HMAC-derived key + ChaCha20 stream

This tool DOES NOT execute Lua. It only parses, decrypts and decompresses.

Usage:
    # 1) Save the raw HTTP body locally (browser / curl / executor HttpGet dump):
    #    https://h4xscripts.xyz/loader  ->  h4x/raw_loader.lua
    # 2) Run:
    python3 h4x/decode_loader.py h4x/raw_loader.lua -o h4x/out

Outputs:
    h4x/out/stage1.lua      decompressed first Lua stage
    h4x/out/stage2.bin      decrypted second stage (may be Lua or VM bytecode)
    h4x/out/keys.json       derived keys / fingerprints
    h4x/out/strings.txt     printable strings extracted from both stages
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import struct
import sys
from pathlib import Path

MASK32 = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# Bit helpers
# ---------------------------------------------------------------------------

def bxor(a: int, b: int) -> int:
    return (a ^ b) & MASK32


def lrotate(x: int, n: int) -> int:
    x &= MASK32
    n %= 32
    return ((x << n) | (x >> (32 - n))) & MASK32


def rrotate(x: int, n: int) -> int:
    x &= MASK32
    n %= 32
    return ((x >> n) | (x << (32 - n))) & MASK32


# ---------------------------------------------------------------------------
# Wrapper key schedule (Nuk5hHVy39jZ7 in the observed sample)
# ---------------------------------------------------------------------------

def derive_root_key() -> bytes:
    laF60l7pmgeDDj = 3372771009
    lg0VCY8hFdoc5QOc2I = 4117640561
    BCtRzr = 2749024259
    TQkPZ3 = 2813859278
    _DG9zd2z80Q2tUR = 2454577118
    d_bpNAi = 308585062
    n2QHO6H9UEq = 1665293933
    QtZXgRRUMTtL8 = 1667652035

    def upd(v, x, a, r):
        return lrotate((bxor(v, x) + a) & MASK32, r)

    # Round 1
    n2QHO6H9UEq = upd(n2QHO6H9UEq, 2788055496, 656158437, 4)
    QtZXgRRUMTtL8 = upd(QtZXgRRUMTtL8, 2471643427, 1116270005, 19)
    lg0VCY8hFdoc5QOc2I = upd(lg0VCY8hFdoc5QOc2I, 1111717989, 892361631, 17)
    laF60l7pmgeDDj = upd(laF60l7pmgeDDj, 390826973, 2287120640, 28)
    d_bpNAi = upd(d_bpNAi, 3028030009, 566828179, 16)
    TQkPZ3 = upd(TQkPZ3, 1367496870, 129683877, 2)
    BCtRzr = upd(BCtRzr, 2600983235, 944264483, 5)
    _DG9zd2z80Q2tUR = upd(_DG9zd2z80Q2tUR, 801184964, 1918516520, 10)

    # Round 2
    n2QHO6H9UEq = upd(n2QHO6H9UEq, 3413025616, 996763719, 11)
    QtZXgRRUMTtL8 = upd(QtZXgRRUMTtL8, 2365177893, 293769351, 29)
    lg0VCY8hFdoc5QOc2I = upd(lg0VCY8hFdoc5QOc2I, 3249015947, 1319670360, 31)
    laF60l7pmgeDDj = upd(laF60l7pmgeDDj, 4102894995, 1571247457, 31)
    d_bpNAi = upd(d_bpNAi, 430615292, 2684038996, 10)
    TQkPZ3 = upd(TQkPZ3, 335574267, 78619117, 31)
    BCtRzr = upd(BCtRzr, 1334679656, 249194452, 15)
    _DG9zd2z80Q2tUR = upd(_DG9zd2z80Q2tUR, 955594290, 1303980486, 28)

    # Round 3
    n2QHO6H9UEq = upd(n2QHO6H9UEq, 4164164779, 1416240390, 8)
    QtZXgRRUMTtL8 = upd(QtZXgRRUMTtL8, 600831109, 498227299, 30)
    lg0VCY8hFdoc5QOc2I = upd(lg0VCY8hFdoc5QOc2I, 2789765552, 877660879, 26)
    laF60l7pmgeDDj = upd(laF60l7pmgeDDj, 2466452379, 603775636, 10)
    d_bpNAi = upd(d_bpNAi, 2698958046, 1551901993, 12)
    TQkPZ3 = upd(TQkPZ3, 3564695541, 4029847667, 30)
    BCtRzr = upd(BCtRzr, 3043590061, 3583540675, 31)
    _DG9zd2z80Q2tUR = upd(_DG9zd2z80Q2tUR, 2594654438, 870999963, 25)

    words = [
        bxor(laF60l7pmgeDDj, 3811804196),
        bxor(lg0VCY8hFdoc5QOc2I, 3639010762),
        bxor(BCtRzr, 1841746439),
        bxor(TQkPZ3, 2278919990),
        bxor(_DG9zd2z80Q2tUR, 522333680),
        bxor(d_bpNAi, 2459650344),
        bxor(n2QHO6H9UEq, 2376347053),
        bxor(QtZXgRRUMTtL8, 1505261735),
    ]
    return b"".join(struct.pack("<I", w) for w in words)


# ---------------------------------------------------------------------------
# HMAC domain separators observed in the wrapper
# ---------------------------------------------------------------------------

DS_ENC = bytes([84, 224, 134, 108, 175, 180, 218, 249, 30, 84, 158, 163, 88, 142, 144, 2])
DS_MAC = bytes([67, 169, 141, 29, 123, 123, 64, 73, 188, 237, 142, 186, 114, 248, 201, 8])
DS_TAG = bytes([130, 176, 137, 194, 67, 180, 124, 151, 105, 135, 249, 61, 111, 121, 219, 187])
DS_STAGE1_KEY = bytes([224, 62, 231, 184, 18, 114, 128, 166, 193, 86, 200, 95, 84, 181, 183, 208])
DS_STAGE2_KEY = bytes([127, 71, 244, 1, 147, 121, 50, 196, 254, 199, 26, 157, 142, 85, 181, 129])


def H(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# ChaCha20 block (20 rounds), matching gY6Kl47vmhl in the wrapper
# ---------------------------------------------------------------------------

def chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    assert len(key) == 32 and len(nonce) == 12
    constants = [1634760805, 857760878, 2036477234, 1797285236]
    k = list(struct.unpack("<8I", key))
    n = list(struct.unpack("<3I", nonce))
    state = constants + k + [counter & MASK32] + n
    orig = state[:]

    def qr(a, b, c, d):
        state[a] = (state[a] + state[b]) & MASK32
        state[d] = lrotate(state[d] ^ state[a], 16)
        state[c] = (state[c] + state[d]) & MASK32
        state[b] = lrotate(state[b] ^ state[c], 12)
        state[a] = (state[a] + state[b]) & MASK32
        state[d] = lrotate(state[d] ^ state[a], 8)
        state[c] = (state[c] + state[d]) & MASK32
        state[b] = lrotate(state[b] ^ state[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12)
        qr(1, 5, 9, 13)
        qr(2, 6, 10, 14)
        qr(3, 7, 11, 15)
        qr(0, 5, 10, 15)
        qr(1, 6, 11, 12)
        qr(2, 7, 8, 13)
        qr(3, 4, 9, 14)

    out = [(state[i] + orig[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, initial_counter: int = 1) -> bytes:
    out = bytearray()
    counter = initial_counter
    for off in range(0, len(data), 64):
        ks = chacha20_block(key, nonce, counter)
        chunk = data[off : off + 64]
        out.extend(b ^ k for b, k in zip(chunk, ks))
        counter = (counter + 1) & MASK32
    return bytes(out)


# ---------------------------------------------------------------------------
# Encrypted record: 12-byte nonce || ciphertext || 32-byte HMAC tag
# ---------------------------------------------------------------------------

def decrypt_record(blob: bytes, root_key: bytes) -> bytes:
    if len(blob) < 44:
        raise ValueError("record too short")
    nonce = blob[:12]
    body = blob[12:-32]
    tag = blob[-32:]

    enc_key = H(root_key, DS_ENC + nonce)
    mac_key = H(root_key, DS_MAC + nonce)
    expect = H(mac_key, DS_TAG + body)
    if not hmac.compare_digest(expect, tag):
        raise ValueError("HMAC tag mismatch")

    return chacha20_xor(enc_key, nonce, body, initial_counter=1)


# ---------------------------------------------------------------------------
# Custom base64 container
# ---------------------------------------------------------------------------

def extract_container(source: str) -> tuple[str, str]:
    # live sample: local A,B="<payload>","<alphabet>"
    m = re.search(r'local\s+[A-Za-z0-9_]+\s*,\s*[A-Za-z0-9_]+\s*=\s*"([^"]+)"\s*,\s*"([^"]+)"', source)
    if not m:
        raise ValueError("could not locate payload/alphabet string pair")
    payload, alphabet = m.group(1), m.group(2)
    if len(alphabet) != 64:
        raise ValueError("alphabet is not 64 characters")
    return payload, alphabet


def b64_to_bytes(payload: str, alphabet: str) -> bytes:
    lookup = {ch: i for i, ch in enumerate(alphabet)}
    acc = 0
    bits = 0
    out = bytearray()
    for ch in payload:
        v = lookup.get(ch)
        if v is None:
            raise ValueError(f"invalid base64 character: {ch!r}")
        acc = (acc << 6) | v
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
            acc &= (1 << bits) - 1
    return bytes(out)


class BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def byte(self):
        if self.pos >= len(self.data):
            return None
        b = self.data[self.pos]
        self.pos += 1
        return b

    def varint(self):
        value = 0
        shift = 1
        for _ in range(5):
            b = self.byte()
            if b is None:
                raise ValueError("truncated varint")
            value += (b % 128) * shift
            if b < 128:
                return value
            shift *= 128
        raise ValueError("varint too long")


def unpack_records(data: bytes) -> tuple[bytes, bytes]:
    r = BitReader(data)
    stages = {1: {}, 2: {}}
    counts = {1: 0, 2: 0}
    totals = {1: 0, 2: 0}

    for _ in range(102):
        idx = r.varint()
        length = r.varint()
        tag = r.varint()
        stage = 1 if tag == 66 else 2 if tag == 48 else 0
        if stage == 0:
            raise ValueError(f"bad record tag {tag}")
        max_idx = 61 if stage == 1 else 41
        if idx < 1 or idx > max_idx or length < 1 or length > 4096 or idx in stages[stage]:
            raise ValueError("bad record frame")
        chunk = bytearray()
        for _ in range(length):
            b = r.byte()
            if b is None:
                raise ValueError("truncated record body")
            chunk.append(b)
        stages[stage][idx] = bytes(chunk)
        counts[stage] += 1
        totals[stage] += length

    if r.byte() is not None:
        raise ValueError("trailing bytes after container")
    if counts[1] != 61 or counts[2] != 41:
        raise ValueError(f"bad record counts: {counts}")
    if totals[1] != 157059 or totals[2] != 113450:
        raise ValueError(f"bad record totals: {totals}")

    s1 = b"".join(stages[1][i] for i in range(1, 62))
    s2 = b"".join(stages[2][i] for i in range(1, 42))
    return s1, s2


# ---------------------------------------------------------------------------
# Stage1 range coder
# ---------------------------------------------------------------------------

FREQ = [
    1,25,1,1,74,1,1,1,1,1,1,1,1,1,1,36,1,1,11,14,1,138,1,12,21,85,1,1,1,125,1,12,
    1,1,5,1,1,1,1,1,27,1,1,1,16,1,1,82,1,1,1,1,1,1,1,17,1,30,1,7,1,1,1,1,19,19,
    1,40,20,1,17,16,1,1,1,1,6,1,1,1,1,10,21,1,8,27,1,39,1,62,1,1,16,55,1,1,1,1,
    1,1,1,21,1,61,132,1,1,1,39,56,1,74,17,1,142,1,28,113,1,1,1,1,1,1,1,16,1,1,
    15,76,43,77,1,16,1,1,28,132,30,40,1,20,1,1,1,1,1,1,189,1,38,1,1,35,10,15,1,
    16,1,1,73,1,17,1,1,1,1,14,1,32,1,5,1,1,1,1,1,1,27,145,1,1,174,1,1,1,1,7,
    1,1,1,29,1,1,107,1,1,1,12,1,1,1,1,1,18,1,1,12,1,20,166,1,1,54,17,18,12,21,
    1,1,1,1,13,1,6,1,4,84,1,6,1,1,31,1,1,27,1,1,1,5,1,1,1,1,50,1,96,1,20,1,4,
    1,1,12,1,6,
]


def build_range_tables():
    if len(FREQ) != 256 or sum(FREQ) != 4096:
        raise ValueError("frequency table is not 256 entries summing to 4096")
    cum = [0] * 256
    inv = [0] * 4096
    total = 0
    for i, f in enumerate(FREQ):
        cum[i] = total
        for j in range(total, total + f):
            inv[j] = i
        total += f
    return cum, inv


def xorshift32(x: int) -> int:
    x ^= (x << 13) & MASK32
    x ^= x >> 17
    x ^= (x << 5) & MASK32
    return x & MASK32


def build_permutation(root_key: bytes) -> list[int]:
    h = 2166136261
    for b in root_key:
        h = bxor((h * 33) & MASK32, b)
    if h == 0:
        h = 1
    perm = list(range(256))  # perm[0] corresponds to Lua index 1
    for i in range(256, 1, -1):
        h = xorshift32(h)
        j = (h % i) + 1
        perm[i - 1], perm[j - 1] = perm[j - 1], perm[i - 1]
    return perm


def range_decompress(data: bytes, root_key: bytes, out_len: int = 210254) -> bytes:
    cum, inv = build_range_tables()
    perm = build_permutation(root_key)
    pos = 0

    def next_byte():
        nonlocal pos
        if pos >= len(data):
            raise ValueError("range coder ran out of input")
        b = data[pos]
        pos += 1
        return b

    if len(data) < 4:
        raise ValueError("range coder input too short")
    code = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
    pos = 4
    if code < 8388608:
        raise ValueError("bad range coder initial code")

    out = bytearray()
    for _ in range(out_len):
        v = code % 4096
        sym = inv[v]
        code = FREQ[sym] * (code // 4096) + v - cum[sym]
        while code < 8388608:
            code = code * 256 + next_byte()
        out.append(perm[sym])

    # final symbol: decoder expects code == 8388608 and EOF
    v = code % 4096
    sym = inv[v]
    code = FREQ[sym] * (code // 4096) + v - cum[sym]
    if code != 8388608 or pos != len(data):
        raise ValueError("range coder final state mismatch")
    return bytes(out)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def decode(source: str) -> dict:
    payload, alphabet = extract_container(source)
    container = b64_to_bytes(payload, alphabet)
    rec1, rec2 = unpack_records(container)

    root_key = derive_root_key()
    stage1_plain = decrypt_record(rec1, root_key)
    if len(stage1_plain) < 33:
        raise ValueError("stage1 too short")

    stage1_key = stage1_plain[:32]
    stage1_compressed = stage1_plain[32:]
    stage1_lua = range_decompress(stage1_compressed, root_key, 210254)

    stage1_key2 = H(root_key, DS_STAGE1_KEY + stage1_key)[:32]
    stage2_key = H(stage1_key2, DS_STAGE2_KEY + stage1_key + hashlib.sha256(stage1_lua).digest())[:32]
    stage2_plain = decrypt_record(rec2, stage2_key)

    return {
        "root_key": root_key,
        "stage1_key": stage1_key,
        "stage1_key2": stage1_key2,
        "stage2_key": stage2_key,
        "stage1_lua": stage1_lua,
        "stage2_plain": stage2_plain,
        "alphabet": alphabet,
        "container_sha256": hashlib.sha256(container).hexdigest(),
        "stage1_sha256": hashlib.sha256(stage1_lua).hexdigest(),
        "stage2_sha256": hashlib.sha256(stage2_plain).hexdigest(),
    }


def printable_strings(data: bytes, minlen: int = 6) -> list[str]:
    return [m.decode("latin1") for m in re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("raw", nargs="?", default="h4x/raw_loader.lua", help="raw HTTP body of the loader")
    ap.add_argument("-o", "--out", default="h4x/out", help="output directory")
    args = ap.parse_args()

    raw = Path(args.raw)
    if not raw.exists():
        print(f"[!] raw loader not found: {raw}", file=sys.stderr)
        print("    Save the response body of https://h4xscripts.xyz/loader to that path first.", file=sys.stderr)
        return 2

    source = raw.read_text(encoding="utf-8", errors="replace")
    result = decode(source)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "stage1.lua").write_bytes(result["stage1_lua"])
    (out / "stage2.bin").write_bytes(result["stage2_plain"])

    keys = {
        "root_key_hex": result["root_key"].hex(),
        "stage1_key_hex": result["stage1_key"].hex(),
        "stage1_key2_hex": result["stage1_key2"].hex(),
        "stage2_key_hex": result["stage2_key"].hex(),
        "container_sha256": result["container_sha256"],
        "stage1_sha256": result["stage1_sha256"],
        "stage2_sha256": result["stage2_sha256"],
        "alphabet": result["alphabet"],
    }
    (out / "keys.json").write_text(json.dumps(keys, indent=2), encoding="utf-8")

    strings = []
    strings.append("=== stage1.lua ===")
    strings.extend(printable_strings(result["stage1_lua"]))
    strings.append("=== stage2.bin ===")
    strings.extend(printable_strings(result["stage2_plain"]))
    (out / "strings.txt").write_text("\n".join(strings), encoding="utf-8")

    print(f"[+] stage1.lua : {len(result['stage1_lua'])} bytes")
    print(f"[+] stage2.bin : {len(result['stage2_plain'])} bytes")
    print(f"[+] keys.json  : {out / 'keys.json'}")
    print(f"[+] strings.txt: {out / 'strings.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
