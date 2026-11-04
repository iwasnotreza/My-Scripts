#!/usr/bin/env python3
"""
Static decoder for the H4xScripts loader wrapper observed at:
    https://h4xscripts.xyz/loader

This version parses the wrapper constants from the supplied raw Lua instead of
relying on a single hardcoded sample. It DOES NOT execute Lua. It only parses,
decrypts and decompresses the container.

Usage:
    python3 h4x/decode_loader.py h4x/raw_loader.lua -o h4x/out

Outputs:
    h4x/out/stage1.lua      decompressed first Lua stage
    h4x/out/stage2.bin      decrypted second stage (may be Lua or VM bytecode)
    h4x/out/keys.json       derived keys / fingerprints / parsed parameters
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
# Static wrapper parsing
# ---------------------------------------------------------------------------

def parse_root_key(source: str) -> bytes:
    """Parse the 8-word bit32 key schedule and final little-endian packing."""
    init = re.search(
        r'local\s+([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*){7})'
        r'\s*=\s*(\d+(?:\s*,\s*\d+){7})\s+local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*false',
        source,
    )
    if not init:
        raise ValueError("could not locate root-key initial state")

    names = [x.strip() for x in init.group(1).split(",")]
    state = {name: int(value) for name, value in zip(names, init.group(2).split(","))}

    final = re.search(
        r'local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{'
        r'(bit32\.bxor\([A-Za-z_][A-Za-z0-9_]*,\d+\)'
        r'(?:\s*,\s*bit32\.bxor\([A-Za-z_][A-Za-z0-9_]*,\d+\)){7})\}',
        source[init.end():],
    )
    if not final:
        raise ValueError("could not locate root-key final XOR table")

    segment = source[init.end():init.end() + final.start()]
    updates = re.finditer(
        r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*bit32\.lrotate\(\(bit32\.bxor\(\1,(\d+)\)\+(\d+)\)%4294967296,(\d+)\)',
        segment,
    )
    count = 0
    for m in updates:
        var, x, a, r = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
        state[var] = lrotate((bxor(state[var], x) + a) & MASK32, r)
        count += 1
    if count != 24:
        raise ValueError(f"expected 24 root-key updates, parsed {count}")

    words = []
    for m in re.finditer(r'bit32\.bxor\(([A-Za-z_][A-Za-z0-9_]*),(\d+)\)', final.group(1)):
        words.append(bxor(state[m.group(1)], int(m.group(2))))
    if len(words) != 8:
        raise ValueError("root-key final table did not contain 8 words")
    return b"".join(struct.pack("<I", w) for w in words)


def parse_domain_separators(source: str) -> dict[str, bytes]:
    """Extract the five 16-byte Lua decimal-escape domain separators."""
    escapes = re.findall(r'"((?:\\\d{3}){16})"', source)
    if len(escapes) < 5:
        raise ValueError("could not locate five 16-byte domain separators")
    ds = [bytes(int(x) for x in re.findall(r'\\(\d{3})', e)) for e in escapes[:5]]
    return {
        "enc": ds[0],
        "mac": ds[1],
        "tag": ds[2],
        "stage1_key": ds[3],
        "stage2_key": ds[4],
    }


def parse_record_params(source: str) -> dict:
    m = re.search(
        r'for\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*1,(\d+)\s+do\s+'
        r'local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[A-Za-z_][A-Za-z0-9_]*\(\)\s*'
        r'local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[A-Za-z_][A-Za-z0-9_]*\(\)\s*'
        r'local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[A-Za-z_][A-Za-z0-9_]*\(\)\s*'
        r'local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[A-Za-z_][A-Za-z0-9_]*\s*==\s*(\d+)\s+and\s+1\s+or\s+'
        r'[A-Za-z_][A-Za-z0-9_]*\s*==\s*(\d+)\s+and\s+2',
        source,
    )
    if not m:
        raise ValueError("could not locate record loop/tag constants")
    record_count, tag1, tag2 = int(m.group(1)), int(m.group(2)), int(m.group(3))

    mx = re.search(r'\([A-Za-z_][A-Za-z0-9_]*==1\s+and\s+(\d+)\s+or\s+(\d+)\)', source)
    if not mx:
        raise ValueError("could not locate per-stage max record index")
    max1, max2 = int(mx.group(1)), int(mx.group(2))

    totals = re.search(
        r'\[1\]\s*~=\s*(\d+)\s+or\s+[A-Za-z_][A-Za-z0-9_]*\[2\]\s*~=\s*(\d+)\s+or\s+'
        r'[A-Za-z_][A-Za-z0-9_]*\[1\]\s*~=\s*(\d+)\s+or\s+[A-Za-z_][A-Za-z0-9_]*\[2\]\s*~=\s*(\d+)',
        source,
    )
    if not totals:
        raise ValueError("could not locate record count/total checks")
    count1, count2, total1, total2 = map(int, totals.groups())

    return {
        "record_count": record_count,
        "tag1": tag1,
        "tag2": tag2,
        "max1": max1,
        "max2": max2,
        "count1": count1,
        "count2": count2,
        "total1": total1,
        "total2": total2,
    }


def parse_freq_table(source: str) -> list[int]:
    for table in re.findall(r'\{(\d+(?:,\d+)*)\}', source):
        nums = [int(x) for x in table.split(",")]
        if len(nums) == 256 and sum(nums) == 4096:
            return nums
    raise ValueError("could not locate 256-entry frequency table summing to 4096")


def parse_stage1_len(source: str) -> int:
    m = re.search(r'if\s+[A-Za-z_][A-Za-z0-9_]*\s*==\s*(\d+)\s+then\s+if\s+[A-Za-z_][A-Za-z0-9_]*\s*~=\s*8388608', source)
    if m:
        return int(m.group(1))
    m = re.search(r'for\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*1,(\d+)-7,8', source)
    if m:
        return int(m.group(1))
    raise ValueError("could not locate stage1 output length")


def parse_wrapper(source: str) -> dict:
    return {
        "root_key": parse_root_key(source),
        "ds": parse_domain_separators(source),
        "records": parse_record_params(source),
        "freq": parse_freq_table(source),
        "stage1_len": parse_stage1_len(source),
    }


# ---------------------------------------------------------------------------
# HMAC / ChaCha20
# ---------------------------------------------------------------------------

def H(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


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


def decrypt_record(blob: bytes, root_key: bytes, ds: dict[str, bytes]) -> bytes:
    if len(blob) < 44:
        raise ValueError("record too short")
    nonce = blob[:12]
    authenticated = blob[:-32]  # nonce || ciphertext
    ciphertext = blob[12:-32]
    tag = blob[-32:]

    enc_key = H(root_key, ds["enc"] + nonce)
    mac_key = H(root_key, ds["mac"] + nonce)
    expect = H(mac_key, ds["tag"] + authenticated)
    if not hmac.compare_digest(expect, tag):
        raise ValueError("HMAC tag mismatch")

    return chacha20_xor(enc_key, nonce, ciphertext, initial_counter=1)


# ---------------------------------------------------------------------------
# Custom base64 container
# ---------------------------------------------------------------------------

def extract_container(source: str) -> tuple[str, str]:
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


def unpack_records(data: bytes, p: dict) -> tuple[bytes, bytes]:
    r = BitReader(data)
    stages = {1: {}, 2: {}}
    counts = {1: 0, 2: 0}
    totals = {1: 0, 2: 0}

    for _ in range(p["record_count"]):
        idx = r.varint()
        tag = r.varint()
        length = r.varint()
        stage = 1 if tag == p["tag1"] else 2 if tag == p["tag2"] else 0
        if stage == 0:
            raise ValueError(f"bad record tag {tag}")
        max_idx = p["max1"] if stage == 1 else p["max2"]
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
    if counts[1] != p["count1"] or counts[2] != p["count2"]:
        raise ValueError(f"bad record counts: {counts}")
    if totals[1] != p["total1"] or totals[2] != p["total2"]:
        raise ValueError(f"bad record totals: {totals}")

    s1 = b"".join(stages[1][i] for i in range(1, p["count1"] + 1))
    s2 = b"".join(stages[2][i] for i in range(1, p["count2"] + 1))
    return s1, s2


# ---------------------------------------------------------------------------
# Stage1 range coder
# ---------------------------------------------------------------------------

def build_range_tables(freq: list[int]):
    if len(freq) != 256 or sum(freq) != 4096:
        raise ValueError("frequency table is not 256 entries summing to 4096")
    cum = [0] * 256
    inv = [0] * 4096
    total = 0
    for i, f in enumerate(freq):
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


def range_decompress(data: bytes, root_key: bytes, freq: list[int], out_len: int) -> bytes:
    cum, inv = build_range_tables(freq)
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
        code = freq[sym] * (code // 4096) + v - cum[sym]
        while code < 8388608:
            code = code * 256 + next_byte()
        out.append(perm[sym])

    if code != 8388608 or pos != len(data):
        raise ValueError(f"range coder final state mismatch: code={code}, pos={pos}/{len(data)}")
    return bytes(out)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def decode(source: str) -> dict:
    cfg = parse_wrapper(source)
    payload, alphabet = extract_container(source)
    container = b64_to_bytes(payload, alphabet)
    rec1, rec2 = unpack_records(container, cfg["records"])

    root_key = cfg["root_key"]
    ds = cfg["ds"]
    stage1_plain = decrypt_record(rec1, root_key, ds)
    if len(stage1_plain) < 33:
        raise ValueError("stage1 too short")

    stage1_key = stage1_plain[:32]
    stage1_compressed = stage1_plain[32:]
    stage1_lua = range_decompress(stage1_compressed, root_key, cfg["freq"], cfg["stage1_len"])

    stage1_key2 = H(root_key, ds["stage1_key"] + stage1_key)[:32]
    stage2_key = H(stage1_key2, ds["stage2_key"] + stage1_key + hashlib.sha256(stage1_lua).digest())[:32]
    stage2_plain = decrypt_record(rec2, stage2_key, ds)

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
        "params": {
            "records": cfg["records"],
            "stage1_len": cfg["stage1_len"],
            "freq_sum": sum(cfg["freq"]),
            "ds_hex": {k: v.hex() for k, v in ds.items()},
        },
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
        "params": result["params"],
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
