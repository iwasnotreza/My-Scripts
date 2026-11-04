#!/usr/bin/env python3
"""Static stage-2 decoder for the H4X loader container.

Everything here is *offline*: it reads `h4x/out/stage2.bin` (produced by
`decode_loader.py`) plus the recovered key material in `h4x/out/keys.json`,
and reconstructs the VM prototype records.  No Roblox / executor code is run.

Pipeline
--------
1.  container  : 3 global strings + 81 prototype records (biased varints)
2.  key chain  : D3 = HMAC(k2, DS_KDF || iPq)          (prototypes 1..17)
                 JO = HMAC(D3, DS_KDF || nf)
                 JO = HMAC(CBfl, DS_KDF || nf)         (prototype 18, user key)
                 JO = HMAC(parent, DS_KDF || route||nf)(prototypes 19..81)
3.  record     : ChaCha20 + HMAC, then `Ge` (raw or range-coded) body
4.  body       : `bu` sections -> instructions / constants / upvalues / lines
5.  constants  : additive stream cipher + mod-65535 checksum
"""
from __future__ import annotations

import hashlib
import hmac
import json
import struct
from pathlib import Path

import decode_loader as dl

# 16-byte domain separator used by the loader's KDF helper (`I5k1`).
DS_KDF = bytes([0xA8, 0x3F, 0x9B, 0x02, 0x10, 0x57, 0x0A, 0x80,
                0x67, 0xC6, 0xA7, 0xCA, 0x93, 0x71, 0x5F, 0xF3])
DS_ROUTE = b"prototype-route-v1"
DS_STATE = b"prototype-state-v1"
DS_RECORD = b"prototype-record-v1"

# Recovered by statically replaying the embedded fingerprint VM (see README).
IPQ_HEX = "43900655d6c42a8da8616980129a523f831b5f160910022529ccb6d08df23b5b"

# 32-byte environment fingerprint produced by stage-2 prototypes 1..17.
# sha256(GATE_HEX) == the `FHMt` constant embedded in stage 1.
GATE_HEX = "2b6c0d85afa5838a7a5530a57895df4b1c4786c66658590ceea2d69d9f384068"
FHMt = bytes([167, 55, 147, 218, 76, 20, 209, 152, 112, 108, 244, 15, 52, 190,
              208, 38, 101, 97, 66, 226, 34, 182, 100, 79, 101, 8, 254, 68,
              137, 157, 131, 216])

M32 = 0xFFFFFFFF


def kdf(key: bytes, msg: bytes) -> bytes:
    """`I5k1` - HMAC-SHA256 with a fixed 16-byte message prefix."""
    return dl.H(key, DS_KDF + msg)


# ---------------------------------------------------------------------------
# varint readers
# ---------------------------------------------------------------------------
class Reader:
    """Bias-16 base-128 varints, as used by the stage-2 container."""

    bias = 16

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def byte(self) -> int:
        v = self.data[self.pos]
        self.pos += 1
        return v

    def uint(self) -> int:
        val, shift = 0, 1
        while True:
            v = self.byte()
            val += ((v & 0x7F) - self.bias) % 128 * shift
            if v < 128:
                return val
            shift *= 128

    def sint(self) -> int:
        x = self.uint()
        return x // 2 if x % 2 == 0 else -((x + 1) // 2)

    def raw(self, n: int) -> bytes:
        v = self.data[self.pos:self.pos + n]
        if len(v) != n:
            raise ValueError("truncated read")
        self.pos += n
        return v

    def eof(self) -> bool:
        return self.pos >= len(self.data)


# ---------------------------------------------------------------------------
# additive string/number cipher
# ---------------------------------------------------------------------------
def stream_xor(data: bytes, seed: int, state: int = 0) -> bytes:
    return bytes((b - (seed + i * 29 + ((i % 7) + 1) * 11 + state)) % 256
                 for i, b in enumerate(data, 1))


def checksum(data: bytes, seed: int, tag: int, base: int, extra: int) -> int:
    acc = (seed + tag * 131 + base + extra) % 65535
    for i, b in enumerate(data, 1):
        acc = (acc + b * i) % 65535
    return acc


def decrypt_blob(data: bytes, seed: int, chk: int, tag: int, base: int,
                 extra: int, state: int = 0) -> bytes:
    if checksum(data, seed, tag, base, extra) != chk:
        raise ValueError(f"constant checksum mismatch (tag {tag})")
    return stream_xor(data, seed, state)


# ---------------------------------------------------------------------------
# container
# ---------------------------------------------------------------------------
HEADER_FIELDS = ("TwT", "vnY", "_EV", "pu", "atmo", "lH", "cgjl", "TP",
                 "jsuZ", "Gr", "BM4")


def parse_container(data: bytes):
    r = Reader(data)
    n = r.uint()
    globals_ = []
    for _ in range(n):
        ln, seed, chk = r.uint(), r.uint(), r.uint()
        enc = r.raw(ln)
        plain = decrypt_blob(enc, seed, chk, 71, 81, 17)
        globals_.append(plain.decode("utf-8", "replace"))

    count = r.uint()
    records = []
    for idx in range(1, count + 1):
        hdr = {name: r.uint() for name in HEADER_FIELDS}
        pairs = [(r.uint(), r.uint()) for _ in range(hdr["BM4"])]
        blob = r.raw(hdr["TP"])
        nf = DS_RECORD + struct.pack(
            "<11I", idx, hdr["TwT"], hdr["Gr"], hdr["pu"], hdr["jsuZ"],
            hdr["vnY"], hdr["_EV"], hdr["lH"], hdr["cgjl"], hdr["atmo"],
            hdr["BM4"])
        for x, y in pairs:
            nf += struct.pack("<II", x, y)
        records.append({"idx": idx, "hdr": hdr, "pairs": pairs,
                        "blob": blob, "nf": nf})
    if r.pos != len(data):
        raise ValueError(f"container trailing bytes: {r.pos} != {len(data)}")
    return globals_, records


# ---------------------------------------------------------------------------
# `Ge` - record body (raw or range coded)
# ---------------------------------------------------------------------------
def build_permutation(key: bytes) -> list[int]:
    x = 2166136261
    for b in key[:32]:
        x = ((x * 33) & M32) ^ b
    if x == 0:
        x = 1
    perm = list(range(256))
    for i in range(256, 1, -1):
        x ^= (x << 13) & M32
        x ^= x >> 17
        x ^= (x << 5) & M32
        x &= M32
        j = x % i
        perm[i - 1], perm[j] = perm[j], perm[i - 1]
    return perm


def range_decode(data: bytes, freq: list[int], key: bytes, out_len: int) -> bytes:
    cum, inv = [], [0] * 4096
    total = 0
    for sym, f in enumerate(freq):
        cum.append(total)
        for v in range(total, total + f):
            inv[v] = sym
        total += f
    if total != 4096:
        raise ValueError("frequency table does not sum to 4096")
    perm = build_permutation(key)
    pos = 4
    code = int.from_bytes(data[:4], "little")
    if code < 8388608:
        raise ValueError("bad initial range code")

    def nxt() -> int:
        nonlocal pos
        b = data[pos]
        pos += 1
        return b

    out = bytearray()
    for _ in range(out_len):
        v = code % 4096
        sym = inv[v]
        code = freq[sym] * (code // 4096) + v - cum[sym]
        while code < 8388608:
            code = code * 256 + nxt()
        out.append(perm[sym])
    if code != 8388608 or pos != len(data):
        raise ValueError(f"range coder final state mismatch ({code}, {pos}/{len(data)})")
    return bytes(out)


def ge_body(plain: bytes, key: bytes, nf: bytes, out_len: int, ds: dict):
    """Decrypt a prototype record and return (body, rUe, mode)."""
    dec = dl.decrypt_record(plain, key, ds)
    if not dec.startswith(nf):
        raise ValueError("nf prefix mismatch")
    pos = len(nf)
    r_ue = int.from_bytes(dec[pos:pos + 4], "little")
    pos += 4
    if not 1 <= r_ue < 65521:
        raise ValueError("bad rUe")
    mode = dec[pos]
    pos += 1
    if mode == 0:
        body = dec[pos:pos + out_len]
        if len(body) != out_len or pos + out_len != len(dec):
            raise ValueError("raw body length mismatch")
    elif mode == 1:
        freq = []
        for _ in range(256):
            val, shift = 0, 1
            while True:
                b = dec[pos]
                pos += 1
                val += (b % 128) * shift
                if b < 128:
                    break
                shift *= 128
            if not 1 <= val <= 4096:
                raise ValueError("bad frequency entry")
            freq.append(val)
        body = range_decode(dec[pos:], freq, key, out_len)
    else:
        raise ValueError(f"unknown Ge mode {mode}")
    return body, r_ue, mode


# ---------------------------------------------------------------------------
# `bu` - prototype body
# ---------------------------------------------------------------------------
# 52 = upvalue descriptors (kind, index); 128 = local-variable debug info
SECTIONS = {62: "numparams", 130: "code", 52: "upvalues", 45: "vararg",
            132: "constants", 128: "localinfo", 114: "viz"}
OPMASK = {126: 0, 129: 1, 117: 2, 133: 3, 124: 4, 83: 5, 127: 6, 84: 7}


def parse_bu(body: bytes, lH: int, cgjl: int):
    r = Reader(body)
    out = {"instructions": [], "A": [], "B": [], "C": [], "constants": [],
           "upvalues": [], "localinfo": [], "numparams": 0, "vararg": False,
           "viz": 0, "sections": []}
    seen = set()
    for _ in range(7):
        tag = r.uint()
        if tag in seen:
            raise ValueError(f"duplicate section {tag}")
        seen.add(tag)
        out["sections"].append(tag)
        if tag == 62:
            out["numparams"] = r.uint()
        elif tag == 130:
            if r.uint() != 0x269F15E7:
                raise ValueError("bad code magic")
            count = r.uint()
            for _ in range(count):
                mask = OPMASK[r.uint()]
                out["instructions"].append(r.uint())
                out["A"].append(r.sint() if mask & 1 else 0)
                out["B"].append(r.sint() if mask & 2 else 0)
                out["C"].append(r.sint() if mask & 4 else 0)
        elif tag == 52:
            out["upvalues"] = [(r.uint(), r.uint()) for _ in range(r.uint())]
        elif tag == 45:
            out["vararg"] = r.uint() != 0
        elif tag == 132:
            n = r.uint()
            for _ in range(n):
                out["constants"].append(parse_const(r))
            out["const_count"] = n
        elif tag == 128:
            n = r.uint()
            a = b = 0
            for _ in range(n):
                a += r.uint()
                b += r.sint()
                out["localinfo"].append((a, b))
        elif tag == 114:
            out["viz"] = r.uint()
        else:
            raise ValueError(f"unknown section {tag}")
    if not r.eof():
        raise ValueError("body trailing bytes")
    # opcode unmasking performed by `bu`
    out["opcodes_raw"] = [((v - cgjl) * lH) % 256 for v in out["instructions"]]
    return out


def parse_const(r: Reader):
    tag = r.uint()
    if tag == 53:
        return {"tag": 53, "value": None}
    if tag == 17:
        return {"tag": 17, "index": r.uint()}
    if tag in (47, 31):
        ln, n = r.uint(), r.uint()
        chunks = []
        for _ in range(n):
            order, seed, size, chk = r.uint(), r.uint(), r.uint(), r.uint()
            chunks.append({"order": order, "seed": seed, "size": size,
                           "chk": chk, "data": r.raw(size)})
        return {"tag": 47, "len": ln, "chunks": chunks, "number": False,
                "no_cache": tag == 31}
    if tag in (71, 43):
        ln, seed, chk = r.uint(), r.uint(), r.uint()
        return {"tag": 71, "len": ln, "seed": seed, "chk": chk,
                "data": r.raw(ln), "number": False, "no_cache": tag == 43}
    if tag == 23:
        ln, n = r.uint(), r.uint()
        chunks = []
        for _ in range(n):
            order, seed, size, chk = r.uint(), r.uint(), r.uint(), r.uint()
            chunks.append({"order": order, "seed": seed, "size": size,
                           "chk": chk, "data": r.raw(size)})
        return {"tag": 23, "len": ln, "chunks": chunks, "number": True}
    if tag == 29:
        seed, chk = r.uint(), r.uint()
        return {"tag": 29, "len": 8, "seed": seed, "chk": chk,
                "data": r.raw(8), "number": True}
    if tag == 41:
        return {"tag": 41, "value": False}
    return {"tag": tag, "value": True}


def resolve_const(c, globals_, state: int = 0):
    tag = c["tag"]
    if tag in (53, 41):
        return c["value"]
    if tag == 17:
        return globals_[c["index"] - 1]
    if "value" in c and tag not in (71, 29, 47, 23):
        return c["value"]
    if tag in (71, 29):
        base = 81 if tag == 71 else 115
        plain = decrypt_blob(c["data"], c["seed"], c["chk"], tag, base, 17, state)
    else:
        base = 81 if tag == 47 else 115
        parts = {}
        for ch in c["chunks"]:
            parts[ch["order"]] = decrypt_blob(
                ch["data"], ch["seed"], ch["chk"], tag, base,
                ch["order"] * 17, state)
        plain = b"".join(parts[k] for k in sorted(parts))
    if len(plain) != c["len"]:
        raise ValueError("constant length mismatch")
    if c.get("number"):
        return struct.unpack("<d", plain)[0]
    return plain.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# instruction stream de-obfuscation (rolling Adler-like mask)
# ---------------------------------------------------------------------------
def instruction_masks(proto: dict, r_ue: int, proto_index: int, state: int = 0):
    code = proto["opcodes_raw"]
    n = len(code)
    seed = r_ue if 1 <= r_ue < 65521 else (proto_index * 3887) % 65521
    masks = [0] * n
    for start in range(0, n, 8):
        acc = (seed + (start + 1) * 3887) % 65521
        end = min(start + 7, n - 1)
        for i in range(start, end + 1):
            masks[i] = (acc + state) % 65521
            if i < end:
                acc = (acc * 21 + (i + 2) * 3887
                       + (code[i] % 65521) * 23
                       + (proto["A"][i] % 65521) * 8
                       + (proto["B"][i] % 65521) * 23
                       + (proto["C"][i] % 65521) * 23) % 65521
    ops, As, Bs, Cs = [], [], [], []
    for i in range(n):
        h, raw = masks[i], code[i]
        ops.append((raw - h) % 256)
        As.append(proto["A"][i] - 218 - h * 19 - raw * 13)
        Bs.append(proto["B"][i] - 141 - h * 11 - raw * 24)
        Cs.append(proto["C"][i] - 95 - h * 25 - raw * 20)
    return ops, As, Bs, Cs


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------
def load_keys(repo: Path):
    keys = json.loads((repo / "h4x/out/keys.json").read_text())
    return {k[:-4]: bytes.fromhex(v) for k, v in keys.items() if k.endswith("_hex")}


def decode_all(verbose: bool = True):
    repo = Path(__file__).resolve().parent.parent
    keys = load_keys(repo)
    ds = dl.parse_domain_separators(
        (repo / "h4x/raw_loader.lua").read_text(errors="replace"))
    data = (repo / "h4x/out/stage2.bin").read_bytes()
    globals_, records = parse_container(data)

    ipq = bytes.fromhex(IPQ_HEX)
    gate = bytes.fromhex(GATE_HEX)
    assert hashlib.sha256(gate).digest() == FHMt, "gate fingerprint mismatch"
    d3 = kdf(keys["stage1_key2"], ipq)
    cbfl = kdf(d3, gate)
    if verbose:
        print(f"globals   : {globals_}")
        print(f"records   : {len(records)}")
        print(f"D3        : {d3.hex()}")
        print(f"CBfl      : {cbfl.hex()}")

    protos = {}
    pending = {}
    for rec in records:
        idx = rec["idx"]
        if idx <= 17:
            pending[idx] = (kdf(d3, rec["nf"]), None)
        elif idx == 18:
            pending[idx] = (kdf(cbfl, rec["nf"]), None)

    done = 0
    while pending:
        idx, (jo, parent) = pending.popitem()
        rec = records[idx - 1]
        hdr = rec["hdr"]
        body, r_ue, mode = ge_body(rec["blob"], jo, rec["nf"], hdr["Gr"], ds)
        proto = parse_bu(body, hdr["lH"], hdr["cgjl"])
        ops, As, Bs, Cs = instruction_masks(proto, r_ue, idx)
        consts = [resolve_const(c, globals_) for c in proto["constants"]]
        entry = {"idx": idx, "hdr": hdr, "mode": mode, "rUe": r_ue,
                 "key": jo.hex(), "parent": parent, "constants": consts,
                 "opcodes": ops, "A": As, "B": Bs, "C": Cs,
                 "upvalues": proto["upvalues"], "numparams": proto["numparams"],
                 "vararg": proto["vararg"], "viz": proto["viz"],
                 "localinfo": proto["localinfo"]}
        protos[idx] = entry
        done += 1
        # CLOSURE instructions register the route that unlocks each child
        for pc, op in enumerate(ops):
            if op != 17:
                continue
            child = Bs[pc] + 1
            if child in protos or child in pending or child > len(records):
                continue
            route = struct.pack("<6I", idx, child, pc + 1, As[pc], Bs[pc], Cs[pc])
            ckey = kdf(jo, DS_ROUTE + route + records[child - 1]["nf"])
            pending[child] = (ckey, idx)
        if verbose:
            print(f"proto {idx:2d}: {len(ops):4d} instrs, {len(consts):3d} consts, "
                  f"mode {mode}, parent {parent}")
    if verbose:
        print(f"decoded {done}/{len(records)} prototypes")
    return globals_, protos, {"D3": d3.hex(), "CBfl": cbfl.hex(),
                              "iPq": IPQ_HEX, "gate": GATE_HEX}


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    globals_, protos, keyinfo = decode_all()
    outdir = repo / "h4x/out/prototypes"
    outdir.mkdir(parents=True, exist_ok=True)
    for idx, entry in sorted(protos.items()):
        (outdir / f"proto{idx:02d}.json").write_text(json.dumps(entry, indent=1))
    (repo / "h4x/out/stage2_keys.json").write_text(json.dumps(keyinfo, indent=1))
    missing = sorted(set(range(1, 82)) - set(protos))
    if missing:
        print("not reachable:", missing)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
