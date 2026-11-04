#!/usr/bin/env python3
"""Disassembler for the H4X stage-2 register VM.

Usage:  python3 disasm.py [proto-number ...]
Reads the JSON produced by decode_stage2.py and prints annotated listings.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# opcode -> (mnemonic, operand layout)
OPS = {
    2: ("NEWTABLE+LOADK", "A ; next: R[nA] = K[nB]"),
    17: ("CLOSURE", "A = closure(proto[B+1])"),
    24: ("SETTABLE_K", "R[A][K[B]] = R[C]"),
    31: ("GETTABLE", "R[A] = R[B][RK(C)]"),
    41: ("MOVE+LOADK", "R[A] = R[B] ; next: R[nA] = K[nB]"),
    43: ("SUB_JMP", "R[A] -= R[A+2] ; pc += B"),
    47: ("LT_K", "if (K[B] < R[C]) != (A!=0) then skip else jump"),
    48: ("LOADBOOL", "R[A] = (B != 0)"),
    49: ("SELF", "R[A+1] = R[B]; R[A] = R[B][K[C]]"),
    50: ("LEN", "R[A] = #R[B]"),
    57: ("TEST", "if bool(R[A]) != (C!=0) then skip else jump"),
    59: ("SETTABLE", "R[A][R[B]] = R[C]"),
    71: ("SETLIST", "R[A][C..] = R[A+1..A+B]"),
    85: ("CLOSE", "close upvalues >= R[A]"),
    87: ("EQ", "if (R[B] == R[C]) != (A!=0) then skip else jump"),
    88: ("MUL", "R[A] = RK(B) * RK(C)"),
    89: ("TFORCALL", "iterator call"),
    91: ("ADD", "R[A] = RK(B) + RK(C)"),
    93: ("RETURN", "return R[A .. A+B-2]"),
    94: ("MOD", "R[A] = R[B] % K[C]"),
    102: ("GETGLOBAL", "R[A] = _ENV[K[B]]"),
    107: ("CLEAR", "R[A..B] = nil"),
    126: ("LOADK+MOVE", "R[A] = K[B] ; next: R[nA] = R[nB]"),
    127: ("LOADK", "R[A] = K[B]"),
    130: ("CALL", "R[A](R[A+1 .. A+B-1]) -> C-1 results"),
    147: ("FORPREP", "numeric for preparation"),
    151: ("LT_K2", "if (R[B] < K[C]) != (A!=0) then skip else jump"),
    155: ("GETGLOBAL+MOVE", "R[A] = _ENV[K[B]] ; next: R[nA] = R[nB]"),
    183: ("GETUPVAL+LOADK", "R[A] = U[B] ; next: R[nA] = K[nB]"),
    189: ("MOVE", "R[A] = R[B]"),
    212: ("NEWTABLE", "R[A] = {}"),
    214: ("EQ_K", "if (R[B] == K[C]) != (A!=0) then skip else jump"),
    216: ("VARARG", "R[A..] = ..."),
    225: ("TAILCALL", "return R[A](...)"),
    242: ("FORLOOP", "numeric for loop back-edge"),
    246: ("JMP", "pc += B"),
    254: ("MOVE+MOVE", "R[A] = R[B] ; next: R[nA] = R[nB]"),
}


def fmt_const(v):
    if isinstance(v, str):
        return repr(v)
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return repr(v)


def disasm(proto, out=None):
    out = out or sys.stdout
    K = proto["constants"]
    ops, A, B, C = proto["opcodes"], proto["A"], proto["B"], proto["C"]
    hdr = proto["hdr"]
    print(f"-- prototype {proto['idx']}: {len(ops)} instructions, "
          f"{len(K)} constants, {proto['numparams']} params, "
          f"vararg={proto['vararg']}, upvalues={proto['upvalues']}", file=out)
    for i, k in enumerate(K):
        print(f"--   K{i} = {fmt_const(k)}", file=out)

    def rk(x):
        return f"K{x - 490}({fmt_const(K[x - 490])})" if x >= 490 else f"R{x}"

    i = 0
    while i < len(ops):
        op, a, b, c = ops[i], A[i], B[i], C[i]
        name, layout = OPS.get(op, (f"OP{op}", "?"))
        extra = ""
        if op in (127, 126, 2, 41, 183):
            extra = f"  ; K{b} = {fmt_const(K[b])}" if b < len(K) else ""
        elif op in (102, 155):
            extra = f"  ; _ENV[{fmt_const(K[b])}]" if b < len(K) else ""
        elif op in (24, 49, 94, 214, 151, 47):
            idx = b if op in (24, 49, 47) else c
            if 0 <= idx < len(K):
                extra = f"  ; K{idx} = {fmt_const(K[idx])}"
        elif op == 17:
            extra = f"  ; proto {b + 1}, route magic {c}"
        elif op in (31, 88, 91):
            extra = f"  ; {rk(b)} , {rk(c)}"
        print(f"{i + 1:4d}  {name:<16} A={a:<4} B={b:<4} C={c:<10}{extra}",
              file=out)
        if op in (2, 41, 126, 155, 183, 254) and i + 1 < len(ops):
            na, nb = A[i + 1], B[i + 1]
            nk = f" = K{nb}({fmt_const(K[nb])})" if op in (2, 41, 183) and nb < len(K) else f" = R{nb}"
            print(f"      +fused           R{na}{nk}", file=out)
            i += 1
        i += 1


def main() -> int:
    here = Path(__file__).resolve().parent / "out/prototypes"
    files = sorted(here.glob("proto*.json"))
    want = {int(x) for x in sys.argv[1:]}
    for f in files:
        p = json.loads(f.read_text())
        if want and p["idx"] not in want:
            continue
        disasm(p)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
