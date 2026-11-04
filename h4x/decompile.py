#!/usr/bin/env python3
"""Reconstruct readable Lua from the decoded H4X stage-2 VM prototypes.

The output is a *reconstruction*: control flow, constants, globals, method
calls and nested closures are recovered exactly, while local variable names
(the bytecode carries no debug names) are regenerated as a1/v3/u2/r7.

Usage:
    python3 decompile.py            # write h4x/out/loader_deobfuscated.lua
    python3 decompile.py 18 29      # print selected prototypes
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

FUSED = {2, 33, 41, 126, 155, 183, 204, 224, 254}
COND = {47, 57, 80, 87, 151, 214}
JMP = 246


def q(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"'


def lit(v):
    if v is None:
        return "nil"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return q(v)
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return repr(v)


class Node:
    __slots__ = ("pc", "nxt", "op", "a", "b", "c", "op2", "a2", "b2", "c2")

    def __init__(self, pc, nxt, op, a, b, c, op2=None, a2=0, b2=0, c2=0):
        self.pc, self.nxt = pc, nxt
        self.op, self.a, self.b, self.c = op, a, b, c
        self.op2, self.a2, self.b2, self.c2 = op2, a2, b2, c2


class Decompiler:
    def __init__(self, protos):
        self.protos = protos
        self.out = []
        self.counter = 0
        self.done = set()

    # ------------------------------------------------------------------
    def build_nodes(self, p):
        ops, A, B, C = p["opcodes"], p["A"], p["B"], p["C"]
        nodes, by_pc = [], {}
        i = 0
        while i < len(ops):
            if ops[i] in FUSED and i + 1 < len(ops):
                n = Node(i, i + 2, ops[i], A[i], B[i], C[i],
                         ops[i + 1], A[i + 1], B[i + 1], C[i + 1])
            elif ops[i] in COND and i + 1 < len(ops):
                n = Node(i, i + 2, ops[i], A[i], B[i], C[i])
            else:
                n = Node(i, i + 1, ops[i], A[i], B[i], C[i])
            nodes.append(n)
            by_pc[n.pc] = n
            i = n.nxt
        return nodes, by_pc

    # ------------------------------------------------------------------
    def decompile(self, idx, upnames=None, indent=0, name=None):
        p = self.protos[idx]
        nodes, by_pc = self.build_nodes(p)
        K = p["constants"]
        ctx = {
            "proto": p, "K": K, "nodes": nodes, "by_pc": by_pc,
            "upnames": upnames or [f"u{i}" for i in range(len(p["upvalues"]))],
            "params": [f"a{i + 1}" for i in range(p["numparams"])],
            "vararg": p["vararg"], "names": {}, "lines": [],
            "B": p["B"], "nilset": set(),
        }
        for i in range(p["numparams"]):
            ctx["names"][i] = ctx["params"][i]
        for i, uv in enumerate(p["upvalues"]):
            ctx["names"][f"U{i}"] = ctx["upnames"][i]
        body = self.emit(ctx, 0, len(p["opcodes"]), indent + 1)
        locals_ = sorted({v for k, v in ctx["names"].items()
                          if isinstance(k, int) and v.startswith("v")},
                         key=lambda t: int(t[1:]))
        if locals_:
            pad = "  " * (indent + 1)
            decl = []
            for k in range(0, len(locals_), 8):
                decl.append(pad + "local " + ", ".join(locals_[k:k + 8]))
            body = decl + body
        params = ctx["params"] + (["..."] if p["vararg"] else [])
        header = f"function({', '.join(params)})"
        if name:
            header = f"local function {name}({', '.join(params)})"
        lines = ["  " * indent + header] + body + ["  " * indent + "end"]
        return lines, ctx

    # ------------------------------------------------------------------
    def reg(self, ctx, n):
        if isinstance(n, str):
            return ctx["names"].get(n, n)
        if n in ctx["nilset"]:
            return "nil"
        if n in ctx["names"]:
            return ctx["names"][n]
        self.counter += 1
        nm = f"v{self.counter}"
        ctx["names"][n] = nm
        return nm

    def rk(self, ctx, x):
        return lit(ctx["K"][x - 490]) if x >= 490 else self.reg(ctx, x)

    def kv(self, ctx, x):
        return ctx["K"][x]

    # ------------------------------------------------------------------
    def emit(self, ctx, lo, hi, ind):
        """Emit Lua statements for the physical instruction range [lo, hi)."""
        out = []
        pad = "  " * ind
        nodes = [n for n in ctx["nodes"] if lo <= n.pc < hi]
        i = 0
        budget = 6 * len(nodes) + 64
        while i < len(nodes):
            budget -= 1
            if budget <= 0:
                out.append(f"{pad}-- [!] control-flow reconstruction stopped here")
                break
            n = nodes[i]
            op, a, b, c = n.op, n.a, n.b, n.c

            # ---- numeric for -------------------------------------
            if op == 43:                      # FORPREP (SUB + JMP)
                loop_pc = n.pc + 1 + b
                end_node = ctx["by_pc"].get(loop_pc)
                if end_node is not None and end_node.op == 242 and loop_pc <= n.nxt:
                    out.append(f"{pad}-- numeric-for back-edge to pc {loop_pc} "
                               f"(counter R{a + 3})")
                    i += 1
                    continue
                if end_node is not None and end_node.op == 242:
                    var = self.reg(ctx, a + 3)
                    init, limit, step = (self.reg(ctx, a), self.reg(ctx, a + 1),
                                         self.reg(ctx, a + 2))
                    body = self.emit(ctx, n.nxt, loop_pc, ind + 1)
                    out.append(f"{pad}for {var} = {init}, {limit}, {step} do")
                    out += body
                    out.append(f"{pad}end")
                    i = max(i + 1, self.skip_to(nodes, end_node.nxt))
                    continue

            # ---- generic for -------------------------------------
            if op == 147:                     # TFORPREP
                jmp = ctx["by_pc"].get(n.nxt)
                t = None
                if jmp is not None and jmp.op == JMP:
                    cand = ctx["by_pc"].get(jmp.pc + 1 + jmp.b)
                    if cand is not None and cand.op == 89:
                        t = cand
                normal = False
                if t is not None:
                    bs = t.pc + 1 + t.b
                    normal = (t.pc > n.pc and n.pc < bs < t.pc and
                              not any(m.op in (89, 147) and n.pc < m.pc < t.pc
                                      for m in ctx["nodes"]))
                if t is not None and not normal:
                    # rotated/interleaved loop layout: keep every instruction,
                    # mark the header instead of restructuring
                    out.append(f"{pad}-- generic-for header: iterator R{a}, "
                               f"body at pc {t.pc + 1 + t.b}, back-edge at pc {t.pc}")
                    i = max(i + 1, self.skip_to(nodes, jmp.nxt))
                    continue
                if t is not None:
                    body_start = t.pc + 1 + t.b
                    names = [self.reg(ctx, a + 3 + k) for k in range(t.c)]
                    parts = [self.reg(ctx, a)]
                    for extra in (a + 1, a + 2):
                        txt = self.reg(ctx, extra)
                        if txt not in ("nil", "0"):
                            parts.append(txt)
                    body = self.emit(ctx, body_start, t.pc, ind + 1)
                    out.append(f"{pad}for {', '.join(names)} in {', '.join(parts)} do")
                    out += body
                    out.append(f"{pad}end")
                    ctx.setdefault("tfor_done", set()).add(t.pc)
                    i = max(i + 1, self.skip_to(nodes, t.nxt))
                    continue

            if op == 89 and n.pc in ctx.get("tfor_done", set()):
                i += 1
                continue

            if op == 89:                      # TFORCALL (loop back-edge)
                body_start = n.pc + 1 + b
                out.append(f"{pad}-- generic-for: loop back to pc {body_start} "
                           f"(iterator R{a}, {c} vars)")
                i += 1
                continue

            # ---- conditional branch ------------------------------
            if op in COND:
                target = n.pc + 2 + ctx["B"][n.pc + 1]
                cond = self.cond_text(ctx, n)
                if target > n.pc:
                    # and/or value idiom: LOADBOOL true (skip) / LOADBOOL false
                    n1 = ctx["by_pc"].get(n.pc + 2)
                    n2 = ctx["by_pc"].get(target)
                    if (n1 is not None and n2 is not None
                            and n1.op == 48 and n1.c != 0 and n2.op == 48
                            and n1.a == n2.a and n1.nxt == target):
                        val = "true" if n1.b else "false"
                        txt = cond if val == "true" else f"not ({cond})"
                        out.append(f"{pad}{self.reg(ctx, n1.a)} = {txt}")
                        i = max(i + 1, self.skip_to(nodes, n2.nxt))
                        continue
                    then_lo = n.pc + 2
                    then_hi, join, ended = target, None, False
                    for m in nodes:
                        if not (then_lo <= m.pc < target):
                            continue
                        if m.op == 93:
                            then_hi, ended = m.nxt, True
                            break
                        if m.op == JMP and m.pc + 1 + m.b >= target:
                            then_hi, join = m.pc, m.pc + 1 + m.b
                            break
                    out.append(f"{pad}if {cond} then")
                    out += self.emit(ctx, then_lo, then_hi, ind + 1)
                    if join is not None and join > target and not ended:
                        out.append(f"{pad}else")
                        out += self.emit(ctx, target, join, ind + 1)
                        end = join
                    else:
                        end = target
                    out.append(f"{pad}end")
                    i = max(i + 1, self.skip_to(nodes, end))
                    continue
                out.append(f"{pad}while {cond} do")
                out += self.emit(ctx, n.pc + 2, hi, ind + 1)
                out.append(f"{pad}end")
                return out

            # ---- plain jump --------------------------------------
            if op == JMP:
                target = n.pc + 1 + b
                if target <= n.pc:
                    out.append(f"{pad}-- loop back to {target + 1}")
                else:
                    nxt = ctx["by_pc"].get(target)
                    if nxt is not None and nxt.op == 93 and nxt.b <= 1 and target < hi:
                        out.append(f"{pad}break")
                        i = max(i + 1, self.skip_to(nodes, target))
                        continue
                    out.append(f"{pad}-- goto L{target + 1}")
                i += 1
                continue

            # ---- everything else ---------------------------------
            stmts = self.simple(ctx, n, ind)
            out += [pad + s for s in stmts]
            i += 2 if (op == 48 and c != 0) else 1
        return out

    def skip_to(self, nodes, pc):
        for k, m in enumerate(nodes):
            if m.pc >= pc:
                return k
        return len(nodes)

    def cond_text(self, ctx, n):
        op, a, b, c = n.op, n.a, n.b, n.c
        if op == 57:
            expr, flag = self.reg(ctx, a), (c != 0)
            return expr if not flag else f"not {expr}"
        if op == 87:
            lhs, rhs, flag = self.reg(ctx, b), self.reg(ctx, c), (a != 0)
            return f"{lhs} {'~=' if flag else '=='} {rhs}"
        if op == 214:
            lhs, rhs, flag = self.reg(ctx, b), lit(self.kv(ctx, c)), (a != 0)
            return f"{lhs} {'~=' if flag else '=='} {rhs}"
        if op == 80:
            lhs, rhs, flag = self.reg(ctx, b), self.reg(ctx, c), (a != 0)
            return f"{lhs} {'>=' if flag else '<'} {rhs}"
        if op == 47:
            lhs, rhs, flag = lit(self.kv(ctx, b)), self.reg(ctx, c), (a != 0)
            return f"{lhs} {'>=' if flag else '<'} {rhs}"
        if op == 151:
            lhs, rhs, flag = self.reg(ctx, b), lit(self.kv(ctx, c)), (a != 0)
            return f"{lhs} {'>=' if flag else '<'} {rhs}"
        return "?"

    # ------------------------------------------------------------------
    def simple(self, ctx, n, ind):
        base = {2: 212, 33: 212, 41: 189, 254: 189, 126: 127,
                155: 102, 224: 102, 183: 187, 204: 187}
        op = base.get(n.op, n.op)
        a, b, c = n.a, n.b, n.c
        K = ctx["K"]
        R = lambda x: self.reg(ctx, x)
        RK = lambda x: self.rk(ctx, x)
        res = []

        def setr(x, expr):
            ctx["nilset"].discard(x)
            res.append(f"{R(x)} = {expr}")

        if op == 127:
            setr(a, lit(K[b]))
        elif op == 189:
            setr(a, R(b))
        elif op == 102:
            setr(a, K[b])
        elif op in (187,):
            setr(a, ctx["upnames"][b])
        elif op == 143:
            res.append(f"{ctx['upnames'][b]} = {R(a)}")
        elif op == 212:
            setr(a, "{}")
        elif op == 31:
            setr(a, f"{R(b)}{self.member(ctx, RK(c))}")
        elif op == 24:
            res.append(f"{R(a)}{self.member(ctx, lit(K[b]))} = {RK(c)}")
        elif op == 171:
            res.append(f"{R(a)}{self.member(ctx, lit(K[b]))} = {lit(K[c])}")
        elif op == 59:
            res.append(f"{R(a)}[{R(b)}] = {R(c)}")
        elif op == 49:
            ctx.setdefault("self", {})[a] = (R(b), K[c])
            ctx["nilset"].discard(a)
        elif op == 50:
            setr(a, f"#{R(b)}")
        elif op == 45:
            setr(a, f"not {R(b)}")
        elif op == 103:
            setr(a, f"-{R(b)}")
        elif op == 48:
            setr(a, "true" if b else "false")
        elif op == 91:
            setr(a, f"{RK(b)} + {RK(c)}")
        elif op == 34:
            setr(a, f"{RK(b)} - {RK(c)}")
        elif op == 88:
            setr(a, f"{RK(b)} * {RK(c)}")
        elif op == 251:
            setr(a, f"{RK(b)} / {RK(c)}")
        elif op == 94:
            setr(a, f"{R(b)} % {lit(K[c])}")
        elif op == 67:
            setr(a, " .. ".join(R(x) for x in range(b, c + 1)))
        elif op == 107:
            for x in range(a, b + 1):
                ctx["names"].pop(x, None)
                ctx["nilset"].add(x)
        elif op == 71:
            base = c - 1
            count = b
            items = [R(a + 1 + k) for k in range(count)] if count else [R(a + 1) + " ..."]
            for k, v in enumerate(items, base + 1):
                res.append(f"{R(a)}[{k}] = {v}")
        elif op == 216:
            setr(a, "...")
        elif op == 17:
            child = b + 1
            upnames = []
            for kind, index in self.protos[child]["upvalues"]:
                if kind == 1:
                    # a captured register is a live upvalue cell even if the
                    # parent has CLEARed it at this point
                    ctx["nilset"].discard(index)
                    upnames.append(R(index))
                else:
                    upnames.append(ctx["upnames"][index])
            nm = f"f{child}"
            sub, _ = self.decompile(child, upnames, ind, name=nm)
            res += sub
            setr(a, nm)
        elif op == 130:
            res.append(self.call_text(ctx, a, b, c, R))
        elif op == 225:
            info = ctx.get("self", {}).pop(a, None)
            if info is not None:
                obj, meth = info
                fn = f"{obj}:{meth}"
                args = [R(a + 2 + k) for k in range(max(b - 2, 0))] if b else [R(a + 2)]
            else:
                fn = R(a)
                args = self.args(ctx, a, b, R)
            res.append(f"return {fn}({', '.join(args)})")
        elif op == 93:
            if b == 1:
                res.append("return")
            else:
                cnt = b - 1
                vals = [R(a + k) for k in range(cnt)] if cnt else ["..."]
                res.append("return " + ", ".join(vals))
        elif op == 85:
            pass
        elif op == 147:
            pass
        elif op == 242:
            pass
        else:
            res.append(f"-- unhandled opcode {op} A={a} B={b} C={c}")

        # fused second instruction: its operation is fixed by the PRIMARY opcode
        if n.op2 is not None:
            a2, b2 = n.a2, n.b2
            second = {254: "move", 41: "loadk", 126: "move", 2: "loadk",
                      33: "move", 155: "move", 224: "loadk",
                      183: "loadk", 204: "move"}.get(n.op)
            if second == "move":
                setr(a2, R(b2))
            elif second == "loadk":
                setr(a2, lit(K[b2]))
            else:
                res.append(f"-- fused opcode {n.op}/{n.op2}")
        return res

    def member(self, ctx, text):
        m = re.fullmatch(r'"([A-Za-z_][A-Za-z0-9_]*)"', text)
        return "." + m.group(1) if m else f"[{text}]"

    def args(self, ctx, a, b, R):
        if b == 0:
            return [R(a + 1)]
        return [R(a + 1 + k) for k in range(b - 1)]

    def callee(self, ctx, a, R):
        info = ctx.get("self", {}).get(a)
        if info:
            obj, meth = info
            return f"{obj}:{meth}", meth
        return R(a), None

    def call_text(self, ctx, a, b, c, R):
        info = ctx.get("self", {}).pop(a, None)
        if info is not None:
            obj, meth = info
            fn = f"{obj}:{meth}"
            args = [f"{R(a + 2 + k)}" for k in range(max(b - 2, 0))] if b else [R(a + 2)]
        else:
            fn = R(a)
            args = self.args(ctx, a, b, R)
        call = f"{fn}({', '.join(args)})"
        if c != 1:
            for k in range(max(c - 1, 1)):
                ctx["nilset"].discard(a + k)
        if c == 1:
            return call
        if c == 0:
            return f"{R(a)} = {call}"
        if c == 2:
            return f"{R(a)} = {call}"
        return ", ".join(R(a + k) for k in range(c - 1)) + f" = {call}"


# ---------------------------------------------------------------------------
def simplify(lines):
    """Inline single-use temporaries into their consumer."""
    assigns = []
    for ln in lines:
        m = re.match(r"^(\s*)(v\d+) = (.*)$", ln)
        assigns.append(m.groups() if m else None)
    changed = True
    while changed:
        changed = False
        for i, m in enumerate(assigns):
            if not m:
                continue
            ind, var, expr = m
            uses = []
            for j in range(i + 1, len(lines)):
                mj = assigns[j]
                if mj and mj[1] == var:
                    break
                if re.search(rf"\b{var}\b", lines[j]):
                    uses.append(j)
                    if len(uses) > 1:
                        break
                if lines[j].strip() in ("end", "else") or lines[j].startswith(ind + "  "):
                    if not lines[j].startswith(ind + "  "):
                        break
            if len(uses) != 1:
                continue
            j = uses[0]
            if j != i + 1 and ("(" in expr or ":" in expr):
                continue
            repl = expr
            if re.search(r"\b(?:and|or|not)\b|[+\-*/%<>~=]", expr) and \
               re.search(rf"\b{var}\b\s*[.\[:+\-*/%<>=]", lines[j]):
                repl = f"({expr})"
            new = re.sub(rf"\b{var}\b", lambda _: repl, lines[j], count=1)
            if len(new) > 400:
                continue
            lines[j] = new
            lines[i] = None
            assigns[i] = None
            assigns[j] = re.match(r"^(\s*)(v\d+) = (.*)$", new).groups() \
                if re.match(r"^(\s*)(v\d+) = (.*)$", new) else None
            changed = True
            break
        lines = [x for x in lines if x is not None]
        assigns = []
        for ln in lines:
            m = re.match(r"^(\s*)(v\d+) = (.*)$", ln)
            assigns.append(m.groups() if m else None)
    return lines


def main() -> int:
    here = Path(__file__).resolve().parent
    protos = {}
    for f in sorted((here / "out/prototypes").glob("proto*.json")):
        p = json.loads(f.read_text())
        protos[p["idx"]] = p
    want = [int(x) for x in sys.argv[1:]]
    d = Decompiler(protos)
    if want:
        for idx in want:
            lines, _ = d.decompile(idx, indent=0, name=f"proto{idx}")
            print("\n".join(simplify(lines)))
            print()
        return 0
    lines, _ = d.decompile(1, indent=0, name="main")
    text = "\n".join(simplify(lines))
    header = (
        "-- H4xScripts loader - stage 2 reconstructed from VM bytecode\n"
        "-- Generated by h4x/decompile.py (static analysis, no executor involved)\n"
        "-- Names are regenerated: a<N> parameter, v<N> local, u<N> upvalue,\n"
        "-- f<N> nested function for prototype <N>.\n\n"
    )
    (here / "out/loader_deobfuscated.lua").write_text(header + text + "\n")
    print(f"wrote out/loader_deobfuscated.lua ({len(text.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
