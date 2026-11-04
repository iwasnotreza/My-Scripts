#!/usr/bin/env python3
"""Static interpreter for the H4X stage-2 register VM.

This is a *re-implementation* of the loader's VM dispatch, used to evaluate the
environment-fingerprint prototypes offline.  It never touches Roblox: every
host function is a local mock with Luau-compatible semantics.
"""
from __future__ import annotations

import math
import struct

M32 = 0xFFFFFFFF


class LuaError(Exception):
    """Lua-style error that carries the original thrown value."""

    def __init__(self, value):
        self.value = value
        super().__init__(value if isinstance(value, str) else lua_type(value))


# ---------------------------------------------------------------------------
# mock host environment (Luau semantics)
# ---------------------------------------------------------------------------
class Instance:
    def __init__(self, cls, name=None):
        self.cls = cls
        self.name = name or cls
        self.services = {}

    def GetService(_self, n):
        return _self.services[n]

    def IsA(_self, c):
        return c == _self.cls or c == "Instance"


class RunService(Instance):
    def IsClient(_self):
        return True

    def IsServer(_self):
        return False

    def IsStudio(_self):
        return False


class Vector3:
    def __init__(self, x=0.0, y=0.0, z=0.0):
        self.X, self.Y, self.Z = float(x), float(y), float(z)

    def get(self, k):
        if k == "X":
            return self.X
        if k == "Y":
            return self.Y
        if k == "Z":
            return self.Z
        if k == "Magnitude":
            return math.sqrt(self.X ** 2 + self.Y ** 2 + self.Z ** 2)
        if k == "Cross":
            return lambda _s, o: Vector3(_s.Y * o.Z - _s.Z * o.Y,
                                         _s.Z * o.X - _s.X * o.Z,
                                         _s.X * o.Y - _s.Y * o.X)
        if k == "Dot":
            return lambda _s, o: _s.X * o.X + _s.Y * o.Y + _s.Z * o.Z
        raise LuaError(f"Vector3 has no member {k}")


class CFrame:
    def __init__(self, x=0.0, y=0.0, z=0.0):
        self.X, self.Y, self.Z = float(x), float(y), float(z)

    def get(self, k):
        if k in ("X", "Y", "Z"):
            return getattr(self, k)
        if k == "Position":
            return Vector3(self.X, self.Y, self.Z)
        raise LuaError(f"CFrame has no member {k}")

    def __mul__(self, o):
        if isinstance(o, CFrame):
            return CFrame(self.X + o.X, self.Y + o.Y, self.Z + o.Z)
        if isinstance(o, Vector3):
            return Vector3(self.X + o.X, self.Y + o.Y, self.Z + o.Z)
        raise LuaError("bad CFrame multiply")


class Table:
    """Lua table with 1-based array part + hash part + optional metatable."""

    def __init__(self):
        self.hash = {}
        self.mt = None

    def get(self, k):
        if k is None:
            return None
        if k in self.hash:
            return self.hash[k]
        if self.mt is not None:
            idx = self.mt.hash.get("__index")
            if isinstance(idx, Table):
                return idx.get(k)
            if callable(idx):
                r = idx(self, k)
                if isinstance(r, (tuple, list)):
                    return r[0] if r else None
                return r
        return None

    def set(self, k, v):
        if v is None:
            self.hash.pop(k, None)
        else:
            self.hash[k] = v

    def length(self):
        n = 0
        while (n + 1) in self.hash or float(n + 1) in self.hash:
            n += 1
        return n

    def array(self):
        return [self.get(i) for i in range(1, self.length() + 1)]


def lua_type(v):
    if v is None:
        return "nil"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, Table):
        return "table"
    if isinstance(v, (Instance, Vector3, CFrame)):
        return "userdata"
    if callable(v):
        return "function"
    return "userdata"


def truthy(v):
    return v is not None and v is not False


def index(obj, key):
    if isinstance(obj, Table):
        return obj.get(key)
    if isinstance(obj, (Vector3, CFrame)):
        return obj.get(key)
    if isinstance(obj, Instance):
        m = getattr(type(obj), key, None)
        if m is not None:
            return m
        return obj.services.get(key)
    if isinstance(obj, str):
        return STRING_LIB.get(key)
    raise LuaError(f"attempt to index {lua_type(obj)} ({key!r})")


def num(v):
    if isinstance(v, bool) or v is None:
        raise LuaError("attempt to perform arithmetic on a non-number")
    return v


def u32(v):
    return int(v) & M32


def make_env(capture):
    """Build `Gg` - the global table exposed to the VM."""
    env = Table()

    def pcall(f, *a):
        try:
            r = f(*a)
        except LuaError as e:
            return (False, e.value)
        except Exception as e:  # noqa: BLE001
            return (False, str(e))
        if isinstance(r, (tuple, list)):
            return (True,) + tuple(r)
        return (True, r)

    def ipairs(t):
        def it(state, i):
            i = int(i or 0) + 1
            v = state.get(i)
            if v is None:
                return (None,)
            return (i, v)
        return (it, t, 0)

    def str_char(*a):
        return "".join(chr(int(x)) for x in a)

    def str_byte(s, i=1, j=None):
        j = i if j is None else j
        return tuple(ord(c) for c in s[int(i) - 1:int(j)])

    def str_sub(s, i, j=-1):
        i, j = int(i), int(j)
        n = len(s)
        if i < 0:
            i = max(n + i + 1, 1)
        elif i == 0:
            i = 1
        if j < 0:
            j = n + j + 1
        j = min(j, n)
        if i > j:
            return ""
        return s[i - 1:j]

    def tbl_concat(t, sep="", i=1, j=None):
        j = t.length() if j is None else int(j)
        return sep.join(str(t.get(k)) for k in range(int(i), j + 1))

    def str_pack(fmt, v):
        if fmt == "<d":
            return struct.pack("<d", v).decode("latin-1")
        raise LuaError(f"string.pack {fmt} unsupported")

    def str_unpack(fmt, s, pos=1):
        if fmt == "<d":
            return struct.unpack("<d", s.encode("latin-1")[int(pos) - 1:])[0]
        raise LuaError(f"string.unpack {fmt} unsupported")

    string_lib = Table()
    for k, v in {"char": str_char, "byte": str_byte, "sub": str_sub,
                 "pack": str_pack, "unpack": str_unpack, "len": len,
                 "format": lambda f, *a: f % a}.items():
        string_lib.set(k, v)

    table_lib = Table()
    table_lib.set("concat", tbl_concat)

    bit32 = Table()
    bit32.set("bxor", lambda *a: _reduce_xor(a))
    bit32.set("band", lambda *a: _reduce_and(a))
    bit32.set("bor", lambda *a: _reduce_or(a))
    bit32.set("bnot", lambda a: (~u32(a)) & M32)
    bit32.set("lshift", lambda a, n: 0 if n >= 32 else (u32(a) << int(n)) & M32)
    bit32.set("rshift", lambda a, n: 0 if n >= 32 else u32(a) >> int(n))
    bit32.set("lrotate", lambda a, n: _lrot(u32(a), int(n)))
    bit32.set("rrotate", lambda a, n: _lrot(u32(a), -int(n)))

    game = Instance("DataModel", "Game")
    game.services["RunService"] = RunService("RunService")

    v3lib = Table()
    v3lib.set("new", lambda x=0, y=0, z=0: Vector3(x, y, z))
    cflib = Table()
    cflib.set("new", lambda x=0, y=0, z=0: CFrame(x, y, z))

    def typeof(v):
        if isinstance(v, Vector3):
            return "Vector3"
        if isinstance(v, CFrame):
            return "CFrame"
        if isinstance(v, Instance):
            return "Instance"
        return lua_type(v)

    def iscclosure(f):
        return callable(f) and not isinstance(f, VMClosure)

    def islclosure(f):
        return isinstance(f, VMClosure)

    def setmetatable(t, mt):
        t.mt = mt
        return t

    def rawget(t, k):
        return t.hash.get(k)

    def error(msg, level=1):
        raise LuaError(msg)

    def gate(value):
        capture.append(value)
        return True

    for k, v in {
        "pcall": pcall, "type": lua_type, "ipairs": ipairs,
        "string": string_lib, "table": table_lib, "bit32": bit32,
        "game": game, "Vector3": v3lib, "CFrame": cflib, "typeof": typeof,
        "iscclosure": iscclosure, "islclosure": islclosure,
        "setmetatable": setmetatable, "rawget": rawget, "error": error,
        "tonumber": lambda v: float(v) if isinstance(v, str) else v,
        "tostring": lambda v: str(v),
        "x1kIJ3Ya": gate,
    }.items():
        env.set(k, v)
    return env, string_lib


def _reduce_xor(a):
    r = 0
    for x in a:
        r ^= u32(x)
    return r & M32


def _reduce_and(a):
    r = M32
    for x in a:
        r &= u32(x)
    return r & M32


def _reduce_or(a):
    r = 0
    for x in a:
        r |= u32(x)
    return r & M32


def _lrot(a, n):
    n %= 32
    return ((a << n) | (a >> (32 - n))) & M32 if n else a


STRING_LIB = Table()


class VMClosure:
    def __init__(self, vm, proto, upvals):
        self.vm = vm
        self.proto = proto
        self.upvals = upvals

    def __call__(self, *args):
        return self.vm.run(self.proto, self.upvals, list(args))


class Upval:
    """Boxed upvalue so nested closures share storage."""

    def __init__(self, regs, key):
        self.regs = regs
        self.key = key
        self.closed = None
        self.is_closed = False

    def get(self):
        return self.closed if self.is_closed else self.regs[self.key]

    def set(self, v):
        if self.is_closed:
            self.closed = v
        else:
            self.regs[self.key] = v

    def close(self):
        if not self.is_closed:
            self.closed = self.regs[self.key]
            self.is_closed = True


class VM:
    def __init__(self, protos, env, trace=None):
        self.protos = protos          # list indexed by proto index - 1
        self.env = env
        self.trace = trace
        self.routes = []
        self.steps = 0

    def run(self, proto, upvals, args):
        ops, A, B, C = proto["opcodes"], proto["A"], proto["B"], proto["C"]
        K = proto["constants"]
        regs = [None] * 512
        nparams = proto["numparams"]
        for i in range(nparams):
            regs[i] = args[i] if i < len(args) else None
        varargs = list(args[nparams:]) if proto["vararg"] else []
        top = nparams
        open_upvals = {}
        pc = 0
        self.depth = getattr(self, "depth", 0) + 1
        if self.depth > 200:
            raise LuaError("VM recursion limit")
        try:
            while pc < len(ops):
                op, a, b, c = ops[pc], A[pc], B[pc], C[pc]
                self.steps += 1
                if self.steps > 5_000_000:
                    raise LuaError("VM step limit")
                if self.trace is not None:
                    self.trace.append((proto["idx"], pc + 1, op, a, b, c))
                pc += 1

                def rk(x):
                    return K[x - 490] if x >= 490 else regs[x]

                if op == 127:            # LOADK
                    regs[a] = K[b]
                elif op == 189:          # MOVE
                    regs[a] = regs[b]
                elif op == 254:          # MOVE + MOVE
                    regs[a] = regs[b]
                    regs[A[pc]] = regs[B[pc]]
                    pc += 1
                elif op == 41:           # MOVE + LOADK
                    regs[a] = regs[b]
                    regs[A[pc]] = K[B[pc]]
                    pc += 1
                elif op == 126:          # LOADK + MOVE
                    regs[a] = K[b]
                    regs[A[pc]] = regs[B[pc]]
                    pc += 1
                elif op == 2:            # NEWTABLE + LOADK
                    regs[a] = Table()
                    regs[A[pc]] = K[B[pc]]
                    pc += 1
                elif op == 212:          # NEWTABLE
                    regs[a] = Table()
                elif op == 102:          # GETGLOBAL
                    regs[a] = self.env.get(K[b])
                elif op == 155:          # GETGLOBAL + MOVE
                    regs[a] = self.env.get(K[b])
                    regs[A[pc]] = regs[B[pc]]
                    pc += 1
                elif op == 183:          # GETUPVAL + LOADK
                    uv = upvals[b]
                    regs[a] = uv.get() if isinstance(uv, Upval) else uv
                    regs[A[pc]] = K[B[pc]]
                    pc += 1
                elif op == 31:           # GETTABLE
                    regs[a] = index(regs[b], rk(c))
                elif op == 24:           # SETTABLE (const key)
                    obj = regs[a]
                    if isinstance(obj, Table):
                        obj.set(K[b], regs[c])
                    else:
                        raise LuaError("SETTABLE on non-table")
                elif op == 59:           # SETTABLE (reg key)
                    regs[a].set(regs[b], regs[c])
                elif op == 49:           # SELF
                    regs[a + 1] = regs[b]
                    regs[a] = index(regs[b], K[c])
                elif op == 50:           # LEN
                    v = regs[b]
                    regs[a] = v.length() if isinstance(v, Table) else len(v)
                elif op == 48:           # LOADBOOL
                    regs[a] = b != 0
                    if c != 0:
                        pc += 1
                elif op == 107:          # CLEAR
                    for i in range(a, b + 1):
                        regs[i] = None
                elif op == 91:           # ADD
                    regs[a] = num(rk(b)) + num(rk(c))
                elif op == 88:           # MUL
                    x, y = rk(b), rk(c)
                    if isinstance(x, (int, float)) and isinstance(y, (int, float)):
                        regs[a] = x * y
                    else:
                        regs[a] = x * y
                elif op == 94:           # MOD
                    x, y = num(regs[b]), num(K[c])
                    regs[a] = x - math.floor(x / y) * y
                elif op == 43:           # SUB + JMP
                    regs[a] = num(regs[a]) - num(regs[a + 2])
                    pc += b
                elif op == 246:          # JMP
                    pc += b
                elif op == 57:           # TEST
                    if truthy(regs[a]) != (c != 0):
                        pc += 1
                    else:
                        pc += 1 + B[pc]
                elif op == 87:           # EQ (reg)
                    if (regs[b] == regs[c]) != (a != 0):
                        pc += 1
                    else:
                        pc += 1 + B[pc]
                elif op == 214:          # EQ (const)
                    if (regs[b] == K[c]) != (a != 0):
                        pc += 1
                    else:
                        pc += 1 + B[pc]
                elif op == 47:           # LT (const left)
                    if (num(K[b]) < num(regs[c])) != (a != 0):
                        pc += 1
                    else:
                        pc += 1 + B[pc]
                elif op == 151:          # LT (const right)
                    if (num(regs[b]) < num(K[c])) != (a != 0):
                        pc += 1
                    else:
                        pc += 1 + B[pc]
                elif op == 17:           # CLOSURE (+ route registration)
                    child = self.protos[b + 1]
                    self.routes.append({
                        "parent": proto["idx"], "child": b + 1,
                        "pc": pc, "A": a, "B": b, "C": c,
                    })
                    uvs = []
                    for kind, idx in child["upvalues"]:
                        if kind == 1:
                            if idx not in open_upvals:
                                open_upvals[idx] = Upval(regs, idx)
                            uvs.append(open_upvals[idx])
                        else:
                            uvs.append(upvals[idx])
                    regs[a] = VMClosure(self, child, uvs)
                elif op == 85:           # CLOSE
                    for i in range(a, len(regs)):
                        if i in open_upvals:
                            open_upvals[i].close()
                elif op == 130:          # CALL
                    f = regs[a]
                    nargs = (top - a - 1) if b == 0 else b - 1
                    callargs = [regs[a + 1 + i] for i in range(max(nargs, 0))]
                    res = self._call(f, callargs, regs, a)
                    if c == 0:
                        for i, v in enumerate(res):
                            regs[a + i] = v
                        top = a + len(res)
                    else:
                        for i in range(c - 1):
                            regs[a + i] = res[i] if i < len(res) else None
                elif op == 225:          # TAILCALL
                    f = regs[a]
                    nargs = (top - a - 1) if b == 0 else b - 1
                    callargs = [regs[a + 1 + i] for i in range(max(nargs, 0))]
                    return self._call(f, callargs, regs, a)
                elif op == 93:           # RETURN
                    if b == 1:
                        return []
                    n = (top - a) if b == 0 else b - 1
                    return [regs[a + i] for i in range(max(n, 0))]
                elif op == 216:          # VARARG
                    if b == 0:
                        for i, v in enumerate(varargs):
                            regs[a + i] = v
                        top = a + len(varargs)
                    else:
                        for i in range(b - 1):
                            regs[a + i] = varargs[i] if i < len(varargs) else None
                elif op == 71:           # SETLIST
                    obj = regs[a]
                    e = c - 1
                    n = (top - a - 1) if b == 0 else b
                    for i in range(1, n + 1):
                        obj.set(e + i, regs[a + i])
                elif op == 147:          # TFORPREP - ensure R[A] is an iterator
                    if not callable(regs[a]):
                        tbl = regs[a]

                        def _iter(t, i):
                            i = int(i or 0) + 1
                            v = t.get(i)
                            return (None,) if v is None else (i, v)

                        regs[a], regs[a + 1], regs[a + 2] = _iter, tbl, 0
                elif op == 242:          # FORLOOP
                    regs[a] = num(regs[a]) + num(regs[a + 2])
                    step, limit = regs[a + 2], regs[a + 1]
                    if (step >= 0 and regs[a] <= limit) or (step < 0 and regs[a] >= limit):
                        regs[a + 3] = regs[a]
                        pc += b
                elif op == 89:           # TFORCALL
                    f = regs[a]
                    res = self._call(f, [regs[a + 1], regs[a + 2]], regs, a)
                    if not isinstance(res, list):
                        res = list(res)
                    if c >= 1 and res and res[0] is not None:
                        regs[a + 2] = res[0]          # control variable
                        for i in range(c):
                            regs[a + 3 + i] = res[i] if i < len(res) else None
                        pc += b
                else:
                    raise LuaError(f"unimplemented opcode {op} "
                                   f"(proto {proto['idx']} pc {pc})")
            return []
        finally:
            self.depth -= 1

    def _call(self, f, args, regs, a):
        if f is None:
            raise LuaError("attempt to call a nil value")
        if isinstance(f, VMClosure):
            return f(*args)
        if callable(f):
            r = f(*args)
            if isinstance(r, tuple):
                return list(r)
            return [] if r is None else [r]
        raise LuaError(f"attempt to call a {lua_type(f)} value")
