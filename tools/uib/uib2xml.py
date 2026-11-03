#!/usr/bin/env python3
"""uib2xml.py - decompile Windows Live Mail 2012 (uxcore.dll) compiled UI ("UIB") resources to XML.

Format reference: FORMAT.md (same directory).  Every opcode/sub-opcode handled here is taken from
the uxcore.dll interpreter (dispatch FUN_100c1c0c); addresses are cited in comments.

Usage:
  python3 -I uib2xml.py FILE.bin [-o OUT.xml] [--targets DIR|none] [--asm]
  python3 -I uib2xml.py --all IN_DIR OUT_DIR [--targets DIR|none]
  python3 -I uib2xml.py --check IN_DIR            (coverage self-check, non-zero exit on any gap)

--targets points at the Windows Live install folder (default: targets/Windows Live at the repository root); referenced
colours (type 4002), rects (4003), images (4000) and strings (4009 + RT_STRING of the language DLL)
are resolved and shown as annotations '{=...}' after the reference.  Nothing else depends on it.
"""
import struct, sys, os, glob, argparse
from xml.sax.saxutils import quoteattr, escape

# --------------------------------------------------------------------------- container
class UIBError(Exception):
    pass


class UIB:
    """Header + tables.  Section layout from the reader object methods (vtable 0x1000e458):
    +0x08 pool, +0x0c classes, +0x10 props, +0x14 entries, +0x18 fragments, +0x1c resources,
    +0x20 code, +0x24 end."""

    def __init__(self, data):
        self.d = d = data
        if d[:4] != b'UIB\0':                      # FUN_100c074a memcmp DAT_1000f098
            raise UIBError('bad magic')
        self.ver, self.ver2 = struct.unpack_from('<HH', d, 4)
        if (self.ver, self.ver2) != (1, 0):        # FUN_100c074a
            raise UIBError('bad version %d.%d' % (self.ver, self.ver2))
        o = self.off = struct.unpack_from('<8I', d, 8)
        if list(o) != sorted(o) or o[7] != len(d) or o[0] != 0x28:
            raise UIBError('section offsets not monotonic / end != file size')
        self.consumed = bytearray(len(d))          # byte coverage map
        self._mark(0, 0x28)
        # pool: NUL separated ASCII (GetString(off) = base+[+8]+off, FUN_100c063d)
        self.pool = d[o[0]:o[1]]
        self._mark(o[0], o[1])
        self._pool_used = bytearray(len(self.pool))
        # classes / props: u32 pool offsets (FUN_100c040a/100c03ae, FUN_100c0541/100c04e5)
        self.classes = [self.string(x) for x in self._u32s(o[1], o[2])]
        self.props = [self.string(x) for x in self._u32s(o[2], o[3])]
        # entries: {NUL-terminated name, u32 code offset} (FUN_100c044a)
        self.entries = []
        p = o[3]
        while p < o[4]:
            e = d.index(b'\0', p)
            name = d[p:e].decode('ascii')
            (co,) = struct.unpack_from('<I', d, e + 1)
            self.entries.append((name, co))
            self._mark(p, e + 5)
            p = e + 5
        if p != o[4]:
            raise UIBError('entry table overrun')
        # fragments: u32 code offsets (FUN_100c06c6 / FUN_100c067c)
        self.fragments = self._u32s(o[4], o[5])
        # resources: 8-byte records (FUN_100c05c5 / FUN_100c0581, consumer FUN_100c2095)
        if (o[6] - o[5]) % 8:
            raise UIBError('resource table not multiple of 8')
        self.resources = []
        for i in range((o[6] - o[5]) // 8):
            rid, w2, typ, mod, w6 = struct.unpack_from('<HHBBH', d, o[5] + 8 * i)
            self.resources.append(dict(id=rid, w2=w2, type=typ, module=mod, w6=w6))
        self._mark(o[5], o[6])
        self.code0, self.code1 = o[6], o[7]
        self._pool_used[0] = 1  # leading NUL (offset 0 = "")

    def _mark(self, a, b):
        for i in range(a, b):
            self.consumed[i] = 1

    def _u32s(self, a, b):
        if (b - a) % 4:
            raise UIBError('table not multiple of 4 at %#x' % a)
        self._mark(a, b)
        return list(struct.unpack_from('<%dI' % ((b - a) // 4), self.d, a))

    def string(self, off):
        if not 0 <= off < len(self.pool):
            raise UIBError('pool offset %#x out of range' % off)
        e = self.pool.index(b'\0', off)
        for i in range(off, e + 1):
            self._pool_used[i] = 1
        return self.pool[off:e].decode('latin-1')

    def pool_coverage(self):
        """pool bytes reached through any reference; the remainder is listed as unreferenced"""
        unref = []
        i = 0
        while i < len(self.pool):
            e = self.pool.index(b'\0', i)
            if not any(self._pool_used[i:e + 1]):
                unref.append((i, self.pool[i:e].decode('latin-1')))
            i = e + 1
        return unref


# --------------------------------------------------------------------------- instructions
# operand bytes after the opcode (FUN_100c4453 / 100c4400 / 100c442b / 100c240f / 100c23bd / 100c2349)
OPLEN = {0x02: 1, 0x03: 2, 0x04: 4, 0x07: 2, 0x09: 2, 0x0a: 2, 0x0b: 2, 0x0c: 2, 0x0d: 2}
OPNAME = {
    0x01: 'halt', 0x02: 'push.u8', 0x03: 'push.u16be', 0x04: 'push.i32be', 0x06: 'pop',
    0x07: 'jmp', 0x09: 'jtrue', 0x0a: 'jgt', 0x0b: 'jge', 0x0c: 'jlt', 0x0d: 'jle',
    0x0e: 'call', 0x0f: 'ret', 0x10: 'newelem', 0x11: 'mkvalue', 0x12: 'setprop', 0x13: 'addchild',
    0x14: 'addchildren', 0x15: 'mklayout', 0x16: 'resvalue', 0x17: 'resref', 0x18: 'bind',
    0x19: 'behavior', 0x1a: 'mksheet', 0x1b: 'entryaddr', 0x1c: 'fragment', 0x1d: 'anim.const',
    0x1e: 'anim.linear', 0x1f: 'anim.inverse', 0x20: 'anim.cycle', 0x21: 'anim.composite',
    0x22: 'dpi', 0x23: 'dpif', 0x24: 'dpivalue', 0x25: 'or', 0x26: 'and', 0x27: 'min',
    0x28: 'max', 0x29: 'pt2font', 0x2a: 'pt2fontf', 0x2b: 'sysmetric', 0x2c: 'sysfontface',
    0x2d: 'hcselect', 0x2e: 'setreg',
}


def disassemble(u):
    """linear sweep over the code section; returns {addr: (op, operand, length)}"""
    d = u.d
    ins = {}
    p = u.code0
    while p < u.code1:
        op = d[p]
        if op not in OPNAME:
            raise UIBError('unknown opcode %#04x at %#x' % (op, p))
        n = OPLEN.get(op, 0)
        if p + 1 + n > u.code1:
            raise UIBError('truncated instruction at %#x' % p)
        b = d[p + 1:p + 1 + n]
        if op == 0x02:
            arg = b[0]
        elif op == 0x03:
            arg = (b[0] << 8) | b[1]                    # FUN_100c4400 CONCAT11(hi,lo), zero-extended
        elif op == 0x04:
            arg = struct.unpack('>i', b)[0]             # FUN_100c114e big-endian
        elif op == 0x07:
            arg = (b[0] << 8) | b[1]                    # FUN_100c240f unsigned, relative to opcode
        elif n == 2:
            arg = struct.unpack('>h', b)[0]             # FUN_100c23bd / 100c2349 signed, relative
        else:
            arg = None
        ins[p] = (op, arg, 1 + n)
        p += 1 + n
    return ins


# --------------------------------------------------------------------------- symbolic values
class Num:
    """int on the VM stack (stack type 1); expr is the source text, val the value at 96 DPI or None"""
    __slots__ = ('val', 'expr')

    def __init__(self, val, expr=None):
        self.val, self.expr = val, expr

    def lit(self):
        if self.expr is not None:
            raise UIBError('literal expected, got %s' % self.expr)
        return self.val

    def __str__(self):
        return self.expr if self.expr is not None else str(self.val)


def mk_num(op, a, b=None):
    return Num(None, op % ((a, b) if b is not None else (a,)))


class Val:
    """DirectUI::Value on the stack (stack type 3)"""

    def __init__(self, kind, text, xml=None, extra=None):
        self.kind, self.text, self.xml, self.extra = kind, text, xml, extra or {}

    def __str__(self):
        return self.text


class Elem:
    """DirectUI::Element under construction (stack type 2)"""

    def __init__(self, cls, addr):
        self.cls, self.addr = cls, addr
        self.props = []     # (name, Val)
        self.extras = []    # xml strings (bindings, behaviors)
        self.children = []


class Layout:
    """DirectUI::Layout (stack type 4)"""

    def __init__(self, text):
        self.text = text

    def __str__(self):
        return self.text


def h(v):
    return '0x%X' % (v & 0xffffffff)


def color_text(v):
    if isinstance(v, Num) and v.expr is not None:
        return str(v)
    v = v.val if isinstance(v, Num) else v
    v &= 0xffffffff
    a, b, g, r = v >> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255
    return 'argb(%d,%d,%d,%d)' % (a, r, g, b)


RES_KIND = {  # sub-type -> provider slot (vtable 0x10018704) - FUN_100c3086 / FUN_100c2095
    1: 'string', 2: 'graphic', 3: 'int', 4: 'color', 5: 'colorize', 6: 'image', 7: 'image',
    8: 'int', 9: 'rect', 10: 'icon', 11: 'cursor', 12: 'animation', 13: 'float',
}
SYSMETRIC_NEG = {  # FUN_100ecdce: SPI_GETNONCLIENTMETRICS / SPI_GETICONMETRICS fields
    -1: 'CaptionFont.Height', -2: 'CaptionFont.Weight', -3: 'CaptionFont.Style',
    -4: 'MenuFont.Height', -5: 'MenuFont.Weight', -6: 'MenuFont.Style',
    -7: 'MessageFont.Height', -8: 'MessageFont.Weight', -9: 'MessageFont.Style',
    -10: 'SmCaptionFont.Height', -11: 'SmCaptionFont.Weight', -12: 'SmCaptionFont.Style',
    -13: 'StatusFont.Height', -14: 'StatusFont.Weight', -15: 'StatusFont.Style',
    -16: 'IconTitleFont.Height', -17: 'IconTitleFont.Weight', -18: 'IconTitleFont.Style',
}
SYSFONT = {1: 'CaptionFont', 2: 'MenuFont', 3: 'MessageFont', 4: 'SmCaptionFont', 5: 'StatusFont',
           6: 'IconTitleFont'}  # FUN_100ecfff


# --------------------------------------------------------------------------- resource annotation
DEFAULT_TARGETS = os.environ.get('WLM_TARGETS', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'targets', 'Windows Live'))
# module name (pool string used by op 0x16 / resource records) -> (resource dll, string dll).
# The mapping is NOT stored in the UIB: the host registers module names at runtime (FUN_10116218 /
# FUN_101160a6 look a name up in a registry; "" = default module).  The table below is inferred from
# resource-id coverage: every referenced id exists in the chosen DLL (see FORMAT.md section 9).
DEFAULT_MODULES = {
    '': ('Mail/mailres2.dll', 'Mail/maillang.dll'),
    'mail': ('Mail/mailres2.dll', 'Mail/maillang.dll'),
    'wlux': ('Shared/wlidux.dll', 'Shared/wliduxloc.dll'),
}


class Resolver:
    """Annotates resource references using the resource-manager formats of uxcore.dll.
    Purely informational: nothing in the decompiled structure depends on it."""

    def __init__(self, targets=None, modules=None):
        self.mods = {}
        if targets is None:
            return
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from peres import PERes
        cache = {}
        for name, (rdll, sdll) in (modules or DEFAULT_MODULES).items():
            pair = []
            for x in (rdll, sdll):
                path = x if os.path.isabs(x) else os.path.join(targets, x)
                if path not in cache:
                    cache[path] = PERes(path) if os.path.exists(path) else None
                pair.append(cache[path])
            self.mods[name] = pair

    def raw(self, mod, typ, rid):
        m = self.mods.get(mod)
        if not m or not m[0]:
            return None
        return m[0].get(typ, rid)

    def color(self, mod, rid, depth=0):
        """CRMColorResource::Load 0x101135df (type 0xfa2=4002; 'J' chains), ToCOLORREF 0x1011382d"""
        b = self.raw(mod, 4002, rid)
        if not b or depth > 8:
            return None
        t = chr(b[0])
        if t == 'J':
            return self.color(mod, struct.unpack_from('<H', b, 1)[0], depth + 1)
        if t == 'N':
            return 'null'
        if t == 'C':
            return color_text(struct.unpack_from('<I', b, 1)[0])
        if t == 'S':     # GetSystemColorIndex 0x1011338e: low 24 bits = COLOR_*, top byte = alpha
            v = struct.unpack_from('<I', b, 1)[0]
            return 'syscolor(%d,alpha=%d)' % (v & 0xffffff, v >> 24)
        if t == 'D':     # colorized: 3 bytes fed to the colorization math (FUN_1011365f), byte 4 alpha
            return 'colorized(%s)' % ','.join(str(x) for x in b[1:])
        return 'raw(%s)' % b.hex()

    def rect(self, mod, rid):
        """RMLoadRect -> FUN_1011718d: type 0xfa3=4003, 18 bytes = RECT + u16 scale mode"""
        b = self.raw(mod, 4003, rid)
        if b is None or len(b) != 18:
            return None
        l, t, r, bt, f = struct.unpack('<iiiiH', b)
        return 'rect(%d,%d,%d,%d)%s' % (l, t, r, bt, (' scale=%d' % f) if f else '')

    def string(self, mod, rid, depth=0):
        """CRMStringResource::Load 0x1011424d: descriptor type 0xfa9=4009 (u16 kind; 3 = redirect to
        u16 id), otherwise the RT_STRING table of the module's language DLL (FUN_10116c42)"""
        m = self.mods.get(mod)
        if not m or depth > 8:
            return None
        for dll in m:
            if dll is None:
                continue
            dsc = dll.get(4009, rid)
            if dsc and len(dsc) >= 4 and struct.unpack_from('<H', dsc, 0)[0] == 3:
                return self.string(mod, struct.unpack_from('<H', dsc, 2)[0], depth + 1)
        for dll in (m[1], m[0]):
            if dll is not None:
                s = dll.string(rid)
                if s is not None:
                    return s
        return None

    def image(self, mod, rid, depth=0):
        """FUN_1010abd4: type 0xfa0=4000, first byte selects the kind"""
        b = self.raw(mod, 4000, rid)
        if not b or depth > 8:
            return None
        t = b[0]
        if t == 0x89 and b[1:4] == b'PNG':
            w, hh = struct.unpack_from('>II', b, 16)
            return 'png %dx%d (mailres type 4000 id %d)' % (w, hh, rid)
        if t == ord('J'):
            return self.image(mod, struct.unpack_from('<H', b, 1)[0], depth + 1)
        if t == ord('R'):
            return 'rle (type 4000 id %d + info in type 4006)' % rid
        if t == ord('N'):
            return 'null'
        if t in (ord('C'), ord('D')):
            return 'color ' + color_text(struct.unpack_from('<I', b, 1)[0])
        if t == ord('S'):
            return 'syscolor(%d)' % (struct.unpack_from('<I', b, 1)[0] & 0xffffff)
        return 'kind %r len %d' % (chr(t), len(b))

    def annotate(self, kind, mod, rid):
        if kind in ('color', 'colorize'):
            return self.color(mod, rid)
        if kind == 'rect':
            return self.rect(mod, rid)
        if kind in ('string', 'int'):
            return self.string(mod, rid)
        if kind in ('image', 'graphic', 'icon'):
            return self.image(mod, rid)
        if kind == 'float':
            return self.string(mod, rid)
        return None


# --------------------------------------------------------------------------- interpreter
class VM:
    def __init__(self, u, ins, res):
        self.u, self.ins, self.res = u, ins, res
        self.executed = set()
        self.frag_cache = {}
        self.stats = {}
        self.errors = []

    # stack helpers --------------------------------------------------------
    def pop(self, kind=None):
        if not self.stack:
            raise UIBError('stack underflow at %#x' % self.ip)
        x = self.stack.pop()
        if kind is not None and not isinstance(x, kind):
            raise UIBError('type mismatch at %#x: want %s got %s' % (self.ip, kind.__name__, type(x).__name__))
        return x

    def popn(self):
        return self.pop(Num)

    def peek_elem(self):     # FUN_100c1051 uses stack vtable +0x1c (peek)
        if not self.stack or not isinstance(self.stack[-1], Elem):
            raise UIBError('element expected on top at %#x' % self.ip)
        return self.stack[-1]

    def pstr(self):          # FUN_100c439f: int = pool offset -> string
        return self.u.string(self.popn().lit())

    def pval_or_zero(self):  # FUN_100c10c0: Value, or int 0 meaning NULL
        x = self.pop()
        if isinstance(x, Val):
            return x
        if isinstance(x, Num) and x.val == 0 and x.expr is None:
            return None
        raise UIBError('Value-or-0 expected at %#x' % self.ip)

    # execution ------------------------------------------------------------
    def run(self, addr):
        self.stack = []
        self.calls = []
        self.ip = addr
        while True:
            if self.ip not in self.ins:
                raise UIBError('jump into middle of instruction at %#x' % self.ip)
            op, arg, ln = self.ins[self.ip]
            self.executed.add(self.ip)
            self.stats[op] = self.stats.get(op, 0) + 1
            nxt = self.ip + ln
            r = self.step(op, arg)
            if r == 'stop':
                break
            self.ip = nxt if r is None else r
        return self.stack

    def step(self, op, arg):
        u = self.u
        if op == 0x01:                               # FUN_100c1c0c case 1: running=0
            return 'stop'
        if op in (0x02, 0x03, 0x04):                 # push int
            self.stack.append(Num(arg))
            return
        if op == 0x06:                               # FUN_100c4345 pop & discard
            self.pop()
            return
        if op == 0x07:                               # FUN_100c240f
            return self.ip + arg
        if op in (0x09, 0x0a, 0x0b, 0x0c, 0x0d):     # FUN_100c23bd / FUN_100c2349
            raise UIBError('conditional jump %#x at %#x needs runtime state (unused in corpus)' % (op, self.ip))
        if op == 0x0e:                               # FUN_100c17c9 call
            raise UIBError('call at %#x (unused in corpus)' % self.ip)
        if op == 0x0f:                               # FUN_100c4632 ret / end
            if not self.calls:
                return 'stop'
            raise UIBError('ret with frames')
        if op == 0x10:                               # FUN_100c2bdd -> FUN_100c1816(class idx)
            ci = self.popn().lit()
            self.stack.append(Elem(u.classes[ci], self.ip))
            return
        if op == 0x11:                               # FUN_100c3583
            self.stack.append(self.mkvalue(self.popn().lit()))
            return
        if op == 0x12:                               # FUN_100c47e1 SetValue
            pi = self.popn().lit()
            if self.stack and isinstance(self.stack[-1], Elem):
                # compiler emitted no value: at runtime FUN_100c08e0 pops the Element, sees stack type 2
                # instead of 3 and returns 0x80004005, aborting the whole entry.  We record it and go on
                # (lenient) so that the rest of the entry is still decoded.
                self.stack[-1].props.append((u.props[pi], Val('error', '', extra={'missing': True})))
                self.errors.append('%#x: setprop %s without a Value (runtime E_FAIL)' % (self.ip, u.props[pi]))
                return
            v = self.pop(Val)
            e = self.peek_elem()
            e.props.append((u.props[pi], v))
            return
        if op == 0x13:                               # FUN_100c117d Add
            c = self.pop(Elem)
            p = self.peek_elem()
            p.children.append(c)
            self.stack.append(c)
            return
        if op == 0x14:                               # FUN_100c11ff (marker -12) - unused
            raise UIBError('addchildren at %#x (unused in corpus)' % self.ip)
        if op == 0x15:                               # FUN_100c2f02
            self.stack.append(self.mklayout(self.popn().lit()))
            return
        if op == 0x16:                               # FUN_100c3086
            self.stack.append(self.resvalue(self.popn().lit()))
            return
        if op == 0x17:                               # FUN_100c3016 -> FUN_100c2095
            self.stack.append(self.resref(self.popn().lit()))
            return
        if op == 0x18:                               # FUN_100c270f
            self.bind()
            return
        if op == 0x19:                               # FUN_100c2626
            a = self.pstr()
            b = self.pstr()
            v = self.pval_or_zero()
            e = self.peek_elem()
            x = '<Behavior ns=%s name=%s' % (quoteattr(a), quoteattr(b))
            x += (' value=%s/>' % quoteattr(str(v))) if v is not None else '/>'
            e.extras.append(x)
            return
        if op == 0x1a:                               # FUN_100c32a8
            self.stack.append(self.mksheet())
            return
        if op == 0x1b:                               # FUN_100c1f64
            raise UIBError('entryaddr at %#x (unused in corpus)' % self.ip)
        if op == 0x1c:                               # FUN_100c2476 -> FUN_100c2215
            k = self.popn().lit()
            if not 0 <= k < len(u.fragments):
                raise UIBError('fragment index %d out of range' % k)
            fv = self.frag_cache.get(k)
            kind = fv.kind if fv else '?'
            self.stack.append(Val('fragref', 'fragment(%d)' % k, extra={'frag': k, 'fkind': kind}))
            return
        if op == 0x1d:                               # FUN_100c1422
            v = self.pop(Val); n = self.popn()
            self.stack.append(Val('anim', 'constanim(%s,%s)' % (v, n)))
            return
        if op == 0x1e:                               # FUN_100c15c3
            a = self.pop(Val); b = self.pop(Val); n = self.popn()
            self.stack.append(Val('anim', 'linearanim(%s,%s,%s)' % (a, b, n)))
            return
        if op == 0x1f:                               # FUN_100c154a
            self.stack.append(Val('anim', 'inverseanim(%s)' % self.pop(Val)))
            return
        if op == 0x20:                               # FUN_100c14b6
            v = self.pop(Val); n = self.popn()
            self.stack.append(Val('anim', 'cycleanim(%s,%s)' % (v, n)))
            return
        if op == 0x21:                               # FUN_100c1385
            a = self.pop(Val); b = self.pop(Val)
            self.stack.append(Val('anim', 'compositeanim(%s,%s)' % (a, b)))
            return
        if op == 0x22:                               # FUN_100c44c4 MulDiv(x,dpi,96)
            x = self.popn()
            self.stack.append(Num(x.val, 'dpi(%s)' % x))
            return
        if op == 0x23:                               # FUN_100c4472 float x*dpi/96
            x = self.popn()
            self.stack.append(Num(x.val, 'dpif(%s)' % x))
            return
        if op == 0x24:                               # FUN_100c4508 scale Size/Rect value
            v = self.pop(Val)
            if v.kind not in ('size', 'rect', 'point'):
                raise UIBError('dpivalue on %s' % v.kind)
            self.stack.append(Val(v.kind, 'dpi(%s)' % v))
            return
        if op in (0x25, 0x26, 0x27, 0x28):           # or / and / min / max
            a = self.popn(); b = self.popn()
            if a.expr is None and b.expr is None:
                f = {0x25: lambda x, y: x | y, 0x26: lambda x, y: x & y, 0x27: min, 0x28: max}[op]
                self.stack.append(Num(f(b.val, a.val)))
            else:
                nm = {0x25: 'or', 0x26: 'and', 0x27: 'min', 0x28: 'max'}[op]
                self.stack.append(Num(None, '%s(%s,%s)' % (nm, b, a)))
            return
        if op == 0x29:                               # FUN_100c42ff -MulDiv(pt,dpi,72)
            x = self.popn()
            v = None if x.val is None else -int(x.val * 96 / 72 + 0.5)   # MulDiv rounds half away from 0
            self.stack.append(Num(v, 'pt(%s)%s' % (x, ('{=%dpx@96dpi}' % v) if v is not None else '')))
            return
        if op == 0x2a:                               # FUN_100c42ad
            x = self.popn()
            self.stack.append(Num(None, 'ptf(%s)' % x))
            return
        if op == 0x2b:                               # FUN_100c46c2 -> FUN_100ecdce
            x = self.popn().lit()
            if x >= 0:
                self.stack.append(Num(None, 'sysmetric(SM_%d)' % x))
            else:
                self.stack.append(Num(None, 'sysmetric(%s)' % SYSMETRIC_NEG.get(x, x)))
            return
        if op == 0x2c:                               # FUN_100c4700 -> FUN_100ecfff
            x = self.popn().lit()
            self.stack.append(Val('string', 'sysfontface(%s)' % SYSFONT.get(x, x)))
            return
        if op == 0x2d:                               # FUN_100c22c4 high-contrast select
            hc = self.pop(Val); normal = self.pop(Val)
            self.stack.append(Val(normal.kind, 'hc(%s,%s)' % (normal, hc), extra={'normal': normal, 'hc': hc}))
            return
        if op == 0x2e:                               # FUN_100c47ca
            raise UIBError('setreg at %#x (unused in corpus)' % self.ip)
        raise UIBError('unhandled opcode %#x' % op)

    # sub-dispatchers ------------------------------------------------------
    def mkvalue(self, t):
        """FUN_100c3583: sub-type popped from stack"""
        P = self.popn
        if t == 1:   # FUN_100c3db6 CreateInt
            return Val('int', str(P()), extra={'num': None})
        if t == 2:   # FUN_100c385f CreateBool
            n = P(); return Val('bool', ('true' if n.lit() else 'false'))
        if t == 5:   # FUN_100c41b9 CreateString(pool)
            return Val('string', self.pstr(), extra={'literal': True})
        if t == 6:   # FUN_100c3f7d CreatePoint(x,y)
            x = P(); y = P(); return Val('point', 'point(%s,%s)' % (x, y))
        if t == 7:   # FUN_100c4134 CreateSize(cx,cy)
            x = P(); y = P(); return Val('size', 'size(%s,%s)' % (x, y))
        if t == 8:   # FUN_100c407a CreateRect(l,t,r,b)
            a = [P() for _ in range(4)]
            return Val('rect', 'rect(%s)' % ','.join(map(str, a)))
        if t == 9:   # FUN_100c3a7f CreateColor
            fl = P().lit(); c = [P()]
            for bit in (1, 2, 4):
                if fl & bit:
                    c.append(P())
            if len(c) == 1 and fl == 0:
                return Val('color', color_text(c[0]), extra={'raw': c[0]})
            return Val('color', 'fill(type=%d,%s%s)' % ((fl >> 8) & 0xff, ','.join(color_text(x) for x in c),
                                                    (',angle=%d' % (fl >> 16)) if fl >> 16 else ''))
        if t == 10:  # FUN_100c3e24 CreateLayout(pop layout)
            return Val('layout', str(self.pop(Layout)))
        if t == 11:  # FUN_100c3c6f CreateGraphic(path, blendmode u8, blendvalue, cx u16, cy u16, x, flags)
            s = self.pstr(); bm = P(); bv = P(); cx = P(); cy = P(); x4 = P(); fl = P()
            return Val('graphic', 'graphic(%s,mode=%s,value=%s,size=%s,%s,arg=%s,flags=%s)' % (s, bm, bv, cx, cy, x4, fl))
        if t == 13:  # FUN_100c37e7 CreateAtom
            return Val('atom', self.pstr())
        if t == 15:  # FUN_100c4002 CreateRLE(pool string)
            return Val('rle', 'rle(%s)' % self.pstr())
        if t == 16:  # FUN_100c4243 pvUnknownNull
            return Val('null', 'null')
        if t == 17:  # FUN_100c3bf7 CreateGUID
            return Val('guid', 'guid(%s)' % self.pstr())
        if t == 18:  # FUN_100c3e9d value list
            n = P().lit(); vs = [self.pop(Val) for _ in range(n)]
            return Val('list', 'list(%s)' % ','.join(map(str, vs)))
        if t == 19:  # FUN_100c38cb CreateColorize
            return Val('colorize', 'colorize(%s)' % color_text(P()))
        if t == 20:  # FUN_100c3939 CreateDFC
            a = P(); b = P(); return Val('dfc', 'dfc(%s,%s)' % (a, b))
        if t == 21:  # FUN_100c39be CreateDTB
            a = P(); b = P(); c = P(); v = self.pval_or_zero()
            return Val('dtb', 'dtb(%s,%s,%s,%s)' % (a, b, c, v if v else 'null'))
        if t == 22:  # FUN_100c36f8 CreateAnimation
            a = P(); v1 = self.pop(Val); v2 = self.pop(Val); b = P()
            return Val('anim', 'animation(%s,%s,%s,%s)' % (a, v1, v2, b))
        if t == 23:  # FUN_100c3b85 CreateFloat: the stack slot's 32 bits are reinterpreted (movss)
            n = P()
            if n.expr is None:
                return Val('float', 'float(%g)' % struct.unpack('<f', struct.pack('<I', n.val & 0xffffffff))[0])
            return Val('float', 'floatbits(%s)' % n)
        if t == 26:  # FUN_100c422c pvStringNull
            return Val('string', '', extra={'nullstring': True})
        raise UIBError('unknown mkvalue sub-type %d at %#x' % (t, self.ip))

    def mklayout(self, t):
        """FUN_100c2f02"""
        P = self.popn
        if t == 1:
            return Layout('BorderLayout()')              # FUN_100c0943
        if t == 2:
            return Layout('FillLayout()')                # FUN_100c09a4
        if t == 3:                                       # FUN_100c1849 FlowLayout(a,b,c,d)
            a = [P() for _ in range(4)]
            return Layout('FlowLayout(%s)' % ','.join(map(str, a)))
        if t == 4:                                       # FUN_100c1919 GridLayout(rows,cols)
            a = [P() for _ in range(2)]
            return Layout('GridLayout(%s)' % ','.join(map(str, a)))
        if t == 5:                                       # FUN_100c1adc TableLayout
            a = P(); b = P(); f = P(); n = a.lit() + b.lit()
            xs = [P() for _ in range(n)]
            return Layout('TableLayout(%s,%s,%s,[%s])' % (a, b, f, ','.join(map(str, xs))))
        if t == 6:
            return Layout('NineGridLayout()')            # FUN_100c0a05
        if t == 7:                                       # FUN_100c19b1 RowLayout(a,b,n x 3 ints)
            a = P(); b = P(); n = P().lit()
            xs = [P() for _ in range(3 * n)]
            return Layout('RowLayout(%s,%s,[%s])' % (a, b, ','.join(map(str, xs))))
        raise UIBError('unknown layout sub-type %d' % t)

    def resvalue(self, t):
        """FUN_100c3086: module (pool string via FUN_100c4367) then resource id (u16) then extra args"""
        P = self.popn
        if t not in RES_KIND:
            raise UIBError('unknown resvalue sub-type %d' % t)
        mod = self.pstr()
        rid = P().lit() & 0xffff
        kind = RES_KIND[t]
        args = ''
        if t == 2:     # FUN_100c28ec graphic: blendmode u8, blendvalue, cx u16, cy u16, flags u8
            bm = P(); bv = P(); cx = P(); cy = P(); fl = P()
            args = ',mode=%s,value=%s,size=%s,%s,flags=%s' % (bm, bv, cx, cy, fl)
        elif t == 10:  # FUN_100c2ce8 icon: cx u16, cy u16, flags u8
            cx = P(); cy = P(); fl = P()
            args = ',size=%s,%s,flags=%s' % (cx, cy, fl)
        elif t in (3, 8):  # FUN_100c2e79 int: bool -> pushes an *int*
            asch = P()
            an = self.res.annotate('int', mod, rid)
            v = None
            if an is not None and not asch.lit():
                try:
                    v = int(an.strip(), 0)
                except ValueError:
                    v = None
            return Num(v, 'resint(%d%s%s)%s' % (rid, (',module=' + mod) if mod else '', ',char' if asch.lit() else '',
                                               ('{=%s}' % an) if an is not None else ''))
        txt = 'res.%s(%d%s%s)' % (kind, rid, (',module=' + mod) if mod else '', args)
        return Val('res:' + kind, txt + self.annot(kind, mod, rid), extra={'rid': rid, 'rkind': kind})

    def annot(self, kind, mod, rid):
        c = self.res.annotate(kind, mod, rid)
        return ('{=%s}' % c) if c is not None else ''

    def resref(self, k):
        """FUN_100c3016 -> FUN_100c2095 (cached per index)"""
        u = self.u
        if not 0 <= k < len(u.resources):
            raise UIBError('resource index %d out of range' % k)
        r = u.resources[k]
        r['used'] = True
        kind = {1: 'string', 4: 'color', 5: 'colorize', 6: 'image', 7: 'image', 9: 'rect', 11: 'cursor',
                13: 'float'}.get(r['type'])
        if kind is None:
            raise UIBError('resource type %d not accepted by FUN_100c2095' % r['type'])
        mod = u.string(r['module'])
        txt = 'res.%s(%d%s)' % (kind, r['id'], (',module=' + mod) if mod else '')
        return Val('res:' + kind, txt + self.annot(kind, mod, r['id']), extra={'rid': r['id'], 'rkind': kind})

    def bind(self):
        """FUN_100c270f"""
        u = self.u
        fl = self.popn().lit()
        n = fl & 0x1f
        if n == 0:
            raise UIBError('binding without path')
        path = [None] * n
        for i in range(n):
            path[n - 1 - i] = self.pstr()
        dv = self.pop(Val) if fl & 0x80 else None
        idx = self.popn() if fl & 0x40 else None
        pi = self.popn().lit()
        e = self.peek_elem()
        x = '<Binding property=%s path=%s' % (quoteattr(u.props[pi]), quoteattr('.'.join(path)))
        if fl & 0x20:
            x += ' twoway="true"'
        if idx is not None:
            x += ' index=%s' % quoteattr(str(idx))
        if dv is not None:
            x += ' default=%s' % quoteattr(str(dv))
        if fl & ~0xff:
            x += ' flags=%s' % quoteattr(h(fl))
        e.extras.append(x + '/>')

    def mksheet(self):
        """FUN_100c32a8 -> PropertySheet rules, each added with FUN_100b4d1e(class, conds, decls).
        Per rule (popped): class index; nDecl; nDecl x FUN_100c320c {prop, Value} (8-byte Decl);
        nCond; nCond x FUN_100c315b {prop, int op, Value} (12-byte Cond).  Rules are popped and added
        top-of-stack first; 'order' below is that runtime insertion order."""
        u = self.u
        P = self.popn
        nrules = P().lit()
        rules = []
        for ri in range(nrules):
            cls = u.classes[P().lit()]                   # FUN_100c1f1d class index
            nd = P().lit()
            decls = []
            for _ in range(nd):                          # FUN_100c320c
                pi = P().lit(); v = self.pop(Val)
                decls.append((u.props[pi], v))
            nc = P().lit()
            conds = []
            for _ in range(nc):                          # FUN_100c315b
                pi = P().lit(); opn = P(); v = self.pop(Val)
                conds.append((u.props[pi], opn, v))
            rules.append((cls, conds, decls))   # all lists kept in pop (= runtime) order
        lines = ['<Sheet rules="%d">' % nrules]
        for i, (cls, conds, decls) in enumerate(rules):
            sel = cls + ''.join('[%s%s%s]' % (n, CONDOP.get(o.val, '?%s?' % o) if o.expr is None else '?%s?' % o, v)
                                for n, o, v in conds)
            lines.append('  <Rule order="%d" selector=%s>' % (i, quoteattr(sel)))
            for n, o, v in conds:
                lines.append('    <If property=%s op="%s" value=%s/>' % (quoteattr(n), o, quoteattr(str(v))))
            for n, v in decls:
                lines.append('    <Set property=%s value=%s/>' % (quoteattr(n), quoteattr(str(v))))
            lines.append('  </Rule>')
        lines.append('</Sheet>')
        return Val('sheet', 'sheet(%d rules)' % nrules, xml=lines)


CONDOP = {0: '=', 1: '!=', 2: '&'}   # FUN_100b4fdb: 0 IsEqual, 1 !IsEqual, 2 Value::BitwiseAnd


# --------------------------------------------------------------------------- XML output
def emit_elem(e, ind, out):
    sp = '  ' * ind
    attrs = []
    complex_ = []
    for n, v in e.props:
        if v.kind == 'error':
            complex_.append((n, v))
        elif v.xml:
            complex_.append((n, v))
        else:
            attrs.append('%s=%s' % (n, quoteattr(str(v))))
    head = '%s<%s%s' % (sp, e.cls, ''.join(' ' + a for a in attrs))
    head += ' _at="%s"' % h(e.addr)
    if not (complex_ or e.extras or e.children):
        out.append(head + '/>')
        return
    out.append(head + '>')
    for n, v in complex_:
        if v.kind == 'error':
            out.append('%s  <Property name=%s _error="no value compiled; runtime SetValue fails (E_FAIL), entry aborts"/>' % (sp, quoteattr(n)))
            continue
        out.append('%s  <Property name=%s>' % (sp, quoteattr(n)))
        for l in v.xml:
            out.append('%s    %s' % (sp, l))
        out.append('%s  </Property>' % sp)
    for x in e.extras:
        out.append('%s  %s' % (sp, x))
    for c in e.children:
        emit_elem(c, ind + 1, out)
    out.append('%s</%s>' % (sp, e.cls))


def decompile(data, resdir=None, name='', asm=False):
    u = UIB(data)
    ins = disassemble(u)
    for a in range(u.code0, u.code1):
        u.consumed[a] = 1
    vm = VM(u, ins, Resolver(resdir))
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           '<!-- decompiled by uib2xml.py; values: dpi(x)=MulDiv(x,dpi,96), pt(x)=-MulDiv(x,dpi,72), '
           'hc(normal,highcontrast), pt(x) shows the 96-DPI result, res.kind(id[,module]) = resource-manager reference, {=...} = value read from the install (annotation only) -->',
           '<uib resource=%s version="%d">' % (quoteattr(name), u.ver)]
    out.append('  <classes>' + ''.join('<c i="%d" n=%s/>' % (i, quoteattr(c)) for i, c in enumerate(u.classes)) + '</classes>')
    out.append('  <properties>' + ''.join('<p i="%d" n=%s/>' % (i, quoteattr(c)) for i, c in enumerate(u.props)) + '</properties>')
    # fragments first (they are referenced by op 0x1c)
    frag_xml = []
    for k, off in enumerate(u.fragments):
        st = vm.run(u.code0 + off)
        if len(st) != 1 or not isinstance(st[0], Val):
            raise UIBError('fragment %d did not leave exactly one Value (stack %r)' % (k, [type(x).__name__ for x in st]))
        vm.frag_cache[k] = st[0]
        v = st[0]
        frag_xml.append('    <fragment index="%d" _at="%s" kind="%s"%s' % (k, h(u.code0 + off), v.kind,
                        '>' if v.xml else ' value=%s/>' % quoteattr(str(v))))
        if v.xml:
            frag_xml += ['      ' + l for l in v.xml] + ['    </fragment>']
    ent_xml = []
    for nm, off in u.entries:
        st = vm.run(u.code0 + off)
        ent_xml.append('    <entry name=%s _at="%s">' % (quoteattr(nm), h(u.code0 + off)))
        for x in st:
            if isinstance(x, Elem):
                emit_elem(x, 3, ent_xml)
            else:
                ent_xml.append('      <leftover value=%s/>' % quoteattr(str(x)))
        ent_xml.append('    </entry>')
    # orphan blocks: code not reachable from any entry/fragment (duplicate definitions whose names the
    # compiler dropped from the entry table).  Each starts right after a 'ret'.
    orph_xml = []
    while True:
        left = sorted(set(ins) - vm.executed)
        if not left:
            break
        a0 = left[0]
        st = vm.run(a0)
        orph_xml.append('    <orphan _at="%s">' % h(a0))
        for x in st:
            if isinstance(x, Elem):
                emit_elem(x, 3, orph_xml)
            else:
                orph_xml.append('      <leftover value=%s/>' % quoteattr(str(x)))
        orph_xml.append('    </orphan>')
    # resources table (after execution so that "used" is known)
    out.append('  <resources>')
    for i, r in enumerate(u.resources):
        kind = {1: 'string', 4: 'color', 5: 'colorize', 6: 'image', 7: 'image', 9: 'rect', 11: 'cursor', 13: 'float'}.get(r['type'], 'type%d' % r['type'])
        an = vm.annot(kind, u.string(r['module']), r['id'])
        out.append('    <r i="%d" kind="%s" type="%d" id="%d"%s%s%s/>' % (
            i, kind, r['type'], r['id'], (' module=%s' % quoteattr(u.string(r['module']))) if r['module'] else '',
            (' w2="%d" w6="%d"' % (r['w2'], r['w6'])) if (r['w2'] or r['w6']) else '',
            (' resolved=%s' % quoteattr(an[2:-1])) if an else ''))
    out.append('  </resources>')
    out.append('  <fragments>')
    out += frag_xml
    out.append('  </fragments>')
    out.append('  <entries>')
    out += ent_xml
    out.append('  </entries>')
    if orph_xml:
        out.append('  <orphans>')
        out += orph_xml
        out.append('  </orphans>')
    if vm.errors:
        out.append('  <!-- runtime-error sites: %s -->' % '; '.join(vm.errors).replace('--', '-'))
    if asm:
        out.append('  <disassembly><![CDATA[')
        for a in sorted(ins):
            op, arg, ln = ins[a]
            out.append('%06x  %-12s %s' % (a, OPNAME[op], '' if arg is None else arg))
        out.append(']]></disassembly>')
    out.append('</uib>')
    # coverage
    cov = dict(
        bytes_total=len(data), bytes_unconsumed=len(data) - sum(u.consumed),
        instructions=len(ins), instructions_unexecuted=len(set(ins) - vm.executed), orphans=len(orph_xml) and sum(1 for l in orph_xml if l.startswith('    <orphan')),
        errors=vm.errors,
        unexecuted_addrs=sorted(set(ins) - vm.executed)[:10],
        resources_unused=[i for i, r in enumerate(u.resources) if not r.get('used')],
        pool_unreferenced=u.pool_coverage(),
        opstats=vm.stats,
    )
    return '\n'.join(out) + '\n', cov


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('inp')
    ap.add_argument('outdir', nargs='?')
    ap.add_argument('-o')
    ap.add_argument('--all', action='store_true')
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--asm', action='store_true')
    ap.add_argument('--targets', default=DEFAULT_TARGETS if os.path.isdir(DEFAULT_TARGETS) else None,
                    help='folder with the Windows Live install (for resource annotations); "none" disables')
    a = ap.parse_args()
    files = sorted(glob.glob(os.path.join(a.inp, '*.bin'))) if (a.all or a.check) else [a.inp]
    bad = 0
    tot = {}
    for f in files:
        rid = os.path.basename(f).split('_')[0]
        try:
            xml, cov = decompile(open(f, 'rb').read(), None if a.targets in (None, 'none') else a.targets, rid, a.asm)
        except UIBError as e:
            print('%s: FAIL %s' % (rid, e)); bad += 1; continue
        for k, v in cov['opstats'].items():
            tot[k] = tot.get(k, 0) + v
        ok = cov['bytes_unconsumed'] == 0 and cov['instructions_unexecuted'] == 0
        if a.check or a.all:
            print('%-6s bytes=%6d unconsumed=%d instr=%5d unexecuted=%d orphans=%d rt_errors=%d res_unused=%d pool_unref=%d %s' % (
                rid, cov['bytes_total'], cov['bytes_unconsumed'], cov['instructions'],
                cov['instructions_unexecuted'], cov['orphans'], len(cov['errors']), len(cov['resources_unused']), len(cov['pool_unreferenced']),
                'OK' if ok else 'GAP'))
            if cov['pool_unreferenced']:
                print('        unreferenced pool strings: %s' % cov['pool_unreferenced'][:8])
            if cov['resources_unused']:
                print('        unused resource records: %s' % cov['resources_unused'][:12])
        if not ok:
            bad += 1
        if a.all and not a.check:
            open(os.path.join(a.outdir, rid + '.xml'), 'w', encoding='utf-8').write(xml)
        elif not (a.all or a.check):
            if a.o:
                open(a.o, 'w', encoding='utf-8').write(xml)
            else:
                sys.stdout.write(xml)
    if a.check or a.all:
        print('opcode use: ' + ' '.join('%s=%d' % (OPNAME[k], v) for k, v in sorted(tot.items())))
        print('files with gaps/failures: %d' % bad)
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
