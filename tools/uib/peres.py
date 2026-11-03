"""Minimal PE resource reader (read-only) used by uib2xml.py to annotate resource references."""
import struct


class PERes:
    def __init__(self, path):
        d = self.d = open(path, 'rb').read()
        pe = struct.unpack_from('<I', d, 0x3c)[0]
        if d[pe:pe + 4] != b'PE\0\0':
            raise ValueError('not PE')
        nsec = struct.unpack_from('<H', d, pe + 6)[0]
        opt = struct.unpack_from('<H', d, pe + 20)[0]
        magic = struct.unpack_from('<H', d, pe + 24)[0]
        dd = pe + 24 + (96 if magic == 0x10b else 112)
        self.rsrc_rva = struct.unpack_from('<I', d, dd + 2 * 8)[0]
        self.secs = []
        for i in range(nsec):
            o = pe + 24 + opt + 40 * i
            vs, va, rs, ra = struct.unpack_from('<IIII', d, o + 8)
            self.secs.append((va, max(vs, rs), ra))
        self.base = self.off(self.rsrc_rva)
        self.tree = self._dir(0, 0)

    def off(self, rva):
        for va, sz, ra in self.secs:
            if va <= rva < va + sz:
                return ra + rva - va
        raise ValueError('rva %#x' % rva)

    def _dir(self, o, depth):
        d = self.d
        p = self.base + o
        nn, ni = struct.unpack_from('<HH', d, p + 12)
        out = {}
        for i in range(nn + ni):
            name, tgt = struct.unpack_from('<II', d, p + 16 + 8 * i)
            if name & 0x80000000:
                q = self.base + (name & 0x7fffffff)
                ln = struct.unpack_from('<H', d, q)[0]
                key = d[q + 2:q + 2 + 2 * ln].decode('utf-16le')
            else:
                key = name
            if tgt & 0x80000000:
                out[key] = self._dir(tgt & 0x7fffffff, depth + 1)
            else:
                rva, sz = struct.unpack_from('<II', d, self.base + tgt)
                out[key] = self.d[self.off(rva):self.off(rva) + sz]
        return out

    def get(self, typ, rid, lang=None):
        t = self.tree.get(typ)
        if not t or rid not in t:
            return None
        langs = t[rid]
        if lang in langs:
            return langs[lang]
        return next(iter(langs.values()))

    def string(self, sid):
        """RT_STRING: block (sid>>4)+1, entry sid&15"""
        b = self.get(6, (sid >> 4) + 1)
        if b is None:
            return None
        p = 0
        for i in range(16):
            ln = struct.unpack_from('<H', b, p)[0]
            s = b[p + 2:p + 2 + 2 * ln].decode('utf-16le')
            if i == (sid & 15):
                return s if ln else None
            p += 2 + 2 * ln
        return None
