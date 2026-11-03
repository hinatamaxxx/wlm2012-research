# Minimal PE32 reader: sections, VA->file offset, resource tree walk. No dependencies.
import struct

class PE:
    def __init__(self, path):
        self.data = d = open(path, 'rb').read()
        pe = struct.unpack_from('<I', d, 0x3c)[0]
        assert d[pe:pe + 4] == b'PE\0\0'
        nsec, = struct.unpack_from('<H', d, pe + 6)
        optsz, = struct.unpack_from('<H', d, pe + 20)
        opt = pe + 24
        magic, = struct.unpack_from('<H', d, opt)
        assert magic == 0x10b, 'PE32 only'
        self.imagebase, = struct.unpack_from('<I', d, opt + 28)
        ddir = opt + 96
        self.res_rva, self.res_size = struct.unpack_from('<II', d, ddir + 2 * 8)
        self.sections = []
        s = opt + optsz
        for i in range(nsec):
            name = d[s:s + 8].rstrip(b'\0').decode()
            vsz, va, rsz, raw = struct.unpack_from('<IIII', d, s + 8)
            self.sections.append((name, va, max(vsz, rsz), raw, rsz))
            s += 40

    def rva2off(self, rva):
        for name, va, sz, raw, rsz in self.sections:
            if va <= rva < va + sz:
                return raw + rva - va
        raise ValueError(hex(rva))

    def va2off(self, va):
        return self.rva2off(va - self.imagebase)

    def read_va(self, va, n):
        o = self.va2off(va)
        return self.data[o:o + n]

    def _name(self, off):
        n, = struct.unpack_from('<H', self.data, off)
        return self.data[off + 2:off + 2 + 2 * n].decode('utf-16le')

    def resources(self):
        """Yield (type, name, lang, file_offset, size); ids are ints, named entries are str."""
        d = self.data
        base = self.rva2off(self.res_rva)

        def entries(doff):
            nn, ni = struct.unpack_from('<HH', d, doff + 12)
            for i in range(nn + ni):
                nm, tgt = struct.unpack_from('<II', d, doff + 16 + 8 * i)
                key = self._name(base + (nm & 0x7fffffff)) if nm & 0x80000000 else nm
                yield key, tgt

        for t, t1 in entries(base):
            for n, t2 in entries(base + (t1 & 0x7fffffff)):
                for l, t3 in entries(base + (t2 & 0x7fffffff)):
                    rva, size = struct.unpack_from('<II', d, base + t3)
                    yield t, n, l, self.rva2off(rva), size

    def resource_map(self, typ):
        return {n: self.data[o:o + s] for t, n, l, o, s in self.resources() if t == typ}
