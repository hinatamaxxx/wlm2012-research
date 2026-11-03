# Minimal PNG reader (8-bit RGB/RGBA, non-interlaced) and RGBA writer. No dependencies.
import struct, zlib


def write_png(path, w, h, rows):
    """rows: list of h lists of (r,g,b,a)."""
    raw = bytearray()
    for row in rows:
        raw.append(0)
        for px in row:
            raw.extend(px)
    def chunk(t, b):
        return struct.pack('>I', len(b)) + t + b + struct.pack('>I', zlib.crc32(t + b) & 0xffffffff)
    data = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)) + \
        chunk(b'IDAT', zlib.compress(bytes(raw), 9)) + chunk(b'IEND', b'')
    open(path, 'wb').write(data)


def png_info(d):
    w, h, bd, ct, cm, fm, il = struct.unpack('>IIBBBBB', d[16:29])
    chunks = []
    p = 8
    while p < len(d):
        n, = struct.unpack('>I', d[p:p + 4])
        t = d[p + 4:p + 8].decode('latin-1')
        body = d[p + 8:p + 8 + n]
        chunks.append((t, body))
        p += 12 + n
    info = dict(width=w, height=h, bit_depth=bd, color_type=ct, interlace=il,
                chunks=[t for t, _ in chunks])
    for t, body in chunks:
        if t == 'pHYs':
            x, y, u = struct.unpack('>IIB', body)
            info['pHYs'] = dict(x=x, y=y, unit=u, dpi_x=round(x * 0.0254) if u == 1 else None)
        elif t == 'tEXt':
            k, _, v = body.partition(b'\0')
            info.setdefault('text', {})[k.decode('latin-1')] = v.decode('latin-1')
    return info, chunks


def read_png(d):
    info, chunks = png_info(d)
    w, h, ct = info['width'], info['height'], info['color_type']
    assert info['bit_depth'] == 8 and info['interlace'] == 0 and ct in (2, 6), info
    bpp = 4 if ct == 6 else 3
    raw = zlib.decompress(b''.join(b for t, b in chunks if t == 'IDAT'))
    stride = w * bpp
    rows = []
    prev = bytearray(stride)
    p = 0
    for y in range(h):
        f = raw[p]; p += 1
        cur = bytearray(raw[p:p + stride]); p += stride
        for i in range(stride):
            a = cur[i - bpp] if i >= bpp else 0
            b = prev[i]
            c = prev[i - bpp] if i >= bpp else 0
            if f == 1:
                cur[i] = (cur[i] + a) & 255
            elif f == 2:
                cur[i] = (cur[i] + b) & 255
            elif f == 3:
                cur[i] = (cur[i] + ((a + b) >> 1)) & 255
            elif f == 4:
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                cur[i] = (cur[i] + pr) & 255
        rows.append([tuple(cur[x * bpp:x * bpp + bpp]) + ((255,) if bpp == 3 else ()) for x in range(w)])
        prev = cur
    return w, h, rows
