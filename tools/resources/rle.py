# Decoder for uxcore "RLE\x01" bitmaps (mailres2 type 4000 tag 'R', and type 4006 entries).
# Reimplemented from uxcore.dll: header accessors 0x10031e65/0x10031f09/0x10031f9e/0x10031fc8/
# 0x10032088/0x100320b3/0x10032172/0x10032204/0x100321d7/0x10031ecf, part draw 0x100eaa40,
# row decoders 0x100cdcb0 (8-bit) / 0x100cd5d0 (5-bit), run decoders 0x100cb500 / 0x100cb2c0,
# alpha run decoder 0x100cb210 and alpha blitter 0x100c8f80, palette mapping 0x100ea530/0x100ea810.
import struct

GRID_PARTS = [1, 2, 2, 4, 2, 3, 4, 6, 2, 4, 3, 6, 4, 6, 6, 9]  # table at 0x1003219f, index = margin mask

# Windows 7 (Aero) default GetSysColor values, index -> (R,G,B). Used for system-colour palette parts.
SYSCOLORS = {
    0: (0xC8, 0xC8, 0xC8), 1: (0x00, 0x00, 0x00), 2: (0x99, 0xB4, 0xD1), 3: (0xBF, 0xCD, 0xDB),
    4: (0xF0, 0xF0, 0xF0), 5: (0xFF, 0xFF, 0xFF), 6: (0x64, 0x64, 0x64), 7: (0x00, 0x00, 0x00),
    8: (0x00, 0x00, 0x00), 9: (0x00, 0x00, 0x00), 10: (0xB4, 0xB4, 0xB4), 11: (0xF4, 0xF7, 0xFC),
    12: (0xAB, 0xAB, 0xAB), 13: (0x33, 0x99, 0xFF), 14: (0xFF, 0xFF, 0xFF), 15: (0xF0, 0xF0, 0xF0),
    16: (0xA0, 0xA0, 0xA0), 17: (0x6D, 0x6D, 0x6D), 18: (0x00, 0x00, 0x00), 19: (0x43, 0x4E, 0x54),
    20: (0xFF, 0xFF, 0xFF), 21: (0x69, 0x69, 0x69), 22: (0xE3, 0xE3, 0xE3), 23: (0x00, 0x00, 0x00),
    24: (0xFF, 0xFF, 0xE1), 25: (0x00, 0x00, 0x00), 26: (0x00, 0x66, 0xCC), 27: (0xB9, 0xD1, 0xEA),
    28: (0xD7, 0xE4, 0xF2), 29: (0x33, 0x99, 0xFF), 30: (0xF0, 0xF0, 0xF0),
}
SYSCOLOR_NAMES = ['COLOR_SCROLLBAR', 'COLOR_BACKGROUND', 'COLOR_ACTIVECAPTION', 'COLOR_INACTIVECAPTION',
                  'COLOR_MENU', 'COLOR_WINDOW', 'COLOR_WINDOWFRAME', 'COLOR_MENUTEXT', 'COLOR_WINDOWTEXT',
                  'COLOR_CAPTIONTEXT', 'COLOR_ACTIVEBORDER', 'COLOR_INACTIVEBORDER', 'COLOR_APPWORKSPACE',
                  'COLOR_HIGHLIGHT', 'COLOR_HIGHLIGHTTEXT', 'COLOR_BTNFACE', 'COLOR_BTNSHADOW',
                  'COLOR_GRAYTEXT', 'COLOR_BTNTEXT', 'COLOR_INACTIVECAPTIONTEXT', 'COLOR_BTNHIGHLIGHT',
                  'COLOR_3DDKSHADOW', 'COLOR_3DLIGHT', 'COLOR_INFOTEXT', 'COLOR_INFOBK', '(unused 25)',
                  'COLOR_HOTLIGHT', 'COLOR_GRADIENTACTIVECAPTION', 'COLOR_GRADIENTINACTIVECAPTION',
                  'COLOR_MENUHILIGHT', 'COLOR_MENUBAR']


class RLEError(Exception):
    pass


class Bits:
    """LSB-first bit reader; mirrors the (ptr, bitpos) state of the uxcore decoders (u16 window)."""
    def __init__(self, data, pos):
        self.d = data
        self.p = pos
        self.b = 0

    def read(self, n):
        lo = self.d[self.p] if self.p < len(self.d) else 0
        hi = self.d[self.p + 1] if self.p + 1 < len(self.d) else 0
        v = ((lo | hi << 8) >> self.b) & ((1 << n) - 1)
        self.b += n
        if self.b > 7:
            self.p += 1
        self.b &= 7
        return v

    def end(self):
        return self.p + (1 if self.b else 0)


def parse_header(d):
    if d[:3] != b'RLE':
        raise RLEError('no RLE magic')
    frames = d[3] & 0x7f
    lensize = (d[4] & 3) + 1
    mask = (d[4] >> 2) & 0xf
    parts = GRID_PARTS[mask]
    dpicode = d[5] & 7
    entries = []
    p = 6
    for i in range(frames * parts):
        ln = int.from_bytes(d[p:p + lensize], 'little')
        entries.append((p + lensize, ln))
        p += lensize + ln
    return dict(version=d[3] >> 7, frames=frames, lensize=lensize, margin_mask=mask, parts_per_frame=parts,
                dpi=None if dpicode == 7 else (dpicode + 4) * 24, dpi_code=dpicode,
                header_byte3=d[3], header_byte4=d[4], header_byte5=d[5],
                entries=entries, end=p, trailing=len(d) - p)


def part_header(u):
    return dict(palette=bool(u & 1), bits8=bool(u & 2), no_rtl_mirror=bool(u & 4),
                width=(u >> 3) & 0x1fff, alpha=bool(u & 0x10000), syscolor=bool(u & 0x20000),
                offset_size=((u >> 18) & 3) + 1, height=u >> 20)


def run_bits(width):
    c = min(width, 255) if width <= 255 else 255
    b = ((c - 1) & 0xff) >> 1
    n = 1
    while b:
        n += 1
        b >>= 1
    return n


def decode_part(d, start, length, stats=None):
    """Return (header, rows) where rows is a list of lists of (r,g,b,a)."""
    u, = struct.unpack_from('<I', d, start)
    h = part_header(u)
    w, ht, osz = h['width'], h['height'], h['offset_size']
    if w == 0 or ht == 0:
        return h, []
    nb = run_bits(w)
    tbl = start + 4
    chan_bits = 8 if h['bits8'] else 5
    paletted = h['palette'] or h['syscolor']
    end_limit = start + length
    rows = []
    for y in range(ht):
        if y == 0:
            p = tbl + (ht - 1) * osz
        else:
            e = tbl + (y - 1) * osz
            p = e + int.from_bytes(d[e:e + osz], 'little')
        br = Bits(d, p)
        nplanes = (2 if chan_bits == 8 else 1) if paletted else 3
        planes = [[] for _ in range(nplanes)]

        def run(out):
            op = br.read(2)
            cnt = br.read(nb) + 1
            if op == 0:
                v = br.read(chan_bits)
                if chan_bits == 5:
                    v <<= 3
                out.extend([v] * cnt)
            elif op == 3:
                for _ in range(cnt):
                    v = br.read(chan_bits)
                    out.append(v << 3 & 0xff if chan_bits == 5 else v)
            else:
                k = br.read(3) + 1
                if not out:
                    if stats is not None:
                        stats['delta_at_row_start'] = stats.get('delta_at_row_start', 0) + 1
                prev = out[-1] if out else 0
                for _ in range(cnt):
                    dv = br.read(k)
                    if chan_bits == 5:
                        dv *= 8
                    prev = (prev - dv) & 0xff if op == 2 else (prev + dv) & 0xff
                    out.append(prev)

        alpha = []
        if h['alpha']:
            pos = 0
            skip = 0
            aend = 0
            while pos < w:
                if pos >= aend:
                    op = br.read(2)
                    if op == 1:
                        # explicit alpha values: an ordinary channel run into the alpha buffer
                        run(alpha)
                        aend = len(alpha)
                    else:
                        cnt = br.read(nb) + 1
                        if op == 3 and stats is not None:
                            stats['alpha_op3'] = stats.get('alpha_op3', 0) + 1
                        alpha.extend([0xff if op == 2 else 0] * cnt)
                        aend = len(alpha)
                        if op == 0:
                            newpos = min(aend, w)
                            skip += newpos - pos
                            pos = newpos
                            continue
                for i in range(len(planes)):
                    if len(planes[i]) + skip <= pos:
                        run(planes[i])
                ends = [len(pl) + skip for pl in planes] + [aend, w]
                pos = min(ends)
        else:
            pos = 0
            while pos < w:
                for i in range(len(planes)):
                    if len(planes[i]) <= pos:
                        run(planes[i])
                pos = min(len(pl) for pl in planes)
        # row consumption check against next row's offset
        if y + 1 < ht:
            e = tbl + y * osz
            nxt = e + int.from_bytes(d[e:e + osz], 'little')
            if br.end() != nxt:
                raise RLEError(f'row {y}: consumed to {br.end()} expected {nxt}')
        else:
            if br.end() > end_limit:
                raise RLEError(f'last row overruns entry ({br.end()} > {end_limit})')
            if stats is not None:
                stats['slack'] = stats.get('slack', 0) + (end_limit - br.end())
        # assemble raw pixels: (c0, c1, c2, alpha) in the part's native mode (see to_rgba)
        row = []
        ci = 0
        for x in range(w):
            a = alpha[x] if h['alpha'] else 0xff
            if h['alpha'] and a == 0:
                row.append((0, 0, 0, 0))
                continue
            if paletted:
                if chan_bits == 8:
                    row.append((planes[0][ci], planes[1][ci], 0, a))
                else:
                    row.append((planes[0][ci] >> 3, planes[0][ci], 0, a))
            else:
                row.append((planes[0][ci], planes[1][ci], planes[2][ci], a))
            ci += 1
        rows.append(row)
    h['mode'] = ('syscolor' if h['syscolor'] else 'sl') if paletted else 'rgb_premultiplied'
    if stats is not None:
        k = 'mode_%s_%dbit' % (h['mode'], chan_bits)
        stats[k] = stats.get(k, 0) + 1
    return h, rows


def to_rgba(px, hdr, colorize=None):
    """Convert a raw decoded pixel to straight-alpha RGBA.
    rgb_premultiplied: un-premultiply (blit at 0x100c8f80 adds dst*(255-a) to the stored colour).
    sl: 8-bit (S*255, L) pair indexing the colorize palette built by 0x100ec2d8: RGB = HSL(hue(colorize), S, L).
        Without a (non-grey) colorize colour the palette pointer is NULL and 0x100ea530 outputs grey L.
    syscolor: index into GetSysColor table (5-bit: value>>3)."""
    c0, c1, c2, a = px
    if a == 0:
        return (0, 0, 0, 0)
    m = hdr['mode']
    if m == 'raw':
        return px
    if m == 'rgb_premultiplied':
        if a == 255:
            return (c0, c1, c2, a)
        return tuple(min(255, (c * 255 + a // 2) // a) for c in (c0, c1, c2)) + (a,)
    if m == 'sl':
        if colorize is None:
            return (c1, c1, c1, a)
        import colorize as cz
        r, g, b = cz.palette_entry(colorize, c0, c1)
        return (r, g, b, a)
    idx = c0 if not hdr['bits8'] else (c0 << 8 | c1)
    r, g, b = SYSCOLORS.get(idx, (0, 0, 0))
    return (r, g, b, a)


def decode(d, stats=None):
    """Decode a whole RLE resource. Returns dict(header, frames=[[part,...],...]) with part=(hdr, rows)."""
    hd = parse_header(d)
    frames = []
    k = 0
    for f in range(hd['frames']):
        parts = []
        for i in range(hd['parts_per_frame']):
            s, ln = hd['entries'][k]
            k += 1
            parts.append(decode_part(d, s, ln, stats))
        frames.append(parts)
    return dict(header=hd, frames=frames)


def grid_layout(mask):
    cols = 1 + (mask & 1) + (mask >> 2 & 1)
    rws = 1 + (mask >> 1 & 1) + (mask >> 3 & 1)
    assert cols * rws == GRID_PARTS[mask]
    return cols, rws


def assemble(res, colorize=None):
    """Compose each frame's parts (row-major grid) into a natural-size image; frames stacked vertically.
    Returns (width, height, pixels rows, per-frame metadata)."""
    mask = res['header']['margin_mask']
    cols, rws = grid_layout(mask)
    frames_img = []
    meta = []
    for parts in res['frames']:
        colw = [parts[c][0]['width'] for c in range(cols)]
        rowh = [parts[r * cols][0]['height'] for r in range(rws)]
        W, H = sum(colw), sum(rowh)
        img = [[(0, 0, 0, 0)] * W for _ in range(H)]
        y0 = 0
        for r in range(rws):
            x0 = 0
            for c in range(cols):
                ph, rows = parts[r * cols + c]
                for yy, row in enumerate(rows):
                    if y0 + yy < H:
                        img[y0 + yy][x0:x0 + len(row)] = [to_rgba(p, ph, colorize) for p in row]
                x0 += colw[c]
            y0 += rowh[r]
        first, last = parts[0][0], parts[-1][0]
        margins = dict(left=first['width'] if mask & 1 else 0, top=first['height'] if mask & 2 else 0,
                       right=last['width'] if mask & 4 else 0, bottom=last['height'] if mask & 8 else 0)
        meta.append(dict(width=W, height=H, margins=margins,
                         parts=[{k: v for k, v in p[0].items()} for p in parts]))
        frames_img.append(img)
    W = max(m['width'] for m in meta) if meta else 0
    rows = []
    for img, m in zip(frames_img, meta):
        for row in img:
            rows.append(row + [(0, 0, 0, 0)] * (W - len(row)))
    return W, len(rows), rows, meta
