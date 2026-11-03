#!/usr/bin/env python3
# Decode Windows Live Mail 2012 non-layout UI resources (uxcore resource-manager types 4000-4012)
# from mailres2.dll and the theme overlay modules (*.thm). See RESOURCES.md for the format spec.
# Usage: python3 -I decode_resources.py [outdir]
import json, os, struct, sys, hashlib, collections

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pe import PE
import rle, png, colorize as cz

ROOT = os.path.dirname(os.path.dirname(HERE))
T = os.path.join(ROOT, 'targets', 'Windows Live')
MODULES = {
    'mailres2': os.path.join(T, 'Mail', 'mailres2.dll'),
    'vista.thm': os.path.join(T, 'Mail', 'vista.thm'),
    'mailhc.thm': os.path.join(T, 'Mail', 'mailhc.thm'),
    'uxctlhc.thm': os.path.join(T, 'Shared', 'uxctlhc.thm'),
    'wliduxhc.thm': os.path.join(T, 'Shared', 'wliduxhc.thm'),
}
# colorize presets: UXColorizer table at uxcore 0x10249fb8 (12 x {u32 sqm_id, u32 colour id}); ids are type-4002
PRESET_TABLE_VA = 0x10249fb8

def hx(b):
    return b.hex(' ')

def argb_hex(r, g, b, a):
    return '#%02X%02X%02X%02X' % (a, r, g, b)

def rgb_hex(r, g, b):
    return '#%02X%02X%02X' % (r, g, b)


# ---------------------------------------------------------------- RMColorInfo (type 4002, also embedded in 4000)
def parse_colorinfo(b):
    """CRMColorResource (Load 0x101135df, ToCOLORREF 0x1011382d, GetTransparency 0x101133b9)."""
    tag = chr(b[0]) if b else ''
    if tag == 'J':
        return dict(kind='jump', target=struct.unpack_from('<H', b, 1)[0])
    if tag == 'N':
        return dict(kind='none')
    if tag in 'CDS' and len(b) >= 5:
        v, = struct.unpack_from('<I', b, 1)
        a = b[4]
        if tag == 'S':
            idx = v & 0xffffff
            r, g, bb = rle.SYSCOLORS.get(idx, (0, 0, 0))
            return dict(kind='system', sys_index=idx,
                        sys_name=rle.SYSCOLOR_NAMES[idx] if idx < len(rle.SYSCOLOR_NAMES) else None,
                        alpha=a, win7_default_argb=argb_hex(r, g, bb, a))
        r, g, bb = b[1], b[2], b[3]
        return dict(kind='colorized' if tag == 'D' else 'color', rgb=rgb_hex(r, g, bb), alpha=a,
                    argb=argb_hex(r, g, bb, a), colorized=(tag == 'D'))
    return dict(kind='unknown', raw=hx(b))


def resolve(table, cid, seen=None):
    seen = seen or []
    e = table.get(cid)
    if e is None:
        return None, seen + [cid]
    if e['kind'] == 'jump':
        if cid in seen:
            return None, seen + [cid]
        return resolve(table, e['target'], seen + [cid])
    return e, seen + [cid]


def colorized_value(e, colorize_ref):
    if e['kind'] == 'colorized':
        rgb = tuple(int(e['rgb'][i:i + 2], 16) for i in (1, 3, 5))
        r, g, b = cz.colorize_rgb(rgb, colorize_ref)
        return argb_hex(r, g, b, e['alpha'])
    if e['kind'] == 'color':
        return e['argb']
    if e['kind'] == 'system':
        return e['win7_default_argb']
    return None


# ---------------------------------------------------------------- type 4000 graphic values (FUN_1010abd4)
def parse_value4000(b):
    t = b[:1]
    if b[:4] == b'\x89PNG':
        return dict(kind='png')
    if b[:3] == b'RLE':
        return dict(kind='rle')
    if b[:2] == b'BM':
        return dict(kind='bmp')
    c = chr(b[0])
    if c in 'JNCD' or (c == 'S' and len(b) == 5):
        ci = parse_colorinfo(b)
        if c == 'S':  # 4000 'S' -> Value::CreateInt((alpha<<24) | (index + 10000))
            ci['dui_int'] = (b[4] << 24) | ((struct.unpack_from('<I', b, 1)[0] & 0xffffff) + 10000)
        return ci
    if c == 'F' and len(b) >= 5:
        typ, state = struct.unpack_from('<HH', b, 1)
        return dict(kind='drawframecontrol', dfc_type=typ, dfc_state=state)
    if c == 'T' and len(b) >= 12:
        cls, part, state = struct.unpack_from('<HHH', b, 1)
        fb = b[7:12]
        fallback = parse_value4000(fb) if fb[:1] == b'F' else hx(fb)
        return dict(kind='themebackground', theme_class_index=cls, part=part, state=state,
                    fallback=fallback)
    if c == 'H' and len(b) >= 25:
        cols = [parse_colorinfo(b[o:o + 5]) for o in (3, 8, 13, 18)]
        return dict(kind='color4', byte1=b[1], byte2=b[2], colors=cols,
                    u16_at_23=struct.unpack_from('<H', b, 23)[0],
                    note='Value::CreateColor(4 colours, byte1, colorized-mask, u16@23); colorized mask bit i = colors[i] is D')
    return dict(kind='stream_unknown', head=hx(b[:16]))


# ---------------------------------------------------------------- RMImageInfo (4006 12 bytes / 4012 26 bytes)
def parse_imageinfo(b):
    l, t, r, bt, fl, dpi = struct.unpack_from('<6H', b, 0)
    d = dict(margins=dict(left=l, top=t, right=r, bottom=bt), flags='0x%04x' % fl,
             frames=fl & 0xfff, frames_horizontal=bool(fl & 0x8000), flag_0x1000_rtl_mirror=bool(fl & 0x1000),
             flag_0x2000=bool(fl & 0x2000), flag_0x4000=bool(fl & 0x4000),
             dpi={0: 'none (no scaling)', 1: 'from PNG pHYs'}.get(dpi, dpi))
    if len(b) >= 26:
        cell, = struct.unpack_from('<I', b, 12)
        sl, st, sr, sb, sheet = struct.unpack_from('<5H', b, 16)
        d.update(cell_flags='0x%05x' % cell, sheet_rect=dict(left=sl, top=st, right=sr, bottom=sb), sheet=sheet)
        # per-cell 2-bit flags; FUN_1012ef6f skips drawing a cell when bit (2k+1) is set
        d['cells_hidden'] = [k for k in range(9) if cell >> (2 * k + 1) & 1] if any((l, t, r, bt)) else \
            ([0] if cell & 2 else [])
    return d


def sprite_frames(info):
    """Frame rectangles inside the sheet, as computed by FUN_1012ef6f / FUN_1012e9e3."""
    r = info['sheet_rect']
    l, t, rr, b = r['left'], r['top'], r['right'], r['bottom']
    if not l < rr:
        return None
    rotated = b < t
    n = info['frames']
    out = []
    if n <= 1:
        return dict(rotated=rotated, frames=[dict(left=l, top=min(t, b), right=rr, bottom=max(t, b))])
    if info['frames_horizontal'] != rotated:  # horizontal strip (bit15) unless rotated
        fw = (rr - l) / n
        for i in range(n):
            x = l + i * (fw + 2.0)
            out.append(dict(left=round(x), top=min(t, b), right=round(x + fw), bottom=max(t, b)))
    else:
        top, bot = min(t, b), max(t, b)
        fh = (bot - top) / n
        for i in range(n):
            y = top + i * (fh + 2.0)
            out.append(dict(left=l, top=round(y), right=rr, bottom=round(y + fh)))
    return dict(rotated=rotated, frames=out)


def parse_rect(b):
    """type 4003: RECT (4 x i32) + u16 design DPI (FUN_1011718d: scaled by FUN_10117352 if non-zero)."""
    l, t, r, bt, dpi = struct.unpack_from('<4iH', b, 0)
    return dict(left=l, top=t, right=r, bottom=bt, dpi=dpi)


def parse_anim(b):
    """type 4008 (CRMDUIParser::CreateAnimationValue 0x1010a220)."""
    w0, = struct.unpack_from('<H', b, 0)
    kind = w0 >> 13
    rep = b[1] & 0x1f
    n, nt = b[2], b[3]
    items = list(struct.unpack_from('<%dH' % n, b, 4))
    times = list(struct.unpack_from('<%dH' % nt, b, 4 + 2 * n))
    return dict(byte0=b[0], kind={0: 'image_strip', 1: 'image_list', 2: 'int_list', 3: 'value_list'}.get(kind, kind),
                repeat=-1 if rep == 0x1f else rep, items=items, durations=times,
                trailing=hx(b[4 + 2 * (n + nt):]))


def parse_string_override(b):
    """type 4009 (CRMStringResource::Load 0x1011424d): u16 tag, u16 value. 3 = jump to string id;
    1/2/4 = fall back to the RT_STRING table (FUN_10116c42); 5 = FUN_10114002 (special)."""
    tag, val = struct.unpack_from('<HH', b, 0)
    d = dict(tag=tag, value=val)
    if tag == 3:
        d['jump'] = val
    return d


# ---------------------------------------------------------------- driver
def main(out):
    os.makedirs(out, exist_ok=True)
    summary = {}
    pe_ux = PE(os.path.join(T, 'Shared', 'uxcore.dll'))
    presets = []
    tb = pe_ux.read_va(PRESET_TABLE_VA, 12 * 8)
    for i in range(12):
        sqm, cid = struct.unpack_from('<II', tb, i * 8)
        presets.append(dict(sqm_id=sqm, color_id=cid))
    all_colors = {}
    for mod, path in MODULES.items():
        p = PE(path)
        res = collections.defaultdict(dict)
        for t, n, l, o, s in p.resources():
            res[t][n] = p.data[o:o + s]
        mo = os.path.join(out, mod)
        os.makedirs(mo, exist_ok=True)
        st = summary.setdefault(mod, {'types': {str(k): len(v) for k, v in res.items()}})
        errors = []

        # 4002 colours
        colors = {n: parse_colorinfo(b) | {'raw': hx(b)} for n, b in res.get(4002, {}).items()}
        for n, e in colors.items():
            if e['kind'] == 'jump':
                tgt, chain = resolve(colors, n)
                e['chain'] = chain
                e['resolved'] = {k: v for k, v in tgt.items() if k != 'raw'} if tgt else None
                if tgt is None:
                    e['unresolved_in_module'] = True
        all_colors[mod] = colors
        json.dump({str(k): v for k, v in sorted(colors.items(), key=lambda x: str(x[0]))}, open(os.path.join(mo, 'colors.json'), 'w'), indent=1)
        st['colors'] = collections.Counter(e['kind'] for e in colors.values())

        # 4000 values / images
        vals = {}
        imgdir = os.path.join(mo, 'images')
        os.makedirs(imgdir, exist_ok=True)
        rstats = {}
        for n, b in sorted(res.get(4000, {}).items(), key=lambda x: str(x[0])):
            v = parse_value4000(b)
            v['size'] = len(b)
            v['sha256'] = hashlib.sha256(b).hexdigest()
            try:
                if v['kind'] == 'png':
                    info, _ = png.png_info(b)
                    v.update({k: info[k] for k in ('width', 'height', 'color_type')})
                    if 'pHYs' in info:
                        v['dpi'] = info['pHYs'].get('dpi_x')
                    open(os.path.join(imgdir, f'{n}.png'), 'wb').write(b)
                    v['file'] = f'images/{n}.png'
                elif v['kind'] == 'bmp':
                    w, h, planes, bpp = struct.unpack_from('<iiHH', b, 18)
                    v.update(width=w, height=h, bpp=bpp)
                    open(os.path.join(imgdir, f'{n}.bmp'), 'wb').write(b)
                    v['file'] = f'images/{n}.bmp'
                elif v['kind'] == 'rle':
                    r = rle.decode(b, rstats)
                    W, H, rows, meta = rle.assemble(r)
                    png.write_png(os.path.join(imgdir, f'{n}.png'), W, H, rows)
                    hd = r['header']
                    v.update(width=W, height=H, frames=hd['frames'], frames_layout='stacked vertically in PNG',
                             margin_mask=hd['margin_mask'], dpi=hd['dpi'], parts_per_frame=hd['parts_per_frame'],
                             frame_meta=meta, file=f'images/{n}.png')
            except Exception as ex:
                errors.append(f'4000/{n}: {ex!r}')
            vals[n] = v
        # resolve 4000 jumps
        for n, v in vals.items():
            if v['kind'] == 'jump':
                chain, cur = [n], v
                while cur and cur['kind'] == 'jump' and cur['target'] not in chain:
                    chain.append(cur['target'])
                    cur = vals.get(cur['target'])
                v['chain'] = chain
                v['resolved_kind'] = cur['kind'] if cur else None
        json.dump({str(k): v for k, v in vals.items()}, open(os.path.join(mo, 'values4000.json'), 'w'), indent=1)
        st['values4000'] = collections.Counter(v['kind'] for v in vals.values())
        st['rle_stats'] = rstats

        # 4006 image info / colorize companions
        infos = {}
        for n, b in res.get(4006, {}).items():
            try:
                if b[:3] == b'RLE':
                    r = rle.decode(b, rstats)
                    W, H, rows, meta = rle.assemble(r)
                    png.write_png(os.path.join(imgdir, f'{n}.colorize-gray.png'), W, H, rows)
                    slrows = rle.assemble(dict(header=r['header'], frames=[[(dict(ph, mode='raw'), pr)
                                                                           for ph, pr in fr] for fr in r['frames']]))[2]
                    png.write_png(os.path.join(imgdir, f'{n}.colorize-SL.png'), W, H, slrows)
                    infos[n] = dict(kind='rle_colorize_companion', width=W, height=H,
                                    modes=sorted({ph['mode'] for fr in r['frames'] for ph, _ in fr}),
                                    gray_file=f'images/{n}.colorize-gray.png', sl_file=f'images/{n}.colorize-SL.png')
                else:
                    infos[n] = dict(kind='imageinfo', raw=hx(b)) | parse_imageinfo(b)
            except Exception as ex:
                errors.append(f'4006/{n}: {ex!r}')
        json.dump({str(k): v for k, v in sorted(infos.items(), key=lambda x: str(x[0]))},
                  open(os.path.join(mo, 'imageinfo4006.json'), 'w'), indent=1)

        # 4011 sheets + 4012 sprites
        sheets = {}
        sheet_px = {}
        sdir = os.path.join(mo, 'sheets')
        os.makedirs(sdir, exist_ok=True)
        for n, b in res.get(4011, {}).items():
            info, _ = png.png_info(b)
            open(os.path.join(sdir, f'{n}.png'), 'wb').write(b)
            sheets[n] = dict(width=info['width'], height=info['height'], dpi=info.get('pHYs', {}).get('dpi_x'),
                             file=f'sheets/{n}.png', sprites=[])
            sheet_px[n] = png.read_png(b)
        sprites = {}
        spdir = os.path.join(mo, 'sprites')
        os.makedirs(spdir, exist_ok=True)
        for n, b in sorted(res.get(4012, {}).items(), key=lambda x: str(x[0])):
            try:
                d = parse_imageinfo(b)
                d['raw'] = hx(b)
                fr = sprite_frames(d)
                d['slice'] = fr
                sh = d['sheet']
                src = sheet_px.get(sh) or (sheet_px.get(sh) if mod == 'mailres2' else None)
                if src is None and mod != 'mailres2':
                    src = None
                if sh in sheets:
                    sheets[sh]['sprites'].append(n)
                if fr and src:
                    w, h, rows = src
                    r0 = d['sheet_rect']
                    x0, x1 = r0['left'], r0['right']
                    y0, y1 = min(r0['top'], r0['bottom']), max(r0['top'], r0['bottom'])
                    crop = [row[x0:x1] for row in rows[y0:y1]]
                    if crop and crop[0] and fr['rotated']:
                        # stored rotated in the sheet; FUN_1012ef6f draws it with a +90 deg (clockwise) transform
                        hh, ww = len(crop), len(crop[0])
                        crop = [[crop[hh - 1 - x][y] for x in range(hh)] for y in range(ww)]
                        d['output_rotated_cw90'] = True
                    if crop and crop[0]:
                        png.write_png(os.path.join(spdir, f'{n}.png'), len(crop[0]), len(crop), crop)
                        d['file'] = f'sprites/{n}.png'
                elif fr is None:
                    d['file'] = f'sheets/{sh}.png' if sh in sheets else None
                    d['note'] = 'rect empty: whole sheet'
                if fr and sh not in sheets:
                    d['sheet_missing_in_module'] = True
                sprites[n] = d
            except Exception as ex:
                errors.append(f'4012/{n}: {ex!r}')
        json.dump({str(k): v for k, v in sheets.items()}, open(os.path.join(mo, 'sheets4011.json'), 'w'), indent=1)
        json.dump({str(k): v for k, v in sprites.items()}, open(os.path.join(mo, 'sprites4012.json'), 'w'), indent=1)

        # 4003 rects, 4008 animations, 4009 string overrides
        misc = {}
        for typ, fn, name in ((4003, parse_rect, 'rects4003'), (4008, parse_anim, 'animations4008'),
                              (4009, parse_string_override, 'strings4009')):
            m = {}
            for n, b in res.get(typ, {}).items():
                try:
                    m[str(n)] = fn(b) | {'raw': hx(b)}
                except Exception as ex:
                    errors.append(f'{typ}/{n}: {ex!r}')
            json.dump(m, open(os.path.join(mo, name + '.json'), 'w'), indent=1)
            misc[name] = len(m)
        st.update(misc)
        st['decoded'] = dict(colors=len(colors), values4000=len(vals), imageinfo4006=len(infos),
                             sheets4011=len(sheets), sprites4012=len(sprites))
        st['errors'] = errors

    # colorize presets (mailres2 4002 ids) and the default
    base = all_colors['mailres2']
    pres = []
    for pz in presets:
        e, chain = resolve(base, pz['color_id'])
        pz = dict(pz)
        pz['entry'] = {k: v for k, v in (e or {}).items() if k != 'raw'}
        if e and e['kind'] in ('color', 'colorized'):
            r, g, b = (int(e['rgb'][i:i + 2], 16) for i in (1, 3, 5))
            pz['colorref'] = '0x%06X' % (r | g << 8 | b << 16)
        pres.append(pz)
    json.dump(pres, open(os.path.join(out, 'colorize_presets.json'), 'w'), indent=1)

    # merged colour table: effective value for the default (Aero) theme = vista.thm overlay, then mailres2
    merged = {}
    for cid in sorted(set(base) | set(all_colors['vista.thm']), key=str):
        src = 'vista.thm' if cid in all_colors['vista.thm'] else 'mailres2'
        tbl = all_colors[src]
        e, chain = resolve(tbl, cid)
        if e is None and src != 'mailres2':
            e, chain = resolve(base, cid)
        row = dict(source=src, chain=chain, kind=e['kind'] if e else None)
        if e:
            row['default'] = colorized_value(e, None)
            row['colorized'] = e.get('colorized', False)
            if e['kind'] == 'system':
                row['sys_name'] = e['sys_name']
            if e['kind'] == 'colorized':
                row['by_preset'] = {str(pz['color_id']): colorized_value(e, int(pz['colorref'], 16))
                                    for pz in pres if 'colorref' in pz}
        merged[str(cid)] = row
    json.dump(merged, open(os.path.join(out, 'colors.json'), 'w'), indent=1)
    json.dump(summary, open(os.path.join(out, 'summary.json'), 'w'), indent=1, default=dict)
    for mod, s in summary.items():
        print(mod, s['decoded'], 'errors:', len(s['errors']), s['errors'][:3])


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'out'))
