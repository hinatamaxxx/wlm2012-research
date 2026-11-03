# Windows Live Mail 2012: non-layout UI resources (uxcore resource manager types 4000–4012)

These resources are loaded by `uxcore.dll` (CRMResource and friends) from `mailres2.dll` and from the theme overlay modules (`vista.thm`, `mailhc.thm`, `Shared/uxctlhc.thm`, `Shared/wliduxhc.thm`). The overlays are resource-only PE DLLs that use the same type numbers. Type 4010 (UIB layout bytecode) is described in `uib-format.md`. When UIB values refer to a colour, image or rect by id, join that id against the JSON tables below.

Every function address is in `Shared/uxcore.dll` (image base 0x10000000) unless the text names `msmail.dll`. The Ghidra pseudocode is in `decomp/uxcore-all/functions/0x<addr>.c`. Labels used below:
- **[O] observed**: read directly from code or data, or checked by a decoder.
- **[I] inferred**: an interpretation that has not been fully proven.

## Files

| file | purpose |
|---|---|
| `pe.py` | Minimal PE32 reader: VA to file offset, and a walk of the resource tree. |
| `rle.py` | Decoder for "RLE" bitmaps: frames, nine-grid parts, alpha, colorize S/L planes, system-colour palette. |
| `colorize.py` | Exact port of uxcore's HSL math, the 'D' colour colorize, and the colorize palette. |
| `png.py` | Minimal PNG reader (8-bit RGB/RGBA) and RGBA writer. |
| `decode_resources.py` | Driver. `python3 -I decode_resources.py [outdir]` writes to `out/` (about 5 s). |

### Outputs

Output per module is written to `out/<module>/`:
- `colors.json`
- `values4000.json` plus `images/`
- `imageinfo4006.json`
- `sheets4011.json` plus `sheets/`
- `sprites4012.json` plus `sprites/`
- `rects4003.json`
- `animations4008.json`
- `strings4009.json`

Global outputs in `out/`:
- `colors.json`: the merged effective colour table (vista.thm overlay first, then mailres2). Jump chains are resolved. Each entry has its default value and its value under each of the 12 colorize presets.
- `colorize_presets.json`
- `summary.json`: counts and errors.

### Verification

Every item of every type in all five modules parses, with 0 errors:

| module | 4002 | 4000 | 4006 | 4011 | 4012 |
|---|---|---|---|---|---|
| mailres2 | 251 | 1159 | 39 | 23 | 514 |
| vista.thm | 1 | 35 | 16 | 3 | 34 |
| mailhc.thm | 116 | 209 | – | 2 | 16 |
| uxctlhc.thm | 78 | 153 | – | – | – |
| wliduxhc.thm | 56 | 154 | – | – | – |

The RLE decoder checks itself strongly. After each row it confirms that the bit reader ends exactly at the next row's stored offset, and it checks that the last row stays inside its entry. All 604 RLE resources pass this check. A visual check of the montages showed correct icons, emoticons, nine-grid frames and caption buttons.

## Resource lookup (FUN_101171fe, CRMResource)

`FindResourceW` searches the registered modules in order, filtered by a module bitmask (0xff = all modules) [O]. The theme module overrides mailres2 when it comes first in that list [I]. `out/colors.json` assumes the overlay comes first.

## Type 4002: colour (CRMColorResource)

- `Load` (0x101135df): loads type 0xfa2. A record starting with `'J' u16` jumps to another 4002 id, and the jump is followed repeatedly. A record starting with `'N'` means no colour (the caller's default is used) [O].
- Record layout: tag byte, then `u32` at offset +1, read as a COLORREF whose top byte is the alpha.
  - `GetTransparency` (0x101133b9) returns byte +4, or 0xff when there is no resource [O].
  - `ToARGB` (0x101137f2) = `alpha<<24 | RGB` [O].

| tag | meaning | evidence |
|---|---|---|
| `C r g b a` | Plain colour. | ToCOLORREF 0x1011382d [O] |
| `D r g b a` | Colorized colour (IsColorized 0x101135af). With colorize colour X: H = hue(X); S = S(stored), or 0 when X is grey; L = L(stored). With X = 0xFFFFFFFF the stored RGB is returned unchanged. | ToCOLORREF; RGB→HSL FUN_1011365f, HSL→RGB FUN_101133cb (H in [0,6), S in [0,1], L in [0,255]) [O] |
| `S idx24 a` | `GetSysColor(idx)` combined with alpha a (IsSystemColor 0x101135c7, GetSystemColorIndex 0x1011338e). | [O] |
| `J u16` | Jump to another id. | [O] |
| `N` | None. | [O] |

mailres2 counts: 181 C, 23 D, 17 S, 29 J, 1 N. `mailhc.thm`, `uxctlhc.thm` and `wliduxhc.thm` are almost entirely `S`, because high-contrast mode uses system colours. `vista.thm` overrides only id 20100, setting it to COLOR_WINDOW.

## Type 4000: graphic value (FUN_1010abd4, called from CreateImageValue 0x1010abb1 and CreateAnimationValue)

The first byte selects the kind of record [O]:

| first bytes | meaning |
|---|---|
| `J u16` | Jump to another 4000 id. |
| `C`/`D` + 4 bytes | `Value::CreateColor(colorref, colorized flag)`. The layout is the same as in 4002. |
| `S idx24 a` | `Value::CreateInt((a<<24) \| (idx + 10000))`. This is the DUI convention for system colours. |
| `F u16 type u16 state` | DrawFrameControl. |
| `T u16 class u16 part u16 state` + `F…` | DrawThemeBackground (theme class index, part, state). The trailing `F` record is a DFC fallback. |
| `H` | Four embedded 5-byte colour records at +3, +8, +13 and +18 (a `D` record sets mask bits 1/2/4/8). Also byte +1 and `u16` at +23. Calls `Value::CreateColor`, so it is a gradient or four-colour fill [I]. Not used in mailres2. |
| `N` | Unset. |
| `RLE` | Calls `Value::CreateRLE(data, 4006 companion of the same id)`. |
| anything else (PNG, `BM`) | Passed as a stream to `CreateImageValueUsingGDIPlus` (0x1010af88), together with the 4006 RMImageInfo of the same id. |

mailres2 contains 587 PNG, 514 RLE, 7 BMP, 29 jumps, 11 `T`, 7 `D`, 2 `C` and 2 `N`. PNG and BMP files are copied unchanged. RLE images are written as straight-alpha PNG.

### RLE format [O]

The format was reimplemented from these functions:

| role | addresses |
|---|---|
| header accessors | 0x10032204, 0x10031f9e, 0x10032088, 0x10032172, 0x100321d7, 0x10031ecf, 0x10031f09 (read from disassembly, because Ghidra dropped the loop) |
| part accessors | 0x10031e65, 0x10031fc8, 0x100320b3 |
| blitters | 0x100eaa40, 0x100cc6e0, 0x100c8f80 |
| run decoders | 0x100cb500 (8-bit), 0x100cb2c0 (5-bit), 0x100cb210 (alpha) |
| palette mapping | 0x100ea530, 0x100ea810 |
| nine-grid | 0x100e95c0 |

```
"RLE" | b3: frames = b3 & 0x7f
      | b4: lensize = (b4 & 3) + 1 ; mask = (b4 >> 2) & 15  (1 = L, 2 = T, 4 = R, 8 = B margins present)
      |     parts/frame = [1,2,2,4,2,3,4,6,2,4,3,6,4,6,6,9][mask]   (row-major grid; mask 15 = nine-grid)
      | b5: dpi = ((b5 & 7) + 4) * 24, or unscaled when (b5 & 7) == 7
entries: frames * parts records, each = lensize-byte length + part
part:  u32 hdr: bit0 colorize palette | bit1 8-bit channels (else 5-bit, value << 3) | bit2 no RTL mirror |
       bits3-15 width | bit16 alpha | bit17 system-colour palette | bits18-19 offset size - 1 | bits20-31 height
       (height - 1) row offsets (each relative to its own position); row 0 starts after the table
row:   LSB-first bit stream (reset at each row). Planes R, G, B are interleaved: the plane with the lowest
       fill position decodes the next run (ties go R, then G, then B). With alpha, the alpha run comes first.
run:   op:2, count-1:nb, where nb = max(1, bitlen(min(w,255) - 1))
       op0 fill value | op3 literal values | op1/op2 delta (+/-): k = read(3) + 1, then each value = prev +/- read(k)
alpha run: op:2 -> 1 = explicit values (an ordinary run); 2 = opaque run; 0 = transparent run
       (colour planes skip transparent pixels); 3 = never seen
colour: premultiplied by alpha (the blit adds dst*(255-a)). Palette modes are straight alpha.
```

Margins come from the parts: left = width of the first part, top = height of the first part, right and bottom = width and height of the last part (FUN_100ea3e6). In the PNG, frames are stacked vertically. Each value carries `frame_meta` with its margins and part sizes.

Observed formats in mailres2: 1701 parts use 5-bit RGB, 802 use 8-bit RGB and 241 use 8-bit S/L. `mailhc.thm` uses the 5-bit system-colour palette.

## Type 4006: RMImageInfo, or the colorize companion

There are two forms:

1. **12-byte RMImageInfo** for PNG values [O] (CreateImageValueUsingGDIPlus 0x1010af88):
   - `u16 margins[4]` (L, T, R, B): nine-grid sizing margins.
   - `u16 flags`:
     - bits 0–11: frame count.
     - 0x8000: frames laid out horizontally (otherwise vertically).
     - 0x4000: changes the stretch mode.
     - 0x1000: sets a graphic flag (0x20), which is RTL mirroring [I].
     - 0x2000: unknown.
   - `u16 dpi`: 0 = no scaling, 1 = use the PNG's pHYs, otherwise the design DPI. The image is scaled to the screen DPI.
2. **RLE companion** with the same id and geometry as the 4000 RLE. Its parts have bit0 set (colorize palette) [O].
   - Two 8-bit planes: S×255 and L. When colorize is active, Paint passes the `Colorize` property palette (DirectUI::Element::Paint 0x100af121, around line 630).
   - That palette is built by `Value::CreateColorize` (0x100a396a) and FUN_100ec2d8 as 256×256 entries: `pal[S][L] = HSL(hue(colorize), S/255, L)`.
   - If the colorize colour is grey, there is no palette and the output is grey L.
   - Output files: `<id>.colorize-gray.png` (the grey L fallback) and `<id>.colorize-SL.png` (R = S, G = L, A = alpha). To recolour, apply `colorize.palette_entry(colorref, S, L)` to each pixel.

## Type 4011 and 4012: PNG sheets and sprites

- **4011**: plain PNG sheets [O]. 23 in mailres2. They are loaded and cached by FUN_101302d5.
- **4012**: a 26-byte record [O] (FUN_1012e88d and FUN_1012ef6f draw it, FUN_1012e9e3 gives its size):
  - First 12 bytes: the same RMImageInfo as 4006.
  - `u32 cell_flags` (+12): 2 bits per nine-grid cell. If bit 2k+1 is set, cell k is not drawn. With no margins, bit1 means the whole image is not drawn.
  - `u16 rect L, T, R, B` (+16): the sprite's rectangle in the sheet.
  - `u16 sheet id` (+24): the 4011 id.
  - Edge cases:
    - L >= R: the whole sheet is used.
    - B < T: the sprite is stored rotated in the sheet and is drawn with a +90° (clockwise) transform. The exported sprite PNG is rotated back upright, which was checked visually (checkmarks and caption buttons are upright).
  - Frames: n = flags & 0xfff. The frame size is extent/n, and frame i starts at `start + i*(size + 2)`. Frames run horizontally when the 0x8000 bit differs from the rotated flag. Frame rectangles are listed in `slice.frames`.
- When an id has no 4012 record, FUN_1012e88d falls back to the 4006 info and uses the same id as the 4011 sheet.

## Other types

- **4003 rect** [O] (FUN_1011718d): 18 bytes = `RECT` (4 × i32) + `u16 design DPI`. If the DPI is non-zero, the rect is scaled to the screen DPI (FUN_10117352, using LOGPIXELSX/Y).
- **4008 animation** [O] (CreateAnimationValue 0x1010a220):
  - `b0`: a parameter of `Value::CreateAnimation`; observed value 0x16.
  - `u16@0 >> 13`: kind (0 = image strip, 1 = image list, 2 = int list, 3 = value list).
  - `b1 & 0x1f`: repeat count (0x1f = infinite).
  - `b2`: number of items, followed by u16 ids.
  - `b3`: number of durations, followed by u16 values (ms [I]).
  - Example: 4067 = strip of image 4067, 60 per frame, looping forever.
- **4009 string override** [O] (CRMStringResource::Load 0x1011424d): `u16 tag, u16 value`.
  - 3 = jump to another id.
  - 1, 2 and 4 = fall back to the RT_STRING table.
  - 5 = special handling (FUN_10114002).
- **Theme `.thm` files**: resource DLLs that use the types above. Each one is decoded into its own `out/<module>/` folder.

## Colorize (user colour scheme)

- `UXColorizer` (0x100684ad and following) reads the colour from the app's `IUXColorizeSettings`.
  - Value type 1 follows the DWM glass colour (`DwmGetColorizationColor`, FUN_10068877).
  - 0xFFFFFFFF means no colorize. The stored `D` colours and the non-companion RLE images are then used unchanged [O].
- The 12 picker presets are in the table at 0x10249fb8 (`{sqm_id, colour id}`). The ids are 4002 entries 20480–20491:

  | id | colour |
  |---|---|
  | 20480 | #CBE5FF |
  | 20481 | #CCCCFF |
  | 20482 | #CCFFFF |
  | 20483 | #CCFFCC |
  | 20484 | #FFFFCC |
  | 20485 | #FFE5CC |
  | 20486 | #FFCCCC |
  | 20487 | #FFCCE5 |
  | 20488 | #FFCCFF |
  | 20489 | #E5CCFF |
  | 20490 | #E5FFCC |
  | 20491 | #EEEEEE (grey, which effectively turns colorize off) |

- **Default scheme [I]**: the out-of-the-box value is held in msmail's `IUXColorizeSettings` and was not traced. The stored `D` colours are already the "Live blue" set (hue about 213°, for example #355A88). With no colorize they render as stored, and preset 20480 (#CBE5FF, hue 210°) changes them only slightly. `out/colors.json` therefore uses no-colorize as `default` and also lists the value for each preset.

## Main-window colours (default Aero theme)

### msmail list-colour switch

msmail FUN_1006d2a9 (msmail.dll 0x1006d2a9) maps an enum to a colour [O]. The meaning of each enum value is not recovered; the role labels are [I], inferred from alpha and value:

| enum | source | default ARGB | probable role [I] |
|---|---|---|---|
| 2, 9, 10 | GetSysColor(COLOR_WINDOW) | #FFFFFFFF | list background |
| 5 | 4002/7528 (D) | #11355A88 | hover fill |
| 6 | 7529 (D) | #33355A88 | selected (inactive) fill |
| 7 | 7530 (D) | #66355A88 | selected (focused) fill |
| 8 | 7533 (D) | #FFE6EFF8 | header / group band |
| 11 | 7535 (D) | #FF6685AE | accent text or border |
| 12 | COLOR_BTNFACE | #FFF0F0F0 | |
| 13 | 7534 (D) | #40ACBED6 | separator |
| 14 | COLOR_HOTLIGHT | #FF0066CC | link / hot text |
| 15 | 7536 (D) | #FF444444 | secondary text |
| 16 | 7537 (D) | #99FFFFFF | highlight overlay |
| 17 | 7538 (D) | #FF000000 | text |
| 18, 19 | 7539 (D) | #40ACBED6 | border |
| 20 | 20367 (C) | #FF9C9C9C | grey text |

### Other ids

- Calendar category palette [I]: 7483–7527 are plain `C` colours in three ranks of 15, for example 7483 #EFB4CF and 7498 #BB8EA4.
- msmail loads 7123 (#C0C0C0) directly at 0x100dd576 and 0x100def8f.
- Other colorized chrome colours, for UIB to join: 3422 #B7C1C2, 3424 #6C6C6C, 3436, 4313 and 20377 #355A88, 3798 #6685AE, 20750 #F0F5F9, 20755 and 20758 #BED6E0, 20757 #E2EAF3, 20760 #6F8A92, 44972 #E6E7EA.
- System-colour aliases: 20720–20734, 20769, 20880, and 20881 (COLOR_HOTLIGHT at alpha 0x55).

### What is still missing

Exact roles (folder pane, message list unread/selected text, reading-pane header, ribbon, status bar) and the font faces and sizes live in the UIB layouts (type 4010). Join those against `out/colors.json`, `values4000.json` and `sprites4012.json` by id.
