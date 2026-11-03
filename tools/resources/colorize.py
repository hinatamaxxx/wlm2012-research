# uxcore colour math, ported from Ghidra pseudocode.
#   rgb_to_hsl : FUN_1011365f (CRMColorResource) == FUN_100ed0d8 (DirectUI)  H in [0,6), S in [0,1], L in [0,255]
#   hsl_to_rgb : FUN_101133cb (CRMColorResource) == FUN_100ec80f (DirectUI)
#   colorize_rgb : CRMColorResource::ToCOLORREF 'D' branch (0x1011382d) / DirectUI::ColorizeRGB (0x100ec045)
#   palette_entry: colorize palette built by FUN_100ec2d8 (DirectUI::Value::CreateColorize 0x100a396a)
# Colours are (R, G, B) tuples; "colorize colour" is the COLORREF the user picked (R = low byte).

NO_COLORIZE = 0xffffffff   # ToCOLORREF(..., 0xffffffff) returns the stored RGB unchanged
GRAYTEXT_COLORIZE = 0xfffffffc  # ColorizeRGB/CreateColorize: use GetSysColor(COLOR_GRAYTEXT)


def rgb_to_hsl(r, g, b):
    mx, mn = (r, g) if r >= g else (g, r)
    if b > mx:
        mx = b
    elif b < mn:
        mn = b
    L = (mn + mx) / 2.0
    d = mx - mn
    if L == 0.0 or d == 0:
        return 0.0, 0.0, L
    S = d / ((510.0 - mx - mn) if L > 127.5 else (mn + mx))
    if r == mx:
        H = 6.0 - (b - g) / d if g < b else (g - b) / d
    elif g == mx:
        H = (b - r) / d + 2.0
    else:
        H = (r - g) / d + 4.0
    return H, S, L


def _b(x):
    return int(x) & 0xff  # (char)(int)x


def hsl_to_rgb(H, S, L):
    if S == 0.0:
        v = _b(L)
        return v, v, v
    m2 = (S * 255.0 + L) - S * L if L > 127.5 else (S + 1.0) * L
    if not m2 > 0.0:
        return 0, 0, 0
    i = int(H)
    m1 = (L + L) - m2
    f = (H - i) * (m2 - m1)
    if i == 0:
        return _b(m2 + .5), _b(f + m1 + .5), _b(m1 + .5)
    if i == 1:
        return _b((m2 - f) + .5), _b(m2 + .5), _b(m1 + .5)
    if i == 2:
        return _b(m1 + .5), _b(m2 + .5), _b(f + m1 + .5)
    if i == 3:
        return _b(m1 + .5), _b((m2 - f) + .5), _b(m2 + .5)
    if i == 4:
        return _b(f + m1 + .5), _b(m1 + .5), _b(m2 + .5)
    if i == 5:
        return _b(m2 + .5), _b(m1 + .5), _b((m2 - f) + .5)
    return 0, 0, 0  # original leaves outputs untouched for H >= 6


def colorref_to_rgb(c):
    return c & 0xff, (c >> 8) & 0xff, (c >> 16) & 0xff


def colorize_rgb(rgb, colorize):
    """'D' colour: keep the resource colour's S and L, take the hue of the colorize colour.
    Saturation is forced to 0 when the colorize colour itself is grey."""
    if colorize is None or colorize == NO_COLORIZE:
        return tuple(rgb)
    Hb, Sb, Lb = rgb_to_hsl(*colorref_to_rgb(colorize))
    _, So, Lo = rgb_to_hsl(*rgb)
    return hsl_to_rgb(Hb, So if Sb != 0.0 else 0.0, Lo)


def palette_entry(colorize, s_byte, l_byte):
    """Colorize palette (FUN_100ec2d8): 256 rows of S (step 1/255) x 256 L values, entry = HSL(hue, S, L)."""
    Hb, Sb, _ = rgb_to_hsl(*colorref_to_rgb(colorize))
    if Sb == 0.0:
        return l_byte, l_byte, l_byte  # palette is NULL -> grey
    return hsl_to_rgb(Hb, s_byte * 0.003921569, float(l_byte))
