# UIB — compiled DirectUI layout format (Windows Live Mail 2012, uxcore.dll)

Resource type 4010 (0xFAA) in `mailres2.dll` (also in `uxctl.dll`, `wlidux.dll`). Loaded by
`CRMDUIParser` (uxcore.dll, image base 0x10000000) and run by a small stack-machine interpreter.

Tags used below:
- **[obs]**: read directly from the decompiled or disassembled uxcore.dll code at the cited address.
- **[inf]**: inferred from the data, naming or consistency. These are not proven by code.

All 29 resources in `mailres2/4010` decode completely with these rules (`uib2xml.py --check`):
every byte is consumed, every instruction is executed and no opcode is unknown.

---------------------------------------------------------------------------------------------------
## 1. Objects involved

| object | vtable | role |
|---|---|---|
| UIB reader | 0x1000e458 (also 0x1000e2f0) | owns the buffer. Its methods are table accessors (section 3) |
| interpreter | 0x1000e424 | fields `+4` reader, `+8` value stack, `+0xc` call stack, `+0x10` resource provider, `+0x14` class cache, `+0x18` property-name cache, `+0x1c` resource-value cache, `+0x20` fragment-value cache, `+0x24` register (op 0x2e), `+0x28` IP (absolute pointer), `+0x2c` LOGPIXELSY, `+0x30` running flag, `+0x31` high-contrast flag |
| value stack | 0x1000e4b4 (ctor FUN_100a85da) | array of 8-byte `{type, payload}` items. Stack types: **1 int, 2 Element, 3 Value, 4 Layout** [obs: FUN_100c08e0 compares the type; FUN_100c1051 requires 2; FUN_100c10c0 accepts 3, or 1 with value 0]. Methods: `+0x14` push(type,val) FUN_100c4c37, `+0x18` pop FUN_100c4994 (LIFO, top = last item), `+0x1c` peek FUN_100c493d, `+0x20` get(index) FUN_100c48de |
| resource provider | 0x10018704 (CRMDUIParser) | slots `+0` CreateStringValue, `+4` CreateColorValue, `+8` CreateInt, `+0xc` CreateFloatValue, `+0x10` CreateImageValue, `+0x14` CreateGraphicValue, `+0x18` CreateRectValue, `+0x1c` CreateIconValue, `+0x20` CreateCursorValue, `+0x24` CreateAnimationValue, `+0x28` CreateColorizeValue [obs: vtable dump and symbol names] |

Interpreter init FUN_100c0e2f [obs]: creates the value stack (capacity 100) and the call stack (10).
It stores the provider. It sets `+0x31 = SPI_GETHIGHCONTRAST & HCF_HIGHCONTRASTON` and
`+0x2c = GetDeviceCaps(LOGPIXELSY)` (96 when there is no DC).
Run FUN_100c0c7b(codeptr) [obs]: wraps the run in `Element::StartDefer/EndDefer`. It saves the IP
when the call is nested, sets IP and running=1, and calls the step function FUN_100c1c0c until
running=0.

---------------------------------------------------------------------------------------------------
## 2. Header (0x28 bytes)

| off | type | value | source |
|---|---|---|---|
| 0x00 | char[4] | `"UIB\0"` (DAT_1000f098) | [obs] FUN_100c074a memcmp → otherwise 0x80004005 |
| 0x04 | u16 | 1 | [obs] FUN_100c074a → otherwise 0x8000FFFF |
| 0x06 | u16 | 0 | [obs] FUN_100c074a |
| 0x08 | u32 | S0 string pool offset (always 0x28) | [obs] FUN_100c063d |
| 0x0C | u32 | S1 class table offset | [obs] FUN_100c040a/100c03ae |
| 0x10 | u32 | S2 property table offset (= end of S1) | [obs] FUN_100c0541/100c04e5 |
| 0x14 | u32 | S3 entry table offset | [obs] FUN_100c044a |
| 0x18 | u32 | S4 fragment table offset | [obs] FUN_100c06c6/100c067c |
| 0x1C | u32 | S5 resource table offset | [obs] FUN_100c05c5/100c0581 |
| 0x20 | u32 | S6 code offset | [obs] FUN_100c044a, 100c067c, 100c07a3 |
| 0x24 | u32 | end of code (= file size) | [obs] FUN_100c0605 (size getter), FUN_100c07a3 |

All offsets are relative to the start of the buffer. A section ends where the next one begins.
Integers in the header and tables are little-endian. **Inline operands in the code are
big-endian** (section 4).

## 3. Sections

- **S0 string pool**: NUL-terminated 8-bit strings. A *string reference* is a byte offset into S0.
  `GetString(off) = buf + hdr[8] + off` (FUN_100c063d, reader vtable +0x1c). Strings are converted
  with `DirectUI::MultiByteToUnicode` before use (FUN_100c439f). Offset 0 is always the empty
  string. [obs] In 27 of the 29 files, offset 1 holds `"MMSG"`, which nothing references. [inf]
  It is the compiler's module or namespace tag.
- **S1 classes**: u32[] of string offsets. `count = (hdr[0x10]-hdr[0xc])/4`. Index → class name →
  class info, resolved once by FUN_100c167a/FUN_100c12d3 and cached at interpreter+0x14
  (FUN_100c1f1d). [obs]
- **S2 properties**: u32[] of string offsets. Index → property *name*. The name is resolved per
  element class on first use: FUN_100c1fcd → FUN_100c1e65 walks the class's PropertyInfo list and
  matches with `_wcsicmp`. Matching is case-insensitive, so `Id`, `ID` and `id` are the same
  property. [obs]
- **S3 entries**: a list of `{ASCIIZ name, u32 code_offset}`. Code offsets are relative to S6.
  FindEntry FUN_100c044a does a linear `_stricmp` scan and returns `buf+hdr[0x20]+code_offset`.
  Entries are the named templates (`CRMDUIParser::CreateElement(name)`). [obs]
- **S4 fragments**: u32[] of code offsets relative to S6. A fragment is a shared code block that
  leaves exactly one Value on the stack. Op 0x1c runs it once and caches the Value
  (FUN_100c2215, cache at interpreter+0x20). In this corpus there is always one fragment: the
  file's property sheet. [obs: code] [inf: "always a sheet" is from the data]
- **S5 resource records**: 8 bytes each. `u16 id; u16 0; u8 kind; u8 module_stroff; u16 0`
  [obs: FUN_100c2095 reads +0 (u16 id), +4 (kind), +5 (string offset of the module name)]. Bytes
  +2/+3 and +6/+7 are zero in every file [inf: padding]. Kinds accepted by FUN_100c2095:
  1 string, 4 color, 5 colorize, 6/7 image, 9 rect, 0xb cursor, 0xd float (provider slots
  +0, +4, +0x28, +0x10, +0x18, +0x20, +0xc). Any other kind gives 0x8000FFFF. The created Value
  is cached per index (interpreter+0x1c).
- **S6 code**: the byte-code (section 4). The reader validates each IP with FUN_100c07a3
  (`code0 <= ip < end`).

## 4. Instruction encoding

One opcode byte, plus inline operands **only** for the ops below. Every other operand comes from
the value stack. Dispatch is FUN_100c1c0c (it calls `reader->Validate(ip)` first). An undefined
opcode (0x00, 0x05, 0x08, >0x2e) returns 0x80DD0004.

| op | name | inline | semantics | source |
|---|---|---|---|---|
| 01 | halt | - | running=0 | FUN_100c1c0c |
| 02 | push.u8 | u8 | push int (zero-extended) | FUN_100c4453 |
| 03 | push.u16 | u16 **BE** | push int | FUN_100c4400 (`CONCAT11(b1,b2)`) |
| 04 | push.i32 | i32 **BE** | push int | FUN_100c442b → FUN_100c114e |
| 06 | pop | - | discard the top item | FUN_100c4345 |
| 07 | jmp | u16 BE | IP = IP_of_opcode + u16 (forward only) | FUN_100c240f |
| 09 | jtrue | i16 BE | pop int; if ≠0 IP += i16, else IP += 3 | FUN_100c23bd |
| 0a/0b/0c/0d | jgt/jge/jlt/jle | i16 BE | pop b, pop a (unsigned); jump if a>b / a>=b / a<b / a<=b | FUN_100c2349 + FUN_100c1f05/1eee/245e/2447 |
| 0e | call | - | pop int target (an absolute pointer from op 1b). Push frame {IP+1, stackdepth-1} on the call stack. IP = target | FUN_100c17c9 |
| 0f | ret | - | empty call stack → running=0 (end of entry/fragment). Otherwise pop the frame, drop the stack items above the saved depth (keeping the result), IP = return address [obs FUN_100c4632; exact cleanup inf] | FUN_100c4632 |
| 10 | newelem | - | pop int class index (S1). `classinfo->CreateInstance` → push Element | FUN_100c2bdd, FUN_100c1816 |
| 11 | mkvalue | - | pop int sub-type, then build a Value (section 5). Push Value | FUN_100c3583 |
| 12 | setprop | - | pop int prop index (S2), pop Value, **peek** Element; `Element::SetValue(e, ppi, PI_Local=1, v)` | FUN_100c47e1 |
| 13 | addchild | - | pop child Element, peek parent, `Element::Add(parent, child)`, push child back | FUN_100c117d |
| 14 | addchildren | - | adds all Elements above an int marker -12 (0xFFFFFFF4) to the Element below it [obs: marker; inf: exact order]. Not used in the corpus | FUN_100c11ff |
| 15 | mklayout | - | pop sub-type → Layout (section 6). Push Layout | FUN_100c2f02 |
| 16 | resvalue | - | pop sub-type → value read from the resource provider (section 7) | FUN_100c3086 |
| 17 | resref | - | pop int index into S5 → cached Value (section 3) | FUN_100c3016 → FUN_100c2095 |
| 18 | bind | - | data binding (section 8) | FUN_100c270f |
| 19 | behavior | - | pop string ns, pop string name, pop Value-or-0. Global behavior factory `DAT_10263704->vtbl[5](ns, name, value, &b)`, then `element->vtbl[0x4c/4](b)` on the peeked Element | FUN_100c2626 |
| 1a | mksheet | - | build a PropertySheet (section 9). Push Value | FUN_100c32a8 |
| 1b | entryaddr | - | pop string → FindEntry → push int absolute code pointer. Not used in the corpus | FUN_100c1f64 |
| 1c | fragment | - | pop int index into S4 → run it once (nested Run), cache, push Value | FUN_100c2476 → FUN_100c2215 |
| 1d | anim.const | - | pop Value, pop int → `Value::CreateConstAnimation` | FUN_100c1422 |
| 1e | anim.linear | - | pop Value a, Value b, int → `CreateLinearAnimation` | FUN_100c15c3 |
| 1f | anim.inverse | - | pop Value → `CreateInverseAnimation` | FUN_100c154a |
| 20 | anim.cycle | - | pop Value, int(u16) → `CreateCycleAnimation` | FUN_100c14b6 |
| 21 | anim.composite | - | pop Value a, b → `CreateCompositeAnimation` | FUN_100c1385 |
| 22 | dpi | - | pop x, push `MulDiv(x, dpi, 96)` | FUN_100c44c4 |
| 23 | dpif | - | float bits: x·dpi/96 | FUN_100c4472 |
| 24 | dpivalue | - | pop Value. Size (type 7) → new Size with both fields scaled; Rect (type 8) → all 4 fields scaled with MulDiv(·,dpi,96). Other types → 0x8000FFFF | FUN_100c4508 (disassembly; Ghidra pruned it) |
| 25/26 | or/and | - | pop a, pop b, push b\|a / b&a | FUN_100c425a / FUN_100c1332 |
| 27/28 | min/max | - | pop a, pop b, push min/max | FUN_100c253d / FUN_100c24e6 |
| 29 | pt2font | - | pop pt, push `-MulDiv(pt, dpi, 72)` (LOGFONT height) | FUN_100c42ff |
| 2a | pt2fontf | - | float version: pt·dpi/-72 | FUN_100c42ad |
| 2b | sysmetric | - | pop n. n≥0 → `GetSystemMetrics(n)`. n<0 → field of the system fonts (table below) | FUN_100c46c2 → FUN_100ecdce |
| 2c | sysfontface | - | pop n → push string Value = face name of a system font (1 Caption, 2 Menu, 3 Message, 4 SmCaption, 5 Status, 6 IconTitle) | FUN_100c4700 → FUN_100ecfff |
| 2d | hcselect | - | pop Value hc, pop Value normal. Push hc when high contrast is on, otherwise normal | FUN_100c22c4 (+0x31 flag) |
| 2e | setreg | - | pop int → interpreter+0x24 (use unknown). Not used in the corpus | FUN_100c47ca |

Big-endian decoding of 03/04/07/09–0d is [obs]: `CONCAT11(ip[1],ip[2])` and FUN_100c114e
`CONCAT31(CONCAT21(CONCAT11(p0,p1),p2),p3)`.

**Argument order:** the first operand a handler pops is the top of the stack. The compiler
pushes arguments in reverse order, so `rect(l,t,r,b)` is pushed as `b r t l`.

`sysmetric` negative codes [obs, FUN_100ecdce disassembly: jump table 0x100ecfbe; NONCLIENTMETRICS
via SPI 0x29, ICONMETRICS via SPI 0x2d]:
-1/-2/-3 Caption font height/weight/style · -4/-5/-6 Menu · -7/-8/-9 **Message** ·
-10/-11/-12 SmCaption · -13/-14/-15 Status · -16/-17/-18 IconTitle.
"style" = `italic | underline<<1 | strikeout<<2`.

## 5. mkvalue (op 0x11) sub-types: FUN_100c3583

The arguments are popped in the order listed. "str" means an int string reference into S0.

| sub | Value | args | source |
|---|---|---|---|
| 1 | Int | int | FUN_100c3db6 |
| 2 | Bool | int (≠0) | FUN_100c385f |
| 5 | String | str | FUN_100c41b9 |
| 6 | Point | x, y | FUN_100c3f7d |
| 7 | Size | cx, cy | FUN_100c4134 (`CreateSize(flags=0,cx,cy)`, 0x100a45b5) |
| 8 | Rect | left, top, right, bottom | FUN_100c407a (`SetRect`, 0x100a4571) |
| 9 | Color / Fill | flags; c1; c2 if flags&1; c3 if &2; c4 if &4 → `CreateColor(c1..c4, type=(flags>>8)&0xff, 0, flags>>16)` | FUN_100c3a7f |
| 10 | Layout | pops a **Layout** item (stack type 4) | FUN_100c3e24 |
| 11 | Graphic | str path, u8 blendmode, int blendvalue, u16 cx, u16 cy, int arg, int flags (bit0 flip, bit1 RTL, bit2 ?) | FUN_100c3c6f |
| 13 | Atom | str | FUN_100c37e7 |
| 15 | RLE | str | FUN_100c4002 |
| 16 | `Value::pvUnknownNull` | - | FUN_100c4243 |
| 17 | GUID | str | FUN_100c3bf7 |
| 18 | ValueList | n, then n Values | FUN_100c3e9d |
| 19 | Colorize | int color | FUN_100c38cb |
| 20 | DFC | a, b | FUN_100c3939 |
| 21 | DTB | a, b, c, Value-or-0 | FUN_100c39be |
| 22 | Animation | int, Value, Value, int | FUN_100c36f8 |
| 23 | Float | int whose 32 bits are reinterpreted as an IEEE float (`movss`, 0x100c3ba7) | FUN_100c3b85 |
| 26 | `Value::pvStringNull` | - | FUN_100c422c |

Others → 0x80004001.

**Colors** are 32-bit `0xAABBGGRR`: a COLORREF with the alpha in the top byte. [obs]
`CRMColorResource::ToCOLORREF` 0x1011382d returns `GetSysColor(i) | alpha<<24` for system colors.
[inf] DirectUI `ARGB()` uses the same layout. The decompiler prints `argb(a,r,g,b)`.
A **system color** used as a property value is the Int `10000 + COLOR_index`
(`CRMDUIParser::CreateColorValue` 0x1010a6ef, FUN_1010abd4 kind 'S').

## 6. mklayout (op 0x15) sub-types: FUN_100c2f02

1 `BorderLayout()` FUN_100c0943 · 2 `FillLayout()` FUN_100c09a4 · 3 `FlowLayout(a,b,c,d)`
FUN_100c1849 · 4 `GridLayout(rows,cols)` FUN_100c1919 ·
5 `TableLayout(a, b, flag==1, ints[a+b])` FUN_100c1adc · 6 `NineGridLayout()` FUN_100c0a05 ·
7 `RowLayout(a, b, n, ints[3n])` FUN_100c19b1. Others → 0x8000FFFF. [obs] The meaning of the
FlowLayout/TableLayout ints follows the DirectUI `Create` signatures. [inf] For FlowLayout:
wrap, alignment, line alignment, … The decompiler prints them raw.

## 7. resvalue (op 0x16): FUN_100c3086

It always pops `str module` first (FUN_100c4367), then `int id` (used as u16, MAKEINTRESOURCE).

| sub | provider | extra args (popped after id) | pushes |
|---|---|---|---|
| 1 | CreateStringValue | - | Value |
| 2 | CreateGraphicValue | u8 mode, int value, u16 cx, u16 cy, u8 flags(bit0, bit1) | Value (FUN_100c28ec) |
| 3, 8 | CreateInt | int bool "as char" (ToChar instead of ToInt) | **int** (stack type 1) (FUN_100c2e79) |
| 4 | CreateColorValue | - | Value |
| 5 | CreateColorizeValue | - | Value |
| 6, 7 | CreateImageValue | - | Value |
| 9 | CreateRectValue | - | Value |
| 10 | CreateIconValue | u16 cx, u16 cy, u8 flags | Value (FUN_100c2ce8) |
| 11 | CreateCursorValue | - | Value |
| 12 | CreateAnimationValue | - | Value |
| 13 | CreateFloatValue | - | Value |

Sub-type 3 lets an int resource (a string such as "45") feed arithmetic or a Size: this is how
the template row heights are stored.

## 8. Resource-manager side (needed to turn ids into values)

The module string selects a registered resource module (FUN_10116218/FUN_101160a6, lookup by name).
`""`/NULL means the default module. **The name → DLL mapping is not in the UIB.** [inf] From
resource-id coverage (every referenced id is present): `""` and `mail` → `mailres2.dll` (strings
in `maillang.dll`), `wlux` → `wlidux.dll` (strings in `wliduxloc.dll`).

| kind | resource type | format | source |
|---|---|---|---|
| color | 4002 (0xFA2) | tag byte: `C`+u32 color, `S`+u32 (low 24 = COLOR_*, high = alpha), `D` colorized (3 bytes HSL-ish + alpha), `J`+u16 redirect id, `N` null | CRMColorResource::Load 0x101135df, ToCOLORREF 0x1011382d, GetSystemColorIndex 0x1011338e |
| rect | 4003 (0xFA3) | 18 bytes: RECT (4×i32) + u16 scale mode (≠0 → FUN_10117352) | RMLoadRect 0x101153ef → FUN_1011718d |
| image | 4000 (0xFA0) | tag byte: PNG stream (0x89), `R` RLE (+ info in 4006), `J` redirect, `C`/`D` color, `S` sys color, `F` DFC, `H` 4-color gradient, `T` DTB, `N` null | FUN_1010abd4 |
| string/int/float | 4009 (0xFA9) descriptor `u16 kind` (3 = redirect to u16 id, 5 = special) or none, then RT_STRING of the language DLL | CRMStringResource::Load 0x1011424d, FUN_10116c42 |
| UIB | 4010 (0xFAA) | this format | FUN_1010a91f |
| animation | 4008 (0xFA8) | - | CreateAnimationValue 0x1010a220 |

## 9. bind (op 0x18): FUN_100c270f

Pop `flags`. `n = flags & 0x1f` (must be ≥1). Pop n strings: the first pop goes to path[n-1], so
the path is in push order. If `flags & 0x80`, pop a Value (default). If `flags & 0x40`, pop an int
index (−1 = none). `Binding::Create(n, path, [index,] default)`. `SetTwoWay(flags & 0x20)`.
Pop int prop index, peek Element, `Element::SetBinding`. [obs]

## 10. mksheet (op 0x1a): FUN_100c32a8

```
pop nRules
repeat nRules (pop order = runtime insertion order):
    pop classIdx (S1)
    pop nDecl ; repeat: pop propIdx, pop Value          -> Decl {ppi, Value}       (FUN_100c320c, 8 bytes)
                 (a Decl whose Value has type -1/unavailable is silently skipped)
    pop nCond ; repeat: pop propIdx, pop int op, pop Value -> Cond {ppi, op, Value} (FUN_100c315b, 12 bytes)
    PropertySheet::AddRule(class, conds, decls)          (FUN_100b4d1e, param order checked)
push Value::CreatePropertySheet
```

Condition operators (FUN_100b4fdb, sheet lookup): **0 = IsEqual, 1 = !IsEqual,
2 = Value::BitwiseAnd (non-zero)**. Op 2 is how `Tag` bit flags are tested (`[Tag&65536]`).
The "property" `Class` is a normal string property. `ID`/`id` conditions carry Atom values.
Lookup returns the Value of the **first** rule in the per-property list whose conditions all hold.
The list is ordered by FUN_100b531f. [inf] It is ordered by specificity, then insertion.

## 11. Program structure (observed in all 29 files)

- An entry builds a tree: `push cls; newelem` → a series of `<value>; push prop; setprop` →
  for each child `<child...>; addchild; pop` → `ret`. The root Element is left on the stack and
  returned to the caller.
- Fragment 0 is the file's sheet. The root elements reference it as `Sheet = fragment(0)`.
- **Dead code** [obs from coverage]: some files contain code blocks that start right after a
  `ret`, that no entry or fragment reaches, and that cannot be reached by any jump (the corpus has
  no jumps or calls). They duplicate common templates (`WLXLinkAutodetect`, `UXEditMenu`, ...).
  [inf] The compiler emitted them for duplicate definitions and kept one name per entry. The
  decompiler outputs them under `<orphans>`.
- **Broken entry**: in 8 files (4500, 4501, 44903, 44904, 6069, 6919, 7006, 7007) the
  `UXEditMenu` entry contains `push Sheet; setprop` with no Value pushed. At runtime FUN_100c08e0
  pops the Element (type 2 ≠ 3) and returns 0x80004005, so the entry cannot be instantiated. The
  decompiler marks it `_error` and keeps decoding.
- The corpus never uses: 01 halt, 07/09–0d jumps, 0e call, 14, 1b, 1d–21, 23, 25–28, 2a, 2e.
  Frequency of the rest: see `uib2xml.py --check`.

## 12. XML produced by uib2xml.py

- `<classes>`, `<properties>`, `<resources>` (S5, with the annotation `resolved=`),
  `<fragments>` (S4 sheets), `<entries>` (S3 trees), `<orphans>`.
- Element tag = class name. Attributes = properties in setprop order. `_at` = address of the
  `newelem` opcode. Complex values (sheets) go in `<Property name=…>`. `<Binding>` and
  `<Behavior ns= name= value=>` are children.
- Value syntax: `rect(l,t,r,b)`, `size(cx,cy)`, `point(x,y)`, `argb(a,r,g,b)`, `true/false`,
  plain text for string/atom, `dpi(x)`, `pt(x){=-Npx@96dpi}`, `sysmetric(MessageFont.Height)`,
  `sysfontface(MessageFont)`, `hc(normal,highcontrast)`, `res.<kind>(id[,module=m][,args])`,
  `resint(id[,module])`, `fragment(k)`. `{=…}` is an annotation read from the installed resource
  DLLs and is not part of the UIB.
- Sheet: `<Rule order= selector=>` with `<If property op value>` and `<Set property value>`, in
  pop/runtime order.
- `--asm` adds a complete linear disassembly (`<disassembly>`) for byte-level checking.
