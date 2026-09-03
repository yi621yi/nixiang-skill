# PE format, byte by byte

This matches exactly what `scripts/pe_inspect.py` parses. All multi-byte
fields are **little-endian**. Follow along in a hex dump (`xxd -l 512 <file>`)
to verify any inspector claim by hand.

## 1. DOS header (64 bytes at file offset 0)

| Offset | Size | Field          | Meaning |
|-------:|-----:|----------------|---------|
| 0x00   | 2    | `e_magic`      | `MZ` (0x5A4D) — the only mandatory check |
| 0x3C   | 4    | `e_lfanew`     | file offset of the PE signature |

Everything between 0x40 and `e_lfanew` is DOS stub + Rich header; the Rich
header (if present, `DanS` XORed) leaks the exact VS toolchain versions used
to build — useful provenance, but only readable in a hex dump.

## 2. Signature + COFF header (at `e_lfanew`)

- `e_lfanew+0`: `PE\0\0` signature.
- `e_lfanew+4`, 20 bytes, struct `<HHIIIHH`:

| Offset | Size | Field                | Notes |
|-------:|-----:|----------------------|-------|
| +0     | 2    | `Machine`            | 0x8664 x64, 0x14C x86, 0xAA64 ARM64 |
| +2     | 2    | `NumberOfSections`   | section table size follows optional header |
| +4     | 4    | `TimeDateStamp`      | Unix time of LINK.EXE run (often zeroed) |
| +12    | 2    | `SizeOfOptionalHeader` | optional header size; section table follows it |
| +18    | 2    | `Characteristics`    | 0x2000 = DLL, 0x0100 = 32-bit words |

## 3. Optional header (COFF +20; offsets below are from its start)

Both PE32 (0x10B) and PE32+ (0x20B) share most offsets until the data dirs:

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| +0     | 2    | `Magic` | 0x10B = PE32, 0x20B = PE32+ (64-bit) |
| +16    | 4    | `AddressOfEntryPoint` | RVA; where the loader starts execution |
| +24/28 | 8/4  | `ImageBase` | preferred load address (PE32+ reads 8 bytes) |
| +68    | 2    | `Subsystem` | 2=GUI, 3=console, 1=native (driver) |
| +70    | 2    | `DllCharacteristics` | ASLR(0x40 DYNAMIC_BASE), DEP(0x100 NX_COMPAT), CFG(0x4000 GUARD_CF) |
| +96/+112 | 16×8 | **Data directories** | PE32 base 96, PE32+ base 112 |

Data directory index → meaning: 0 Export, 1 Import, 2 Resource, 3 Exception,
4 Security (Authenticode), 5 BaseReloc, 6 Debug, 9 TLS, 12 IAT, 13 DelayImport.
Each entry is `(VirtualAddress, Size)` — RVAs, not file offsets.

**RVA → file offset**: find the section `s` with
`s.VirtualAddress <= rva < s.VirtualAddress + max(VirtualSize, SizeOfRawData)`;
then `offset = rva - s.VirtualAddress + s.PointerToRawData`. RVAs below the
first section's VA map 1:1 (headers). An RVA inside a section but past
`SizeOfRawData` exists only in memory (e.g. `.bss` zero-fill) — no bytes on
disk. This is the single most common hand-verification trap.

## 4. Section table (optional header end; 40 bytes each, struct `<8sIIIIIIHHI`)

| Offset | Field | Notes |
|-------:|-------|-------|
| +0     | `Name`        | 8 bytes, NUL-padded, *not* guaranteed unique |
| +8     | `VirtualSize` | size in memory |
| +12    | `VirtualAddress` | RVA of section start |
| +16    | `SizeOfRawData` | size on disk (usually aligned) |
| +20    | `PointerToRawData` | file offset of section start |
| +36    | `Characteristics` | 0x20 code, 0x40 idata, 0x80 udata, 0x20000000 exec, 0x40000000 read, 0x80000000 write |

Red flags: writable+executable (self-modifying/packed code), `VirtualSize ≫
SizeOfRawData` in an exec section (unpacking target), nonstandard names in an
otherwise boring binary.

## 5. Export directory (data dir 0)

`<IIHHIIIIIII` at the mapped RVA:

| Field | Use |
|-------|-----|
| `Name` RVA    | DLL's own advertised name |
| `Base`        | first ordinal number |
| `NumberOfFunctions` / `NumberOfNames` | exports can exceed named exports (ordinal-only exports) |
| `AddressOfFunctions` | RVA→array of 4-byte function RVAs, indexed by (ordinal − Base) |
| `AddressOfNames` / `AddressOfNameOrdinals` | name strings and per-name index into the functions array |

**Forwarder check**: if a function RVA points *inside the export directory
itself*, the "function" is an ASCII string like `OTHERDLL.realFunc` — the
loader resolves it in the other module. The inspector flags these.

## 6. Import directory (data dir 1)

Array of 20-byte `IMAGE_IMPORT_DESCRIPTOR` (`<IIIII`:
`OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk`),
terminated by an all-zero entry.

- `Name` → RVA of DLL name string.
- Walk `OriginalFirstThunk` (or `FirstThunk` if bound) as thunk array:
  PE32+ entries are 8 bytes, PE32 are 4. High bit set = import **by ordinal**
  (low 16 bits); otherwise the value is an RVA to a 2-byte hint followed by
  the ASCII function name. By-ordinal imports are the standard way to hide
  what a binary calls.
- `TimeDateStamp == 0` = load-time bound; `0xFFFFFFFF` = delay-bound via
  dir 13.

## 7. Debug directory (data dir 6) — PDB paths

Array of 28-byte `IMAGE_DEBUG_DIRECTORY`; type 2 = CODEVIEW. For those,
`PointerToRawData` (field at +24) points to an NB10 string: `...path\foo.pdb`
— the build machine's path. Also present in dir 6: type 1 = COFF symbols,
type 12 = reproducible-build flags (means the linker timestamp is fake-safe,
see `TimeDateStamp` above).

## 8. Strings extraction

The inspector greps runs of printable ASCII (`[ -~]{N,}`) and, with
`--utf16`, runs of ASCII alternating with `\x00` (UTF-16LE — most Windows
UI strings). Sort findings by offset: strings clustered near the entry-point
section tend to be runtime boilerplate; those in `.rdata` near the import
names are the author's. URLs, mutex names (`Global\...`), registry paths,
PDB paths and format strings are the highest-yield patterns.

## 9. Delay-load directory (data dir 13)

Array of 32-byte `ImgDelayDescr` (`<IIIIIIII`: `grAttrs, szName, phmod, pIAT,
pINT, pBoundIAT, pUnloadIAT, dwTimeStamp`), NULL-terminated. Hardened and
packed binaries keep the static import table at one or two entries and put
the real dependency list here — always read it before believing "this binary
barely imports anything".

Key detail: **`grAttrs & 1` (dlattrRva) decides the address style.** Set =
`szName`/`pIAT`/`pINT` are RVAs (modern MSVC); clear = they are *absolute
VAs under the preferred ImageBase* (legacy) — subtract ImageBase before
mapping RVA→offset. Walk `pINT` (fall back to `pIAT`) as a normal thunk
array (see §6): high bit = import by ordinal, else RVA to hint+name.

## 10. TLS directory (data dir 9)

One `IMAGE_TLS_DIRECTORY`: 40 bytes in PE32+ (`StartAddressOfRawData` 8,
`EndAddressOfRawData` 8, `AddressOfIndex` 8, **`AddressOfCallBacks` 8**,
`SizeOfZeroFill` 4, `Characteristics` 4); 24 bytes in PE32 (4-byte pointers).
Note these are *pointers*, i.e. VAs, not RVAs.

`AddressOfCallBacks` → NULL-terminated array of callback VAs. Every entry
runs in `DllMain`-context **before the entry point**, which is why packed
binaries, anti-cheat modules and anti-debug tricks live there: a TLS
callback executes even if the process is created suspended and the entry
point is never reached by a naive debugger. Count and RVAs of the callback
array are the first thing to check when dir 9 is present. A callback that
is a bare `jmp qword ptr [rip+N]` thunk sitting next to the entry point is
the stock MSVC CRT stub — normal, not injected.

## 11. Resource directory (data dir 2)

A tree, always 3 levels: **type → id/name → language**. Every level is an
`IMAGE_RESOURCE_DIRECTORY` (16 bytes: characteristics, timestamp, major,
minor, `NumberOfNamedEntries`, `NumberOfIDEntries`) followed by 8-byte
entries (`NameOrId, OffsetToData`).

- `NameOrId` high bit set → it is a *name*: lower 31 bits are an offset (from
  the resource base) to `IMAGE_RESOURCE_DIR_STRING_U` (WORD length + WCHARs,
  **not** NUL-terminated). Clear → integer ID. Type level uses IDs:
  1 CURSOR, 2 BITMAP, 3 ICON, 4 MENU, 5 DIALOG, 6 STRING, 10 RCDATA,
  12 GROUP_CURSOR, 14 GROUP_ICON, 16 VERSION, 24 MANIFEST.
- Entry `OffsetToData` high bit set → *subdirectory*: lower 31 bits offset
  from resource base. Clear → leaf `IMAGE_RESOURCE_DATA_ENTRY`: `DataRVA,
  Size, CodePage, Reserved` — the RVA is into the image (map RVA→offset
  with the usual section math).

All offsets inside the resource tree are relative to the resource directory
start, not to the file.

## 12. VS_VERSIONINFO (VERSION resource payload)

Layout: node = `wLength, wValueLength, wType` (6 bytes) + szKey (UTF-16LE,
NUL-terminated) + pad-to-4 + Value + pad-to-4 + children. Root key
`VS_VERSION_INFO`, Value = 52-byte `VS_FIXEDFILEINFO` (signature
`0xFEEF04BD`; FileVersionMS/LS at +8/+12, ProductVersionMS/LS at +16/+20;
each `.%d.%d` pair comes from HIWORD/LOWORD).

Then `StringFileInfo` → StringTable (key = 8 hex digits: langid+codepage,
e.g. `040904b0`) → String nodes (key = `CompanyName`, `FileDescription`,
`FileVersion`, `ProductName`, ...; Value = UTF-16LE text).

**The classic trap**: `wValueLength` counts **WORDS (characters) when
`wType == 1` (text)** but **bytes when `wType == 0` (binary)**. Using it as
a byte count on text truncates strings mid-codepoint — if decoded version
strings end in U+FFFD, this is why. Also `VarFileInfo` → `Translation`
contains additional (langid, codepage) pairs beyond the StringTable key.
