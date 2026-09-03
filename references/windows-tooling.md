# Tooling on this machine (Windows x64)

## Installed (verified 2026-09-04)

| Tool | Path | Use |
|------|------|-----|
| radare2 6.0.8 | `C:\Users\VOS_User\tools\radare2\radare2-6.0.8-w64\bin\radare2.exe` | full analysis: `r2 -q -c "aaa" -c "afl" <file>`, `pdf @ sym...` |
| Ghidra 12.1.3 | `C:\Users\VOS_User\tools\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat` | headless import+analysis+**decompilation** (needs JAVA_HOME, see below) |
| Temurin JDK 21.0.12 | `C:\Users\VOS_User\tools\jdk-21.0.12+8` | set `JAVA_HOME` to this before analyzeHeadless |
| Python 3.14 | `python` on PATH | bundled skill scripts |
| capstone 5.0.9 | pip user site | disasm.py / functions.py |
| Git Bash utils | `file`, `xxd`, `grep` | quick magic-byte checks |

Ghidra headless template (decompile all exports):

```bash
export JAVA_HOME="C:\\Users\\VOS_User\\tools\\jdk-21.0.12+8"
"C:/Users/VOS_User/tools/ghidra_12.1.3_PUBLIC/support/analyzeHeadless.bat" \
  "C:\\Users\\VOS_User\\tools\\ghidra-projects" <ProjName> \
  -import <target> \
  -scriptPath "C:\\Users\\VOS_User\\.agents\\skills\\reverse-engineering\\scripts" \
  -postScript DecompileExports.java -deleteProject
```

**Ghidra script gotcha:** `.py` postscripts fail headless with "Ghidra was
not started with PyGhidra" — use **Java** postscripts (compiled in-JVM,
always work); `scripts/DecompileExports.java` is the working example.

Measured reference points (Anomaly.Core.dll, 6.8MB): r2 `aaa` 28s → 8,886
functions; `.pdata` map → 15,125 (exact; heuristics miss ~40% pointer-only
functions); Ghidra headless analysis of a 300KB DLL ≈ 75s.

## Downloading on this box — the IDM route

`github.com` is **unreachable for direct connections** (curl: instant SSL
reset; the Watt Toolkit accelerator does not help non-browser tools).
**IDM works** — multi-threaded engine pulls 4-6 MB/s from GitHub releases.
Scripted use:

```bash
MSYS_NO_PATHCONV=1 powershell -NoProfile -Command "& 'C:\Program Files (x86)\Internet Download Manager\IDMan.exe' /d '<URL>' /p 'C:\Users\VOS_User\tools' /f '<name>' /n"
```

Gotchas learned: IDM writes nothing to the target until completion (poll
the final file, not temp); silent `/n` still pops a completion dialog that
can stall the queue — close it and tick "don't ask again"; row status
**等待控制** = queued-not-started (fix: toolbar 继续 or `/s` after a
restart), **没有找到** = bad URL (404 — confirm release asset filenames
first; build dates in filenames ≠ upload dates); re-firing the same `/d`
spawns a duplicate queue entry. Killing and relaunching IDMan.exe clears
stuck queue states and makes the UI automatable again (a fresh
non-elevated instance exposes UIA; an elevated or dialog-blocked one may
not).

## Pre-installed basics

| Tool | Where | Use |
|------|-------|-----|
| PowerShell 5.1 | `powershell` | `Get-AuthenticodeSignature <file>` verifies Authenticode dir 4 entries properly |

Not installed: MSVC (cl), CMake, IDA, pefile. pip/PyPI are reachable.

**Network reality (verified 2026-09-04):** direct connections to github.com
fail (instant SSL reset); winget works but has no radare2/Ghidra package;
the PyPI `radare2` package is a source dist needing MSVC (fails). The
working route for GitHub artifacts is **IDM** — see the section above.

Function discovery additionally runs fully offline: `scripts/functions.py`
reads the x64 `.pdata` exception table (dir 3) for the exact vendor
function map and disassembles with capstone — see SKILL.md §5.

## Which tool for which question

| Question | Cheapest sufficient tool |
|----------|--------------------------|
| What is this file at all? | `file` + magic bytes, bundled inspector |
| What can it do? | imports/exports from bundled inspector |
| Who built it / where? | PDB path, linker timestamp, version block, `Get-AuthenticodeSignature` |
| Is it packed? | section names/entropy, import count (~all ordinal, few DLLs) |
| What's at this address? | `scripts/disasm.py` (capstone; entry/RVA/export anchors) |
| List functions / disasm one? | `scripts/functions.py` (.pdata map, thunk-following) |
| What does function X do? (deep) | r2 `pdf` (28s/6.8MB `aaa`) → Ghidra headless decompile (DecompileExports.java) |
| What's in its resources/version? | bundled inspector (resources + VERSION parsed); pefile for oddballs |

## Entropy check (packer detection) — one-liner

No default tool computes section entropy; use Python when needed:

```python
import math
def entropy(b):
    if not b: return 0.0
    c = [0]*256
    for x in b: c[x] += 1
    return -sum(v/len(b)*math.log2(v/len(b)) for v in c if v)
```

`.text` normally ~6.0–6.5; a "code" section at ≥7.2 with almost no imports
is packed/encrypted. (7.999 ≈ compressed or encrypted.)
