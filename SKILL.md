---
name: reverse-engineering
description: >
  Static reverse engineering of binaries on this Windows machine — PE/DLL/EXE
  structure, imports/exports, strings, PDB paths, file formats, CTF challenges,
  SDK/interop questions, and unknown-file triage. Use whenever the user asks to
  analyze, inspect, "看看这个 DLL/EXE 是干嘛的", reverse, unpack, or understand a
  binary or unknown file. Zero tooling required (bundled pure-Python PE parser);
  escalation paths for pefile/capstone/radare2/Ghidra when justified. Scope:
  legitimate analysis only — refuse to help bypass anti-cheat/DRM, replicate
  online-game cheats, or attack systems without authorization, and say why.
---

# Reverse Engineering (static-first, Windows)

Analyze binaries by reading bytes, not by running them. Every step below is
safe: static inspection cannot execute the sample.

## 1. Scope check (do this before touching the file)

Legitimate targets: the user's own binaries, locally-owned software being
analyzed for interop/learning, CTF challenges, SDK samples, suspicious files
the user was sent, malformed documents, malware triage in an offline setting.

Refuse (and briefly say why) when the goal is:

- Replicating cheats/cheat plugins for **online** games (e.g. memory-edit
  unlocks, ESP, teleport in a live service), or bypassing anti-cheat.
- Stripping DRM or licensing from commercial software.
- Attacking or intruding on systems the user doesn't own or have written
  authorization to test.

Analysis of a locally-installed **modding runtime's** plugin interface
(ABI, exports, manifest conventions) is interop work and is fine; analysis
whose *purpose* is cloning game-state manipulation is not. When unsure, ask
what outcome the user wants before starting.

## 2. Case hygiene

1. Work on a **copy** in a scratch directory (e.g. `./re-case/<name>/`); never
   modify the original.
2. Record the SHA-256 up front (the bundled script prints it) so later
   re-analysis can be tied to the same sample.
3. Keep a running `NOTES.md` in the case dir: observation → evidence (file
   offset / RVA) → hypothesis. Hypotheses get revised; evidence doesn't.
4. **Never execute the sample on this machine** to "see what it does". Dynamic
   analysis belongs in an isolated VM, and only when there's a real need.

## 3. Triage workflow

Run the bundled inspector first — it needs nothing but Python and answers
most structural questions:

```bash
python "<skill-dir>/scripts/pe_inspect.py" <target>            # full report
python "<skill-dir>/scripts/pe_inspect.py" <target> --strings 6 --utf16 | head -100
```

`<skill-dir>` is `C:\Users\VOS_User\.agents\skills\reverse-engineering`.
String extraction cost scales with file size (a 250MB binary takes over a
minute): for a targeted question, pipe straight into `grep -iE "<pattern>"`;
only persist the full dump (`... > strings.txt`) when you will query it
repeatedly, and do that once per case.

Read the report in this order and note what each layer tells you:

1. **Machine / PE32+ / subsystem** — x64 driver vs GUI exe vs console tool
   sets expectations before anything else. `NATIVE` subsystem means kernel
   driver territory.
2. **Linker timestamp** — build date; correlates against file version info
   and known releases. (Can be faked/zeroed; treat as a hint.)
3. **Sections** — names (` .text/.rdata/.data` are stock; odd names like
   `UPX0`/`.aspack` scream packer; a section with EXECUTE+WRITE is suspicious),
   and raw-size ≫ virtual-size gaps.
4. **Data directories** — a `Security` entry means an Authenticode signature;
   the report enumerates **TLS callbacks** (they run before `main`, so they
   are a classic early-execution/anti-debug hook spot — a few callbacks in a
   game or packed binary deserve a look at their RVAs); `Debug` may leak a
   **PDB path** — the single highest-value string in a
   first pass, it names the developer's build tree and original project.
5. **Imports** — the "what can it do" list: `WriteProcessMemory`/
   `CreateRemoteThread`/`SetWindowsHookEx` = injection; `WinHttpSendRequest`
   /`InternetOpenUrl` = networking; `CryptEncrypt` = crypto/ransomware;
   `RegSetValue`+`MoveFileEx` = persistence; imports resolved by ordinal
   only (`#1234`) hide intent and deserve a second look. A **tiny static
   import table on a large binary is itself a finding** (custom loader or
   packer): the real dependencies sit in the **delay imports** section of
   the report, or are resolved at runtime via `LoadLibrary`+`GetProcAddress`
   (in which case expect the strings to carry DLL names but no imports).
6. **Resources & version block** — the report summarizes resource types
   (icons/dialogs/manifest) and decodes the `VERSION` block: file/product
   version, CompanyName, FileDescription, OriginalFilename. This is the
   cheapest cross-check on the signer and often reveals internal product
   names the vendor didn't put on the box.
7. **Exports** — for DLLs this is the contract: one export like
   `AnomalyPluginEntryV1` is an ABI entry point; hundreds of C++-mangled
   names (`?fn@@YA...`) reveal the original API surface. Note forwarders
   (`-> forwarded to X.Y`): the real code lives in another module.

For non-PE files, identify by magic bytes before assuming: `file <target>`,
or read the first 16 bytes with `xxd -l 16`. ZIP/OLE/SQLite/Mach-O/ELF magic
changes the whole plan. (Many "DLLs" are actually ZIPs renamed.)

## 4. Interpreting vs. asserting

State confidence explicitly. "Imports WriteProcessMemory and exports a single
`Init`" is evidence; "this is an injector" is a hypothesis that needs the
code path or a corroborating string. Quote strings with their file offset so
claims are checkable. When the answer genuinely isn't in static data —
obfuscated config, encrypted strings, VM-protected code — say so and list
what tooling would be needed next instead of guessing.

## 5. Escalation (only when static basics aren't enough)

**Tier 1 — offline (always available here).** capstone is installed; the
bundled scripts cover function-level work without any network:

```bash
# exact function map from the x64 .pdata exception table (dir 3):
python "<skill-dir>/scripts/functions.py" <target> --list --top 20
# disassemble the real body of an export (auto-follows ILT jump thunks):
python "<skill-dir>/scripts/functions.py" <target> --export AnomalyStart --disasm
# which function contains this address + neighbors:
python "<skill-dir>/scripts/functions.py" <target> --where 0x18004CF80
# free-form disassembly at any anchor (entry point / RVA):
python "<skill-dir>/scripts/disasm.py" <target> --entry
```

x64 `.pdata` gives every function's exact bounds — no heuristics — but only
covers registered non-leaf functions (thunks/hand-written asm are absent,
hence the thunk-following and linear-fallback in the script). Read forward
from anchors until `ret` or `int3` padding; `jmp [rip+...]` thunks are
link-table style.

**Tier 2 — radare2 + Ghidra headless (installed 2026-09-04, see
`references/windows-tooling.md` for exact paths).** Use when static basics
aren't enough: r2 for fast full-program analysis (`r2 -q -c "aaa" -c "afl"
<file>` ≈ 30s per 7MB), Ghidra headless for C-like decompilation via the
bundled `scripts/DecompileExports.java` postscript (needs
`JAVA_HOME=C:\Users\VOS_User\tools\jdk-21.0.12+8`; `.py` postscripts do
NOT work headless on this install — Java only). Note: r2's heuristic
`aaa` finds fewer functions than the exact `.pdata` map — run both.
Ghidra analysis is static and never executes the sample.

Never install tools silently, and don't re-download anything from GitHub
directly — use the IDM route documented in windows-tooling.md.

## 6. Deliverable

Close every analysis with a short report: what the binary is (type, arch,
build date, signer), what it can do (imports/exports summary), notable
strings/PDB paths with offsets, open questions, and next-step options. Write
it to `NOTES.md` in the case dir and summarize inline in the reply.

## References (read on demand)

- `references/pe-format.md` — byte-level PE walkthrough: every struct the
  inspector parses, with offsets, so findings can be verified by hand.
- `references/windows-tooling.md` — what's available on this machine, how to
  install the rest (pip/winget/scoop), and which tool for which job.
