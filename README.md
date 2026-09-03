# reverse-engineering — ZCode/AI agent skill

A static-first reverse engineering skill for AI coding agents (ZCode skill
format; works for any agent that reads SKILL.md). Built and battle-tested on
a real Windows x64 box.

## What's inside

- `SKILL.md` — the workflow: scope/authorization check, case hygiene, layered
  PE triage (sections → data directories → imports/delay-imports → TLS →
  resources/version → strings), interpretation discipline, tool escalation.
- `scripts/pe_inspect.py` — zero-dependency PE parser: headers, sections,
  data directories, imports **and delay imports**, exports (with forwarder
  detection), TLS callbacks, resource tree, VS_VERSIONINFO, strings.
- `scripts/functions.py` — exact x64 function map from the `.pdata` exception
  table (vendor-provided, no heuristics) + capstone disassembly with ILT
  thunk-following. 867k functions from a 266MB game exe in 0.6s.
- `scripts/disasm.py` — capstone disassembly anchored at entry/RVA/export.
- `scripts/DecompileExports.java` — Ghidra headless postscript that
  decompiles every exported entry point to C (Java, because `.py`
  postscripts don't work without PyGhidra).
- `references/pe-format.md` — byte-level PE walkthrough with the classic
  traps (RVA→offset math, wValueLength WORDS-vs-BYTES, delay-descriptor
  address styles).
- `references/windows-tooling.md` — tool inventory + the IDM download route
  for GitHub behind hostile networks (China), with real gotchas.

## Scope

Static analysis of binaries you own or are authorized to analyze: CTF,
SDK/interop, suspicious-file triage, malware analysis. The skill explicitly
refuses online-game cheat replication, anti-cheat/DRM bypass, and
unauthorized targeting.

## License

MIT
