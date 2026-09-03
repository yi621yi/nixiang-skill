#!/usr/bin/env python3
"""disasm.py - capstone-based static disassembler for PE files. Never executes code.

Usage:
  python disasm.py <file> --entry               # at AddressOfEntryPoint
  python disasm.py <file> 0x1800012F3           # by VA (>= ImageBase) or RVA
  python disasm.py <file> 0x10689EC0 -n 10      # 10 instructions at an RVA
  python disasm.py <file> --export AnomalyStart # at an export's address

Requires: python -m pip install --user capstone
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_inspect import PE, PEError  # noqa: E402


def resolve(pe, ib, arg):
    v = int(arg, 16) if arg.lower().startswith("0x") else int(arg, 16)
    if ib and v >= ib:
        return v                      # already a VA
    if not ib:
        sys.exit("no ImageBase; pass a VA")
    return ib + v                     # treat as RVA


def main():
    ap = argparse.ArgumentParser(description="Static disassembler for PE files (capstone)")
    ap.add_argument("file")
    ap.add_argument("address", nargs="?", help="hex VA or RVA")
    ap.add_argument("--entry", action="store_true", help="disassemble at AddressOfEntryPoint")
    ap.add_argument("--export", metavar="NAME", help="disassemble at a named export")
    ap.add_argument("-n", "--count", type=int, default=24, help="instruction count (default 24)")
    args = ap.parse_args()

    try:
        import capstone
    except ImportError:
        sys.exit("capstone not installed. Run:\n  python -m pip install --user capstone")

    data = open(args.file, "rb").read()
    try:
        pe = PE(data)
    except PEError as e:
        sys.exit("ERROR: %s" % e)
    ib = pe.opt.get("image_base", 0)

    if args.entry:
        if not pe.opt:
            sys.exit("no optional header (no entry point)")
        va = ib + pe.opt["entry"]
    elif args.export:
        exp = pe.exports()
        match = [e for e in (exp or {}).get("entries", []) if e["name"] == args.export]
        if not match:
            sys.exit("export %r not found (named exports: %d)" % (
                args.export, (exp or {}).get("named", 0)))
        va = ib + match[0]["rva"]
    elif args.address:
        va = resolve(pe, ib, args.address)
    else:
        sys.exit("give an address, --entry, or --export")

    rva = va - ib
    off = pe.rva_to_off(rva)
    if off is None:
        sys.exit("address 0x%X (RVA 0x%X) is not mapped to file bytes" % (va, rva))
    sec = next((s for s in pe.sections
                if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"])), None)
    remaining = (sec["rawptr"] + sec["rawsize"] - off) if sec else len(data) - off
    code = data[off:off + min(remaining, max(args.count * 16, 256))]

    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if pe.pe32plus else capstone.CS_MODE_32)
    print("=== DISASM %s @ VA=0x%X (RVA=0x%X, section=%s) ===" % (
        args.file, va, rva, sec["name"] if sec else "?"))
    n = 0
    for insn in md.disasm(code, va):
        print("  0x%012X  %-22s %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
        n += 1
        if n >= args.count:
            break
    if n == 0:
        print("  (capstone decoded 0 instructions — data, not code?)")


if __name__ == "__main__":
    main()
