#!/usr/bin/env python3
"""functions.py - x64 function discovery from .pdata + capstone disassembly.

On x64 PE images, dir 3 (Exception/.pdata) holds a sorted RUNTIME_FUNCTION
table (StartRVA, EndRVA, UnwindRVA, 12 bytes each) for every non-leaf
function — an exact, vendor-provided function map that needs no heuristic
analysis. Combine with capstone for per-function disassembly. Static only.

Jump thunks (ILT `jmp rel32` / `jmp [rip+disp]`) are not in .pdata; targets
that land on one are followed a single hop automatically.

Usage:
  python functions.py <file> --list --top 20           # count + N largest
  python functions.py <file> --where 0x18004CF80       # containing function + context
  python functions.py <file> --disasm 0x4CF80 -n 60    # disasm whole function
  python functions.py <file> --export AnomalyStart --disasm
"""
import argparse
import bisect
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_inspect import PE, PEError  # noqa: E402


def load_pdata(pe):
    rva, size = pe.dirs[3]
    if not (rva and size):
        return None
    off = pe.rva_to_off(rva)
    if off is None:
        return None
    funcs = []
    for i in range(size // 12):
        s, e, _u = struct.unpack_from("<III", pe.data, off + i * 12)
        if s:
            funcs.append((s, e))
    return funcs


def label_for(pe, ib, start_rva, exports):
    if start_rva in exports:
        return exports[start_rva]
    if pe.opt and pe.opt.get("entry") == start_rva:
        return "<entry point>"
    return None


def resolve_addr(arg, ib):
    v = int(arg, 16)
    return v - ib if ib and v >= ib else v  # VA if >= ImageBase, else RVA


def follow_thunk(pe, ib, rva):
    """If rva points at a jmp thunk, return the target VA (one hop)."""
    off = pe.rva_to_off(rva)
    if off is None:
        return None
    b = pe.data[off:off + 6]
    if b[:1] == b"\xE9":  # jmp rel32
        rel = struct.unpack_from("<i", pe.data, off + 1)[0]
        return ib + rva + 5 + rel
    if b[:2] == b"\xFF\x25":  # jmp qword ptr [rip+disp32]
        disp = struct.unpack_from("<i", pe.data, off + 2)[0]
        slot_off = pe.rva_to_off(rva + 6 + disp)
        if slot_off is not None:
            return struct.unpack_from("<Q", pe.data, slot_off)[0]
    return None


def find_func(funcs, starts, rva):
    i = bisect.bisect_right(starts, rva) - 1
    if i >= 0 and funcs[i][0] <= rva < funcs[i][1]:
        return i
    return None


def disasm_range(pe, ib, start_rva, end_rva, count):
    import capstone
    foff = pe.rva_to_off(start_rva)
    code = pe.data[foff:foff + (end_rva - start_rva)]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    n = 0
    for insn in md.disasm(code, ib + start_rva):
        print("  0x%012X  %-20s %s %s" % (insn.address, insn.bytes.hex(),
                                          insn.mnemonic, insn.op_str))
        n += 1
        if n >= count:
            print("  ... truncated at %d instructions (%d bytes total)" % (
                count, end_rva - start_rva))
            break
    if n == 0:
        print("  (0 instructions decoded)")


def main():
    ap = argparse.ArgumentParser(description="Function map from .pdata + capstone disasm")
    ap.add_argument("file")
    ap.add_argument("--list", action="store_true", help="summarize function map")
    ap.add_argument("--top", type=int, default=15, metavar="N")
    ap.add_argument("--where", metavar="ADDR", help="function containing this hex VA/RVA")
    ap.add_argument("--disasm", nargs="?", const="", default=None, metavar="ADDR",
                    help="disassemble containing function (address optional when "
                         "combined with --export/--where)")
    ap.add_argument("--export", metavar="NAME", help="resolve named export as target")
    ap.add_argument("-n", "--count", type=int, default=200, help="max instructions for --disasm")
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    try:
        pe = PE(data)
    except PEError as e:
        sys.exit("ERROR: %s" % e)
    if not pe.pe32plus:
        sys.exit(".pdata function map requires x64 PE32+ (this file is PE32)")
    ib = pe.opt.get("image_base", 0)
    exp = pe.exports() or {}
    exports = {e["rva"]: e["name"] for e in exp.get("entries", [])
               if not e.get("forwarder")}
    funcs = load_pdata(pe)
    if not funcs:
        sys.exit("no usable .pdata (dir 3) — function map unavailable")
    starts = [s for s, _ in funcs]

    want_disasm = args.disasm is not None
    target_rva = None
    if args.export:
        hit = [e for e in exp.get("entries", []) if e["name"] == args.export]
        if not hit:
            sys.exit("export %r not found" % args.export)
        target_rva = hit[0]["rva"]
    elif args.disasm:
        target_rva = resolve_addr(args.disasm, ib)
    elif args.where:
        target_rva = resolve_addr(args.where, ib)

    if target_rva is None:
        if want_disasm or args.where:
            sys.exit("--disasm without an address needs --export or --where")
        total_bytes = sum(e - s for s, e in funcs)
        print("=== FUNCTION MAP: %s ===" % args.file)
        print("functions: %d   code covered: %.1f MB" % (len(funcs), total_bytes / 1048576))
        print("largest %d:" % args.top)
        for s, e in sorted(funcs, key=lambda f: f[1] - f[0], reverse=True)[:args.top]:
            print("  0x%-9X-0x%-9X %8d bytes  %s" % (
                s, e, e - s, label_for(pe, ib, s, exports) or ""))
        return

    i = find_func(funcs, starts, target_rva)
    if i is None:
        tv = follow_thunk(pe, ib, target_rva)  # thunk targets aren't in .pdata
        if tv is not None:
            trva = tv - ib if ib and tv >= ib else tv
            j = find_func(funcs, starts, trva)
            if j is not None:
                print("(followed thunk 0x%X -> 0x%X)" % (ib + target_rva, tv))
                target_rva, i = trva, j

    if i is not None:
        s, e = funcs[i]
        lab = label_for(pe, ib, s, exports) or "sub_%x" % s
        if args.where and not want_disasm:
            print("0x%X is inside function %s (RVA 0x%X-0x%X, %d bytes)" % (
                ib + target_rva, lab, s, e, e - s))
            print("context:")
            for fs, fe in funcs[max(0, i - 2):i + 3]:
                labn = label_for(pe, ib, fs, exports) or "sub_%x" % fs
                print("  %s 0x%-9X-0x%-9X %s" % ("->" if fs == s else "  ", fs, fe, labn))
            return
        print("=== function %s: RVA 0x%X-0x%X (%d bytes) @ VA 0x%X ===" % (
            lab, s, e, e - s, ib + s))
        disasm_range(pe, ib, s, e, args.count)
    elif want_disasm:
        print("=== linear disasm @ VA=0x%X (not in .pdata, no thunk followed) ===" % (
            ib + target_rva))
        sec = next((s for s in pe.sections
                    if s["va"] <= target_rva < s["va"] + max(s["vsize"], s["rawsize"])), None)
        end = sec["va"] + sec["rawsize"] if sec else target_rva + args.count * 16
        disasm_range(pe, ib, target_rva, min(end, target_rva + args.count * 16), args.count)
    else:
        sys.exit("address 0x%X is not inside any .pdata function (and is not a "
                 "known thunk)" % (ib + target_rva))


if __name__ == "__main__":
    main()
