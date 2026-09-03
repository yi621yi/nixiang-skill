#!/usr/bin/env python3
"""pe_inspect.py - zero-dependency PE (Windows executable) static inspector.

Parses headers, sections, data directories, import table, export table,
debug (PDB) paths and extracts strings, using only the Python stdlib.
Reads the target file only; never executes it.

Usage:
  python pe_inspect.py <file>                 # full structural report
  python pe_inspect.py <file> --strings 6     # also dump ASCII strings >= 6 chars
  python pe_inspect.py <file> --utf16         # also extract UTF-16LE strings
"""
import argparse
import datetime
import hashlib
import re
import struct
import sys

MACHINE = {0x14C: "x86 (I386)", 0x8664: "x64 (AMD64)", 0xAA64: "ARM64",
           0x1C0: "ARM", 0x1C4: "ARMNT", 0x200: "IA64"}
SUBSYSTEM = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 5: "OS2_CUI",
             7: "POSIX_CUI", 9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION",
             11: "EFI_BOOT_SERVICE_DRIVER", 12: "EFI_RUNTIME_DRIVER",
             13: "EFI_ROM", 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION"}
DIR_NAMES = ["Export", "Import", "Resource", "Exception", "Security",
             "BaseReloc", "Debug", "Architecture", "GlobalPtr", "TLS",
             "LoadConfig", "BoundImport", "IAT", "DelayImport", "COM", "Reserved"]
SEC_FLAGS = [(0x20, "CODE"), (0x40, "IDATA"), (0x80, "UDATA"),
             (0x02000000, "DISCARDABLE"), (0x04000000, "NOT_CACHED"),
             (0x08000000, "NOT_PAGED"), (0x10000000, "SHARED"),
             (0x20000000, "EXECUTE"), (0x40000000, "READ"), (0x80000000, "WRITE")]
DLL_CHARS = ["", "reserved", "", "", "", "HIGH_ENTROPY_VA", "DYNAMIC_BASE",
             "FORCE_INTEGRITY", "NX_COMPAT", "NO_ISOLATION", "NO_SEH", "NO_BIND",
             "APPCONTAINER", "WDM_DRIVER", "GUARD_CF", "TERMINAL_SERVER_AWARE"]
RES_TYPES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
             6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
             10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
             14: "GROUP_ICON", 16: "VERSION", 23: "HTML", 24: "MANIFEST"}


def align4(n):
    return (n + 3) & ~3


def human_flags(value, table):
    return "|".join(name for bit, name in table if value & bit) or "-"


class PEError(Exception):
    pass


class PE:
    def __init__(self, data):
        self.data = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PEError("not a PE file (missing MZ signature)")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise PEError("missing PE\\0\\0 signature (corrupt or DOS-only file)")
        off = e_lfanew + 4
        (self.machine, n_sections, self.timestamp, _, _,
         opt_size, self.chars) = struct.unpack_from("<HHIIIHH", data, off)
        off += 20  # COFF header is 20 bytes
        self.oh = off  # optional header starts here
        self.pe32plus = opt_size and struct.unpack_from("<H", data, off)[0] == 0x20B
        self.opt = {}
        self.dirs = [(0, 0)] * 16
        if opt_size:
            entry = struct.unpack_from("<I", data, off + 16)[0]
            if self.pe32plus:
                image_base = struct.unpack_from("<Q", data, off + 24)[0]
                n_dirs_off = off + 112
            else:
                image_base = struct.unpack_from("<I", data, off + 28)[0]
                n_dirs_off = off + 96
            self.opt = {"entry": entry, "image_base": image_base}
            self.dirs = [struct.unpack_from("<II", data, n_dirs_off + i * 8)
                         for i in range(16)]
        sec_off = off + opt_size
        self.sections = []
        for i in range(n_sections):
            name, vsize, va, rawsize, rawptr, _, _, _, _, sc = struct.unpack_from(
                "<8sIIIIIIHHI", data, sec_off + i * 40)
            self.sections.append({"name": name.rstrip(b"\x00").decode("ascii", "replace"),
                                  "vsize": vsize, "va": va, "rawsize": rawsize,
                                  "rawptr": rawptr, "chars": sc})

    def rva_to_off(self, rva):
        for s in self.sections:
            span = max(s["vsize"], s["rawsize"])
            if s["va"] <= rva < s["va"] + span:
                delta = rva - s["va"]
                return s["rawptr"] + delta if delta < s["rawsize"] else None
        if self.sections and rva < self.sections[0]["va"]:
            return rva  # header-mapped memory
        return None

    def cstr(self, off, max_len=512):
        if off is None or off >= len(self.data):
            return "?"
        end = self.data.find(b"\x00", off, off + max_len)
        if end < 0:
            end = min(off + max_len, len(self.data))
        return self.data[off:end].decode("latin-1", "replace")

    def exports(self):
        rva, size = self.dirs[0]
        if not rva:
            return None
        off = self.rva_to_off(rva)
        if off is None:
            return {"dll": "?", "error": "export RVA not mapped to file", "entries": []}
        (_, _, _, _, name_rva, ordinal_base, n_funcs, n_names,
         funcs_rva, names_rva, ords_rva) = struct.unpack_from("<IIHHIIIIIII", self.data, off)
        out = {"dll": self.cstr(self.rva_to_off(name_rva)) if name_rva else "?",
               "ordinal_base": ordinal_base, "functions": n_funcs,
               "named": n_names, "entries": []}
        names_off = self.rva_to_off(names_rva)
        ords_off = self.rva_to_off(ords_rva)
        funcs_off = self.rva_to_off(funcs_rva)
        if None in (names_off, ords_off, funcs_off):
            return out
        for i in range(min(n_names, 4096)):
            name_rva_i = struct.unpack_from("<I", self.data, names_off + i * 4)[0]
            ord_i = struct.unpack_from("<H", self.data, ords_off + i * 2)[0]
            fname = self.cstr(self.rva_to_off(name_rva_i)) if name_rva_i else "?"
            f_rva = struct.unpack_from("<I", self.data, funcs_off + ord_i * 4)[0]
            f_off = self.rva_to_off(f_rva)
            # a function RVA landing inside the export directory itself means
            # the export is a forwarder (its "body" is a string like "ntdll.X")
            forwarder = self.cstr(f_off) if f_off is not None and rva <= f_rva < rva + size else None
            out["entries"].append({"name": fname, "ordinal": ordinal_base + ord_i,
                                   "rva": f_rva, "forwarder": forwarder})
        return out

    def _thunks(self, thunk_rva, entry_size, ordinal_flag):
        """Walk an import thunk array (INT or IAT); shared by imports/delay-imports."""
        syms = []
        toff = self.rva_to_off(thunk_rva) if thunk_rva else None
        if toff is None:
            return syms
        for j in range(8192):
            raw = struct.unpack_from("<Q" if self.pe32plus else "<I",
                                     self.data, toff + j * entry_size)[0]
            if raw == 0:
                break
            if raw & ordinal_flag:
                syms.append("#%d" % (raw & 0xFFFF))
            else:
                hint_off = self.rva_to_off(raw & 0x7FFFFFFF)
                syms.append(self.cstr(hint_off + 2) if hint_off else "?<unmapped>")
        return syms

    def imports(self):
        rva, _ = self.dirs[1]
        if not rva:
            return None
        off = self.rva_to_off(rva)
        if off is None:
            return [{"dll": "?", "error": "import RVA not mapped to file", "symbols": []}]
        entry_size = 8 if self.pe32plus else 4
        ordinal_flag = 1 << 63 if self.pe32plus else 1 << 31
        out = []
        for i in range(4096):
            base = off + i * 20
            oft_rva, _, _, name_rva, iat_rva = struct.unpack_from("<IIIII", self.data, base)
            if not (oft_rva or name_rva or iat_rva):
                break  # null terminator descriptor
            dll = self.cstr(self.rva_to_off(name_rva)) if name_rva else "?"
            syms = self._thunks(oft_rva or iat_rva, entry_size, ordinal_flag)
            out.append({"dll": dll, "symbols": syms})
        return out

    def delay_imports(self):
        """Dir 13: ImgDelayDescr array (32 bytes each). grAttrs bit0 (dlattrRva)
        means fields are RVAs; legacy images store VAs (subtract ImageBase)."""
        rva, _ = self.dirs[13]
        if not rva:
            return None
        off = self.rva_to_off(rva)
        if off is None:
            return [{"dll": "?", "error": "delay-import RVA not mapped to file", "symbols": []}]
        ib = self.opt.get("image_base", 0)
        entry_size = 8 if self.pe32plus else 4
        ordinal_flag = 1 << 63 if self.pe32plus else 1 << 31

        def to_rva(field):
            if gr_attrs & 1:
                return field
            return field - ib if ib and field >= ib else None

        out = []
        for i in range(1024):
            base = off + i * 32
            gr_attrs, name_f, _, iat_f, int_f, _, _, _ = struct.unpack_from(
                "<IIIIIIII", self.data, base)
            if not (name_f or iat_f or int_f):
                break  # null terminator
            name_rva = to_rva(name_f)
            dll = self.cstr(self.rva_to_off(name_rva)) if name_rva else "?"
            syms = self._thunks(to_rva(int_f or iat_f), entry_size, ordinal_flag)
            out.append({"dll": dll, "symbols": syms})
        return out

    def tls_callbacks(self):
        """Dir 9: IMAGE_TLS_DIRECTORY; AddressOfCallBacks is a preferred-base VA
        pointing to a NULL-terminated array of callback VAs."""
        rva, size = self.dirs[9]
        if not (rva and size):
            return None
        off = self.rva_to_off(rva)
        if off is None:
            return {"error": "TLS RVA not mapped to file", "callbacks": []}
        cb_va = struct.unpack_from("<Q" if self.pe32plus else "<I", self.data,
                                   off + (24 if self.pe32plus else 16))[0]
        if not cb_va:
            return {"callbacks": []}
        ib = self.opt.get("image_base", 0)
        cbs = []
        if ib and cb_va >= ib:
            arr_off = self.rva_to_off(cb_va - ib)
            if arr_off is not None:
                esz = 8 if self.pe32plus else 4
                for j in range(64):
                    va = struct.unpack_from("<Q" if self.pe32plus else "<I",
                                            self.data, arr_off + j * esz)[0]
                    if va == 0:
                        break
                    cbs.append(va)
        return {"address_of_callbacks": cb_va, "callbacks": cbs}

    def _res_dir_string(self, off):
        """IMAGE_RESOURCE_DIR_STRING_U: WORD length, then that many WCHARs."""
        n = struct.unpack_from("<H", self.data, off)[0]
        return self.data[off + 2:off + 2 + n * 2].decode("utf-16le", "replace")

    def resources(self):
        """Dir 2: walk the 3-level tree (type -> id/name -> lang); return leaves."""
        rva, _ = self.dirs[2]
        if not rva:
            return None
        base_off = self.rva_to_off(rva)
        if base_off is None:
            return [{"error": "resource RVA not mapped to file"}]
        leaves, visited = [], set()

        def entry_name(off):
            id_or_name, _ = struct.unpack_from("<II", self.data, off)
            if id_or_name & 0x80000000:
                return self._res_dir_string(base_off + (id_or_name & 0x7FFFFFFF))
            return id_or_name

        def walk(off, path):
            if off in visited or off + 16 > len(self.data) or len(path) > 3:
                return
            visited.add(off)
            _, _, _, _, n_name, n_id = struct.unpack_from("<IIHHHH", self.data, off)
            for i in range(n_name + n_id):
                eoff = off + 16 + i * 8
                name = entry_name(eoff)
                sub = struct.unpack_from("<I", self.data, eoff + 4)[0]
                if sub & 0x80000000:
                    walk(base_off + (sub & 0x7FFFFFFF), path + [name])
                else:
                    data_rva, dsize, _, _ = struct.unpack_from("<IIII", self.data, base_off + sub)
                    leaves.append({"path": path, "name": name, "rva": data_rva,
                                   "size": dsize, "file_off": self.rva_to_off(data_rva)})

        walk(base_off, [])
        return leaves

    def pdb_path(self):
        rva, size = self.dirs[6]
        if not (rva and size):
            return None
        off = self.rva_to_off(rva)
        if off is None:
            return None
        for i in range(size // 28):
            entry = off + i * 28
            dtype = struct.unpack_from("<I", self.data, entry + 12)[0]
            if dtype == 2:  # CODEVIEW: "RSDS" + 16-byte GUID + 4-byte age, then path
                ptr = struct.unpack_from("<I", self.data, entry + 24)[0]
                return self.cstr(ptr + 24)
        return None

    def strings(self, min_len=5, utf16=False):
        found = []
        if utf16:
            for m in re.finditer(b"(?:[ -~]\x00){%d,}" % min_len, self.data):
                found.append(("utf16", m.start(), m.group().decode("utf-16le", "replace")))
        for m in re.finditer(rb"[ -~]{%d,}" % min_len, self.data):
            found.append(("ascii", m.start(), m.group().decode("latin-1")))
        return found


def parse_version_resource(data):
    """Parse a VS_VERSIONINFO blob: VS_FIXEDFILEINFO numbers + string pairs."""
    out = {"fixed": None, "strings": {}}

    def u16z(buf, off):
        chars = []
        while off + 2 <= len(buf):
            w = struct.unpack_from("<H", buf, off)[0]
            if w == 0:
                break
            chars.append(w)
            off += 2
        return "".join(chr(c) for c in chars)

    def node(off):
        wlen, wvlen, wtype = struct.unpack_from("<HHH", data, off)
        if wlen < 6 or off + wlen > len(data):
            return None
        key = u16z(data, off + 6)
        voff = align4(off + 6 + (len(key) + 1) * 2)
        # text (wType=1) values count WORDS; binary (fixed info) count BYTES
        vbytes = wvlen * 2 if wtype == 1 else wvlen
        value = data[voff:voff + vbytes] if wvlen else b""
        kids = []
        coff = align4(voff + vbytes)
        while coff + 6 <= off + wlen:
            k = node(coff)
            if k is None:
                break
            kids.append(k)
            coff = align4(coff + k["len"])
        return {"key": key, "len": wlen, "vlen": wvlen, "value": value, "kids": kids}

    root = node(0)
    if not root:
        return out
    if root["vlen"] >= 52 and struct.unpack_from("<I", root["value"], 0)[0] == 0xFEEF04BD:
        v = root["value"]
        fms, fls, pms, pls = struct.unpack_from("<IIII", v, 8)
        out["fixed"] = {
            "file": "%d.%d.%d.%d" % (fms >> 16, fms & 0xFFFF, fls >> 16, fls & 0xFFFF),
            "product": "%d.%d.%d.%d" % (pms >> 16, pms & 0xFFFF, pls >> 16, pls & 0xFFFF)}
    for sfi in root["kids"]:
        for table in sfi["kids"]:
            for s in table["kids"]:
                try:
                    val = s["value"].decode("utf-16le", "replace").rstrip("\x00")
                except Exception:
                    val = "<undecodable>"
                out["strings"][s["key"]] = val
    return out


def report(path):
    data = open(path, "rb").read()
    sha256 = hashlib.sha256(data).hexdigest()
    try:
        pe = PE(data)
    except PEError as e:
        print("ERROR: %s (%d bytes, sha256=%s)" % (e, len(data), sha256))
        return None
    lines = []
    add = lines.append
    add("=== PE INSPECT: %s ===" % path)
    add("size: %d bytes  sha256: %s" % (len(data), sha256))
    add("machine: %s   PE32+ (64-bit): %s" % (
        MACHINE.get(pe.machine, "0x%X" % pe.machine), pe.pe32plus))
    add("compiled (linker timestamp): %s UTC" %
        datetime.datetime.fromtimestamp(pe.timestamp, tz=datetime.timezone.utc))
    if pe.opt:
        add("entry point RVA: 0x%X   image base: 0x%X" % (pe.opt["entry"], pe.opt["image_base"]))
        sub = struct.unpack_from("<H", data, pe.oh + 68)[0]   # Subsystem: offset 68 in both formats
        dllchars = struct.unpack_from("<H", data, pe.oh + 70)[0]
        add("subsystem: %s" % SUBSYSTEM.get(sub, "0x%X" % sub))
        add("dll characteristics: 0x%04X [%s]" % (
            dllchars, human_flags(dllchars, [(1 << i, n) for i, n in enumerate(DLL_CHARS)])))
    add("")
    add("--- sections (%d) ---" % len(pe.sections))
    for s in pe.sections:
        add("  %-8s VA=0x%06X VSize=0x%06X Raw=0x%06X+0x%06X  [%s]" % (
            s["name"], s["va"], s["vsize"], s["rawptr"], s["rawsize"],
            human_flags(s["chars"], SEC_FLAGS)))
    add("")
    add("--- data directories (non-empty) ---")
    for i, (rva, size) in enumerate(pe.dirs):
        if rva:
            extra = "  (digitally signed)" if i == 4 and size else ""
            add("  [%02d] %-11s RVA=0x%06X size=0x%X%s" % (i, DIR_NAMES[i], rva, size, extra))
    pdb = pe.pdb_path()
    if pdb:
        add("  debug (CODEVIEW) PDB path: %s" % pdb)
    add("")
    exp = pe.exports()
    add("--- exports ---")
    if not exp:
        add("  (none)")
    else:
        add("  dll name: %s   functions=%d named=%d ordinal_base=%d" % (
            exp["dll"], exp["functions"], exp["named"], exp["ordinal_base"]))
        for e in exp["entries"]:
            line = "  [%4d] RVA=0x%06X  %s" % (e["ordinal"], e["rva"], e["name"])
            if e["forwarder"]:
                line += "  -> forwarded to %s" % e["forwarder"]
            add(line)
    imp = pe.imports()
    add("")
    add("--- imports (%d DLLs) ---" % (len(imp) if imp else 0))
    if imp:
        for d in imp:
            add("  %s (%d)" % (d["dll"], len(d["symbols"])))
            for s in d["symbols"]:
                add("    %s" % s)
    dimp = pe.delay_imports()
    add("")
    add("--- delay imports (%d DLLs) ---" % (len(dimp) if dimp else 0))
    if dimp:
        for d in dimp:
            add("  %s (%d)" % (d["dll"], len(d["symbols"])))
            for s in d["symbols"]:
                add("    %s" % s)
    tls = pe.tls_callbacks()
    add("")
    add("--- TLS callbacks ---")
    if tls is None:
        add("  (no TLS directory)")
    elif tls.get("error"):
        add("  %s" % tls["error"])
    else:
        add("  AddressOfCallBacks: 0x%X (%d registered)" % (
            tls.get("address_of_callbacks", 0), len(tls["callbacks"])))
        for i, va in enumerate(tls["callbacks"]):
            rva = va - pe.opt["image_base"] if pe.opt.get("image_base") and va >= pe.opt["image_base"] else None
            add("  [%d] VA=0x%X (RVA=0x%X)" % (i, va, rva) if rva else "  [%d] VA=0x%X" % (i, va))
    res = pe.resources()
    add("")
    add("--- resources ---")
    if res is None:
        add("  (no resource directory)")
    elif res and res[0].get("error"):
        add("  %s" % res[0]["error"])
    else:
        def tname(t):
            return RES_TYPES.get(t, str(t)) if isinstance(t, int) else t
        by_type = {}
        for leaf in res:
            t = leaf["path"][0] if leaf["path"] else "?"
            by_type.setdefault(tname(t), 0)
            by_type[tname(t)] += 1
        add("  types: %s" % ", ".join("%s x%d" % (k, v) for k, v in sorted(by_type.items())))
        for leaf in res:
            t = tname(leaf["path"][0]) if leaf["path"] else "?"
            if t in ("VERSION", "MANIFEST") or isinstance(leaf["name"], str):
                rid = leaf["path"][1] if len(leaf["path"]) > 1 else "-"
                lang = (leaf["path"][2] if len(leaf["path"]) > 2
                        else leaf["name"] if len(leaf["path"]) > 1 else "-")
                add("  %-11s id=%-20s lang=%-6s RVA=0x%06X size=0x%X" % (
                    t, rid, lang, leaf["rva"], leaf["size"]))
        for leaf in res:
            if leaf["path"] and leaf["path"][0] == 16 and leaf["file_off"] is not None:
                blob = data[leaf["file_off"]:leaf["file_off"] + leaf["size"]]
                vi = parse_version_resource(blob)
                if vi["fixed"]:
                    add("  file version:    %s" % vi["fixed"]["file"])
                    add("  product version: %s" % vi["fixed"]["product"])
                for k, v in sorted(vi["strings"].items()):
                    add("  %-24s %s" % (k + ":", v[:100]))
                break
    print("\n".join(lines))
    return pe


def main():
    ap = argparse.ArgumentParser(description="Zero-dependency PE static inspector")
    ap.add_argument("file")
    ap.add_argument("--strings", type=int, default=0, metavar="N",
                    help="also print ASCII strings of length >= N")
    ap.add_argument("--utf16", action="store_true", help="include UTF-16LE strings")
    args = ap.parse_args()
    report(args.file)
    if args.strings:
        data = open(args.file, "rb").read()
        print("\n=== STRINGS (len>=%d%s) ===" % (args.strings, ", +utf16" if args.utf16 else ""))
        for kind, off, s in PE(data).strings(args.strings, utf16=args.utf16):
            print("0x%08X %-6s %s" % (off, kind, s))


if __name__ == "__main__":
    main()
