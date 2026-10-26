#!/usr/bin/env python3
"""Checks a staged release archive against its matrix row and the import allow-list.

    check-release-artifact.py --triple <triple> --allow-list <file> <archive>

The archive is a `.zip` for a Windows triple and a `.tar.gz` for any other;
any other pairing fails. It must hold one directory with a BUILD-PROVENANCE.txt whose `target
triple` line is <triple>, whose `commit`, `rustc`, `built by`, `oxicrypt release
key` and `load check` lines each appear once with a value, and whose `oxicrypt
library` line names a library the artifact ships with that sha256.

Every ELF and PE file in the artifact is checked, including those inside an
AppImage, whose squashfs payload is unpacked with `unsquashfs`. The NEEDED
libraries of an ELF file (`readelf -d`) and the DLLs a PE file imports
(`objdump -p`) must each match an entry of the allow-list for that format. An
entry is `<format> <kind> <pattern>`: format `elf` or `pe`, kind `system` (the
host provides it) or `bundled` (a file of that name must be in the artifact),
and a shell-style pattern. PE names compare case-insensitively. Any ELF or PE
file with no imports fails, except the AppImage runtime, which must instead be
static: no program interpreter and no NEEDED entry.

Every file in the artifact must be a binary of a known kind or a recognised
data file (provenance, licences, desktop entries, icons, and the AppImage's
AppRun script). Anything else fails, as does a file that starts like an ELF or
PE image but does not parse as one.

Needs readelf, objdump and unsquashfs. Exits 0 when the archive passes, 1
when it fails a check (naming each), 2 on a usage error.
"""

import argparse
import fnmatch
import hashlib
import os
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile


def archive_format(triple):
    """The archive format a leg for `triple` ships: zip on Windows, tar.gz elsewhere."""
    return "zip" if "-windows-" in triple else "tar.gz"


def extract(archive, dest):
    """Unpack a .zip or .tar.gz into dest, refusing members that escape it."""
    if archive.endswith(".zip"):
        root = os.path.realpath(dest)
        with zipfile.ZipFile(archive) as z:
            for member in z.namelist():
                target = os.path.realpath(os.path.join(dest, member))
                if not target.startswith(root + os.sep):
                    raise ValueError(f"zip member escapes the archive: {member}")
            z.extractall(dest)
    else:
        with tarfile.open(archive) as t:
            t.extractall(dest, filter="data")


def read_allow_list(path):
    entries = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 3 or parts[0] not in ("elf", "pe") or parts[1] not in ("system", "bundled"):
                raise SystemExit(f"{path}:{n}: expected '<elf|pe> <system|bundled> <pattern>'")
            entries.append(tuple(parts))
    if not entries:
        raise SystemExit(f"{path}: no entries")
    return entries


# Files that are not binaries and may ship: matched on the base name.
DATA_NAMES = ("BUILD-PROVENANCE.txt", "LICENSE-*", "*.desktop", "*.svg", "*.png", ".DirIcon")


def kind_of(path):
    """elf, pe or appimage; 'malformed' for a file that starts like one but does not parse; None otherwise."""
    with open(path, "rb") as f:
        head = f.read(64)
        if head[:4] == b"\x7fELF":
            if len(head) < 64 or head[4] != 2:
                return "malformed"
            if head[8:10] == b"AI":
                return "appimage" if head[10] == 2 else "malformed"
            return "elf"
        if head[:2] == b"MZ":
            if len(head) < 64:
                return "malformed"
            (pe_at,) = struct.unpack_from("<I", head, 0x3C)
            f.seek(pe_at)
            return "pe" if f.read(4) == b"PE\0\0" else "malformed"
    return None


def is_data(path):
    name = os.path.basename(path)
    if any(fnmatch.fnmatchcase(name, pat) for pat in DATA_NAMES):
        return True
    if name == "AppRun":
        with open(path, "rb") as f:
            return f.read(2) == b"#!"
    return False


def is_static_elf(path):
    """No program interpreter and no NEEDED entry: static, or static-pie."""
    headers = subprocess.run(["readelf", "-lW", path], capture_output=True, text=True, check=True).stdout
    return not re.search(r"^\s*INTERP\s", headers, re.M) and not imports(path, "elf")


def elf_end(path):
    """The end of an ELF file's section header table: where an AppImage's payload starts."""
    with open(path, "rb") as f:
        h = f.read(64)
    if h[4] != 2:
        raise ValueError("not a 64-bit ELF file")
    order = "<" if h[5] == 1 else ">"
    shoff = struct.unpack_from(order + "Q", h, 0x28)[0]
    shentsize, shnum = struct.unpack_from(order + "HH", h, 0x3A)
    return shoff + shentsize * shnum


def imports(path, kind):
    if kind == "elf":
        out = subprocess.run(["readelf", "-d", path], capture_output=True, text=True, check=True).stdout
        return re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", out)
    out = subprocess.run(["objdump", "-p", path], capture_output=True, text=True, check=True).stdout
    return re.findall(r"^\s*DLL Name: (\S+)\s*$", out, re.M)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--triple", required=True)
    ap.add_argument("--allow-list", required=True)
    ap.add_argument("archive")
    args = ap.parse_args()
    if not os.path.isfile(args.archive):
        print(f"not a file: {args.archive}", file=sys.stderr)
        return 2
    allow = read_allow_list(args.allow_list)
    problems = []
    name = os.path.basename(args.archive)
    want = archive_format(args.triple)
    if not name.endswith("." + want):
        print(f"{name}: a {args.triple} artifact must be a .{want}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        extract(args.archive, tmp)
        tops = os.listdir(tmp)
        if len(tops) != 1 or not os.path.isdir(os.path.join(tmp, tops[0])):
            print(f"{name}: expected one top-level directory, found {tops}", file=sys.stderr)
            return 1
        root = os.path.join(tmp, tops[0])

        prov_path = os.path.join(root, "BUILD-PROVENANCE.txt")
        fields = {}
        if os.path.isfile(prov_path):
            with open(prov_path, encoding="utf-8") as f:
                for line in f:
                    m = re.match(r"^([a-z][a-z ]*[a-z])\s+: (.*)$", line.rstrip("\n"))
                    if m:
                        fields.setdefault(m.group(1), []).append(m.group(2))
        else:
            problems.append("no BUILD-PROVENANCE.txt")
        triples = fields.get("target triple", [])
        if triples != [args.triple]:
            problems.append(f"provenance target triple {triples} is not the matrix row's {args.triple}")
        for key in ("commit", "rustc", "built by", "oxicrypt release key", "load check"):
            if len(fields.get(key, [])) != 1 or not fields[key][0].strip():
                problems.append(f"provenance has no single '{key}' line")

        # Unpack each AppImage beside the files, so its contents are checked too.
        files = []
        for d, _, fs in os.walk(root):
            files += [os.path.join(d, f) for f in fs]
        for path in list(files):
            if not os.path.islink(path) and kind_of(path) == "appimage":
                dest = path + ".unpacked"
                subprocess.run(
                    ["unsquashfs", "-q", "-no-progress", "-d", dest, "-o", str(elf_end(path)), path],
                    check=True, stdout=subprocess.DEVNULL,
                )
                for d, _, fs in os.walk(dest):
                    files += [os.path.join(d, f) for f in fs]

        regular = [p for p in files if os.path.isfile(p) and not os.path.islink(p)]
        for p in files:
            if os.path.islink(p) and not is_data(p):
                problems.append(f"{os.path.relpath(p, tmp)} is a link to something other than a data file")
        shipped = {os.path.basename(p) for p in regular}
        shipped_lower = {n.lower() for n in shipped}

        lib = fields.get("oxicrypt library", [""])
        m = re.match(r"^(\S+) sha256:([0-9a-f]{64})$", lib[0]) if len(lib) == 1 else None
        if not m:
            problems.append(f"provenance oxicrypt library line is not '<file> sha256:<hex>': {lib}")
        else:
            copies = [p for p in regular if os.path.basename(p) == m.group(1)]
            if not copies:
                problems.append(f"the artifact ships no {m.group(1)}")
            for p in copies:
                if sha256(p) != m.group(2):
                    problems.append(f"{os.path.relpath(p, tmp)} is not the oxicrypt library the provenance names")

        checked = 0
        for path in regular:
            kind = kind_of(path)
            rel = os.path.relpath(path, tmp)
            if kind == "malformed":
                problems.append(f"{rel} starts like an ELF or PE image but does not parse as one")
                continue
            if kind is None:
                if not is_data(path):
                    problems.append(f"{rel} is neither a binary of a known kind nor a recognised data file")
                continue
            checked += 1
            if kind == "appimage":
                if not is_static_elf(path):
                    problems.append(f"{rel}: the AppImage runtime is dynamically linked")
                continue
            deps = imports(path, kind)
            if not deps:
                problems.append(f"{rel} ({kind}) has no imports, so none could be checked")
            for dep in deps:
                fold = (lambda s: s.lower()) if kind == "pe" else (lambda s: s)
                hit = [e for e in allow if e[0] == kind and fnmatch.fnmatchcase(fold(dep), fold(e[2]))]
                if not hit:
                    problems.append(f"{rel} ({kind}) imports {dep}, which the allow-list does not name")
                elif all(e[1] == "bundled" for e in hit):
                    present = dep.lower() in shipped_lower if kind == "pe" else dep in shipped
                    if not present:
                        problems.append(f"{rel} imports {dep}, which is bundled but not in the artifact")
        if checked == 0:
            problems.append("no ELF or PE file in the artifact")

    for p in problems:
        print(f"{name}: {p}", file=sys.stderr)
    if problems:
        return 1
    print(f"{name}: ok ({checked} binaries, target {args.triple})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
