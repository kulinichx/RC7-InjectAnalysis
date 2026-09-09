#!/usr/bin/env python3
"""Verify that the final RootHide deb differs from the exact baseline only at approved Analysis integration paths."""
import argparse
import io
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
from email.parser import Parser
from pathlib import Path

from versioning import VERSION
ALLOWED_CHANGED = {
    "Applications/RootHide.app/RootHide",
    "DEBIAN/control",
}
ALLOWED_NEW = {
    "Applications/RootHide.app/Frameworks/RCInjectAnalysis.dylib",
    "Applications/RootHide.app/Frameworks/RCInjectAnalysis.buildinfo.plist",
}

ALLOWED_NEW_ARCHIVE = {
    "Applications/RootHide.app/Frameworks",
    "Applications/RootHide.app/Frameworks/RCInjectAnalysis.dylib",
    "Applications/RootHide.app/Frameworks/RCInjectAnalysis.buildinfo.plist",
}
EXPECTED_NEW_MODES = {
    "Applications/RootHide.app/Frameworks": ("dir", 0o755),
    "Applications/RootHide.app/Frameworks/RCInjectAnalysis.dylib": ("file", 0o755),
    "Applications/RootHide.app/Frameworks/RCInjectAnalysis.buildinfo.plist": ("file", 0o644),
}
BASELINE_PARENT = "Applications/RootHide.app"



def _norm_tar_name(name: str) -> str:
    while name.startswith('./'):
        name = name[2:]
    return name.rstrip('/')


def _tar_kind(m: tarfile.TarInfo) -> str:
    if m.isdir(): return 'dir'
    if m.isfile(): return 'file'
    if m.issym(): return 'symlink'
    if m.islnk(): return 'hardlink'
    return f'type:{m.type!r}'


def archive_metadata(deb: Path, control: bool = False):
    flag = '--ctrl-tarfile' if control else '--fsys-tarfile'
    raw = subprocess.check_output(['dpkg-deb', flag, str(deb)])
    out = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:*') as tf:
        for m in tf.getmembers():
            name = _norm_tar_name(m.name)
            if not name:
                continue
            out[name] = (
                _tar_kind(m), m.mode & 0o7777, m.uid, m.gid,
                m.uname or '', m.gname or '', int(m.mtime), m.linkname or ''
            )
    return out


def verify_archive_metadata(orig: Path, built: Path) -> None:
    om = archive_metadata(orig, control=False)
    bm = archive_metadata(built, control=False)
    new = set(bm) - set(om)
    removed = set(om) - set(bm)
    if removed:
        raise SystemExit(f'unexpected removed data archive entries: {sorted(removed)}')
    if new != ALLOWED_NEW_ARCHIVE:
        raise SystemExit(f'unexpected new data archive entries: got={sorted(new)} expected={sorted(ALLOWED_NEW_ARCHIVE)}')
    for name in sorted(set(om) & set(bm)):
        if om[name] != bm[name]:
            raise SystemExit(f'archive metadata changed for {name}: original={om[name]} built={bm[name]}')
    parent = om.get(BASELINE_PARENT)
    if parent is None:
        raise SystemExit(f'baseline parent archive metadata missing: {BASELINE_PARENT}')
    _pkind, _pmode, puid, pgid, puname, pgname, pmtime, _plink = parent
    for name, (kind, mode) in EXPECTED_NEW_MODES.items():
        expected = (kind, mode, puid, pgid, puname, pgname, pmtime, '')
        got = bm.get(name)
        if got != expected:
            raise SystemExit(f'new Analysis archive metadata mismatch for {name}: got={got} expected={expected}')

    oc = archive_metadata(orig, control=True)
    bc = archive_metadata(built, control=True)
    if set(oc) != set(bc):
        raise SystemExit(f'control archive entry set changed: original={sorted(oc)} built={sorted(bc)}')
    for name in sorted(oc):
        if oc[name] != bc[name]:
            raise SystemExit(f'control archive metadata changed for {name}: original={oc[name]} built={bc[name]}')
    print('archive metadata: PASS (existing type/mode/uid/gid/uname/gname/mtime preserved; new Analysis entries inherit RootHide.app ownership metadata)')




def ar_metadata(deb: Path):
    raw = deb.read_bytes()
    if not raw.startswith(b"!<arch>\n"):
        raise SystemExit(f"not an ar archive: {deb}")
    out = {}
    pos = 8
    while pos < len(raw):
        if pos + 60 > len(raw):
            raise SystemExit("truncated ar header")
        h = raw[pos:pos+60]
        if h[58:60] != b"`\n":
            raise SystemExit("invalid ar member trailer")
        name = h[:16].decode("ascii").strip().rstrip("/")
        ts = int(h[16:28].decode("ascii").strip() or "0")
        uid = int(h[28:34].decode("ascii").strip() or "0")
        gid = int(h[34:40].decode("ascii").strip() or "0")
        mode = int(h[40:48].decode("ascii").strip() or "0", 8)
        size = int(h[48:58].decode("ascii").strip() or "0")
        out[name] = (ts, uid, gid, mode)
        pos += 60 + size + (size & 1)
    return out


def verify_ar_metadata(orig: Path, built: Path) -> None:
    om = ar_metadata(orig)
    bm = ar_metadata(built)
    if set(om) != set(bm):
        raise SystemExit(f"deb ar member set changed: original={sorted(om)} built={sorted(bm)}")
    expected = {"debian-binary", "control.tar.gz", "data.tar.lzma"}
    if set(om) != expected:
        raise SystemExit(f"unexpected baseline deb ar members: {sorted(om)}")
    for name in sorted(om):
        if om[name] != bm[name]:
            raise SystemExit(f"deb ar metadata changed for {name}: original={om[name]} built={bm[name]}")
    print("deb ar metadata: PASS (member names/timestamps/uid/gid/mode preserved; sizes may change)")

def extract(deb: Path, dst: Path) -> None:
    subprocess.run(["dpkg-deb", "-R", str(deb), str(dst)], check=True, stdout=subprocess.DEVNULL)


def leaf_entries(root: Path):
    out = {}
    for base, dirs, files in os.walk(root):
        b = Path(base)
        for name in files:
            p = b / name
            rel = p.relative_to(root).as_posix()
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("symlink", stat.S_IMODE(st.st_mode), os.readlink(p))
            else:
                out[rel] = ("file", stat.S_IMODE(st.st_mode), p.read_bytes())
    return out


def parse_control(path: Path):
    msg = Parser().parsestr(path.read_text(encoding="utf-8", errors="strict"))
    return {k: v for k, v in msg.items()}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("original_deb")
    ap.add_argument("built_deb")
    a = ap.parse_args()
    orig = Path(a.original_deb).resolve()
    built = Path(a.built_deb).resolve()
    if shutil.which("dpkg-deb") is None:
        raise SystemExit("dpkg-deb not found")
    if not orig.is_file() or not built.is_file():
        raise SystemExit("original or built deb missing")

    with tempfile.TemporaryDirectory(prefix="rcanalysis-delta-") as td:
        td = Path(td)
        od = td / "original"
        bd = td / "built"
        extract(orig, od)
        extract(built, bd)
        a_entries = leaf_entries(od)
        b_entries = leaf_entries(bd)

        new = set(b_entries) - set(a_entries)
        removed = set(a_entries) - set(b_entries)
        if removed:
            raise SystemExit(f"unexpected removed package entries: {sorted(removed)}")
        if new != ALLOWED_NEW:
            raise SystemExit(f"unexpected new package entries: got={sorted(new)} expected={sorted(ALLOWED_NEW)}")

        changed = set()
        for rel in set(a_entries) & set(b_entries):
            if a_entries[rel] != b_entries[rel]:
                changed.add(rel)
        if changed != ALLOWED_CHANGED:
            raise SystemExit(f"unexpected changed package entries: got={sorted(changed)} expected={sorted(ALLOWED_CHANGED)}")

        oc = parse_control(od / "DEBIAN/control")
        bc = parse_control(bd / "DEBIAN/control")
        ov = oc.pop("Version", None)
        bv = bc.pop("Version", None)
        if oc != bc:
            keys = sorted(set(oc) | set(bc))
            diff = [k for k in keys if oc.get(k) != bc.get(k)]
            raise SystemExit(f"DEBIAN/control changed outside Version: {diff}")
        expected = f"{ov}+analysis{VERSION}"
        if bv != expected:
            raise SystemExit(f"unexpected Version delta: original={ov!r} built={bv!r} expected={expected!r}")

        verify_ar_metadata(orig, built)
        verify_archive_metadata(orig, built)

        print("package delta: PASS")
        print(f"changed-only: {sorted(ALLOWED_CHANGED)}")
        print(f"new-only: {sorted(ALLOWED_NEW)}")
        print(f"Version: {ov} -> {bv}")


if __name__ == "__main__":
    main()
