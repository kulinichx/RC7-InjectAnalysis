#!/usr/bin/env python3
"""Rebuild the pinned RootHide deb while preserving baseline tar/ar metadata exactly.

This avoids dpkg-deb -b normalizing ownership to the build host.  The pinned RootHide
archive intentionally has unusual tar headers: numeric uid=501/gid=20 while
uname/gname are root/wheel.  Existing entries retain their original TarInfo;
only approved Analysis entries are added with the same app-bundle ownership
model.  File bytes come from an already-modified dpkg-deb -R tree.
"""
from __future__ import annotations

import argparse
import gzip
import io
import lzma
import os
import stat
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path

NEW_DATA = {
    "Applications/RootHide.app/Frameworks": ("dir", 0o755),
    "Applications/RootHide.app/Frameworks/RCInjectAnalysis.dylib": ("file", 0o755),
    "Applications/RootHide.app/Frameworks/RCInjectAnalysis.buildinfo.plist": ("file", 0o644),
}
BASELINE_PARENT = "Applications/RootHide.app"


@dataclass(frozen=True)
class ArMember:
    name: str
    timestamp: int
    uid: int
    gid: int
    mode: int
    data: bytes


def parse_ar(path: Path) -> list[ArMember]:
    raw = path.read_bytes()
    if not raw.startswith(b"!<arch>\n"):
        raise SystemExit(f"not a Debian ar archive: {path}")
    out: list[ArMember] = []
    pos = 8
    while pos < len(raw):
        if pos + 60 > len(raw):
            raise SystemExit("truncated ar header")
        h = raw[pos:pos+60]
        if h[58:60] != b"`\n":
            raise SystemExit("invalid ar member trailer")
        name = h[:16].decode("ascii").strip()
        if name.endswith("/"):
            name = name[:-1]
        try:
            ts = int(h[16:28].decode("ascii").strip() or "0")
            uid = int(h[28:34].decode("ascii").strip() or "0")
            gid = int(h[34:40].decode("ascii").strip() or "0")
            mode = int(h[40:48].decode("ascii").strip() or "0", 8)
            size = int(h[48:58].decode("ascii").strip() or "0")
        except ValueError as e:
            raise SystemExit(f"invalid ar numeric field for {name}: {e}")
        start = pos + 60
        end = start + size
        if end > len(raw):
            raise SystemExit(f"truncated ar member: {name}")
        out.append(ArMember(name, ts, uid, gid, mode, raw[start:end]))
        pos = end + (size & 1)
    return out


def ar_header(m: ArMember, size: int) -> bytes:
    # All pinned RootHide member names fit the classic 16-byte ar name field.
    name = (m.name + "/") if len(m.name) < 16 else m.name
    mode_field = f"{m.mode:o}".ljust(8)
    fields = (
        f"{name:<16}"
        f"{m.timestamp:<12d}"
        f"{m.uid:<6d}"
        f"{m.gid:<6d}"
        f"{mode_field}"
        f"{size:<10d}`\n"
    )
    b = fields.encode("ascii")
    if len(b) != 60:
        raise SystemExit(f"internal ar header length error for {m.name}: {len(b)}")
    return b


def write_ar(path: Path, members: list[tuple[ArMember, bytes]]) -> None:
    with path.open("wb") as f:
        f.write(b"!<arch>\n")
        for meta, data in members:
            f.write(ar_header(meta, len(data)))
            f.write(data)
            if len(data) & 1:
                f.write(b"\n")


def _raw_tar_from_deb(deb: Path, control: bool) -> bytes:
    flag = "--ctrl-tarfile" if control else "--fsys-tarfile"
    return subprocess.check_output(["dpkg-deb", flag, str(deb)])


def _clone_info(src: tarfile.TarInfo) -> tarfile.TarInfo:
    m = tarfile.TarInfo(src.name)
    # Preserve all semantic header fields supported by tarfile.
    m.mode = src.mode
    m.uid = src.uid
    m.gid = src.gid
    m.mtime = src.mtime
    m.type = src.type
    m.linkname = src.linkname
    m.uname = src.uname
    m.gname = src.gname
    m.devmajor = src.devmajor
    m.devminor = src.devminor
    m.pax_headers = dict(src.pax_headers)
    return m


def _fs_path(pkg: Path, name: str, control: bool) -> Path:
    norm = name
    while norm.startswith("./"):
        norm = norm[2:]
    if norm in ("", "."):
        return (pkg / "DEBIAN") if control else pkg
    return ((pkg / "DEBIAN") if control else pkg) / norm


def _add_from_path(tf: tarfile.TarFile, info: tarfile.TarInfo, path: Path) -> None:
    if info.isdir():
        if not path.is_dir():
            raise SystemExit(f"expected directory missing: {path}")
        info.size = 0
        tf.addfile(info)
        return
    if info.isfile():
        if not path.is_file():
            raise SystemExit(f"expected file missing: {path}")
        data = path.read_bytes()
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        return
    if info.issym():
        if not path.is_symlink():
            raise SystemExit(f"expected symlink missing: {path}")
        info.linkname = os.readlink(path)
        info.size = 0
        tf.addfile(info)
        return
    if info.islnk():
        info.size = 0
        tf.addfile(info)
        return
    raise SystemExit(f"unsupported baseline tar entry type for {info.name}: {info.type!r}")


def rebuild_tar(original_deb: Path, pkg: Path, *, control: bool) -> bytes:
    raw = _raw_tar_from_deb(original_deb, control)
    src_tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    original = src_tf.getmembers()
    names = set()
    out = io.BytesIO()
    # USTAR is sufficient for the pinned package paths and preserves explicit
    # numeric IDs plus uname/gname without adding host-dependent PAX metadata.
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for src in original:
            names.add(src.name.lstrip("./").rstrip("/"))
            info = _clone_info(src)
            _add_from_path(tf, info, _fs_path(pkg, src.name, control))

        if not control:
            parent_src = next((m for m in original if m.name.lstrip("./").rstrip("/") == BASELINE_PARENT), None)
            if parent_src is None:
                raise SystemExit(f"baseline parent metadata missing: {BASELINE_PARENT}")
            for rel, (kind, mode) in NEW_DATA.items():
                if rel in names:
                    raise SystemExit(f"new Analysis path already existed in baseline: {rel}")
                p = pkg / rel
                if kind == "dir" and not p.is_dir():
                    raise SystemExit(f"new Analysis directory missing: {p}")
                if kind == "file" and not p.is_file():
                    raise SystemExit(f"new Analysis file missing: {p}")
                m = tarfile.TarInfo(rel)
                m.mode = mode
                m.uid = parent_src.uid
                m.gid = parent_src.gid
                m.uname = parent_src.uname
                m.gname = parent_src.gname
                m.mtime = parent_src.mtime
                if kind == "dir":
                    m.type = tarfile.DIRTYPE
                    m.size = 0
                    tf.addfile(m)
                else:
                    m.type = tarfile.REGTYPE
                    data = p.read_bytes()
                    m.size = len(data)
                    tf.addfile(m, io.BytesIO(data))
    return out.getvalue()


def gzip_bytes(raw: bytes) -> bytes:
    out = io.BytesIO()
    # Deterministic compressor timestamp; tar member mtimes remain baseline exact.
    with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=9, mtime=0) as gz:
        gz.write(raw)
    return out.getvalue()


def lzma_alone_bytes(raw: bytes) -> bytes:
    return lzma.compress(raw, format=lzma.FORMAT_ALONE, preset=6)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("original_deb")
    ap.add_argument("modified_package_tree", help="directory produced by dpkg-deb -R and modified in-place")
    ap.add_argument("output_deb")
    a = ap.parse_args()
    orig = Path(a.original_deb).resolve()
    pkg = Path(a.modified_package_tree).resolve()
    out = Path(a.output_deb).resolve()
    if not orig.is_file():
        raise SystemExit(f"original deb missing: {orig}")
    if not pkg.is_dir() or not (pkg / "DEBIAN/control").is_file():
        raise SystemExit(f"invalid modified package tree: {pkg}")

    members = parse_ar(orig)
    by_name = {m.name: m for m in members}
    required = {"debian-binary", "control.tar.gz", "data.tar.lzma"}
    if set(by_name) != required:
        raise SystemExit(f"unexpected pinned deb ar member set: {sorted(by_name)}")
    if by_name["debian-binary"].data != b"2.0\n":
        raise SystemExit("unexpected debian-binary content")

    ctrl_tar = rebuild_tar(orig, pkg, control=True)
    data_tar = rebuild_tar(orig, pkg, control=False)
    ctrl = gzip_bytes(ctrl_tar)
    data = lzma_alone_bytes(data_tar)

    out.parent.mkdir(parents=True, exist_ok=True)
    write_ar(out, [
        (by_name["debian-binary"], by_name["debian-binary"].data),
        (by_name["control.tar.gz"], ctrl),
        (by_name["data.tar.lzma"], data),
    ])
    print(f"metadata-preserving deb rebuilt: {out}")
    print("existing tar entries: baseline uid/gid/uname/gname/mode/mtime/type preserved")
    print("new Analysis entries: inherited RootHide.app uid/gid/uname/gname/mtime with fixed safe modes")

if __name__ == "__main__":
    main()
