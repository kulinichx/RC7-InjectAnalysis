#!/usr/bin/env python3
"""Pin the complete RootHide rollback/build input package, not only its main executable."""
import argparse, hashlib, io, shutil, subprocess, tarfile
from pathlib import Path

EXPECTED_DEB_SHA256 = "5392005d50c2a3e6189545e408aa4723bad401995ec508efcb48010c53d57f28"
EXPECTED_FIELDS = {
    "Package": "com.roothide.manager",
    "Version": "1.3.9+bindtrust1",
    "Architecture": "iphoneos-arm64e",
}

def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()

def verify_archive_model(p: Path) -> None:
    for flag, label in (("--ctrl-tarfile", "control"), ("--fsys-tarfile", "data")):
        raw = subprocess.check_output(["dpkg-deb", flag, str(p)])
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
            members = tf.getmembers()
        if not members:
            raise SystemExit(f"original RootHide {label} archive is empty")
        bad = []
        for m in members:
            if (m.uid, m.gid, m.uname, m.gname) != (501, 20, "root", "wheel"):
                bad.append((m.name, m.uid, m.gid, m.uname, m.gname))
        if bad:
            raise SystemExit(f"original RootHide {label} tar ownership model drifted: {bad[:3]}")
    print("archive ownership model: PASS (numeric uid=501 gid=20; uname=root gname=wheel)")

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('deb'); a=ap.parse_args(); p=Path(a.deb).resolve()
    if not p.is_file(): raise SystemExit(f'original deb missing: {p}')
    got=sha256(p)
    if got != EXPECTED_DEB_SHA256:
        raise SystemExit(f'original RootHide deb SHA-256 mismatch: {got} != {EXPECTED_DEB_SHA256}')
    if shutil.which('dpkg-deb') is None: raise SystemExit('dpkg-deb not found')
    for field,want in EXPECTED_FIELDS.items():
        value=subprocess.check_output(['dpkg-deb','-f',str(p),field], text=True).strip()
        if value != want: raise SystemExit(f'original RootHide {field} mismatch: {value!r} != {want!r}')
    verify_archive_model(p)
    print(f'original RootHide deb exact match: {got}')
    print('metadata: Package=com.roothide.manager Version=1.3.9+bindtrust1 Architecture=iphoneos-arm64e')
if __name__=='__main__': main()
