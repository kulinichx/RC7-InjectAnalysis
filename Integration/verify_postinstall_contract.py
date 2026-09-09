#!/usr/bin/env python3
"""Verify the original RootHide postinst is untouched and still defines the expected installation state."""
import argparse, hashlib, shutil, subprocess, tempfile
from pathlib import Path

EXPECTED_POSTINST_SHA256 = "52e9fabdcf3fd065bebfa6b564fabefc0690e8e1ed57c11bd0a3371bb18c482c"
EXPECTED_LINES = [
    "uicache -p /Applications/RootHide.app",
    "chown 0:0 /Applications/RootHide.app/RootHide",
    "chmod +s /Applications/RootHide.app/RootHide",
]

def extract_control(deb: Path, dst: Path) -> bytes:
    subprocess.run(["dpkg-deb", "-e", str(deb), str(dst)], check=True, stdout=subprocess.DEVNULL)
    p = dst / "postinst"
    if not p.is_file():
        raise SystemExit(f"postinst missing: {deb}")
    return p.read_bytes()

def validate_original(data: bytes) -> None:
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_POSTINST_SHA256:
        raise SystemExit(f"original postinst SHA-256 mismatch: {sha}")
    text = data.decode("utf-8", "strict")
    positions = []
    for line in EXPECTED_LINES:
        pos = text.find(line)
        if pos < 0:
            raise SystemExit(f"original postinst missing required command: {line}")
        positions.append(pos)
    if positions != sorted(positions):
        raise SystemExit("original postinst commands are not in the expected order")

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("original_deb")
    ap.add_argument("--built-deb")
    a = ap.parse_args()
    if shutil.which("dpkg-deb") is None:
        raise SystemExit("dpkg-deb not found")
    orig = Path(a.original_deb).resolve()
    if not orig.is_file():
        raise SystemExit(f"original deb missing: {orig}")
    with tempfile.TemporaryDirectory(prefix="rcanalysis-postinst-") as td:
        td = Path(td)
        original_data = extract_control(orig, td / "original")
        validate_original(original_data)
        print("original RootHide postinst: PASS")
        print("expected installed RootHide state: uid=0 gid=0, executable, setuid present (actual mode is reported; chmod +s may also set setgid)")
        if a.built_deb:
            built = Path(a.built_deb).resolve()
            if not built.is_file():
                raise SystemExit(f"built deb missing: {built}")
            built_data = extract_control(built, td / "built")
            if built_data != original_data:
                raise SystemExit("built package postinst differs from original RootHide")
            print("built postinst byte-identical to original: PASS")

if __name__ == "__main__":
    main()
