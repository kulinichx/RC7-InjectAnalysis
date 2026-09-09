#!/usr/bin/env python3
"""Create a compact immutable receipt for a statically verified RootHide Analysis release."""
import argparse
import hashlib
import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path
from versioning import VERSION


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("original_deb")
    ap.add_argument("built_deb")
    ap.add_argument("output")
    a = ap.parse_args()
    orig, built, out = map(lambda x: Path(x).resolve(), (a.original_deb, a.built_deb, a.output))
    if not orig.is_file() or not built.is_file():
        raise SystemExit("original/built deb missing")
    verify = Path(__file__).resolve().parent / "verify_release.py"
    subprocess.run([sys.executable, str(verify), str(orig), "--built-deb", str(built)], check=True)
    version = subprocess.check_output(["dpkg-deb", "-f", str(built), "Version"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="rcanalysis-receipt-") as td:
        td = Path(td)
        subprocess.run(["dpkg-deb", "-R", str(built), str(td / "pkg")], check=True, stdout=subprocess.DEVNULL)
        app = td / "pkg/Applications/RootHide.app"
        dylib = app / "Frameworks/RCInjectAnalysis.dylib"
        manifest_path = app / "Frameworks/RCInjectAnalysis.buildinfo.plist"
        with manifest_path.open("rb") as f:
            m = plistlib.load(f)
        lines = [
            f"RCInjectAnalysis release receipt {VERSION}",
            f"PackageVersion={version}",
            f"OriginalDebSHA256={sha(orig)}",
            f"BuiltDebSHA256={sha(built)}",
            f"DylibSHA256={sha(dylib)}",
            f"ManifestDylibSHA256={m.get('DylibSHA256','')}",
            f"ManifestSchema={m.get('ManifestSchema','')}",
            f"BuildID={m.get('BuildID','')}",
            f"SourceTreeSHA256={m.get('SourceTreeSHA256','')}",
            f"SourceFileCount={m.get('SourceFileCount','')}",
            f"LoadMode={m.get('LoadMode','')}",
            f"InstallName={m.get('ExpectedInstallName','')}",
            f"arm64UUID={(m.get('DylibUUIDs') or {}).get('arm64','')}",
            f"arm64eUUID={(m.get('DylibUUIDs') or {}).get('arm64e','')}",
            "StaticReleaseGate=PASS",
            "RuntimeDeviceTest=NOT_PERFORMED",
        ]
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"release receipt: {out}")


if __name__ == "__main__":
    main()
