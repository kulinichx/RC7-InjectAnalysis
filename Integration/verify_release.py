#!/usr/bin/env python3
"""One-command prebuild/final-artifact verifier for the RootHide Analysis integration."""
import argparse
import plistlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from versioning import VERSION


def run(cmd, *, cwd=None):
    print("+", " ".join(map(str, cmd)))
    subprocess.run([str(x) for x in cmd], cwd=cwd, check=True)


def extract_deb(deb: Path, dst: Path):
    run(["dpkg-deb", "-R", deb, dst])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("original_deb")
    ap.add_argument("--project-root", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--dylib")
    ap.add_argument("--built-deb")
    a = ap.parse_args()

    root = Path(a.project_root).resolve()
    integ = root / "Integration"
    original = Path(a.original_deb).resolve()
    if shutil.which("dpkg-deb") is None:
        raise SystemExit("dpkg-deb not found")
    if not original.is_file():
        raise SystemExit(f"original deb missing: {original}")

    run([sys.executable, integ / "verify_version_consistency.py"])
    run([sys.executable, integ / "verify_original_deb.py", original])
    run([sys.executable, integ / "verify_source_invariants.py", root])
    run([sys.executable, integ / "rule_matrix_selftest.py"])

    with tempfile.TemporaryDirectory(prefix="rcanalysis-release-") as td:
        td = Path(td)
        original_dir = td / "original"
        extract_deb(original, original_dir)
        original_bin = original_dir / "Applications/RootHide.app/RootHide"
        run([sys.executable, integ / "verify_roothide_baseline.py", original_bin])
        original_ent = td / "original-entitlements.plist"
        run([sys.executable, integ / "extract_entitlements.py", original_bin, original_ent])
        with original_ent.open("rb") as f:
            ent = plistlib.load(f)
        if len(ent) != 199:
            raise SystemExit(f"unexpected entitlement count: {len(ent)} (expected 199)")
        print("original entitlements: PASS (199 keys)")

        if a.dylib:
            dylib = Path(a.dylib).resolve()
            run([sys.executable, integ / "verify_dylib.py", dylib])
            print("candidate dylib: PASS")

        if a.built_deb:
            built = Path(a.built_deb).resolve()
            if not built.is_file():
                raise SystemExit(f"built deb missing: {built}")
            final_dir = td / "final"
            extract_deb(built, final_dir)
            app = final_dir / "Applications/RootHide.app"
            final_bin = app / "RootHide"
            dylib = app / "Frameworks/RCInjectAnalysis.dylib"
            manifest = app / "Frameworks/RCInjectAnalysis.buildinfo.plist"
            run([sys.executable, integ / "verify_macho.py", final_bin])
            run([sys.executable, integ / "verify_dylib.py", dylib])
            run([sys.executable, integ / "verify_build_manifest.py", manifest, dylib])
            final_ent = td / "final-entitlements.plist"
            run([sys.executable, integ / "extract_entitlements.py", final_bin, final_ent])
            run([sys.executable, integ / "compare_entitlements.py", original_ent, final_ent])
            version = subprocess.check_output(["dpkg-deb", "-f", str(built), "Version"], text=True).strip()
            if not version.endswith(f"+analysis{VERSION}"):
                raise SystemExit(f"unexpected final package version: {version}")
            print(f"built package version: PASS ({version})")
            run([sys.executable, integ / "verify_package_delta.py", original, built])
            run([sys.executable, integ / "verify_postinstall_contract.py", original, "--built-deb", built])

    print("RELEASE GATE PASS")
    print("Note: this is static/pre-install verification; it does not replace real iOS loading/signature/runtime testing.")


if __name__ == "__main__":
    main()
