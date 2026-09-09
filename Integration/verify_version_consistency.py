#!/usr/bin/env python3
"""Fail closed if project/runtime/integration version sources drift apart."""
import re
import sys
from pathlib import Path
from versioning import ROOT, VERSION, PACKAGE_SUFFIX


def main() -> None:
    header = ROOT / "Sources/RCVersion.generated.h"
    if not header.is_file():
        raise SystemExit("generated version header missing")
    expected = f'#define RC_ANALYSIS_VERSION @"{VERSION}"'
    text = header.read_text(encoding="utf-8")
    if expected not in text:
        raise SystemExit(f"generated header drift: expected {expected!r}")

    build = (ROOT / "Sources/RCBuildInfo.m").read_text(encoding="utf-8")
    if 'kRCAnalysisVersion = RC_ANALYSIS_VERSION' not in build:
        raise SystemExit("RCBuildInfo.m is not bound to generated RC_ANALYSIS_VERSION")

    mk = (ROOT / "Makefile").read_text(encoding="utf-8")
    if 'Integration/generate_version_header.py' not in mk:
        raise SystemExit("Makefile does not regenerate the version header before build")

    builder = (ROOT / "Integration/build_roothide_deb.sh").read_text(encoding="utf-8")
    for token in ('< "$ROOT/VERSION"', 'SUFFIX="+analysis$VERSION"'):
        if token not in builder:
            raise SystemExit(f"builder not bound to VERSION: missing {token}")

    for rel in ("make_build_manifest.py", "verify_build_manifest.py", "verify_release.py", "verify_package_delta.py", "make_deployment_kit.py", "verify_deployment_kit.py", "source_fingerprint.py", "make_source_snapshot.py", "verify_source_snapshot.py"):
        p = ROOT / "Integration" / rel
        s = p.read_text(encoding="utf-8")
        if 'from versioning import VERSION' not in s:
            raise SystemExit(f"{rel} does not import central VERSION")
        if re.search(r'^VERSION\s*=\s*[\"\']', s, flags=re.M):
            raise SystemExit(f"{rel} still hard-codes VERSION")

    # Current release version may appear in docs and generated header, but not in implementation/integration code.
    allowed = {ROOT / "Sources/RCVersion.generated.h", ROOT / "VERSION"}
    for base in (ROOT / "Sources", ROOT / "Integration"):
        for p in base.rglob("*"):
            if not p.is_file() or p in allowed or p.suffix in {".plist", ".md", ".txt", ".pyc"}:
                continue
            try:
                s = p.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if VERSION in s:
                raise SystemExit(f"hard-coded current version outside central source: {p.relative_to(ROOT)}")

    print(f"version consistency: PASS ({VERSION}, suffix={PACKAGE_SUFFIX})")


if __name__ == "__main__":
    main()
