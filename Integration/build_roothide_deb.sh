#!/bin/sh
set -eu
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <original-roothide.deb> <RCInjectAnalysis.dylib> <output.deb>" >&2
  exit 2
fi
ORIG="$1"; DYLIB="$2"; OUT="$3"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VERSION="$(tr -d '\r\n ' < "$ROOT/VERSION")"
[ -n "$VERSION" ] || { echo "Invalid empty VERSION" >&2; exit 1; }
SUFFIX="+analysis$VERSION"
PATCH="$ROOT/Integration/patch_load_command.py"
EXTRACT="$ROOT/Integration/extract_entitlements.py"
COMPARE_ENT="$ROOT/Integration/compare_entitlements.py"
VERIFY_ORIGINAL_DEB="$ROOT/Integration/verify_original_deb.py"
VERIFY_BASE="$ROOT/Integration/verify_roothide_baseline.py"
VERIFY_SOURCE="$ROOT/Integration/verify_source_invariants.py"
VERIFY_VERSION="$ROOT/Integration/verify_version_consistency.py"
VERIFY="$ROOT/Integration/verify_macho.py"
VERIFY_DYLIB="$ROOT/Integration/verify_dylib.py"
MAKE_MANIFEST="$ROOT/Integration/make_build_manifest.py"
VERIFY_MANIFEST="$ROOT/Integration/verify_build_manifest.py"
VERIFY_DELTA="$ROOT/Integration/verify_package_delta.py"
VERIFY_POSTINST="$ROOT/Integration/verify_postinstall_contract.py"
REPACK="$ROOT/Integration/repack_deb_preserving_metadata.py"
for x in dpkg-deb python3 ldid; do command -v "$x" >/dev/null 2>&1 || { echo "Missing required tool: $x" >&2; exit 1; }; done
[ -f "$ORIG" ] || { echo "Missing original deb: $ORIG" >&2; exit 1; }
[ -f "$DYLIB" ] || { echo "Missing dylib: $DYLIB" >&2; exit 1; }
python3 "$VERIFY_ORIGINAL_DEB" "$ORIG"
python3 "$VERIFY_VERSION"
python3 "$VERIFY_SOURCE" "$ROOT"
python3 "$VERIFY_DYLIB" "$DYLIB"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/rcanalysis.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP/pkg"
dpkg-deb -R "$ORIG" "$TMP/pkg"
APP="$TMP/pkg/Applications/RootHide.app"
BIN="$APP/RootHide"
[ -f "$BIN" ] || { echo "Unexpected package: RootHide executable not found" >&2; exit 1; }

# Fail closed if a different Manager build is supplied.
python3 "$VERIFY_BASE" "$BIN"
python3 "$EXTRACT" "$BIN" "$TMP/original-entitlements.plist"

mkdir -p "$APP/Frameworks"
cp "$DYLIB" "$APP/Frameworks/RCInjectAnalysis.dylib"
chmod 0755 "$APP/Frameworks/RCInjectAnalysis.dylib"
python3 "$PATCH" "$BIN" "$TMP/RootHide.patched" --weak
mv "$TMP/RootHide.patched" "$BIN"

# Sign embedded code first, then preserve the original RootHide executable entitlements.
ldid -S "$APP/Frameworks/RCInjectAnalysis.dylib"
python3 "$VERIFY_DYLIB" "$APP/Frameworks/RCInjectAnalysis.dylib"
MANIFEST="$APP/Frameworks/RCInjectAnalysis.buildinfo.plist"
python3 "$MAKE_MANIFEST" "$APP/Frameworks/RCInjectAnalysis.dylib" "$MANIFEST"
python3 "$VERIFY_MANIFEST" "$MANIFEST" "$APP/Frameworks/RCInjectAnalysis.dylib"
ldid -S"$TMP/original-entitlements.plist" "$BIN"
python3 "$VERIFY" "$BIN"
python3 "$EXTRACT" "$BIN" "$TMP/signed-entitlements.plist"
python3 "$COMPARE_ENT" "$TMP/original-entitlements.plist" "$TMP/signed-entitlements.plist"

# Preserve RootHide metadata/postinst; only the prototype version suffix changes.
CTRL="$TMP/pkg/DEBIAN/control"
python3 - "$CTRL" "$SUFFIX" <<'PY'
from pathlib import Path
import sys,re
p=Path(sys.argv[1]); s=p.read_text()
m=re.search(r'(?m)^Version:\s*(.+)$',s)
if not m: raise SystemExit('control file has no Version field')
v=m.group(1).strip()
suffix=sys.argv[2]
if not v.endswith(suffix):
    s=s[:m.start(1)]+v+suffix+s[m.end(1):]
p.write_text(s)
PY

# Preserve the pinned RootHide archive's exact tar metadata instead of letting
# dpkg-deb -b reinterpret ownership through the build host.  The baseline uses
# numeric uid=501/gid=20 while also storing uname=root/gname=wheel.  Existing
# entries retain their original TarInfo; the three new Analysis entries inherit
# the RootHide.app ownership/mtime model with fixed safe modes.
chmod 0755 "$APP/Frameworks" "$APP/Frameworks/RCInjectAnalysis.dylib"
chmod 0644 "$MANIFEST" "$CTRL"
[ ! -f "$TMP/pkg/DEBIAN/postinst" ] || chmod 0755 "$TMP/pkg/DEBIAN/postinst"
python3 "$REPACK" "$ORIG" "$TMP/pkg" "$OUT"

# Re-open the finished package and verify the exact artifact that will be installed.
mkdir -p "$TMP/verify"
dpkg-deb -R "$OUT" "$TMP/verify"
VBIN="$TMP/verify/Applications/RootHide.app/RootHide"
VDYLIB="$TMP/verify/Applications/RootHide.app/Frameworks/RCInjectAnalysis.dylib"
VMANIFEST="$TMP/verify/Applications/RootHide.app/Frameworks/RCInjectAnalysis.buildinfo.plist"
[ -f "$VDYLIB" ] || { echo "Finished package is missing Analysis dylib" >&2; exit 1; }
[ -f "$VMANIFEST" ] || { echo "Finished package is missing Analysis build manifest" >&2; exit 1; }
python3 "$VERIFY_DYLIB" "$VDYLIB"
python3 "$VERIFY_MANIFEST" "$VMANIFEST" "$VDYLIB"
python3 "$VERIFY" "$VBIN"
python3 "$EXTRACT" "$VBIN" "$TMP/final-entitlements.plist"
python3 "$COMPARE_ENT" "$TMP/original-entitlements.plist" "$TMP/final-entitlements.plist"
VER="$(dpkg-deb -f "$OUT" Version)"
case "$VER" in *"$SUFFIX") ;; *) echo "Unexpected output version: $VER" >&2; exit 1;; esac
python3 "$VERIFY_DELTA" "$ORIG" "$OUT"
python3 "$VERIFY_POSTINST" "$ORIG" --built-deb "$OUT"

printf 'Built and verified: %s\n' "$OUT"
printf 'Version: %s\n' "$VER"
printf 'Original input was never modified. Keep it as rollback package.\n'
