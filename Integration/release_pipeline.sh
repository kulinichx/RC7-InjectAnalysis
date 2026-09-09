#!/bin/sh
set -eu
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "Usage: $0 <original-roothide.deb> [output-directory]" >&2
  exit 2
fi
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
ORIG="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OUTDIR="${2:-$ROOT/dist}"
VERSION="$(tr -d '\r\n ' < "$ROOT/VERSION")"
OUT="$OUTDIR/com.roothide.manager_1.3.9+bindtrust1+analysis$VERSION.deb"
RECEIPT="$OUTDIR/RCInjectAnalysis-$VERSION-RELEASE-RECEIPT.txt"
SOURCE_PROVENANCE="$OUTDIR/RCInjectAnalysis-$VERSION-SOURCE-PROVENANCE.json"
SOURCE_SNAPSHOT="$OUTDIR/RCInjectAnalysis-$VERSION-BUILD-SOURCE.zip"
DEPLOYMENT_KIT="$OUTDIR/RCInjectAnalysis-$VERSION-DEPLOYMENT-KIT.zip"
mkdir -p "$OUTDIR"

python3 "$ROOT/Integration/check_toolchain.py"
python3 "$ROOT/Integration/generate_version_header.py"
python3 "$ROOT/Integration/verify_version_consistency.py"
python3 "$ROOT/Integration/make_source_snapshot.py" "$SOURCE_SNAPSHOT" "$SOURCE_PROVENANCE"
python3 "$ROOT/Integration/verify_source_snapshot.py" "$SOURCE_SNAPSHOT" "$SOURCE_PROVENANCE"
python3 "$ROOT/Integration/verify_release.py" "$ORIG"

(
  cd "$ROOT"
  make clean
  make
)

if [ -n "${RC_ANALYSIS_DYLIB:-}" ]; then
  DYLIB="$RC_ANALYSIS_DYLIB"
else
  DYLIB="$(python3 "$ROOT/Integration/find_built_dylib.py" "$ROOT/.theos")"
fi
[ -f "$DYLIB" ] || { echo "Selected dylib missing: $DYLIB" >&2; exit 1; }
echo "Selected dylib: $DYLIB"
python3 "$ROOT/Integration/verify_release.py" "$ORIG" --dylib "$DYLIB"
"$ROOT/Integration/build_roothide_deb.sh" "$ORIG" "$DYLIB" "$OUT"
python3 "$ROOT/Integration/verify_release.py" "$ORIG" --built-deb "$OUT"
python3 "$ROOT/Integration/make_release_receipt.py" "$ORIG" "$OUT" "$RECEIPT"
python3 "$ROOT/Integration/make_deployment_kit.py" "$ORIG" "$OUT" "$RECEIPT" "$SOURCE_SNAPSHOT" "$SOURCE_PROVENANCE" "$DEPLOYMENT_KIT" --preverified
python3 "$ROOT/Integration/verify_deployment_kit.py" "$DEPLOYMENT_KIT"

printf '\nRELEASE PIPELINE PASS\n'
printf 'Package: %s\n' "$OUT"
printf 'Receipt: %s\n' "$RECEIPT"
printf 'Source provenance: %s\n' "$SOURCE_PROVENANCE"
printf 'Build source snapshot: %s\n' "$SOURCE_SNAPSHOT"
printf 'Deployment kit: %s\n' "$DEPLOYMENT_KIT"
printf 'Device runtime test is still required before treating this as a stable build.\n'
