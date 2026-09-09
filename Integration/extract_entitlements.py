#!/usr/bin/env python3
"""Extract RootHide entitlements from a signed Mach-O.

Unlike the 1.0.1 helper, this scans all embedded XML plists and selects the
entitlement dictionary by semantic keys. That avoids accidentally treating an
unrelated embedded plist as the code-signing entitlements.
"""
import argparse, plistlib, sys
from pathlib import Path

REQUIRED_SENTINEL = 'platform-application'

def find_entitlements(blob: bytes) -> dict:
    starts = []
    pos = 0
    while True:
        a = blob.find(b'<?xml', pos)
        b = blob.find(b'<plist', pos)
        candidates = [x for x in (a, b) if x >= 0]
        if not candidates:
            break
        start = min(candidates)
        if not starts or starts[-1] != start:
            starts.append(start)
        pos = start + 1

    for start in starts:
        end = blob.find(b'</plist>', start)
        if end < 0:
            continue
        raw = blob[start:end + len(b'</plist>')]
        try:
            obj = plistlib.loads(raw)
        except Exception:
            continue
        if isinstance(obj, dict) and REQUIRED_SENTINEL in obj:
            return obj
    raise ValueError('no entitlement plist containing platform-application found')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('macho')
    ap.add_argument('output')
    a = ap.parse_args()
    obj = find_entitlements(Path(a.macho).read_bytes())
    out = Path(a.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(plistlib.dumps(obj, fmt=plistlib.FMT_XML, sort_keys=False))
    print(f'Wrote {out} ({len(obj)} entitlement keys)')

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('ERROR:', e, file=sys.stderr)
        sys.exit(1)
