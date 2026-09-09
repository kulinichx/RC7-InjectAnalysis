#!/usr/bin/env python3
"""Fail closed unless the input executable matches the RootHide 1.3.9 integration assumptions."""
import argparse, struct, sys, hashlib
from pathlib import Path
from patch_load_command import slices, parse_thin, arch_name, make_dylib_command
from extract_entitlements import find_entitlements

EXPECTED_LOAD='@executable_path/Frameworks/RCInjectAnalysis.dylib'
EXPECTED_SHA256='c12b596acd1856677b8fb9753fcebdd88c7601318f10b6b7a8926e2568de687e'
REQUIRED_TOKENS=[
    b'SettingViewController',
    b'BlacklistViewController',
    b'groupTitle', b'items', b'textLabel', b'detailTextLabel',
    b'type', b'url',
    b'LSApplicationWorkspace', b'allInstalledApplications',
    b'applicationProxyForIdentifier:',
    b'__Z6jbrootP8NSString',
]

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('macho'); a=ap.parse_args()
    blob=Path(a.macho).read_bytes(); buf=bytearray(blob)
    actual_sha256=hashlib.sha256(blob).hexdigest()
    if actual_sha256 != EXPECTED_SHA256:
        print(f'RootHide executable SHA-256 mismatch: {actual_sha256}', file=sys.stderr)
        print(f'expected exact 1.3.9+bindtrust1 baseline: {EXPECTED_SHA256}', file=sys.stderr)
        sys.exit(2)
    print(f'baseline SHA-256 exact match: {actual_sha256}')
    sls=slices(buf)
    names=[arch_name(s.cputype,s.cpusubtype) for s in sls]
    ok=True
    for req in ('arm64','arm64e'):
        if req not in names:
            print(f'missing required slice: {req}', file=sys.stderr); ok=False
    lc_size=len(make_dylib_command(EXPECTED_LOAD, True))
    for sl in sls:
        name=arch_name(sl.cputype,sl.cpusubtype)
        n,sz,first,loads=parse_thin(buf,sl)
        start=sl.offset; end=sl.offset+sl.size; sb=blob[start:end]
        missing=[t.decode('utf-8','replace') for t in REQUIRED_TOKENS if t not in sb]
        remaining=first-(32+sz)
        print(f'{name}: ncmds={n} sizeofcmds={sz} first_section=0x{first:x} header_padding={remaining}')
        if missing:
            print(f'{name}: baseline tokens missing: {missing}', file=sys.stderr); ok=False
        if remaining < lc_size:
            print(f'{name}: insufficient header padding for Analysis load command', file=sys.stderr); ok=False
        if EXPECTED_LOAD in loads:
            print(f'{name}: Analysis load command already present; expected pristine RootHide baseline', file=sys.stderr); ok=False
    try:
        ent=find_entitlements(blob)
        for key in ('platform-application','com.apple.private.security.no-sandbox'):
            if ent.get(key) is not True:
                print(f'entitlement {key!r} is not true', file=sys.stderr); ok=False
        print(f'entitlements: {len(ent)} keys; baseline privilege sentinels present')
    except Exception as e:
        print(f'entitlement verification failed: {e}', file=sys.stderr); ok=False
    if not ok: sys.exit(2)
    print('RootHide baseline assumptions verified')
if __name__=='__main__': main()
