#!/usr/bin/env python3
"""Fail closed unless deployment kit binds install, rollback and exact build source provenance."""
from __future__ import annotations
import argparse, hashlib, json, plistlib, subprocess, sys, tempfile, zipfile
from pathlib import Path
from versioning import VERSION

def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
    return h.hexdigest()

def parse_receipt(path: Path)->dict:
    out={}
    for line in path.read_text(encoding='utf-8').splitlines():
        if '=' in line: k,v=line.split('=',1); out[k]=v
    return out

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('kit'); a=ap.parse_args(); kit=Path(a.kit).resolve()
    if not kit.is_file(): raise SystemExit(f'kit missing: {kit}')
    root=Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix='rcanalysis-kit-verify-') as td:
        td=Path(td)
        with zipfile.ZipFile(kit) as z:
            names=z.namelist()
            if len(names)!=len(set(names)): raise SystemExit('duplicate deployment-kit member')
            name_set=set(names)
            for name in names:
                pp=Path(name)
                if pp.is_absolute() or '..' in pp.parts: raise SystemExit(f'unsafe deployment-kit member: {name}')
            for req in ('DEPLOYMENT-MANIFEST.json','SHA256SUMS','RELEASE-RECEIPT.txt'):
                if req not in name_set: raise SystemExit(f'kit missing: {req}')
            z.extractall(td)
        m=json.loads((td/'DEPLOYMENT-MANIFEST.json').read_text(encoding='utf-8'))
        if m.get('DeploymentSchema')!=2: raise SystemExit('unexpected deployment schema')
        if m.get('AnalysisVersion')!=VERSION: raise SystemExit(f'deployment version mismatch: {m.get("AnalysisVersion")} != {VERSION}')
        if m.get('RuntimeDeviceTest')!='NOT_PERFORMED': raise SystemExit('deployment manifest must not claim device runtime success')
        pre=m.get('PreInstall') or {}
        required_pre={'StaticReleaseGate':'PASS','RuntimeDeviceTest':'NOT_PERFORMED','RollbackBaselinePinned':True,'InstallArtifactPinned':True,'SourceSnapshotPinned':True,'PostInstallContract':'UNCHANGED_ROOTHIDE_POSTINST'}
        for k,v in required_pre.items():
            if pre.get(k)!=v: raise SystemExit(f'preinstall contract mismatch: {k}={pre.get(k)!r}')
        expected={
            'DEPLOYMENT-MANIFEST.json','SHA256SUMS','RELEASE-RECEIPT.txt',m['InstallDeb']['Path'],m['RollbackDeb']['Path'],
            m['SourceProvenance']['Path'],m['SourceSnapshot']['Path'],*{f'docs/{n}' for n in m.get('Documents',{})},
        }
        if name_set!=expected: raise SystemExit(f'unexpected deployment-kit members: extra={sorted(name_set-expected)} missing={sorted(expected-name_set)}')
        pairs=[(td/m['InstallDeb']['Path'],m['InstallDeb']['SHA256'],'install'),(td/m['RollbackDeb']['Path'],m['RollbackDeb']['SHA256'],'rollback'),(td/m['ReleaseReceipt']['Path'],m['ReleaseReceipt']['SHA256'],'receipt'),(td/m['SourceProvenance']['Path'],m['SourceProvenance']['SHA256'],'source provenance'),(td/m['SourceSnapshot']['Path'],m['SourceSnapshot']['SHA256'],'source snapshot')]
        for p,want,label in pairs:
            if not p.is_file(): raise SystemExit(f'{label} file missing: {p}')
            if sha256(p)!=want: raise SystemExit(f'{label} SHA mismatch')
        for name,want in m.get('Documents',{}).items():
            p=td/'docs'/name
            if not p.is_file() or sha256(p)!=want: raise SystemExit(f'document mismatch: {name}')
        install=td/m['InstallDeb']['Path']; rollback=td/m['RollbackDeb']['Path']; receipt=td/m['ReleaseReceipt']['Path']
        provenance=td/m['SourceProvenance']['Path']; snapshot=td/m['SourceSnapshot']['Path']
        subprocess.run([sys.executable,str(root/'Integration/verify_source_snapshot.py'),str(snapshot),str(provenance)],check=True)
        subprocess.run([sys.executable,str(root/'Integration/verify_release.py'),str(rollback),'--built-deb',str(install)],check=True)
        subprocess.run([sys.executable,str(root/'Integration/verify_postinstall_contract.py'),str(rollback),'--built-deb',str(install)],check=True)
        prov=json.loads(provenance.read_text(encoding='utf-8')); rr=parse_receipt(receipt)
        with tempfile.TemporaryDirectory(prefix='rcanalysis-kit-pkg-') as pd:
            pd=Path(pd); subprocess.run(['dpkg-deb','-R',str(install),str(pd/'pkg')],check=True,stdout=subprocess.DEVNULL)
            with (pd/'pkg/Applications/RootHide.app/Frameworks/RCInjectAnalysis.buildinfo.plist').open('rb') as f: bm=plistlib.load(f)
        ident=m.get('BuildIdentity') or {}
        for key in ('BuildID','SourceTreeSHA256','SourceFileCount','DylibSHA256','DylibUUIDs','ManifestSchema'):
            if ident.get(key)!=bm.get(key): raise SystemExit(f'deployment BuildIdentity mismatch: {key}')
        if prov.get('TreeSHA256')!=bm.get('SourceTreeSHA256') or prov.get('FileCount')!=bm.get('SourceFileCount'):
            raise SystemExit('source provenance does not bind to packaged build manifest')
        if rr.get('BuildID')!=bm.get('BuildID') or rr.get('SourceTreeSHA256')!=bm.get('SourceTreeSHA256') or rr.get('RuntimeDeviceTest')!='NOT_PERFORMED':
            raise SystemExit('release receipt identity/runtime semantics mismatch')
        sums=(td/'SHA256SUMS').read_text(encoding='utf-8').splitlines()
        expected_sum_paths=expected-{'SHA256SUMS'}
        seen=set()
        for line in sums:
            digest,rel=line.split('  ',1); p=td/rel; seen.add(rel)
            if not p.is_file() or sha256(p)!=digest: raise SystemExit(f'SHA256SUMS mismatch: {rel}')
        if seen!=expected_sum_paths: raise SystemExit(f'SHA256SUMS path-set mismatch: extra={sorted(seen-expected_sum_paths)} missing={sorted(expected_sum_paths-seen)}')
    print('DEPLOYMENT KIT PASS')
    print(f'BuildID={m["BuildIdentity"]["BuildID"]}')
    print(f'SourceTreeSHA256={m["BuildIdentity"]["SourceTreeSHA256"]}')
    print('contains exact rollback + statically verified install + exact build-source snapshot/provenance')
    print('RuntimeDeviceTest remains NOT_PERFORMED until a real RootHide device report is collected.')

if __name__=='__main__': main()
