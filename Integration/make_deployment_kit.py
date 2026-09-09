#!/usr/bin/env python3
"""Create deterministic first-device kit with rollback + exact build-source provenance."""
from __future__ import annotations
import argparse, hashlib, json, plistlib, subprocess, sys, tempfile, zipfile
from pathlib import Path
from versioning import VERSION

FIXED_DT=(1980,1,1,0,0,0)

def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()

def zip_write_bytes(z: zipfile.ZipFile, arc: str, data: bytes):
    zi=zipfile.ZipInfo(arc, FIXED_DT); zi.compress_type=zipfile.ZIP_DEFLATED; zi.create_system=3; zi.external_attr=(0o100644 & 0xFFFF)<<16
    z.writestr(zi,data)

def parse_receipt(path: Path) -> dict:
    out={}
    for line in path.read_text(encoding='utf-8').splitlines():
        if '=' in line:
            k,v=line.split('=',1); out[k]=v
    return out

def packaged_manifest(built: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix='rcanalysis-kit-manifest-') as td:
        td=Path(td); subprocess.run(['dpkg-deb','-R',str(built),str(td/'pkg')],check=True,stdout=subprocess.DEVNULL)
        p=td/'pkg/Applications/RootHide.app/Frameworks/RCInjectAnalysis.buildinfo.plist'
        with p.open('rb') as f: return plistlib.load(f)

def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument('original_deb'); ap.add_argument('built_deb'); ap.add_argument('release_receipt')
    ap.add_argument('source_snapshot'); ap.add_argument('source_provenance'); ap.add_argument('output_zip'); ap.add_argument('--preverified', action='store_true', help='pipeline-only: exact built deb already passed verify_release/postinstall; final kit verifier still re-runs both')
    a=ap.parse_args(); root=Path(__file__).resolve().parent.parent
    orig=Path(a.original_deb).resolve(); built=Path(a.built_deb).resolve(); receipt=Path(a.release_receipt).resolve()
    snapshot=Path(a.source_snapshot).resolve(); provenance=Path(a.source_provenance).resolve(); out=Path(a.output_zip).resolve()
    for p in (orig,built,receipt,snapshot,provenance):
        if not p.is_file(): raise SystemExit(f'missing deployment input: {p}')
    if not a.preverified:
        subprocess.run([sys.executable,str(root/'Integration/verify_release.py'),str(orig),'--built-deb',str(built)],check=True)
        subprocess.run([sys.executable,str(root/'Integration/verify_postinstall_contract.py'),str(orig),'--built-deb',str(built)],check=True)
    else:
        print('make_deployment_kit: using pipeline preverified input; verify_deployment_kit must still run before release')
    subprocess.run([sys.executable,str(root/'Integration/verify_source_snapshot.py'),str(snapshot),str(provenance)],check=True)
    prov=json.loads(provenance.read_text(encoding='utf-8')); bm=packaged_manifest(built); rr=parse_receipt(receipt)
    if prov.get('TreeSHA256') != bm.get('SourceTreeSHA256'): raise SystemExit('source provenance does not match packaged build manifest')
    if prov.get('FileCount') != bm.get('SourceFileCount'): raise SystemExit('source provenance file count does not match packaged build manifest')
    if rr.get('BuildID') != bm.get('BuildID') or rr.get('SourceTreeSHA256') != bm.get('SourceTreeSHA256'):
        raise SystemExit('release receipt does not match packaged build/source identity')
    if rr.get('RuntimeDeviceTest') != 'NOT_PERFORMED': raise SystemExit('release receipt must not claim device runtime success')
    docs=[root/'README.md',root/'GITHUB-BUILD.md',root/'FIRST-RUN-TEST.md',root/'FIELD-REPORT-TEMPLATE.md',root/'RELEASE-CHECKLIST.md',root/'DEPLOYMENT-README.md']
    for p in docs:
        if not p.is_file(): raise SystemExit(f'missing deployment document: {p.name}')
    entries={
        f'install/{built.name}':built,
        f'rollback/{orig.name}':orig,
        'RELEASE-RECEIPT.txt':receipt,
        f'provenance/{snapshot.name}':snapshot,
        'provenance/SOURCE-PROVENANCE.json':provenance,
        **{f'docs/{p.name}':p for p in docs},
    }
    manifest={
        'DeploymentSchema':2,
        'AnalysisVersion':VERSION,
        'BuildIdentity':{
            'BuildID':bm.get('BuildID',''), 'SourceTreeSHA256':bm.get('SourceTreeSHA256',''),
            'SourceFileCount':bm.get('SourceFileCount',0), 'DylibSHA256':bm.get('DylibSHA256',''),
            'DylibUUIDs':bm.get('DylibUUIDs',{}), 'ManifestSchema':bm.get('ManifestSchema',0),
        },
        'InstallDeb':{'Path':f'install/{built.name}','SHA256':sha256(built)},
        'RollbackDeb':{'Path':f'rollback/{orig.name}','SHA256':sha256(orig)},
        'ReleaseReceipt':{'Path':'RELEASE-RECEIPT.txt','SHA256':sha256(receipt)},
        'SourceProvenance':{'Path':'provenance/SOURCE-PROVENANCE.json','SHA256':sha256(provenance)},
        'SourceSnapshot':{'Path':f'provenance/{snapshot.name}','SHA256':sha256(snapshot)},
        'PreInstall':{
            'StaticReleaseGate':'PASS','RuntimeDeviceTest':'NOT_PERFORMED','RollbackBaselinePinned':True,
            'InstallArtifactPinned':True,'SourceSnapshotPinned':True,'PostInstallContract':'UNCHANGED_ROOTHIDE_POSTINST',
        },
        'RuntimeDeviceTest':'NOT_PERFORMED',
        'PostInstallContract':'unchanged RootHide postinst; expected RootHide uid=0 gid=0 with executable + setuid',
    }
    for p in docs: manifest.setdefault('Documents',{})[p.name]=sha256(p)
    out.parent.mkdir(parents=True,exist_ok=True)
    manifest_bytes=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode()
    sums=[]
    for arc,src in sorted(entries.items()): sums.append(f'{sha256(src)}  {arc}')
    mf_sha=hashlib.sha256(manifest_bytes).hexdigest(); sums.append(f'{mf_sha}  DEPLOYMENT-MANIFEST.json')
    sums_bytes=('\n'.join(sums)+'\n').encode()
    with zipfile.ZipFile(out,'w') as z:
        for arc,src in sorted(entries.items()): zip_write_bytes(z,arc,src.read_bytes())
        zip_write_bytes(z,'DEPLOYMENT-MANIFEST.json',manifest_bytes); zip_write_bytes(z,'SHA256SUMS',sums_bytes)
    print(f'deployment kit created: {out}')
    print(f'BuildID={bm.get("BuildID","")}')
    print(f'SourceTreeSHA256={bm.get("SourceTreeSHA256","")}')
    print(f'InstallSHA256={manifest["InstallDeb"]["SHA256"]}')
    print(f'RollbackSHA256={manifest["RollbackDeb"]["SHA256"]}')

if __name__=='__main__': main()
