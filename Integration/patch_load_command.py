#!/usr/bin/env python3
"""Add an LC_LOAD_WEAK_DYLIB/LC_LOAD_DYLIB to thin or FAT Mach-O in-place.

Designed for the pinned RootHide Manager baseline. The patch only consumes existing
header padding; it never moves sections or changes FAT slice sizes.

Any Mach-O header edit invalidates the existing code signature. Re-sign the
result after patching.
"""
from __future__ import annotations
import argparse, os, struct, sys
from dataclasses import dataclass
from pathlib import Path

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC_64_LE = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x80000018
DYLIB_COMMANDS = {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, 0x8000001F, 0x80000023, 0x20}

@dataclass
class Slice:
    offset: int
    size: int
    cputype: int
    cpusubtype: int


def u32be(b, off): return struct.unpack_from('>I', b, off)[0]
def u64be(b, off): return struct.unpack_from('>Q', b, off)[0]

def slices(buf: bytes) -> list[Slice]:
    if len(buf) < 4:
        raise ValueError('file too small')
    magic_be = u32be(buf, 0)
    if magic_be == FAT_MAGIC:
        if len(buf) < 8: raise ValueError('truncated FAT header')
        n = u32be(buf, 4); pos = 8; out=[]
        for _ in range(n):
            if pos + 20 > len(buf): raise ValueError('truncated fat_arch')
            cpu, sub, off, size, align = struct.unpack_from('>iiIII', buf, pos)
            if off + size > len(buf): raise ValueError('FAT slice out of bounds')
            out.append(Slice(off,size,cpu,sub)); pos += 20
        return out
    if magic_be == FAT_MAGIC_64:
        if len(buf) < 8: raise ValueError('truncated FAT64 header')
        n=u32be(buf,4); pos=8; out=[]
        for _ in range(n):
            if pos + 32 > len(buf): raise ValueError('truncated fat_arch_64')
            cpu, sub = struct.unpack_from('>ii',buf,pos)
            off,size = struct.unpack_from('>QQ',buf,pos+8)
            if off + size > len(buf): raise ValueError('FAT64 slice out of bounds')
            out.append(Slice(off,size,cpu,sub)); pos += 32
        return out
    # Thin Mach-O is little-endian bytes cf fa ed fe; interpreted LE -> FEEDFACF.
    if struct.unpack_from('<I', buf, 0)[0] == MH_MAGIC_64_LE:
        cpu, sub = struct.unpack_from('<ii',buf,4)
        return [Slice(0,len(buf),cpu,sub)]
    raise ValueError('unsupported file: expected MH_MAGIC_64 or FAT Mach-O')


def arch_name(cpu:int, sub:int)->str:
    if cpu == 0x0100000C:
        subtype = sub & 0x00FFFFFF
        caps = sub & 0xFF000000
        if subtype == 2 and caps:
            return 'arm64e'
        if subtype == 2:
            return 'arm64e'
        return 'arm64'
    return f'cpu=0x{cpu & 0xffffffff:x}/sub=0x{sub & 0xffffffff:x}'


def parse_thin(buf: bytearray, sl: Slice):
    base=sl.offset
    if base+32 > len(buf): raise ValueError('truncated mach_header_64')
    magic = struct.unpack_from('<I',buf,base)[0]
    if magic != MH_MAGIC_64_LE: raise ValueError(f'{arch_name(sl.cputype,sl.cpusubtype)}: unsupported thin magic')
    ncmds, sizeofcmds = struct.unpack_from('<II',buf,base+16)
    pos=base+32; end=pos+sizeofcmds
    if end > base+sl.size: raise ValueError('load commands exceed slice')
    min_section=None; existing=[]
    for _ in range(ncmds):
        if pos+8 > end: raise ValueError('truncated load command')
        cmd,cmdsize=struct.unpack_from('<II',buf,pos)
        if cmdsize < 8 or pos+cmdsize > end: raise ValueError('invalid load command size')
        if cmd == LC_SEGMENT_64 and cmdsize >= 72:
            nsects=struct.unpack_from('<I',buf,pos+64)[0]
            secpos=pos+72
            for _s in range(nsects):
                if secpos+80 > pos+cmdsize: break
                sec_off=struct.unpack_from('<I',buf,secpos+48)[0]
                if sec_off and (min_section is None or sec_off < min_section): min_section=sec_off
                secpos += 80
        if cmd in DYLIB_COMMANDS and cmdsize >= 24:
            nameoff=struct.unpack_from('<I',buf,pos+8)[0]
            if 0 < nameoff < cmdsize:
                raw=bytes(buf[pos+nameoff:pos+cmdsize]).split(b'\0',1)[0]
                try: existing.append(raw.decode('utf-8'))
                except UnicodeDecodeError: pass
        pos += cmdsize
    if pos != end: raise ValueError('load command table size mismatch')
    if min_section is None: raise ValueError('could not determine first section file offset')
    return ncmds,sizeofcmds,min_section,existing


def make_dylib_command(path:str, weak:bool)->bytes:
    p=path.encode('utf-8')+b'\0'
    cmdsize=(24+len(p)+7)&~7
    cmd=LC_LOAD_WEAK_DYLIB if weak else LC_LOAD_DYLIB
    b=bytearray(cmdsize)
    # dylib_command: cmd, cmdsize, name.offset, timestamp, current_version, compatibility_version
    struct.pack_into('<IIIIII',b,0,cmd,cmdsize,24,0,0,0)
    b[24:24+len(p)]=p
    return bytes(b)


def patch_one(buf:bytearray, sl:Slice, dylib_path:str, weak:bool):
    ncmds,sizeofcmds,first_section,existing=parse_thin(buf,sl)
    name=arch_name(sl.cputype,sl.cpusubtype)
    if dylib_path in existing:
        return {'arch':name,'status':'already-present','ncmds':ncmds,'sizeofcmds':sizeofcmds,'first_section':first_section}
    lc=make_dylib_command(dylib_path,weak)
    insert=sl.offset+32+sizeofcmds
    capacity=sl.offset+first_section-insert
    if capacity < len(lc):
        raise ValueError(f'{name}: insufficient header padding: need {len(lc)}, have {capacity}')
    # Require the padding we consume to be zero. This protects against overwriting unknown data.
    old=bytes(buf[insert:insert+len(lc)])
    if any(old):
        raise ValueError(f'{name}: target header padding is not zero; refusing in-place patch')
    buf[insert:insert+len(lc)]=lc
    struct.pack_into('<II',buf,sl.offset+16,ncmds+1,sizeofcmds+len(lc))
    return {'arch':name,'status':'patched','ncmds':ncmds+1,'sizeofcmds':sizeofcmds+len(lc),'first_section':first_section,'used':len(lc),'remaining':capacity-len(lc)}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('output')
    ap.add_argument('--path',default='@executable_path/Frameworks/RCInjectAnalysis.dylib')
    g=ap.add_mutually_exclusive_group()
    g.add_argument('--weak',action='store_true',default=True,help='add LC_LOAD_WEAK_DYLIB (default)')
    g.add_argument('--strong',action='store_true',help='add LC_LOAD_DYLIB')
    args=ap.parse_args()
    inp=Path(args.input); out=Path(args.output)
    if inp.resolve()==out.resolve():
        ap.error('input and output must differ; this tool intentionally does not patch in place')
    data=bytearray(inp.read_bytes())
    sls=slices(data)
    reports=[]
    for sl in sls:
        reports.append(patch_one(data,sl,args.path,weak=not args.strong))
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_bytes(data)
    os.chmod(out, os.stat(inp).st_mode)
    print(f'Wrote: {out}')
    for r in reports:
        print(r)
    print('NOTE: Mach-O header was modified; the original code signature is now invalid. Re-sign before installation.')

if __name__=='__main__':
    try: main()
    except Exception as e:
        print(f'ERROR: {e}',file=sys.stderr); sys.exit(1)
