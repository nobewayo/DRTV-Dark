"""Exact public-source integrity and deterministic source-only copies."""
if not __debug__:
    raise RuntimeError('Optimized Python is unsupported')
import argparse
import hashlib
import json
from pathlib import Path
import re
from json_unique import unique

ROOT=Path(__file__).resolve().parents[1]
APPROVAL='releases/publication-approval.json'


def sha(data):return hashlib.sha256(data).hexdigest()
def require(ok,msg):
    if not ok:raise ValueError(msg)
def files():
    value=json.loads((ROOT/'maintenance/public-files.json').read_bytes(),object_pairs_hook=unique)
    require(value['schema']==1 and value['files']==sorted(set(value['files'])),'Source layout')
    return set(value['files'])
def scan(name,data):
    require(not data.startswith((b'PK\x03\x04',b'\xfe\xed\xfe\xed')),'Archive/keystore in source: '+name)
    require(not re.search(rb'(?m)^[ \t]*-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----',data),'Private PEM')
    if name.endswith('.json'):
        def walk(v):
            if isinstance(v,dict):
                require(not (v.get('kty') and set(v)&{'d','p','q','dp','dq','qi','oth'}),'Private JWK')
                for x in v.values():walk(x)
            elif isinstance(v,list):
                for x in v:walk(x)
        walk(json.loads(data,object_pairs_hook=unique))


def verify(directory,expected_manifest=None,*,checkout=False):
    root=Path(directory);require(root.is_dir() and not root.is_symlink(),'Source root')
    require(not checkout or bool(expected_manifest),'Checkout requires external manifest pin')
    raw=(root/'EXPORT-MANIFEST.json').read_bytes()
    if expected_manifest:require(sha(raw)==expected_manifest,'External manifest pin mismatch')
    value=json.loads(raw,object_pairs_hook=unique);allowed=files()
    require(value['schema']==1 and value['publicationReady'] is False,'Source state')
    require(set(value['files'])==allowed-{APPROVAL} and value['unmanifested']==[APPROVAL],'Source manifest allowlist')
    require(not (root/'.git').is_symlink(),'Linked Git metadata')
    require(not (root/'.git').exists() or (root/'.git').is_dir(),'Git metadata must be a directory')
    nodes=[p for p in root.rglob('*') if not (checkout and p.relative_to(root).parts[0]=='.git')]
    require(all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in nodes),'Links/special files')
    require({p.relative_to(root).as_posix() for p in nodes if p.is_file()}==allowed|{'EXPORT-MANIFEST.json'},'Exact source files')
    dirs={str(p) for n in allowed for p in Path(n).parents if str(p)!='.'}
    require({p.relative_to(root).as_posix() for p in nodes if p.is_dir()}==dirs,'Exact source directories')
    for name,digest in value['files'].items():
        raw=(root/name).read_bytes();require(sha(raw)==digest,'Source hash: '+name);scan(name,raw)
    scan(APPROVAL,(root/APPROVAL).read_bytes())
    return dict(status='PASS',files=len(allowed),manifestSha256=sha((root/'EXPORT-MANIFEST.json').read_bytes()))


def write_manifest(root):
    root=Path(root);allowed=files()
    value=dict(schema=1,publicationReady=False,files={n:sha((root/n).read_bytes()) for n in sorted(allowed-{APPROVAL})},unmanifested=[APPROVAL])
    (root/'EXPORT-MANIFEST.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    return verify(root)


def export(source,out):
    source=Path(source);out=Path(out).resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'work'),'New ignored work output required')
    # Building may have added ignored inputs/outputs; copy only maintained sources.
    out.mkdir(parents=True)
    for name in sorted(files()):
        p=source/name
        require(p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(source.resolve()),'Unsafe source')
        require(all(not x.is_symlink() for x in p.parents if x==source or source in x.parents),'Linked parent')
        data=p.read_bytes();scan(name,data)
        target=out/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    return write_manifest(out)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--manifest-sha256',required=True)
    a=p.parse_args();print(json.dumps(verify(a.source,a.manifest_sha256,checkout=True)))
