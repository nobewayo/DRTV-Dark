"""Verify prebuilt static material. Default approval record rejects all deployment."""
if not __debug__: raise RuntimeError('Optimized Python is unsupported: security checks use assertions')
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import zipfile
from static_policy import CSP, require
from static_assets import TOP_LEVEL_FILES, DIRECTORIES
from release_data import verify_signed, check_envelope, check_updates, load
from update_metadata import verify as verify_updates


def sha(b): return hashlib.sha256(b).hexdigest()


def audit(root):
    root = Path(root)
    nodes = list(root.rglob('*'))
    require(root.is_dir() and not root.is_symlink(), 'Artifact directory')
    require(all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in nodes), 'Links/special files')
    files = {str(p.relative_to(root)): p.read_bytes() for p in nodes if p.is_file()}
    require(len(files) <= 128 and sum(map(len, files.values())) <= 32*1024*1024, 'Static bounds')
    inv = json.loads(files['integrity.json'])
    require(inv['schema'] == 3 and set(inv['files']) == set(files)-{'integrity.json','.nojekyll'}, 'Exact inventory')
    require(all(sha(files[n]) == h for n,h in inv['files'].items()), 'Asset hashes')
    trust = json.loads(files['trust.json']); cfg = json.loads(files['config.json'])
    require(not set(trust['releaseKey']) & {'d','p','q','dp','dq','qi','oth'}, 'Private JWK')
    production = trust['developmentOnly'] is False
    omit = {'trust.json','synthetic-v1.json','synthetic-v2.json','updates-development.json'}
    expected = (set(TOP_LEVEL_FILES)-omit if production else set(TOP_LEVEL_FILES))
    expected |= {'trust.json','recipe.json','config.json','integrity.json','.nojekyll'}
    expected |= {'drtv-release.json','updates.json'} if production else {'drtv-development.json'}
    expected |= {d+'/'+n for d,ns in DIRECTORIES.items() for n in ns if n!='01-afinstaller-dr-tv.webp'}
    expected.add('guide.json')
    normalized = {re.sub(r'\.[0-9a-f]{16}(?=\.(?:mjs|css)$)', '', n) for n in files}
    require(normalized == expected and len(files) == len(expected), 'Exact static allowlist')
    require({str(p.relative_to(root)) for p in nodes if p.is_dir()} == set(DIRECTORIES), 'Exact directories')
    require(files['.nojekyll'] == b'', 'Nojekyll')
    html = files['index.html'].decode()
    require(f'<meta http-equiv="Content-Security-Policy" content="{CSP}">' in html, 'CSP')
    require(not re.search(r'\s(?:style|on\w+)=|<base\b', html, re.I), 'Inline execution/base')
    executable = {n for n in files if n.endswith(('.mjs','.css'))}
    require(all(re.search(r'\.[0-9a-f]{16}\.(mjs|css)$',n) for n in executable), 'Executable versioning')
    require(len({re.search(r'\.([0-9a-f]{16})\.(?:mjs|css)$',n)[1] for n in executable})==1,'Mixed build identifiers')
    refs = re.findall(r'(?:src|href)="([^"]+)" integrity="([^"]+)"', html)
    require({n for n,_ in refs} == executable, 'Complete SRI')
    for n,h in refs:
        require(h == 'sha384-'+base64.b64encode(hashlib.sha384(files[n]).digest()).decode(), 'SRI digest')
    for n,b in files.items():
        require(b'PRIVATE KEY' not in b and not b.startswith((b'PK\x03\x04',b'\xfe\xed\xfe\xed')), 'Forbidden payload')
    # Only validated production material enables processing; test identities never do.
    require(cfg['processingEnabled'] is production, 'Processing state must match the production identity')
    require(cfg['schema']==3 and cfg['sourceVerified'] is True and cfg['developmentOnly'] is (not production) and cfg['realRuntimeAccepted'] is production,'Static release-state binding')
    require(cfg['defaultRelease']=='drtv' and ('drtv' in cfg['releases']),'Static release catalog')
    if production:require(set(cfg['releases'])=={'drtv'},'Production fixture exclusion')
    name = 'drtv-release.json' if production else 'drtv-development.json'
    require(len(files[name])<=2*1024*1024 and len(json.loads(files[name])['payload'].encode())<=2*1024*1024,'Signed envelope size limit')
    release = verify_signed(root/name, trust)
    require(release['commonCertificate'] == trust['commonCertificate'], 'Signer binding')
    require(release['developmentOnly'] is (not production) and release['released'] is production and release['realRuntimeAccepted'] is production,'Signed release-state binding')
    require(release['package'] == 'io.github.nobewayo.drtvdark' and release['sourcePackage'] == 'dk.dr.tvplayer', 'Package binding')
    require(release['themeCorrections']['totalSites'] == 121, 'B14 theme count')
    updates = verify_updates(root/('updates.json' if production else 'updates-development.json'), trust, 0)
    require(updates['schema']==6 and updates['expiresAt']=='', 'Maintenance-free signed policy')
    require(updates['verification']['publicSigningSha256']==sha(files[name]), 'Update/envelope binding')
    return dict(status='PASS', production=production, assets=len(files), sri=len(refs),
                integritySha256=sha(files['integrity.json']), trustSha256=sha(files['trust.json']))


def approved(root, record, source=None):
    """source: the approved public source tree (the deploying checkout); always required."""
    require(record.get('schema') == 1 and record.get('approved') is True, 'Owner production approval absent')
    result = audit(root); require(result['production'], 'Development/rehearsal cannot publish')
    root = Path(root)
    for key in ('integritySha256','trustSha256'):
        require(result[key] == record[key], 'Approved '+key)
    trust = json.loads((root/'trust.json').read_bytes())
    require(trust['commonCertificate'] == record['certificateSha256'], 'Approved APK identity')
    require(sha(base64.b64decode(trust['releaseSpki'])) == record['metadataSpkiSha256'], 'Approved metadata identity')
    require(record['package']=='io.github.nobewayo.drtvdark', 'Approved package')
    data = record['releaseData']; check_envelope(verify_signed(root/'drtv-release.json',trust), data)
    from release_data import validate
    validate(data)
    require(data['release']['released'] and not data['release']['developmentOnly'], 'Production facts')
    require(sha((json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=False)).encode()) == record['releaseDataCanonicalSha256'], 'Approved release facts')
    from static_build import validate as material_check
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        material=Path(tmp)
        for n in ('trust.json','drtv-release.json','updates.json'):(material/n).write_bytes((root/n).read_bytes())
        data_path=material/'data.json';data_path.write_text(json.dumps(data))
        # Validator requires exactly the three public material files.
        with tempfile.NamedTemporaryFile(mode='w',suffix='.json') as f:
            json.dump(data,f);f.flush();data_path.unlink()
            material_check(material,record['trustSha256'],Path(f.name))
    require(re.fullmatch('[0-9a-f]{64}',record['sourceExportManifestSha256']), 'Audited source export pin')
    require(source is not None, 'Approved source tree required')
    from source_manifest import verify as verify_source, APPROVAL
    # Exact allowlisted files whose manifest is the pinned one; nothing added or changed.
    verify_source(source, record['sourceExportManifestSha256'], checkout=True)
    require(json.loads((Path(source)/APPROVAL).read_bytes()) == record, 'Approval record differs from the approved source tree')
    return result


def extract(archive, out, digest):
    archive=Path(archive);out=Path(out)
    require(archive.stat().st_size<=32*1024*1024 and sha(archive.read_bytes())==digest, 'Approved archive digest')
    require(not out.exists(), 'Fresh extraction directory')
    with zipfile.ZipFile(archive) as z:
        entries=z.infolist();require(0<len(entries)<=128,'Archive entry budget')
        require(len({e.filename for e in entries})==len(entries),'Duplicate archive paths')
        require(sum(e.file_size for e in entries)<=32*1024*1024,'Expansion budget')
        for e in entries:
            name=Path(e.filename);mode=e.external_attr>>16
            require(e.compress_type in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED) and not e.flag_bits&1,'Archive compression/encryption')
            require(e.orig_filename==e.filename and bool(name.parts),'Archive original path')
            require(not name.is_absolute() and '..' not in name.parts and '\\' not in e.filename and str(name)==e.filename,'Archive path')
            require(not e.is_dir() and stat.S_IFMT(mode) in (0,stat.S_IFREG),'Archive special file')
        out.mkdir(parents=True)
        for e in entries:
            p=out/e.filename;p.parent.mkdir(parents=True,exist_ok=True)
            total=0
            with z.open(e) as reader,p.open('wb') as writer:
                while True:
                    block=reader.read(65536)
                    if not block:break
                    total+=len(block);require(total<=e.file_size,'Entry expansion bound');writer.write(block)
            require(total==e.file_size,'Entry size')


def pack(root, destination):
    """Deterministic prebuilt artifact; packing does not authorize publication."""
    root=Path(root);destination=Path(destination)
    result=audit(root);require(not destination.exists(),'New static archive required')
    with zipfile.ZipFile(destination,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in sorted(root.rglob('*')):
            if not p.is_file():continue
            info=zipfile.ZipInfo(str(p.relative_to(root)),(1980,1,1,0,0,0))
            info.create_system=3;info.external_attr=0o100644<<16;info.compress_type=zipfile.ZIP_DEFLATED
            z.writestr(info,p.read_bytes(),compresslevel=9)
    return dict(sha256=sha(destination.read_bytes()),bytes=destination.stat().st_size,
                production=result['production'],publicationAuthorized=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifact',type=Path);p.add_argument('--archive',type=Path);p.add_argument('--extract',type=Path)
    p.add_argument('--approval',type=Path,default=Path('releases/publication-approval.json'))
    p.add_argument('--source',type=Path,required=True,help='Approved public source tree, normally the deploying checkout')
    a=p.parse_args()
    record=json.loads(a.approval.read_text())
    require(record.get('approved') is True,'Owner production approval absent; no deployment')
    if a.archive:extract(a.archive,a.extract,record['archiveSha256'])
    print(json.dumps(approved(a.extract if a.archive else a.artifact,record,a.source),sort_keys=True))
