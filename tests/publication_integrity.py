"""Publication gate: the exact approved source tree and static artifact pass together;
any altered or mismatched artifact, source tree, identity or record is rejected.
Usage: publication_integrity.py STATIC_ARCHIVE FINAL_SOURCE_EXPORT_DIR"""
if not __debug__: raise RuntimeError('Optimized Python is unsupported: security checks use assertions')
import copy
import hashlib
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from approval_record import record, check
from publication import approved, extract
from source_manifest import APPROVAL

source = Path(sys.argv[2]).resolve()
archive = Path(sys.argv[1]).resolve()
workspace = tempfile.TemporaryDirectory(prefix='publication-test-')
candidate = Path(workspace.name)
shutil.copyfile(archive, candidate/'static-candidate.zip')
initial = json.loads((source/APPROVAL).read_bytes())
extract(archive, candidate/'site', initial['archiveSha256'])
data = Path(__file__).resolve().parents[1]/'releases/drtv-dark-v1.json'
good = record(candidate, data, source)
assert json.loads((source/APPROVAL).read_bytes()) == good, 'Final source export must carry the exact record'
assert check(candidate, good, source)['status'] == 'PASS'
results = {'exact source tree and static artifact': 'PASS'}

def rejected(name, operation):
    try: operation()
    except (ValueError, AssertionError, KeyError, FileNotFoundError, json.JSONDecodeError) as e:
        results[name] = 'REJECTED: '+type(e).__name__; return
    raise RuntimeError('Gate accepted: '+name)

other_digest = hashlib.sha256(b'a different but well-formed source export').hexdigest()
for field, value in [('approved', False), ('archiveSha256', '0'*64), ('integritySha256', '0'*64), ('trustSha256', '0'*64),
                     ('certificateSha256', '0'*64), ('metadataSpkiSha256', '0'*64), ('package', 'dk.dr.tvplayer'),
                     ('releaseDataCanonicalSha256', '0'*64), ('sourceExportManifestSha256', 'not-a-digest'),
                     ('sourceExportManifestSha256', other_digest)]:
    bad = dict(good, **{field: value})
    rejected('record %s=%s' % (field, str(value)[:12]), lambda: check(candidate, bad, source))
bad = copy.deepcopy(good); bad['releaseData']['release']['darkVersion'] = '2'
rejected('record altered release facts', lambda: check(candidate, bad, source))
rejected('no approved source tree', lambda: check(candidate, good, None))

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    def changed(label, mutate):
        root = tmp/label.replace(' ', '-')/'source'; shutil.copytree(source, root)
        before = {q.relative_to(root): q.read_bytes() for q in root.rglob('*') if q.is_file()}
        mutate(root)
        assert before != {q.relative_to(root): q.read_bytes() for q in root.rglob('*') if q.is_file()}, 'Mutation had no effect: '+label
        return root
    # A deploying checkout may contain .git and nothing else extra.
    git = changed('checkout with git metadata', lambda r: ((r/'.git').mkdir(), (r/'.git/HEAD').write_text('ref: refs/heads/main\n')))
    assert check(candidate, good, git)['status'] == 'PASS'; results['checkout with .git'] = 'PASS'
    def regenerated(r):
        (r/'LICENSE').write_text('x'); v = json.loads((r/'EXPORT-MANIFEST.json').read_text())
        v['files']['LICENSE'] = hashlib.sha256(b'x').hexdigest()
        (r/'EXPORT-MANIFEST.json').write_text(json.dumps(v, sort_keys=True, indent=2)+'\n')
    for label, mutate in [
        ('source file modified', lambda r: (r/'site/app.mjs').write_text((r/'site/app.mjs').read_text()+'\n')),
        ('workflow modified', lambda r: (r/'.github/workflows/pages-manual.yml').write_text((r/'.github/workflows/pages-manual.yml').read_text().replace('ubuntu-24.04', 'ubuntu-latest', 1))),
        ('extra source file', lambda r: (r/'scripts/extra.py').write_text('print(1)\n')),
        ('source file removed', lambda r: (r/'LICENSE').unlink()),
        ('different approval record in tree', lambda r: (r/APPROVAL).write_text(json.dumps(dict(good, integritySha256='1'*64), indent=2)+'\n')),
        ('manifest regenerated for altered tree', regenerated),
    ]:
        root = changed(label, mutate)
        rejected('source '+label, lambda: check(candidate, good, root))

    def altered(label, mutate):
        site = tmp/label.replace(' ', '-')/'site'; shutil.copytree(candidate/'site', site)
        before = {q.relative_to(site): q.read_bytes() for q in site.rglob('*') if q.is_file()}
        mutate(site)
        assert before != {q.relative_to(site): q.read_bytes() for q in site.rglob('*') if q.is_file()}, 'Mutation had no effect: '+label
        rejected('artifact '+label, lambda: approved(site, good, source))
    altered('config.json processing flag', lambda s: (s/'config.json').write_text((s/'config.json').read_text().replace('"processingEnabled": true', '"processingEnabled": false')))
    altered('index.html byte', lambda s: (s/'index.html').write_text((s/'index.html').read_text().replace('</body>', ' </body>')))
    altered('extra file', lambda s: (s/'extra.txt').write_text('x'))
    def resign(s):
        v = json.loads((s/'updates.json').read_text()); v['signature'] = ('B' if v['signature'][0] == 'A' else 'A')+v['signature'][1:]
        (s/'updates.json').write_text(json.dumps(v))
    altered('updates.json signature', resign)
    altered('trust identity modified', lambda s: (s/'trust.json').write_text((s/'trust.json').read_text().replace(good['certificateSha256'], '0'*64)))
    z = tmp/'repacked.zip'
    with zipfile.ZipFile(candidate/'static-candidate.zip') as src, zipfile.ZipFile(z, 'w') as dst:
        for info in src.infolist(): dst.writestr(info, src.read(info))
        dst.writestr('extra.txt', 'x')
    rejected('repacked archive', lambda: extract(z, tmp/'x', good['archiveSha256']))
print(json.dumps(results, indent=1))
print('PASS publication gate: exact source and artifact accepted, %d mismatches rejected' % sum(v.startswith('REJECTED') for v in results.values()))
