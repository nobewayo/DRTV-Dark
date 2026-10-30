"""Conservative source comparison. A report never admits or migrates an APK."""
if not __debug__:
    raise RuntimeError('Optimized Python is unsupported')
import argparse
from collections import Counter
import json
import struct
from pathlib import Path
import sys
import zipfile
from product_common import ROOT, run, save, sha
from product_baseline import load, DIRECTORY
sys.path.insert(0, str(ROOT/'tools'))
from resources import Table, xml_values


def descriptors():
    _, _, release, _ = load()
    recipe = json.loads((ROOT/'site/recipe.json').read_bytes())
    return [('recipe', i, s) for i, s in enumerate(recipe['sites'])] + [
        ('release', i, s) for i, s in enumerate(release['themeCorrections']['sites'])]


def sites():
    value = json.loads((DIRECTORY/'theme-sites.json').read_bytes())
    rows = descriptors()
    assert value['schema'] == 1 and len(value['sites']) == len(rows) == 121
    for record, (origin, index, descriptor) in zip(value['sites'], rows):
        assert record['id'] == descriptor['id'] and record['file'] == descriptor['file']
        assert record['descriptor'] == dict(document=origin, index=index, sha256=sha(
            json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode()))
    return value['sites']


def read_apk(path):
    """Bound inspection of untrusted candidate ZIPs; never extract or execute them."""
    path = Path(path)
    assert 0 < path.stat().st_size <= 128*1024*1024, 'APK size budget'
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        assert len(names) == len(set(names)) <= 10000, 'Duplicate/too many entries'
        assert sum(i.file_size for i in z.infolist()) <= 256*1024*1024, 'Expansion budget'
        for i in z.infolist():
            assert i.file_size <= 64*1024*1024 and not i.flag_bits & 1
            assert not i.filename.startswith('/') and '..' not in Path(i.filename).parts and '\\' not in i.filename
        return {n: z.read(n) for n in names}


def compare(previous, candidate):
    """Only complete identical owner bytes qualify as unchanged/relocated.

    Partial method/resource matches deliberately remain review-required. Even a
    relocated identical file is a candidate, never automatic selector acceptance.
    """
    records = sites()
    by_hash = {}
    for name, content in candidate.items():
        by_hash.setdefault(sha(content), []).append(name)
    results = []
    for site in records:
        name = site['file']; expected = site['sourceFileSha256']
        assert name in previous and sha(previous[name]) == expected, 'Wrong predecessor owner: '+name
        if name in candidate and sha(candidate[name]) == expected:
            status, matches = 'unchanged', [name]
        else:
            matches = [n for n in by_hash.get(expected, []) if Path(n).suffix == Path(name).suffix]
            if name not in candidate and len(matches) == 1:
                status = 'relocated-candidate'
            elif name in candidate or matches:
                status = 'modified-or-ambiguous'
            else:
                status = 'missing'
        results.append(dict(id=site['id'], owner=site['owner'], file=name, status=status,
                            candidates=matches, action='Validate authenticated selector' if status == 'unchanged'
                            else 'Review ownership and exact selector; no migration accepted'))
    structural, artwork, parse_errors = [], [], []
    def bright(typ, data):
        if typ not in (28,29,30,31): return False
        if typ == 31: rgb = [(data & 15)*17]*3
        elif typ == 30: rgb = [((data >> n) & 15)*17 for n in (8,4,0)]
        else: rgb = [(data >> n) & 255 for n in (16,8,0)]
        return min(rgb) >= 200
    def inspect(name, content):
        if name == 'resources.arsc':
            table = Table(content)
            refs = {v.resource_id:v for v in table.values if v.attribute is None}
            def pale(v):
                seen=set()
                while v.type==1 and v.data in refs and v.data not in seen:
                    seen.add(v.data);v=refs[v.data]
                return bright(v.type,v.data)
            return [(v.name, v.config, v.attribute) for v in table.values if pale(v) and
                    (v.attribute in (0x10100d4,0x1010054) or v.name.startswith('color/bg_'))]
        if name.startswith('res/') and name.endswith('.xml'):
            values=xml_values(content)
            if any(v['element']=='vector' for v in values): return []
            return [(v['path'],v['attribute'],v['data']) for v in values if v['attribute'] in
                    (0x10100d4,0x1010054) and bright(v['type'],v['data'])]
        return []
    for name, content in candidate.items():
        if name.endswith(('.png','.jpg','.jpeg','.webp','.webm','.svg')):
            if previous.get(name) != content: artwork.append(name)
            continue
        if previous.get(name) == content: continue
        try:
            if name.startswith('res/') and name.endswith('.xml') and any(v['element']=='vector' for v in xml_values(content)):
                artwork.append(name)
                continue
            old = set(inspect(name,previous[name])) if name in previous else set()
            for target in inspect(name,content):
                if target not in old: structural.append(dict(file=name, selector=target, action='Review structural bright surface'))
        except (ValueError,AssertionError,IndexError,KeyError,UnicodeError,struct.error) as e:
            parse_errors.append(dict(file=name,error=type(e).__name__,action='Manual inspection required'))
    return dict(schema=1, admissionGranted=False, automaticMigration=False,
                counts=dict(Counter(v['status'] for v in results)), sites=results,
                potentialBrightStructure=structural, contentOrArtworkDoNotRecolor=artwork,
                inspectionErrors=parse_errors,
                limitations=['Conservative whole-owner matching; changed owners always require review.',
                             'Static backgrounds only; server artwork and runtime-created UI require later owner testing.',
                             'No candidate official version is supported by generating this report.'])


def inspect_apk(path):
    entries = read_apk(path)
    signature = run([__import__('product_common').BT/'apksigner','verify','--print-certs',path], check=False)
    badging = run([__import__('product_common').BT/'aapt2','dump','badging',path], check=False)
    return dict(sha256=sha(Path(path).read_bytes()), entries=len(entries),
                signatureValid=signature.returncode == 0, signature=signature.stdout.decode(errors='replace'),
                manifestValid=badging.returncode == 0,
                manifest=badging.stdout.decode(errors='replace').splitlines()[:3], admissionGranted=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--previous',type=Path);p.add_argument('--candidate',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    assert not a.out.exists(), 'Fresh report path required'
    report=inspect_apk(a.candidate)
    if a.previous:
        baseline,_,release,_=load()
        allowed=[f['sha256'] for s in release['sources'] for f in s['files'] if f['role']=='base']
        assert sha(a.previous.read_bytes()) in allowed, 'Predecessor must be exact admitted original'
        report.update(compare(read_apk(a.previous),read_apk(a.candidate)))
    save(a.out,report)
    lines=['# Official-source inspection (no admission or migration)', '',
           'Candidate SHA-256: '+report['sha256'], '', 'Signature valid: '+str(report['signatureValid'])]
    if a.previous:
        lines += ['', 'Site status: '+json.dumps(report['counts']), '',
                  '| Site | Owner | Status |', '|---|---|---|']
        lines += [f"| {s['id']} | {s['owner']} | {s['status']} |" for s in report['sites'] if s['status']!='unchanged']
        lines += ['', 'Potential new bright structural sites: '+str(len(report['potentialBrightStructure'])),
                  'Changed content/artwork excluded from recoloring: '+str(len(report['contentOrArtworkDoNotRecolor'])),
                  'Inspection errors requiring review: '+str(len(report['inspectionErrors']))]
    a.out.with_suffix('.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({k:report[k] for k in ('sha256','signatureValid','admissionGranted')} | {'counts':report.get('counts',{})}))


if __name__=='__main__':main()
