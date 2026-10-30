"""Write an explicit offline build authorization with reviewed predecessor identities.

The record binds the exact release-data bytes, the public trust bytes exported from the
permanent identities, the approved website and native endpoint, and an explicit schema6
predecessor list (empty only for the first production installation). It authorizes building
and signing one candidate offline; publication needs releases/publication-approval.json.
"""
if not __debug__: raise RuntimeError('Optimized Python is unsupported: security checks use assertions')
import argparse
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_data import load, is_public

WEBSITE = 'https://nobewayo.github.io/DRTV-Dark/'
ENDPOINT = 'https://nobewayo.github.io/DRTV-Dark/updates.json'


def sha(b): return hashlib.sha256(b).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data', type=Path, required=True); p.add_argument('--trust', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--upgrade-from',type=Path,help='Explicit reviewed schema6 predecessor list; required after v1')
    a = p.parse_args()
    data = load(a.data); assert is_public(data), 'Approved public release facts required'
    trust_raw = a.trust.read_bytes(); trust = json.loads(trust_raw)
    assert trust['schema'] == 3 and trust['developmentOnly'] is False, 'Production public trust required'
    assert trust_raw == (json.dumps(trust, indent=2, ensure_ascii=False)+'\n').encode(), 'Canonical adapter trust export required'
    assert not a.out.exists(), 'New authorization record required'
    origins=json.loads(a.upgrade_from.read_bytes()) if a.upgrade_from else []
    assert isinstance(origins,list) and len(origins)<=32
    from release_data import TEXT
    for item in origins:
        assert set(item)=={'sequence','darkVersion','originalVersionName','originalVersionCode'}
        assert type(item['sequence']) is int and data['release']['minInstalledSequence']<=item['sequence']<data['release']['sequence']
        assert TEXT.fullmatch(item['darkVersion']) and TEXT.fullmatch(item['originalVersionName'])
        assert type(item['originalVersionCode']) is int and 1<=item['originalVersionCode']<=2147483647
    assert len({json.dumps(item,sort_keys=True) for item in origins})==len(origins)
    if data['release']['sequence']>32:
        assert a.upgrade_from, 'Explicit reviewed predecessors required after v1'
        assert dict(sequence=32,darkVersion='1',originalVersionName='4.39.0',originalVersionCode=439000) in origins, 'Preserve v1 update path'
    record = dict(schema=1, approved=True, releaseDataSha256=sha(a.data.read_bytes()), trustSha256=sha(trust_raw),
                  website=WEBSITE, endpoint=ENDPOINT, upgradeFrom=origins)
    a.out.write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(dict(authorization=str(a.out), authorizationSha256=sha(a.out.read_bytes()),
                          certificateSha256=trust['commonCertificate'], releaseId=data['release']['id'])))


if __name__ == '__main__': main()
