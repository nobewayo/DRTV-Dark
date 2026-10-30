"""Derive the protected publication record from one audited production candidate.

Run only after the owner has accepted that exact candidate. The record binds the
deterministic static ZIP, its inventory, both public identities, the release facts and
the final public source export manifest, which deliberately excludes this record. With
the record placed in that export, the same gate the manual Pages workflow runs verifies
the exact source tree and static artifact together. Nothing is uploaded or deployed.
"""
if not __debug__: raise RuntimeError('Optimized Python is unsupported: security checks use assertions')
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parent))
from publication import approved, extract
from release_data import load


def sha(b): return hashlib.sha256(b).hexdigest()


def record(candidate, data_path, source):
    candidate = Path(candidate); site = candidate/'site'
    trust = json.loads((site/'trust.json').read_bytes()); data = load(data_path)
    return dict(schema=1, approved=True,
                archiveSha256=sha((candidate/'static-candidate.zip').read_bytes()),
                integritySha256=sha((site/'integrity.json').read_bytes()),
                trustSha256=sha((site/'trust.json').read_bytes()),
                certificateSha256=trust['commonCertificate'],
                metadataSpkiSha256=sha(base64.b64decode(trust['releaseSpki'])),
                package='io.github.nobewayo.drtvdark', releaseData=data,
                releaseDataCanonicalSha256=sha(json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()),
                sourceExportManifestSha256=sha((Path(source)/'EXPORT-MANIFEST.json').read_bytes()))


def check(candidate, value, source):
    """The workflow's exact path: pinned archive digest, bounded extraction, full gate."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)/'audited-static'
        extract(Path(candidate)/'static-candidate.zip', out, value['archiveSha256'])
        return approved(out, value, source)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate', type=Path, required=True); p.add_argument('--data', type=Path, required=True)
    p.add_argument('--source', type=Path, required=True, help='Final public source export; its manifest excludes the approval record')
    p.add_argument('--write', type=Path, help='Write the record (normally releases/publication-approval.json), then re-export and run without --write')
    a = p.parse_args()
    value = record(a.candidate, a.data, a.source)
    if a.write:
        a.write.write_text(json.dumps(value, indent=2, ensure_ascii=False)+'\n')
        print(json.dumps(dict(written=str(a.write), sourceExportManifestSha256=value['sourceExportManifestSha256'], archiveSha256=value['archiveSha256'])))
    else:
        result = check(a.candidate, value, a.source)
        print(json.dumps(dict(gate=result['status'], archiveSha256=value['archiveSha256'], integritySha256=value['integritySha256'],
                              sourceExportManifestSha256=value['sourceExportManifestSha256'], certificateSha256=value['certificateSha256'])))
