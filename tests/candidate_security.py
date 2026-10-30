"""Focused identity, signature and sequence negatives, with disposable keys only."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from release_data import verify_signed
from update_metadata import verify
from cryptography.exceptions import InvalidSignature

folder=Path(sys.argv[1]);profile=Path(sys.argv[2])
trust=json.loads((folder/'trust.json').read_bytes())
assert trust['developmentOnly'] is True, 'Disposable rehearsal only'
results={}
def rejected(label,call):
    try:call()
    except (AssertionError,ValueError,InvalidSignature):results[label]='REJECTED';return
    raise RuntimeError('Accepted '+label)
with tempfile.TemporaryDirectory() as tmp:
    tmp=Path(tmp)
    for name,verify_fn in [('release.json',lambda p:verify_signed(p,trust)),('updates.json',lambda p:verify(p,trust,0))]:
        value=json.loads((folder/name).read_bytes());value['signature']='A'+value['signature'][1:] if value['signature'][0]!='A' else 'B'+value['signature'][1:]
        bad=tmp/name;bad.write_text(json.dumps(value));rejected(name+' signature',lambda:verify_fn(bad))
    rejected('metadata rollback',lambda:verify(folder/'updates.json',trust,2147483647))
    p=json.loads(profile.read_bytes())
    for field in ('certificateSha256','metadataSpkiSha256'):
        value=copy.deepcopy(p);value[field]='0'*64;bad=tmp/(field+'.json');bad.write_text(json.dumps(value))
        code="import sys;sys.path.insert(0,'scripts');from signing import load\ntry:load(sys.argv[1])\nexcept AssertionError as e:\n assert str(e)=='External identity pin mismatch';sys.exit(17)\n"
        result=subprocess.run([sys.executable,'-B','-c',code,str(bad)],capture_output=True)
        assert result.returncode==17, 'Wrong rejection reason or accepted identity: '+field
        results[field]='REJECTED'
print(json.dumps(results,indent=2))
