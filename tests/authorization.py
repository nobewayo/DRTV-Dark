"""Unsigned authorization fixtures only; never loads a private key or signs a release."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
tool=ROOT/'scripts/authorize.py'
with tempfile.TemporaryDirectory() as tmp:
    tmp=Path(tmp)
    data=json.loads((ROOT/'releases/drtv-dark-v1.json').read_bytes())
    data['release'].update(id='authorization-fixture-only',darkVersion='999',sequence=33)
    data['release']['changes'][0]['version']='999'
    facts=tmp/'fixture-data.json';facts.write_text(json.dumps(data))
    origins=[dict(sequence=32,darkVersion='1',originalVersionCode=439000,originalVersionName='4.39.0')]
    source=tmp/'origins.json';source.write_text(json.dumps(origins))
    base=[sys.executable,'-B',str(tool),'--data',str(facts),'--trust',str(ROOT/'maintenance/4.39.0/trust.json')]
    def execute(name,rows=None):
        out=tmp/(name+'.json');args=base+['--out',str(out)]
        if rows is not None:source.write_text(json.dumps(rows));args+=['--upgrade-from',str(source)]
        result=subprocess.run(args,capture_output=True)
        return result,out
    r,out=execute('missing');assert r.returncode!=0 and not out.exists()
    r,out=execute('preserved-v1',origins);assert r.returncode==0
    assert json.loads(out.read_bytes())['upgradeFrom']==origins
    for label,rows in [('empty',[]),('duplicate',origins*2),('wrong-version',[{**origins[0],'darkVersion':'other'}]),('rollback',[{**origins[0],'sequence':33}])]:
        r,out=execute(label,rows);assert r.returncode!=0 and not out.exists(),label
print('PASS explicit v1 predecessor retained; missing, empty, duplicate, wrong predecessor and rollback rejected; no signing')
