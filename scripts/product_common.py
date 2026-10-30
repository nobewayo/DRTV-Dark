"""Offline product tooling. Standard subprocesses, explicit external identities only."""
if not __debug__:
    raise RuntimeError('Optimized Python is unsupported')
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
SDK=Path(os.environ.get('ANDROID_SDK_ROOT',str(Path.home()/'Android/Sdk')))
BT=SDK/'build-tools/35.0.0'
ANDROID=SDK/'platforms/android-35/android.jar'


def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n')


def run(argv,*,cwd=ROOT,check=True,log=None,env=None):
    result=subprocess.run(list(map(str,argv)),cwd=cwd,env=env,capture_output=True)
    record=dict(argv=list(map(str,argv)),exit=result.returncode,
                stdout=result.stdout.decode(errors='replace'),stderr=result.stderr.decode(errors='replace'))
    if log is not None:log.append(record)
    if check and result.returncode:raise RuntimeError(record)
    return result


def key_paths():
    from signing import load
    state=load();return state['key'],state['cert']


def sign_envelope(value):
    from signing import sign
    return sign(value)
