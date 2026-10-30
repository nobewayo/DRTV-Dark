"""Sign externally supplied schema6 update data using the existing offline adapter."""
if not __debug__:
    raise RuntimeError('Optimized Python is unsupported')
import argparse
import json
import os
from pathlib import Path
from signing import load, sign
from update_metadata import validate_upgrade, verify
from product_common import save


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--profile',type=Path,required=True);p.add_argument('--input',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--previous-sequence',type=int,required=True)
    a=p.parse_args();assert not a.out.exists() and not os.environ.get('DRTV_SIGNING_PROFILE')
    state=load(a.profile);os.environ['DRTV_SIGNING_PROFILE']=str(a.profile.resolve())
    value=json.loads(a.input.read_bytes());assert value['schema']==6 and value['sequence']>a.previous_sequence>=0
    assert value['commonCertificate']==state['trust']['commonCertificate'];validate_upgrade(value)
    if state['profile']['mode']=='rehearsal':assert value['released'] is False, 'Test metadata cannot be released'
    # Verify the complete schema with the same public verifier before publishing output.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path=Path(tmp)/'signed.json';save(path,sign(value));verify(path,state['trust'],a.previous_sequence+1)
        a.out.write_bytes(path.read_bytes())
    print('PASS signed schema6 metadata; no deployment')


if __name__=='__main__':main()
