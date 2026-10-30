"""Stable product maintenance commands. No upload, deployment or permanent-key generation."""
if not __debug__:
    raise RuntimeError('Optimized Python is unsupported')
import argparse
import json
import os
from pathlib import Path
from product_common import ROOT, run, save, sha


def candidate(a):
    from release_builder import build
    from signing import load, exclude_private
    from product_baseline import load as baseline
    from verify_candidate import verify_candidate
    assert not os.environ.get('DRTV_SIGNING_PROFILE'), 'Use explicit profile'
    out=a.out.resolve();assert out.is_relative_to(ROOT/'work') and not out.exists()
    data_path=a.data or ROOT/'maintenance/rehearsal.json'
    from release_data import load as release_data
    data=release_data(data_path)
    if a.mode=='production':
        assert a.profile and a.approval and a.approval_sha256, 'Explicit external identities and authorization required'
        reference,trust,_,_=baseline()
        # Never rebuild the immutable approved v1, nor regress the release sequence.
        assert data['release']['sequence']>reference['acceptedSequence'], 'Approved v1 is immutable; production sequence must increase'
        assert data['release']['minInstalledSequence']<=reference['acceptedSequence'], 'Preserve installed v1 update eligibility'
        from signing import authorize
        profile=load(a.profile)
        assert profile['profile']['mode']=='production'
        assert profile['trust']['commonCertificate']==trust['commonCertificate'], 'Compatible production APK identity required'
        assert profile['trust']['releaseSpki']==trust['releaseSpki'], 'Existing metadata trust required'
        authorization=authorize(data_path,a.approval,a.approval_sha256)
        predecessor=dict(sequence=32,darkVersion='1',originalVersionCode=439000,originalVersionName='4.39.0')
        assert predecessor in authorization['upgradeFrom'], 'Explicit compatible v1 predecessor required'
    else:
        assert not a.approval and not a.approval_sha256 and not data['release']['released']
        if a.profile:
            profile=load(a.profile);assert profile['profile']['mode']=='rehearsal'
    out.mkdir(parents=True)
    if a.mode=='rehearsal' and not a.profile:
        from rehearsal_identity import create
        a.profile=create(out/'private')
    build(out/'release',data_path,a.identity_plan,theme_corrections=True,b14=True,profile=a.profile,
          authorization=a.approval,authorization_sha256=a.approval_sha256,original_dir=a.original_dir)
    result=verify_candidate(out/'release',a.original_dir)
    result['keyExclusion']=exclude_private([out/'release'])
    save(out/'verification.json',result)
    print(json.dumps(result))


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    q=sub.add_parser('candidate',help='Build and independently verify current admitted source')
    q.add_argument('--mode',choices=['rehearsal','production'],required=True)
    q.add_argument('--out',type=Path,required=True);q.add_argument('--original-dir',type=Path,required=True)
    for name in ('data','profile','approval','identity-plan'):q.add_argument('--'+name,type=Path)
    q.add_argument('--approval-sha256')
    q=sub.add_parser('inspect');q.add_argument('--candidate',type=Path,required=True);q.add_argument('--out',type=Path,required=True)
    q=sub.add_parser('compare');q.add_argument('--previous',type=Path,required=True);q.add_argument('--candidate',type=Path,required=True);q.add_argument('--out',type=Path,required=True)
    q=sub.add_parser('verify');q.add_argument('--release',type=Path,required=True);q.add_argument('--original-dir',type=Path,required=True)
    q=sub.add_parser('export');q.add_argument('--out',type=Path,required=True)
    q=sub.add_parser('publication');q.add_argument('--source',type=Path,required=True);q.add_argument('--archive',type=Path,required=True);q.add_argument('--extract',type=Path,required=True);q.add_argument('--approval',type=Path,required=True)
    a=p.parse_args()
    if a.command=='candidate':candidate(a)
    elif a.command in ('inspect','compare'):
        args=['python3','-B',ROOT/'scripts/theme_maintenance.py','--candidate',a.candidate,'--out',a.out]
        if a.command=='compare':args+=['--previous',a.previous]
        print(run(args).stdout.decode())
    elif a.command=='verify':
        from verify_candidate import verify_candidate
        print(json.dumps(verify_candidate(a.release,a.original_dir)))
    elif a.command=='export':
        from source_manifest import export
        print(json.dumps(export(ROOT,a.out)))
    elif a.command=='publication':
        from publication import extract,approved
        record=json.loads(a.approval.read_bytes());extract(a.archive,a.extract,record['archiveSha256'])
        print(json.dumps(approved(a.extract,record,a.source)))


if __name__=='__main__':main()
