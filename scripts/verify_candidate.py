"""Current v1 payload, signature, trust, coverage and rollback gates; no historical APK."""
if not __debug__:
    raise RuntimeError('Optimized Python is unsupported')
import argparse
import copy
import json
from pathlib import Path
import tempfile
import zipfile
from product_common import ROOT, BT, run, sha, save
from release_data import verify_signed, check_envelope, check_updates, embedded, load
from update_metadata import verify, eligible
from product_baseline import load as accepted
from theme_maintenance import sites


def verify_candidate(folder, originals):
    folder=Path(folder);originals=Path(originals)
    reference,_,_,_=accepted();assert len(sites())==121
    trust=json.loads((folder/'trust.json').read_bytes())
    release=verify_signed(folder/'release.json',trust)
    data=load(folder/'release-data.json');check_envelope(release,data)
    updates=verify(folder/'updates.json',trust,data['release']['sequence'])
    check_updates(updates,(folder/'release.json').read_bytes(),data)
    assert release['package']==reference['applicationPackage'] and release['sourcePackage']==reference['source']['package']
    assert release['themeCorrections']['totalSites']==121 and len(release['themeCorrections']['sites'])==11
    config=embedded(release)
    assert config['releaseSpki']==trust['releaseSpki'] and config['commonCertificate']==trust['commonCertificate']
    assert config['website']==updates['website'] and config['diagnostics'] is False
    assert updates['expiresAt']==''
    checked=0
    with zipfile.ZipFile(folder/'drtv-dark.apks') as outer:
        for role,name in [('base','base.apk'),('split','split_config.xhdpi.apk')]:
            path=folder/'signed'/name;assert outer.read(name)==path.read_bytes()
            assert sha(path.read_bytes())==release['signatures'][role]['signedSha256']==updates['upgrade']['target'][role+'Sha256']
            signature=run([BT/'apksigner','verify','--verbose','--print-certs','--min-sdk-version','24',path]).stdout.decode()
            assert trust['commonCertificate'] in signature and 'Verified using v2 scheme (APK Signature Scheme v2): true' in signature
            run([BT/'zipalign','-c','-P','16','4',path])
            with zipfile.ZipFile(path) as z:
                assert len(z.namelist())==len(set(z.namelist())) and set(z.namelist())==set(reference['payloads'][role])
                for n,digest in reference['payloads'][role].items():
                    if n=='assets/drtv-dark-release.json':
                        assert json.loads(z.read(n))==config
                    else:
                        assert sha(z.read(n))==digest, 'Accepted authored payload drift: '+role+':'+n
                    checked+=1
    # An independently varied installed state exercises signer, identity and rollback.
    value=copy.deepcopy(updates);value['released']=True
    origin=value['upgrade']['from'][0] if value['upgrade']['from'] else dict(sequence=value['sequence']-1,darkVersion='fixture',originalVersionCode=439000,originalVersionName='4.39.0')
    installed=dict(origin,package=release['package'],sourcePackage=release['sourcePackage'],commonCertificate=trust['commonCertificate'])
    assert eligible(value,installed)==bool(value['upgrade']['from'])
    value['sequence']+=1;value['verification']['sequence']=value['sequence'];value['upgrade']['sequence']=value['sequence']
    installed.update(sequence=updates['sequence'],darkVersion=updates['darkVersion'])
    value['darkVersion']='fixture-next';value['upgrade']['target']['darkVersion']='fixture-next'
    value['upgrade']['from']=[{k:installed[k] for k in ('sequence','darkVersion','originalVersionCode','originalVersionName')}]
    assert eligible(value,installed)
    for bad in ({'commonCertificate':'0'*64},{'package':'dk.dr.tvplayer'},{'sequence':value['sequence']}):
        assert not eligible(value,{**installed,**bad})
    assert not eligible(value,installed,highest=value['sequence']+1)
    # Reconstruct in separate scratch; never overwrite the inspected output.
    with tempfile.TemporaryDirectory(prefix='verify-',dir=ROOT/'work') as tmp:
        scratch=Path(tmp)
        for n in ('trust.json','release.json'):(scratch/n).write_bytes((folder/n).read_bytes())
        run(['node',ROOT/'scripts/reconstruct.mjs',scratch,originals/'base.apk',originals/'split_config.xhdpi.apk'])
        assert (scratch/'drtv-dark.apks').read_bytes()==(folder/'drtv-dark.apks').read_bytes(), 'Deterministic browser reconstruction'
        transaction=json.loads((scratch/'browser-transaction.json').read_bytes())
        assert {s['id'] for s in transaction['darkSites']}=={s['id'] for s in sites()}
        assert all(s['applied'] and s['postPatch']['verified'] for s in transaction['darkSites'])
    return dict(status='PASS',payloads=checked,sites=121,apkV2=True,deterministic=True,
                equivalentAcceptedPayloads=True,productionByteEqualityClaimed=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--release',type=Path,required=True)
    p.add_argument('--original-dir',type=Path,required=True);p.add_argument('--report',type=Path)
    a=p.parse_args();result=verify_candidate(a.release,a.original_dir)
    if a.report:assert not a.report.exists();save(a.report,result)
    print(json.dumps(result))
