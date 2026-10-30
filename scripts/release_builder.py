"""Independent coexistence construction with B13/B14 theme extensions; no publication.

Requires bsdiff4==1.2.6 only on the offline build host. Browser outputs contain no
dependency, private key or standalone original/modified APK/DEX payload.
"""
if not __debug__:
    raise RuntimeError('Optimized Python is unsupported for release validation')
import argparse,base64,copy,json,os,struct,sys,zipfile
from pathlib import Path
from product_common import ROOT,BT,ANDROID,sha,canonical,save,run,sign_envelope,key_paths
import release_data as R
from delta import make_delta,decode
from update_metadata import verify as verify_metadata
sys.path.insert(0,str(ROOT/'tools'))
from coexistence import OLD,DARK,patch_xml,patch_arsc,isolate_filters
from resources import xml_values

def checked(args,log):
    r=run(args,log=log);return r.stdout

def build(out,data_path,cached_plan=None,*,theme_corrections=False,b14=False,profile=None,authorization=None,authorization_sha256=None,baseline_material=None,original_dir=None):
    out=out.resolve();assert out.is_relative_to(ROOT/'work') and not out.exists(), 'Fresh ignored work output required'
    data=R.load(data_path);assert data.get('application')=={'package':DARK,'distribution':'coexistence'}
    approval=None;external=None
    if profile:
        assert b14
        os.environ['DRTV_SIGNING_PROFILE']=str(profile.resolve())
        from signing import load,authorize
        external=load()
        if external['profile']['mode']=='production':
            assert R.is_public(data) and authorization and authorization_sha256,'Production approval inputs required'
            approval=authorize(data_path,authorization,authorization_sha256)
        else:assert data['release']['developmentOnly'] and not data['release']['released']
    else:
        assert not os.environ.get('DRTV_SIGNING_PROFILE'),'Explicit external profile required'
        assert data['release']['developmentOnly'] and not data['release']['released']
    assert data['original']=={'package':OLD,'versionName':'4.39.0','versionCode':439000}
    out.mkdir(parents=True,exist_ok=False);log=[]
    save(out/'release-data.json',data)
    assert baseline_material is None, 'Use versioned accepted material, not historical templates'
    from product_baseline import construction_seed
    baseline,trust,current_template=construction_seed()
    assert baseline['package']==OLD and baseline['commonCertificate']==trust['commonCertificate']
    R.check_seed(baseline,data)
    if external:trust=external['trust']
    save(out/'trust.json',trust)
    seed=copy.deepcopy(baseline);seed.pop('signatures',None)
    save(out/'baseline-seed.json',seed)
    original_dir=Path(original_dir) if original_dir else ROOT/'original'
    originals=[original_dir/'base.apk',original_dir/'split_config.xhdpi.apk']
    original_pins=[sha(p.read_bytes()) for p in originals]
    checked(['node',ROOT/'scripts/canonicalize.mjs',out/'baseline-seed.json',ROOT/'site/recipe.json',out/'baseline',*originals],log)
    source_dex=out/'identity-source.dex'
    with zipfile.ZipFile(out/'baseline/base.apk') as z:source_dex.write_bytes(z.read('classes4.dex'))
    # SDK dexlib only changes explicitly audited string references and field values.
    sdk=BT.parent.parent
    sdk_external=sdk/'cmdline-tools/latest/lib/external'
    patterns=['com/android/tools/smali/smali-dexlib2/3.0.9/*.jar','com/google/guava/guava/33.4.0-jre/*.jar',
              'com/google/guava/failureaccess/1.0.2/*.jar','com/google/code/findbugs/jsr305/3.0.2/*.jar']
    jars=[p for pattern in patterns for p in sorted(sdk_external.glob(pattern))]
    assert len(jars)==4,'Pinned SDK dexlib/Guava dependencies required'
    if b14:
        dependencies=json.loads((ROOT/'releases/build-dependencies.json').read_text())['files']
        for jar in jars:assert sha(jar.read_bytes())==dependencies[str(jar.relative_to(sdk_external))],'SDK dependency digest'
        assert sha((ROOT/'tools/apktool.jar').read_bytes())==dependencies['tools/apktool.jar'],'Apktool digest'
    (ROOT/'build/java').mkdir(parents=True,exist_ok=True)
    checked(['javac','-cp',ROOT/'tools/apktool.jar','-d',ROOT/'build/java',ROOT/'tools/DexIndex.java'],log)
    cp=':'.join(map(str,jars));(out/'java').mkdir()
    checked(['javac','-cp',cp,'-d',out/'java',ROOT/'tools/IdentityTransform.java'],log)
    dex_audit=checked(['java','-cp',cp+':'+str(out/'java'),'IdentityTransform',source_dex,out/'identity-target.dex',DARK,'--isolate-links'],log)
    (out/'identity-dex-audit.txt').write_bytes(dex_audit)
    assert b'PASS\t5 exact string constants' in dex_audit
    plan={'schema':1,'sourcePackage':OLD,'package':DARK,'files':{'base':{},'split':{}}}
    cache=json.loads(cached_plan.read_text()) if cached_plan else None
    audits={};expected={};theme=None
    for role,filename in [('base','base.apk'),('split','split_config.xhdpi.apk')]:
        with zipfile.ZipFile(out/'baseline'/filename) as z:
            targets={}
            source=z.read('AndroidManifest.xml');target,audit=patch_xml(source,labels=role=='base')
            if role=='base':target,links=isolate_filters(target);audit={'attributes':audit,'links':links}
            targets['AndroidManifest.xml']=target;audits[role+':manifest']=audit
            targets['resources.arsc']=patch_arsc(z.read('resources.arsc'),role=='base')
            if role=='base':
                targets['classes4.dex']=(out/'identity-target.dex').read_bytes()
                name='res/drawable/ic_drtv_background.xml';vector=z.read(name);values=xml_values(vector)
                fill=[v for v in values if v['path']=='vector/group/path' and v['attribute_name']=='fillColor']
                assert len(fill)==1 and (fill[0]['type'],fill[0]['data'])==(29,0xffff001e)
                vector=bytearray(vector);struct.pack_into('<I',vector,fill[0]['offset']+4,0xff242424)
                targets[name]=bytes(vector)
                png='res/mipmap-xhdpi-v4/ic_launcher.png'
                (out/'icon-source.png').write_bytes(z.read(png))
                script="import fs from 'node:fs/promises';import {recolorIcon} from './site/icon.mjs';const [a,b]=process.argv.slice(1);await fs.writeFile(b,await recolorIcon(new Uint8Array(await fs.readFile(a))));"
                checked(['node','--input-type=module','-e',script,out/'icon-source.png',out/'icon-target.png'],log)
                targets[png]=(out/'icon-target.png').read_bytes()
            if role=='base' and theme_corrections:
                from theme_hooks import extend
                theme=extend(out,targets,cp,log)
                if b14:
                    from theme_surfaces import extend as extend_b14
                    theme=extend_b14(targets,z,theme,out)
                save(out/'theme-corrections.json',theme)
            expected[role]={}
            for name,target in targets.items():
                source=z.read(name);expected[role][name]=sha(target)
                if source==target:continue
                if name.endswith('.png'):
                    spec={'encoding':'png-red-to-charcoal-v1','sourceSha256':sha(source),'targetSha256':sha(target),'sourceSize':len(source),'targetSize':len(target)}
                elif cache and name in cache['files'][role] and cache['files'][role][name]['targetSha256']==sha(target):
                    spec=cache['files'][role][name]
                    assert (spec['sourceSha256'],spec['targetSha256'])==(sha(source),sha(target))
                    import zlib
                    assert decode(source,zlib.decompress(base64.b64decode(spec['data'])))==target
                else:
                    spec,audit=make_delta(source,target);audits[role+':'+name]=audit
                plan['files'][role][name]=spec
    save(out/'identity-plan.json',plan);save(out/'identity-audit.json',audits)
    # Compile only authored notifier sources; embedded provenance still names DR TV.
    classes=out/'notifier-classes';dex=out/'notifier-dex';classes.mkdir();dex.mkdir()
    sources=sorted((ROOT/'notifier/src').rglob('*.java'))
    checked(['javac','--release','8','-cp',ANDROID,'-d',classes,*sources],log)
    checked([BT/'d8','--min-api','24','--lib',ANDROID,'--output',dex,*sorted(classes.rglob('*.class'))],log)
    R.apply(seed,data);seed.update(package=DARK,sourcePackage=OLD,identity=plan,realRuntimeAccepted=bool(approval),commonCertificate=trust['commonCertificate'])
    if external:seed['signingProfile']=external['profile']['mode']
    if theme:seed['themeCorrections']=theme
    for asset in seed['notifier']['assets']:
        if asset['name']=='classes7.dex':content=(dex/'classes.dex').read_bytes()
        else:
            assert asset['name']=='assets/drtv-dark-release.json'
            info=json.loads(base64.b64decode(asset['base64']));R.config(info,data)
            info.update(endpoint=approval['endpoint'] if approval else 'https://example.invalid/drtv-dark/updates.json',website=approval['website'] if approval else 'https://example.invalid/drtv-dark/',diagnostics=False,commonCertificate=trust['commonCertificate'],releaseSpki=trust['releaseSpki'])
            content=canonical(info).encode()
        asset.update(base64=base64.b64encode(content).decode(),size=len(content),sha256=sha(content))
    save(out/'seed.json',seed)
    checked(['node',ROOT/'scripts/canonicalize.mjs',out/'seed.json',ROOT/'site/recipe.json',out/'canonical',*originals],log)
    checked(['python3','-B',ROOT/'scripts/attach_signatures.py','--seed',out/'seed.json','--canonical',out/'canonical',
             '--out',out/'signed','--envelope',out/'release.json','--external-profile' if external else '--disposable-development'],log)
    release_bytes=(out/'release.json').read_bytes();assert len(release_bytes)<=2*1024*1024,'Existing envelope limit must remain'
    release=R.verify_signed(out/'release.json',trust);assert not R.check_envelope(release,data)
    checked(['node',ROOT/'scripts/reconstruct.mjs',out,*originals],log)
    # SDK checks are independent of the browser signature/hash implementation.
    files={};base_payloads={}
    with zipfile.ZipFile(out/'drtv-dark.apks') as outer:
        assert outer.testzip() is None
        for role,name in [('base','base.apk'),('split','split_config.xhdpi.apk')]:
            path=out/'signed'/name;assert outer.read(name)==path.read_bytes()
            for api in (24,30,36):
                sig=checked([BT/'apksigner','verify','--verbose','--print-certs','--min-sdk-version',str(api),'--max-sdk-version',str(api),path],log).decode()
                assert trust['commonCertificate'] in sig and 'Verified using v2 scheme (APK Signature Scheme v2): true' in sig
            checked([BT/'zipalign','-c','-P','16','4',path],log)
            badge=checked([BT/'aapt2','dump','badging',path],log).decode();assert "name='"+DARK+"'" in badge
            checked([BT/'aapt2','dump','resources',path],log)
            with zipfile.ZipFile(path) as z,zipfile.ZipFile(out/'baseline'/name) as old:
                assert set(z.namelist())==set(old.namelist())
                changed=[n for n in z.namelist() if z.read(n)!=old.read(n)]
                allowed=set(expected[role])|({'classes7.dex','assets/drtv-dark-release.json'} if role=='base' else set())
                assert set(changed)<=allowed
                for n,pin in expected[role].items():assert sha(z.read(n))==pin
                if role=='base':
                    config=json.loads(z.read('assets/drtv-dark-release.json'))
                    assert config['original']==data['original'] and config['applicationPackage']==DARK
                for n in changed:
                    if n.endswith('.xml'):checked([BT/'aapt2','dump','xmltree',path,'--file',n],log)
                files[role]={'sha256':sha(path.read_bytes()),'changedPayloads':sorted(changed),'v2Api24_30_36':True,'package':DARK}
    count=theme['totalSites'] if theme else 110
    transaction=json.loads((out/'browser-transaction.json').read_text());assert len(transaction['darkSites'])==count
    # Signed schema6 explicitly separates admitted source from installed target.
    current=copy.deepcopy(current_template);r=data['release'];sequence=r['sequence']
    current.update(sequence=sequence,darkVersion=r['darkVersion'],minInstalledSequence=r['minInstalledSequence'],releaseDate=r['releaseDate'],
                   released=data['release']['released'],commonCertificate=trust['commonCertificate'],website=approval['website'] if approval else 'https://example.invalid/drtv-dark/',artifactsVerified=True,issuedAt=r['releaseDate']+'T00:00:00Z',expiresAt='')
    artifact_hash=sha((out/'drtv-dark.apks').read_bytes())
    current['verification']={'sequence':sequence,'independentlyVerified':True,'browserPatchSha256':sha((ROOT/'site/recipe.json').read_bytes()),
                             'publicSigningSha256':sha(release_bytes),'releaseArtifactsSha256':artifact_hash}
    target={'baseSha256':files['base']['sha256'],'splitSha256':files['split']['sha256'],'commonCertificate':trust['commonCertificate'],
            'darkVersion':r['darkVersion'],'minSdk':24,'sourceCatalogSha256':sha(canonical(current['originals']).encode()),'versionCode':439000,'versionName':'4.39.0'}
    current['upgrade']={'package':DARK,'sourcePackage':OLD,'sequence':sequence,'releaseArtifactsSha256':artifact_hash,'target':target,'from':[]}
    if approval:current['upgrade']['from']=approval['upgradeFrom']
    save(out/'updates.json',sign_envelope(current));verified=verify_metadata(out/'updates.json',trust,sequence);R.check_updates(verified,release_bytes,data)
    assert [sha(p.read_bytes()) for p in originals]==original_pins
    save(out/'verification.json',{'developmentOnly':data['release']['developmentOnly'],'released':data['release']['released'],'applicationPackage':DARK,'sourcePackage':OLD,
         'apksSha256':artifact_hash,'certificateSha256':trust['commonCertificate'],'files':files,'darkSites':count,
         'envelopeBytes':len(release_bytes),'authoredSourceSha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sources},
         'publicProcessingEnabled':bool(approval),'productionKeyGenerated':False,'signingProfile':external['profile']['mode'] if external else 'development'})
    save(out/'commands.json',log)
    print(canonical({'out':str(out),'apksSha256':artifact_hash,'envelopeBytes':len(release_bytes),'darkSites':count,'released':data['release']['released']}))

