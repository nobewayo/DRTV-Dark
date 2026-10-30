"""Build the production static candidate from externally supplied public material.

No keys, APKs, lab descriptors or deployment APIs. All three material files are
public signed output of the offline production adapter. Processing is enabled only
after validate() has proven a production trust root, an authorized signed release
and maintenance-free schema6 metadata; publication still needs a separate approval.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
if not __debug__:
 raise RuntimeError('Optimized Python is unsupported for release validation')
from static_assets import copy_assets,TOP_LEVEL_FILES
from release_data import embedded,verify_signed,check_envelope,check_updates,load
from update_metadata import verify

ROOT=Path(__file__).resolve().parents[1]
MATERIAL=('trust.json','drtv-release.json','updates.json')
OMIT={'trust.json','synthetic-v1.json','synthetic-v2.json','updates-development.json'}
def require(ok,message):
 if not ok:raise ValueError(message)
def sha(b):return hashlib.sha256(b).hexdigest()
def validate(material,trust_sha256,data_path):
 m=Path(material);require(m.is_dir() and not m.is_symlink(),'Production public material directory required')
 require({p.name for p in m.iterdir()}==set(MATERIAL),'Exact public production material set required')
 for n in MATERIAL:require((m/n).is_file() and not (m/n).is_symlink(),'No material links/special files')
 raw=(m/'trust.json').read_bytes();require(sha(raw)==trust_sha256,'External production trust pin mismatch')
 trust=json.loads(raw);require(set(trust)=={'schema','developmentOnly','commonCertificate','releaseKey','releaseSpki'} and trust['schema']==3,'Public trust schema')
 require(trust['developmentOnly'] is False,'Development trust cannot build a production candidate')
 require(not set(trust['releaseKey'])&{'d','p','q','dp','dq','qi','oth'},'Private JWK')
 require(trust['releaseKey'].get('kty')=='RSA' and trust['releaseKey'].get('alg')=='RS256' and trust['releaseKey'].get('key_ops')==['verify'],'Public RSA verification key')
 # Permanent rejection of the known disposable B3 metadata identity.
 require(sha(base64.b64decode(trust['releaseSpki']))!='3e1eb63894b943bdf47499bf936c2335531f75a29753da8a84d2633a0b42d4f0','Disposable development identity')
 require(trust['commonCertificate']!='8c0f45c692eabe55cee10e0741131b372b5b7180980644e6c9bf7ce20d9c79a4','Disposable APK identity')
 from cryptography.hazmat.primitives import serialization
 from cryptography.hazmat.primitives.asymmetric import rsa
 key=serialization.load_der_public_key(base64.b64decode(trust['releaseSpki'],validate=True))
 require(isinstance(key,rsa.RSAPublicKey) and key.key_size>=3072,'Metadata key strength');numbers=key.public_numbers()
 unb64=lambda s:int.from_bytes(base64.urlsafe_b64decode(s+'='*((-len(s))%4)),'big')
 require((numbers.n,numbers.e)==(unb64(trust['releaseKey']['n']),unb64(trust['releaseKey']['e'])),'JWK/SPKI binding')
 release=verify_signed(m/'drtv-release.json',trust);data=load(data_path);check_envelope(release,data)
 require(release.get('signingProfile')=='production','Production adapter identity required')
 require(release['released'] is True and release['developmentOnly'] is False and release['realRuntimeAccepted'] is True,'Approved production release required')
 updates=verify(m/'updates.json',trust,data['release']['sequence']);check_updates(updates,(m/'drtv-release.json').read_bytes(),data)
 require(updates['schema']==6 and updates['expiresAt']=='' and updates['released'] is True and updates['artifactsVerified'] is True and updates['verification']['independentlyVerified'] is True,'Approved maintenance-free schema6 artifacts required')
 require(updates['commonCertificate']==release['commonCertificate']==trust['commonCertificate'],'Common APK signer binding')
 cfg=embedded(release)
 require(cfg['diagnostics'] is False,'No native diagnostics')
 require(cfg['releaseSpki']==trust['releaseSpki'],'Native metadata key binding')
 require(cfg['website']==updates['website'],'Native website pin')
 for n in ('endpoint','website'):
  require(re.fullmatch(r'https://[A-Za-z0-9.-]+/[A-Za-z0-9_./-]*',cfg[n]) and '.invalid' not in cfg[n] and not re.search(r'https://(?:127\.|10\.|localhost)',cfg[n]),'Approved direct HTTPS production address')
 target=updates['upgrade']['target']
 require(all(target[r+'Sha256']==release['signatures'][r]['signedSha256'] for r in ('base','split')),'Target APK identity')
 require(updates['verification']['browserPatchSha256']==sha((ROOT/'site/recipe.json').read_bytes()),'Recipe attestation')
 return release
def build(material,out,trust_sha256,data):
 validate(material,trust_sha256,data)
 out=Path(out).resolve();require(not out.exists() and out!=ROOT and (ROOT not in out.parents or out.is_relative_to(ROOT/'work')),'Use a new ignored work directory or a directory outside source')
 out.mkdir(parents=True)
 names=[n for n in TOP_LEVEL_FILES if n not in OMIT]+['recipe.json']
 guide=copy_assets(ROOT/'site',out,names,coexistence=True)
 js="import fs from 'node:fs';import {describeRelease,guideForRelease} from './site/releaseinfo.mjs';const [r,g]=process.argv.slice(1);console.log(JSON.stringify(guideForRelease(describeRelease(JSON.parse(JSON.parse(fs.readFileSync(r)).payload)),JSON.parse(g))))"
 r=subprocess.run(['node','--input-type=module','-e',js,str(Path(material)/'drtv-release.json'),json.dumps(guide)],cwd=ROOT,capture_output=True,check=True)
 guide=json.loads(r.stdout)
 (out/'guide.json').write_text(json.dumps(guide,ensure_ascii=False,indent=2)+'\n')
 for n in MATERIAL:(out/n).write_bytes((Path(material)/n).read_bytes())
 config={'schema':3,'processingEnabled':True,'developmentOnly':False,'sourceVerified':True,'realRuntimeAccepted':True,'defaultRelease':'drtv','releases':{'drtv':{'envelope':'drtv-release.json','recipe':'recipe.json'}},'guide':guide}
 (out/'config.json').write_text(json.dumps(config,sort_keys=True,ensure_ascii=False)+'\n')
 version=sha(b''.join(p.read_bytes() for p in sorted(out.iterdir()) if p.is_file()))[:16]
 renames={p.name:p.stem+'.'+version+p.suffix for p in out.iterdir() if p.suffix in ('.mjs','.css')}
 for p in list(out.iterdir()):
  if p.suffix in ('.mjs','.html'):
   text=p.read_text()
   for old,new in renames.items():text=text.replace('./'+old,'./'+new).replace('"'+old+'"','"'+new+'"')
   p.write_text(text)
 for old,new in renames.items():(out/old).rename(out/new)
 def sri(n):return 'sha384-'+base64.b64encode(hashlib.sha384((out/n).read_bytes()).digest()).decode()
 html=(out/'index.html').read_text()
 for n in (renames['app.mjs'],renames['style.css']):
  attr='src' if n.endswith('.mjs') else 'href';html=html.replace(attr+'="'+n+'"',attr+'="'+n+'" integrity="'+sri(n)+'" crossorigin="anonymous"')
 html=html.replace('</head>',''.join('<link rel="modulepreload" href="'+n+'" integrity="'+sri(n)+'" crossorigin="anonymous">' for n in sorted(renames.values()) if n.endswith('.mjs'))+'</head>');(out/'index.html').write_text(html)
 files={p.relative_to(out).as_posix():sha(p.read_bytes()) for p in sorted(out.rglob('*')) if p.is_file()}
 (out/'integrity.json').write_text(json.dumps({'schema':3,'files':files},indent=2)+'\n');(out/'.nojekyll').write_text('')
 return {'status':'PASS','processingEnabled':True,'publicationReady':False,'integritySha256':sha((out/'integrity.json').read_bytes())}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--material',type=Path,required=True);p.add_argument('--trust-sha256',required=True);p.add_argument('--release-data',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 print(json.dumps(build(a.material,a.out,a.trust_sha256,a.release_data),sort_keys=True))
