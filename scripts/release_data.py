"""Authoritative DRTV Dark release data (releases/drtv-dark.json).

The file holds only descriptive facts for one release: its id, DRTV Dark version,
sequence, date, change log and status flags, plus the identity (package, versionName,
versionCode) of the DR TV original it is built from. It holds no hashes and cannot
admit an APK: source pins only come from the verified seed, computed from actual
original bytes, and the release tool requires the seed identity to equal this file.

The offline release tool copies these facts into the signed release envelope and the
notifier configuration embedded in the APK; the signed update manifest is derived from
that envelope. The website reads only the signed envelope. `check` proves that all of
them agree, so a version change is one edit here followed by an offline re-release.
"""
if not __debug__: raise RuntimeError('Optimized Python is unsupported: security checks use assertions')
import base64
import datetime
import hashlib
import json
import re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];DEFAULT=ROOT/'releases/drtv-dark-v1.json'
PUBLIC=re.compile(r'[1-9]\d{0,3}(\.\d{1,4}){0,2}')  # same rule as site/naming.mjs
TEXT=re.compile(r'[A-Za-z0-9.-]{1,64}')
CONFIG='assets/drtv-dark-release.json'
def unique(pairs):
 keys=[k for k,_ in pairs];assert len(keys)==len(set(keys)),'Duplicate key';return dict(pairs)
def date(value):
 assert isinstance(value,str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}',value),'Date must be YYYY-MM-DD';datetime.date.fromisoformat(value);return value
def public_text(value,limit):
 assert isinstance(value,str) and 0<len(value)<=limit,'Text length'
 assert not re.search(r'[\u0000-\u001f—<>]',value),'Public text: no control characters, em dashes or markup';return value
def is_public(data):return data['release']['released'] is True and data['release']['developmentOnly'] is False
def validate(data):
 assert set(data)=={'schema','release','original'}|({'application'} if 'application' in data else set()) and data['schema']==1,'Release data schema'
 r=data['release'];o=data['original']
 assert set(r)=={'id','darkVersion','sequence','minInstalledSequence','releaseDate','released','developmentOnly','changes'},'Release fields'
 assert set(o)=={'package','versionName','versionCode'},'Original fields'
 assert isinstance(r['id'],str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,63}',r['id']),'Release id'
 for k in ('released','developmentOnly'):assert type(r[k]) is bool,k
 assert not (r['released'] and r['developmentOnly']),'A development build cannot be marked released'
 if 'application' in data:
  assert set(data['application'])=={'package','distribution'} and data['application']=={'package':'io.github.nobewayo.drtvdark','distribution':'coexistence'},'Development coexistence candidate only'
  # Production authorization is enforced by the offline signing adapter and publication gate.
 for k in ('sequence','minInstalledSequence'):assert type(r[k]) is int and 1<=r[k]<=2147483647,k
 assert r['minInstalledSequence']<=r['sequence'],'minInstalledSequence'
 date(r['releaseDate'])
 if is_public(data):assert PUBLIC.fullmatch(r['darkVersion']),'A public DRTV Dark version is plain: 1, 1.1, 2'
 else:assert TEXT.fullmatch(r['darkVersion']) and 'development' in r['darkVersion'] and 'development' in r['id'],'Development releases must be marked development'
 assert type(r['changes']) is list and len(r['changes'])<=50,'Change log'
 for c in r['changes']:
  assert set(c)=={'version','date','text'} and TEXT.fullmatch(c['version']),'Change entry';date(c['date']);public_text(c['text'],400)
 assert len({c['version'] for c in r['changes']})==len(r['changes']),'Duplicate change log version'
 if is_public(data):assert r['changes'] and r['changes'][0]['version']==r['darkVersion'] and r['changes'][0]['date']==r['releaseDate'],'The newest change log entry must describe this release'
 assert o['package']=='dk.dr.tvplayer','Only the DR TV package is a supported original'
 assert isinstance(o['versionName'],str) and re.fullmatch(r'\d{1,4}(\.\d{1,4}){1,3}',o['versionName']),'Original versionName'
 assert type(o['versionCode']) is int and 1<=o['versionCode']<=2147483647,'Original versionCode'
 return data
def load(path=DEFAULT):return validate(json.loads(Path(path).read_text(),object_pairs_hook=unique))
def embedded(release):
 """The notifier configuration that is inside the APK the release produces."""
 assets=[a for a in release['notifier']['assets'] if a['name']==CONFIG];assert len(assets)==1,'Embedded release configuration'
 return json.loads(base64.b64decode(assets[0]['base64']))
def check_seed(seed,data):
 """The verified seed (pins computed from real original bytes) must be the original named here."""
 o=data['original'];assert (seed.get('sourcePackage',seed['package']),seed['versionName'],seed['versionCode'])==(o['package'],o['versionName'],o['versionCode']),'Seed is not the original named in the release data'
def apply(seed,data):
 """Release facts for the envelope; the caller writes the embedded config with config()."""
 r=data['release'];seed.update(id=r['id'],released=r['released'],developmentOnly=r['developmentOnly'],darkVersion=r['darkVersion'],releaseDate=r['releaseDate'],changes=r['changes'])
def config(info,data):
 r=data['release'];info.update(darkVersion=r['darkVersion'],sequence=r['sequence'],original=dict(data['original']))
 if 'application' in data:info['applicationPackage']=data['application']['package']
def check_envelope(release,data):
 """Signed envelope payload versus the release data. Returns notes on legacy fields."""
 r=data['release'];o=data['original'];notes=[]
 assert (release.get('sourcePackage',release['package']),release['versionName'],release['versionCode'])==(o['package'],o['versionName'],o['versionCode']),'Envelope original differs from release data'
 target=data.get('application',o)['package'];assert release['package']==target,'Envelope application differs'
 assert release['id']==r['id'] and release['released']==r['released'] and release['developmentOnly']==r['developmentOnly'],'Envelope status differs from release data'
 info=embedded(release)
 assert info['darkVersion']==r['darkVersion'] and info['sequence']==r['sequence'],'Embedded APK version differs from release data'
 assert info['original']==o and info['commonCertificate']==release['commonCertificate'],'Embedded APK original or signer differs'
 assert info.get('applicationPackage',info['original']['package'])==target,'Embedded application identity differs'
 for k in ('darkVersion','releaseDate','changes'):
  if k in release:assert release[k]==r[k],'Envelope '+k+' differs from release data'
  else:
   # B5/B6 development envelopes predate these fields; a public release must carry them.
   assert not is_public(data),'A public envelope must carry '+k;notes.append('legacy development envelope without top-level '+k)
 return notes
def check_updates(value,envelope_bytes,data):
 r=data['release'];o=data['original'];t=value['upgrade']['target']
 assert value['darkVersion']==t['darkVersion']==r['darkVersion'] and value['sequence']==r['sequence'],'Update manifest version differs'
 assert value['releaseDate']==r['releaseDate'] and value['released']==r['released'] and value['minInstalledSequence']==r['minInstalledSequence'],'Update manifest facts differ'
 assert (t['versionName'],t['versionCode'])==(o['versionName'],o['versionCode']) and all((x['package'],x['versionName'],x['versionCode'])==(o['package'],o['versionName'],o['versionCode']) for x in value['originals']),'Update manifest original differs'
 assert value['upgrade']['package']==data.get('application',o)['package'],'Update target application differs'
 assert value['upgrade'].get('sourcePackage',value['upgrade']['package'])==o['package'],'Update source application differs'
 assert value['verification']['publicSigningSha256']==hashlib.sha256(envelope_bytes).hexdigest(),'Update manifest is not bound to this envelope'
def verify_signed(path,trust):
 from cryptography.hazmat.primitives import hashes,serialization
 from cryptography.hazmat.primitives.asymmetric import padding
 envelope=json.loads(Path(path).read_text(),object_pairs_hook=unique);assert set(envelope)=={'payload','signature'}
 key=serialization.load_der_public_key(base64.b64decode(trust['releaseSpki'],validate=True))
 key.verify(base64.b64decode(envelope['signature'],validate=True),envelope['payload'].encode(),padding.PKCS1v15(),hashes.SHA256())
 value=json.loads(envelope['payload'],object_pairs_hook=unique);assert json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)==envelope['payload'];return value
def version_literals(release):
 """Every version string a signed envelope carries; short ones are too ambiguous to search for."""
 found={release['versionName'],str(release['versionCode']),release.get('darkVersion','')}
 found|={json.loads(base64.b64decode(x['base64'])).get('darkVersion','') for x in release['notifier']['assets'] if x['name']==CONFIG}
 return {v for v in found if len(v)>=4}
def hardcoded(releases,pages):
 """(version, page) pairs where a page file names a version instead of reading the envelope."""
 return sorted((v,n) for r in releases for v in version_literals(r) for n,t in pages.items() if v in t)
def check(data_path=DEFAULT,envelope=ROOT/'maintenance/4.39.0/release.json',updates=ROOT/'maintenance/4.39.0/updates.json',trust=ROOT/'maintenance/4.39.0/trust.json'):
 data=load(data_path);trust=json.loads(Path(trust).read_text());release=verify_signed(envelope,trust)
 assert release['commonCertificate']==trust['commonCertificate'],'Envelope signer differs from trust root'
 notes=check_envelope(release,data)
 if updates:check_updates(verify_signed(updates,trust),Path(envelope).read_bytes(),data)
 return {'status':'PASS','releaseId':data['release']['id'],'darkVersion':data['release']['darkVersion'],'public':is_public(data),'original':data['original'],'notes':notes}
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser(description='Validate release data and prove that signed outputs agree with it.');p.add_argument('command',choices=['validate','check']);p.add_argument('--data',type=Path,default=DEFAULT);p.add_argument('--envelope',type=Path,default=ROOT/'maintenance/4.39.0/release.json');p.add_argument('--updates',type=Path,default=ROOT/'maintenance/4.39.0/updates.json');p.add_argument('--no-updates',action='store_true');p.add_argument('--trust',type=Path,default=ROOT/'maintenance/4.39.0/trust.json');a=p.parse_args()
 if a.command=='validate':d=load(a.data);print(json.dumps({'status':'PASS','releaseId':d['release']['id'],'public':is_public(d)}))
 else:print(json.dumps(check(a.data,a.envelope,None if a.no_updates else a.updates,a.trust),ensure_ascii=False,indent=1))
