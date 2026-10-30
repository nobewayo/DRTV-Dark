"""Independent schema 4/5/6 verifier; schema6 upgrade policy, public key only."""
if not __debug__:
 raise RuntimeError('Optimized Python is unsupported for metadata validation')
from json_unique import unique
import base64,json,datetime,re,hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding,rsa
def verify(path,trust,minimum=0):
 raw=path.read_bytes();assert len(raw)<=32768
 envelope=json.loads(raw,object_pairs_hook=unique);assert set(envelope)=={'payload','signature'}
 payload=envelope['payload'];assert isinstance(payload,str) and len(payload.encode())<=24576
 value=json.loads(payload,object_pairs_hook=unique);assert json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)==payload
 key=serialization.load_der_public_key(base64.b64decode(trust['releaseSpki'],validate=True));assert isinstance(key,rsa.RSAPublicKey) and key.key_size>=3072
 key.verify(base64.b64decode(envelope['signature'],validate=True),payload.encode(),padding.PKCS1v15(),hashes.SHA256())
 expected={'artifactsVerified','commonCertificate','darkVersion','latestOfficial','minInstalledSequence','originals','releaseDate','released','schema','sequence','verification','website'}
 if value['schema']>=5:expected|={'issuedAt','expiresAt'}
 if value['schema']==6:expected.add('upgrade')
 assert set(value)==expected
 if value['schema']>=5:
  start=timestamp(value['issuedAt']);assert start.timestamp()>0
  if not (value['schema']==6 and value['expiresAt']==''):
   end=timestamp(value['expiresAt']);assert datetime.timedelta(0)<end-start<=datetime.timedelta(days=7)
 assert value['schema'] in (4,5,6) and type(value['sequence']) is int and value['sequence']>=minimum
 assert value['commonCertificate']==trust['commonCertificate']
 proof=value['verification'];assert set(proof)=={'browserPatchSha256','independentlyVerified','publicSigningSha256','releaseArtifactsSha256','sequence'}
 assert type(proof['sequence']) is int and proof['sequence']==value['sequence']
 assert type(proof['independentlyVerified']) is bool
 for k in ('browserPatchSha256','publicSigningSha256','releaseArtifactsSha256'):assert re.fullmatch('[0-9a-f]{64}',proof[k])
 for k in ('released','artifactsVerified'):assert type(value[k]) is bool
 assert type(value['minInstalledSequence']) is int and 0<=value['minInstalledSequence']<=value['sequence']
 if value['schema']==6:validate_upgrade(value)
 return value
def validate_upgrade(value):
 def integer(v,low,high=2147483647):assert type(v) is int and low<=v<=high
 def text(v):assert isinstance(v,str) and re.fullmatch('[A-Za-z0-9.-]{1,64}',v)
 def digest(v):assert isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v)
 u=value['upgrade'];assert set(u)=={'from','package','releaseArtifactsSha256','sequence','target'}|({'sourcePackage'} if 'sourcePackage' in u else set())
 assert type(u['sequence']) is int and u['sequence']==value['sequence']
 assert isinstance(u['package'],str) and re.fullmatch('[A-Za-z0-9_.]{1,128}',u['package'])
 source=u.get('sourcePackage',u['package']);assert isinstance(source,str) and re.fullmatch('[A-Za-z0-9_.]{1,128}',source)
 digest(u['releaseArtifactsSha256']);assert u['releaseArtifactsSha256']==value['verification']['releaseArtifactsSha256']
 t=u['target'];assert set(t)=={'baseSha256','commonCertificate','darkVersion','minSdk','sourceCatalogSha256','splitSha256','versionCode','versionName'}
 for k in ('baseSha256','splitSha256','commonCertificate','sourceCatalogSha256'):digest(t[k])
 assert t['commonCertificate']==value['commonCertificate'] and t['darkVersion']==value['darkVersion'];text(t['darkVersion']);text(t['versionName']);integer(t['versionCode'],1);integer(t['minSdk'],24)
 assert t['sourceCatalogSha256']==hashlib.sha256(json.dumps(value['originals'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
 originals=value['originals'];assert type(originals) is list and 0<len(originals)<=8
 for o in originals:
  assert set(o)=={'package','variants','versionCode','versionName'} and o['package']==source and o['versionName']==t['versionName'];integer(o['versionCode'],1);assert o['versionCode']==t['versionCode']
  assert type(o['variants']) is list and 0<len(o['variants'])<=8
  for v in o['variants']:
   assert set(v)=={'baseSha256','id','splitSha256'};text(v['id']);digest(v['baseSha256']);digest(v['splitSha256'])
 origins=u['from'];assert type(origins) is list and len(origins)<=32;seen=set()
 for f in origins:
  assert set(f)=={'darkVersion','originalVersionCode','originalVersionName','sequence'};text(f['darkVersion']);text(f['originalVersionName']);integer(f['originalVersionCode'],1);integer(f['sequence'],value['minInstalledSequence'],value['sequence']-1)
  identity=json.dumps(f,sort_keys=True);assert identity not in seen;seen.add(identity)
def timestamp(value):
 assert isinstance(value,str) and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',value)
 return datetime.datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
def time_valid(value,now):
 start=timestamp(value['issuedAt']);assert start.timestamp()>0
 assert now>=start-datetime.timedelta(minutes=5)
 if value['schema']==6 and value['expiresAt']=='':return True
 end=timestamp(value['expiresAt']);assert datetime.timedelta(0)<end-start<=datetime.timedelta(days=7)
 return now<end
def eligible(value,installed,*,sdk=36,highest=0,now=None):
 """Independent host oracle. Android's actual verifier is tested on-device too."""
 try:
  assert value['schema']==6;validate_upgrade(value)
  now=now or datetime.datetime.now(datetime.timezone.utc)
  assert time_valid(value,now)
  assert value['released'] is True and value['artifactsVerified'] is True and value['verification']['independentlyVerified'] is True
  u=value['upgrade'];t=u['target'];assert u['package']==installed['package'] and t['commonCertificate']==installed['commonCertificate']
  assert u.get('sourcePackage',u['package'])==installed.get('sourcePackage',installed['package'])
  assert sdk>=t['minSdk'] and t['versionCode']>=installed['originalVersionCode']
  assert value['sequence']>installed['sequence'] and value['sequence']>=highest and installed['sequence']>=value['minInstalledSequence'] and value['darkVersion']!=installed['darkVersion']
  assert {k:installed[k] for k in ('sequence','darkVersion','originalVersionCode','originalVersionName')} in u['from']
  return True
 except (AssertionError,KeyError,ValueError,TypeError):return False
def official(value):
 try:
  o=value['latestOfficial']
  if value['schema']>=5:
   assert set(o)=={'evidence','limitations','observedAt','package','status','verifiedAt','versionCode','versionName'}
   assert o['package']=='dk.dr.tvplayer' and o['status']=='verified' and type(o['versionCode']) is int and o['versionCode']>0
   assert re.fullmatch('[A-Za-z0-9.-]{1,64}',o['versionName']) and 0<len(o['limitations'])<=256
   def timestamp(s):
    assert re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',s)
    return datetime.datetime.fromisoformat(s.replace('Z','+00:00'))
   assert timestamp(o['verifiedAt'])>=timestamp(o['observedAt'])
   assert 0<len(o['evidence'])<=8
   from urllib.parse import urlsplit
   for e in o['evidence']:
    assert set(e)=={'sha256','sourceId','url'} and re.fullmatch('[0-9a-f]{64}',e['sha256']) and re.fullmatch('[A-Za-z0-9._/-]{1,128}',e['sourceId'])
    u=urlsplit(e['url']);assert len(e['url'])<=512 and u.scheme=='https' and u.hostname and not u.username and not u.password and not u.fragment
   return o
  assert set(o)=={'package','sourceId','sourceUrl','verified','verifiedOn','versionCode','versionName'}
  assert o['verified'] is True and o['package']=='dk.dr.tvplayer' and type(o['versionCode']) is int and o['versionCode']>0
  assert re.fullmatch('[A-Za-z0-9.-]{1,64}',o['versionName']) and re.fullmatch('[A-Za-z0-9._/-]{1,128}',o['sourceId'])
  assert re.fullmatch(r'https://[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9_./-]*',o['sourceUrl'])
  datetime.date.fromisoformat(o['verifiedOn']);return o
 except (AssertionError,ValueError,KeyError,TypeError):return None
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('file',type=Path);p.add_argument('--minimum',type=int,default=32)
 p.add_argument('--trust',type=Path,default=Path(__file__).resolve().parents[1]/'maintenance/4.39.0/trust.json');a=p.parse_args()
 trust=json.loads(a.trust.read_text());v=verify(a.file,trust,a.minimum);print({'status':'PASS','sequence':v['sequence'],'released':v['released'],'officialVerified':official(v) is not None})
