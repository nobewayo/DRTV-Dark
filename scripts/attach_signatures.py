"""SDK-sign canonical APKs and emit public signature blocks plus authenticated metadata.

External identities are supplied only by the guarded release command. No keys are generated here.
"""
if not __debug__: raise RuntimeError('Optimized Python is unsupported for signing/theme validation')
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from product_common import *
import argparse
import copy
import base64
import struct
p=argparse.ArgumentParser();p.add_argument('--seed',type=Path,required=True);p.add_argument('--canonical',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--envelope',type=Path,required=True);p.add_argument('--disposable-development',action='store_true');p.add_argument('--external-profile',action='store_true');a=p.parse_args();assert a.disposable_development != a.external_profile;assert bool(os.environ.get('DRTV_SIGNING_PROFILE')) == a.external_profile;out=a.out.resolve();assert out.is_relative_to(ROOT/'work');out.mkdir(parents=True,exist_ok=False);seed=json.loads(a.seed.read_text());log=[]
def zip_parts(b):
 e=len(b)-22;assert struct.unpack_from('<I',b,e)[0]==0x06054b50 and struct.unpack_from('<H',b,e+20)[0]==0
 cd=struct.unpack_from('<I',b,e+16)[0];length=struct.unpack_from('<I',b,e+12)[0];assert cd+length==e;return cd,e
seed['signatures']={}
for role,name in [('base','base.apk'),('split','split_'+seed['split']+'.apk')]:
 unsigned=a.canonical/name;signed=out/name;key,cert=key_paths();run([BT/'apksigner','sign','--key',key,'--cert',cert,'--min-sdk-version','24','--alignment-preserved','true','--v1-signing-enabled','false','--v2-signing-enabled','true','--v3-signing-enabled','false','--v4-signing-enabled','false','--out',signed,unsigned],log=log);u=unsigned.read_bytes();s=signed.read_bytes();ucd,ue=zip_parts(u);scd,se=zip_parts(s);blocksize=struct.unpack_from('<Q',s,scd-24)[0];at=scd-blocksize-8;assert s[scd-16:scd]==b'APK Sig Block 42' and at==ucd
 # This exact comparison is the proof that no unsigned bytes were silently repacked.
 assert u[:ucd]==s[:at] and u[ucd:ue]==s[scd:se]
 adjusted=bytearray(s[se:]);struct.pack_into('<I',adjusted,16,ucd);assert bytes(adjusted)==u[ue:]
 block=s[at:scd];assert struct.unpack_from('<Q',block)[0]==len(block)-8
 certificate=run([BT/'apksigner','verify','--verbose','--print-certs','--min-sdk-version','24',signed],log=log).stdout.decode();assert seed['commonCertificate'] in certificate
 run([BT/'zipalign','-c','-P','16','4',signed],log=log)
 seed['signatures'][role]={'schema':1,'scheme':'APK-v2-RSA-SHA256','package':seed['package'],'versionCode':seed['versionCode'],'versionName':seed['versionName'],'split':'' if role=='base' else seed['split'],'certificateSha256':seed['commonCertificate'],'unsignedSize':len(u),'unsignedSha256':sha(u),'signedSize':len(s),'signedSha256':sha(s),'centralDirectoryOffset':ucd,'block':base64.b64encode(block).decode()}
save(a.envelope,sign_envelope(seed));save(out/'sdk-signing-commands.json',log);save(out/'public-signature-summary.json',{role:{k:v for k,v in m.items() if k!='block'} for role,m in seed['signatures'].items()});print('Detached public material:',a.envelope)
