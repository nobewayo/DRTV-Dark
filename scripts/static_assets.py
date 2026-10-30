"""Explicit static-asset boundary; no recursive unchecked directory inclusion."""
if not __debug__: raise RuntimeError('Optimized Python is unsupported: security checks use assertions')
from pathlib import Path
import json,shutil
TOP_LEVEL_FILES=('index.html','style.css','app.mjs','worker.mjs','binary.mjs','sha256.mjs','zip.mjs','signatures.mjs','dark.mjs','dex.mjs','xml.mjs','resources.mjs','manifest.mjs','envelope.mjs','detached.mjs','engine.mjs','identity.mjs','theme.mjs','icon.mjs','naming.mjs','releaseinfo.mjs','favicon.svg','trust.json','synthetic-v1.json','synthetic-v2.json','updates-development.json')
# Every subdirectory must contain exactly these files: an unexpected file fails the build.
DIRECTORIES={
 'guide':{'01-afinstaller-dr-tv.webp','02-google-play.webp','03-tilladelse.webp','04-web-installer.webp','05-forbind.webp','06-send-filen.webp','07-modtag-filen.webp','08-bekraeft.webp','09-installeret.webp'},
 'images':{'home-before.webp','home-after.webp','programme-seasons-before.webp','programme-seasons-after.webp'},
 'fonts':{'schibsted-grotesk-latin.woff2','schibsted-grotesk-latin-ext.woff2','OFL.txt'},
}
GUIDE=DIRECTORIES['guide']
OPTIONAL_DIRECTORIES={'guide':{'01-behold-dr-tv.webp'}}
GUIDE_KEYS={'where','title','text','src','alt','caption','app'}
def copy_assets(source,out,names,*,coexistence=False):
 source=Path(source);out=Path(out);assert not source.is_symlink()
 directories={d:set(files) for d,files in DIRECTORIES.items()}
 # The independent app keeps official DRTV, so its first guide step has no screenshot.
 if coexistence:directories['guide']=directories['guide']-{'01-afinstaller-dr-tv.webp'}
 paths=[*names,'guide.json',*(d+'/'+n for d,files in directories.items() for n in sorted(files))]
 for d,files in DIRECTORIES.items():
  actual=set(p.name for p in (source/d).iterdir());optional=OPTIONAL_DIRECTORIES.get(d,set())
  required=directories[d]
  assert required<=actual and actual<=files|optional,'Unexpected '+d+' asset'
 for name in paths:
  relative=Path(name);assert not relative.is_absolute() and '..' not in relative.parts
  file=source/relative;assert file.is_file() and file.resolve().is_relative_to(source.resolve()),'External asset'
  assert all(not p.is_symlink() for p in [file,*file.parents] if p==source or source in p.parents),'Symlink asset'
 guide=json.loads((source/'guide.json').read_text())
 assert isinstance(guide,list) and guide and all(isinstance(s,dict) and (s.get('src') in {'guide/'+n for n in GUIDE} or coexistence and i==0 and s.get('src')=='') for i,s in enumerate(guide)),'Unapproved guide reference'
 assert all(set(s)<=GUIDE_KEYS and s.get('where') in ('tv','device') and all(isinstance(s.get(k),str) and (s[k] or coexistence and i==0 and k in ('alt','caption')) for k in ('title','text','alt','caption')) for i,s in enumerate(guide)),'Malformed guide step'
 assert not any('—' in v for s in guide for v in s.values() if isinstance(v,str)),'Public copy must not use em dashes'
 for name in names:shutil.copyfile(source/name,out/name)
 for d,files in directories.items():
  (out/d).mkdir()
  for name in sorted(files):shutil.copyfile(source/d/name,out/d/name)
 return guide
