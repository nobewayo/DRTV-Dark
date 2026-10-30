import {need,sha,read,enc,abort,crcBytes} from './binary.mjs';
import {shaBlob} from './sha256.mjs';
import {openZip,unpack,writeZip} from './zip.mjs';
import {verifyV2} from './signatures.mjs';
import {parseXml} from './xml.mjs';
import {normalizeManifest,injectProvider} from './manifest.mjs';
import {patchFile} from './dark.mjs';
import {finalize} from './detached.mjs';
import {authenticate} from './envelope.mjs';
import {outputFilename} from './naming.mjs';
import {checkIdentityPlan,transformIdentity} from './identity.mjs';
import {themePlan,verifyThemeFile} from './theme.mjs';
const obsolete=n=>n.toUpperCase()==='META-INF/MANIFEST.MF'||n==='stamp-cert-sha256'||/^META-INF\/[^/]+\.(SF|RSA|DSA|EC)$/i.test(n);
export function identity(bytes){const p=parseXml(bytes),roots=p.nodes.filter(n=>n.path==='manifest');need(roots.length===1,'Manifest identity root');const value=name=>{const a=roots[0].attrs.filter(a=>a.attribute_name===name);need(a.length<=1,'Duplicate manifest identity');return a[0]?.type===3?p.pool[a[0].data]:a[0]?.data;};return {package:value('package'),versionCode:value('versionCode'),versionName:value('versionName')||'',split:value('split')||''};}
export async function validateSelection(files,release,{signal}={}){
 checkIdentityPlan(release);const sourcePackage=release.sourcePackage??release.package;
 abort(signal);need(files.length>0&&files.length<=2,'Vælg den originale TV-fil.');const pins=release.sources.flatMap(v=>v.files.map(f=>({...f,variant:v.id}))),selected=[];
 async function admit(blob){const hash=await shaBlob(blob,signal),matches=pins.filter(p=>p.sha256===hash&&p.size===blob.size);need(matches.length===1,'Denne fil er ikke en understøttet DRTV-original.');selected.push({blob,pin:matches[0]});}
 for(const f of files){need(f.size>0&&f.size<=128*1024*1024,'Filen er tom eller for stor.');if(files.length===2){await admit(f);continue;}const hash=await shaBlob(f,signal),match=pins.find(p=>p.sha256===hash&&p.size===f.size);if(match){selected.push({blob:f,pin:match});continue;}const outer=await openZip(f,{signal});need(outer.entries.size<=16,'For mange filer i pakken.');for(const e of outer.entries.values()){need(!e.name.includes('/')&&(/\.apk$/.test(e.name)||['manifest.json','icon.png'].includes(e.name)),'Ukendt pakkelayout.');if(e.name.endsWith('.apk'))await admit(await unpack(e,signal));}}
 need(selected.length===2&&new Set(selected.map(x=>x.pin.role)).size===2&&new Set(selected.map(x=>x.pin.variant)).size===1,'Originalens dele mangler eller passer ikke sammen.');
 for(const c of selected){await verifyV2(c.blob,{certificate:release.originalCertificate,signal,allowPinnedSourcePadding:true});c.zip=await openZip(c.blob,{apk:true,signal});const manifest=await unpack(c.zip.entries.get('AndroidManifest.xml'),signal),id=identity(await read(manifest));need(id.package===sourcePackage&&id.versionCode===release.versionCode&&id.split===(c.pin.role==='base'?'':release.split),'Forkert TV-app eller version.');if(c.pin.role==='base')need(id.versionName===release.versionName,'Forkert versionsnavn.');need(![...c.zip.entries.keys()].some(n=>n.startsWith('lib/')),'Ukendt enhedsvariant.');}
 return {variant:selected[0].pin.variant,records:selected.sort((a,b)=>a.pin.role==='base'?-1:b.pin.role==='base'?1:0)};
}
export async function canonicalize(prepared,recipe,release,{signal,progress=()=>{}}={}){
 const apks=[],darkSites=[],themeSites=[],additional=[],plan=checkIdentityPlan(release),theme=themePlan(release),transformed=new Set();
 for(const c of prepared.records){progress('Gør den mørk');const entries=[],expected=release.payloads[c.pin.role];
  need(expected&&Object.keys(expected).length===[...c.zip.entries.keys()].filter(n=>!obsolete(n)).length,'Original APK entry set changed');
  for(const e of [...c.zip.entries.values()].sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0)){
   abort(signal);if(obsolete(e.name))continue;let blob=await unpack(e,signal),checksum=e.checksum;
   if(e.name==='AndroidManifest.xml'&&c.pin.normalization){const r=await normalizeManifest(await read(blob),c.pin.normalization);blob=new Blob([r.bytes]);checksum=(crcBytes(r.bytes)^0xffffffff)>>>0;additional.push({role:c.pin.role,...r.audit});}
   need(await shaBlob(blob,signal)===expected[e.name],'Original payload mismatch: '+e.name);
   if(c.pin.role==='base'&&recipe?.files[e.name]){const r=await patchFile(await read(blob),e.name,recipe,{signal});blob=new Blob([r.bytes]);checksum=(crcBytes(r.bytes)^0xffffffff)>>>0;darkSites.push(...r.report);}
   if(c.pin.role==='base'&&e.name==='AndroidManifest.xml'&&release.notifier){const r=await injectProvider(await read(blob),release.notifier.manifest);blob=new Blob([r.bytes]);checksum=(crcBytes(r.bytes)^0xffffffff)>>>0;additional.push(r.audit);}
   const spec=plan?.files[c.pin.role]?.[e.name];if(spec){const r=await transformIdentity(await read(blob),spec,{signal});blob=new Blob([r.bytes]);checksum=(crcBytes(r.bytes)^0xffffffff)>>>0;additional.push({role:c.pin.role,name:e.name,...r.audit});transformed.add(c.pin.role+':'+e.name);}
   if(c.pin.role==='base'&&theme&&theme.sites.some(s=>s.file===e.name))themeSites.push(...await verifyThemeFile(await read(blob),e.name,release));
   entries.push({name:e.name,data:blob,checksum});
  }
  if(c.pin.role==='base'&&release.notifier){
   for(const asset of release.notifier.assets){need(!entries.some(e=>e.name===asset.name),'Notifier asset collision');const bytes=Uint8Array.from(atob(asset.base64),x=>x.charCodeAt(0));need(await sha(bytes)===asset.sha256&&bytes.length===asset.size,'Notifier asset integrity');entries.push({name:asset.name,data:new Blob([bytes]),checksum:(crcBytes(bytes)^0xffffffff)>>>0});additional.push({kind:'notifier-authored-asset',name:asset.name,size:asset.size,sha256:asset.sha256,verified:true});}
  }
  entries.sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0);const unsigned=await writeZip(entries,{signal,apkAlignment:true});apks.push({role:c.pin.role,name:c.pin.role==='base'?'base.apk':'split_'+release.split+'.apk',blob:unsigned});
 }
 if(plan)need(transformed.size===Object.values(plan.files).reduce((n,f)=>n+Object.keys(f).length,0),'Incomplete identity transaction');
 if(recipe)need(darkSites.length===110&&darkSites.every(s=>s.applied&&s.postPatch.verified),'Incomplete 110-site transaction');
 if(theme)need(themeSites.length===theme.totalSites-110,'Incomplete B13 theme extension');
 darkSites.push(...themeSites);return {apks,darkSites,additional};
}
export async function makeProduct(files,recipe,envelope,trust,{signal,progress=()=>{},prepared}={}){
 const start=performance.now(),stages=[];function stage(label){abort(signal);stages.push({label,ms:performance.now()-start});progress(label);}
 const release=await authenticate(envelope,trust.releaseKey);need(release.schema===3&&release.commonCertificate===trust.commonCertificate,'Release trust/catalog identity');need(release.recipeSha256===await sha(enc.encode(JSON.stringify(recipe))),'Recipe identity mismatch');stage('Validerer');prepared??=await validateSelection(files,release,{signal});const canonical=await canonicalize(prepared,recipe,release,{signal,progress:stage});const signed=[];
 stage('Færdiggør');for(const apk of canonical.apks){const material=release.signatures[apk.role];need(material&&material.certificateSha256===trust.commonCertificate&&material.package===release.package&&material.versionCode===release.versionCode&&material.split===(apk.role==='base'?'':release.split),'Signature material package/split mismatch');const r=await finalize(apk.blob,material,{signal});signed.push({...apk,blob:r.blob});}
 stage('Pakker');const common={export_timestamp:0,label:release.label,package:release.package,version_code:release.versionCode,version_name:release.versionName},icon=Uint8Array.from(atob(release.icon),x=>x.charCodeAt(0));const metadata=[{name:'meta.sai_v2.json',data:new Blob([JSON.stringify({...common,meta_version:2,split_apk:true,min_sdk:24,target_sdk:35,backup_components:[{type:'apk_files',size:signed.reduce((n,a)=>n+a.blob.size,0)}]})])},{name:'meta.sai_v1.json',data:new Blob([JSON.stringify(common)])},{name:'icon.png',data:new Blob([icon])}];
 const output=await writeZip([...metadata,...signed.map(a=>({name:a.name,data:a.blob}))],{signal});stage('Slutkontrol');const reopened=await openZip(output,{signal});need([...reopened.entries.keys()].join('|')===[...metadata.map(x=>x.name),...signed.map(x=>x.name)].join('|'),'Final .apks layout');
 for(const apk of signed){const inner=await unpack(reopened.entries.get(apk.name),signal);need(await shaBlob(inner,signal)===release.signatures[apk.role].signedSha256,'Final .apks APK hash');const z=await openZip(inner,{apk:true,signal}),id=identity(await read(await unpack(z.entries.get('AndroidManifest.xml'),signal)));need(id.package===release.package&&id.versionCode===release.versionCode&&id.split===(apk.role==='base'?'':release.split),'Final package/split mismatch');}
 const hash=await shaBlob(output,signal);abort(signal);stage('Færdig');return {blob:output,hash,filename:outputFilename(release),certificate:trust.commonCertificate,variant:prepared.variant,darkSites:canonical.darkSites,additional:canonical.additional,metrics:{inputBytes:files.reduce((n,f)=>n+f.size,0),outputBytes:output.size,totalMs:performance.now()-start,stages,persistentTemporaryApkBytes:0}};
}
