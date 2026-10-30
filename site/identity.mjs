// Exact-source development coexistence transforms, authenticated by the release envelope.
// Copy spans are taken only from the user's hash-pinned input. No APK/DEX is hosted.
import {need,sha,range,u32,abort} from './binary.mjs';
import {recolorIcon} from './icon.mjs';
export const DARK_PACKAGE='io.github.nobewayo.drtvdark';
const HASH=/^[0-9a-f]{64}$/;
const FILES={base:new Set(['AndroidManifest.xml','resources.arsc','classes4.dex','res/drawable/ic_drtv_background.xml','res/mipmap-xhdpi-v4/ic_launcher.png','res/layout/fragment_sports_detail.xml','res/layout/drshe1_view_holder.xml','res/layout-v22/drshe1_view_holder.xml','res/layout/custom_dialog_fragment_item_simple_layout.xml']),split:new Set(['AndroidManifest.xml','resources.arsc'])};
export function checkIdentityPlan(release){
 if(release.identity===undefined){need(release.sourcePackage===undefined,'Source identity needs an authenticated transform');return null;}
 const p=release.identity;
 need((release.developmentOnly===true&&release.released===false)||(release.developmentOnly===false&&release.released===true&&release.signingProfile==='production'),'Coexistence release gates');
 need(p?.schema===1&&p.sourcePackage==='dk.dr.tvplayer'&&release.sourcePackage===p.sourcePackage&&p.package===DARK_PACKAGE&&release.package===p.package,'Coexistence source/output binding');
 need(Object.keys(p).sort().join(',')==='files,package,schema,sourcePackage'&&Object.keys(p.files).sort().join(',')==='base,split','Identity plan fields');
 for(const role of ['base','split']){
  need(Object.keys(p.files[role]).length>0&&Object.keys(p.files[role]).length<=FILES[role].size,'Identity file count');
  for(const [name,s] of Object.entries(p.files[role]))need(FILES[role].has(name)&&s&&HASH.test(s.sourceSha256)&&HASH.test(s.targetSha256)&&Number.isSafeInteger(s.sourceSize)&&s.sourceSize>0&&s.sourceSize<=64*1024*1024&&Number.isSafeInteger(s.targetSize)&&s.targetSize>0&&s.targetSize<=64*1024*1024,'Identity file allowlist/bounds');
 }
 return p;
}
async function inflate(bytes,size,signal){
 need(Number.isSafeInteger(size)&&size>0&&size<=16*1024*1024,'Identity delta expansion bound');
 const reader=new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate')).getReader();
 const parts=[];let total=0;
 try{for(;;){abort(signal);const {value,done}=await reader.read();if(done)break;total+=value.length;need(total<=size,'Identity delta expansion overflow');parts.push(value);}}
 finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
 need(total===size,'Identity delta expanded size');const out=new Uint8Array(size);let p=0;for(const b of parts){out.set(b,p);p+=b.length;}return out;
}
export async function transformIdentity(source,spec,{signal}={}){
 abort(signal);need(source.length===spec.sourceSize&&await sha(source)===spec.sourceSha256,'Identity exact source hash/size');
 let out,operations=0;
 if(spec.encoding==='png-red-to-charcoal-v1')out=await recolorIcon(source,{signal});
 else{
  need(spec.encoding==='copy-add-zlib-v1'&&typeof spec.data==='string'&&spec.data.length<=1800000&&/^[A-Za-z0-9+/]+={0,2}$/.test(spec.data),'Identity delta encoding');
  const packed=Uint8Array.from(atob(spec.data),c=>c.charCodeAt(0)),patch=await inflate(packed,spec.expandedSize,signal);
  out=new Uint8Array(spec.targetSize);let p=0,w=0;
  while(p<patch.length){abort(signal);need(++operations<=500000,'Identity operation budget');const h=u32(patch,p);p+=4;const length=h&0x3fffffff,kind=h>>>30;need(length>0&&w+length<=out.length&&(kind===1||kind===2),'Identity operation bounds');
   const offset=u32(patch,p);p+=4;const original=range(source,offset,length);
   if(kind===2)out.set(original,w);
   else{const differences=range(patch,p,length);for(let i=0;i<length;i++)out[w+i]=(original[i]+differences[i])&255;p+=length;}
   w+=length;
  }
  need(w===out.length,'Incomplete identity transaction');
 }
 need(out.length===spec.targetSize&&await sha(out)===spec.targetSha256,'Identity target hash/size');
 return {bytes:out,audit:{kind:'coexistence-identity',encoding:spec.encoding,sourceSha256:spec.sourceSha256,targetSha256:spec.targetSha256,operations,verified:true}};
}
