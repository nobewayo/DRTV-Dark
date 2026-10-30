import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {authenticate} from '../site/envelope.mjs';
import {themePlan,verifyThemeFile} from '../site/theme.mjs';
import {validateSelection} from '../site/engine.mjs';
import {checkIdentityPlan,transformIdentity} from '../site/identity.mjs';
import {openZip,unpack} from '../site/zip.mjs';
const E=process.env.DRTV_RELEASE||'work/rehearsal/release';
const json=async p=>JSON.parse(await fs.readFile(p,'utf8'));
const trust=await json(E+'/trust.json'),envelope=await json(E+'/release.json'),r=await authenticate(envelope,trust.releaseKey);
const z=await openZip(new Blob([await fs.readFile(E+'/signed/base.apk')]),{apk:true});
const bytes=async n=>new Uint8Array(await (await unpack(z.entries.get(n))).arrayBuffer());
test('all eleven extension sites verify the actual signed final payloads',async()=>{
 const p=themePlan(r);assert.equal(p.totalSites,121);let count=0;
 for(const n of new Set(p.sites.map(s=>s.file)))count+=(await verifyThemeFile(await bytes(n),n,r)).length;
 assert.equal(count,11);
});
test('missing/duplicate sites, wrong component and wrong colors fail closed',async()=>{
 for(const change of [v=>v.sites.pop(),v=>v.sites[8].id=v.sites[0].id,v=>v.sites.find(s=>s.id==='b14-sports-0').file='res/layout/other.xml']){
  const c=structuredClone(r);change(c.themeCorrections);assert.throws(()=>themePlan(c));
 }
 for(const change of [s=>s.color=0xffffffff,s=>s.offset++,s=>s.path='other']){
  const c=structuredClone(r),s=c.themeCorrections.sites.find(s=>s.id==='b14-sports-0');change(s);
  await assert.rejects(verifyThemeFile(await bytes('res/layout/fragment_sports_detail.xml'),'res/layout/fragment_sports_detail.xml',c));
 }
});
test('signature, envelope size and exact source admission are enforced',async()=>{
 await assert.rejects(authenticate({...envelope,signature:'A'.repeat(envelope.signature.length)},trust.releaseKey));
 await assert.rejects(authenticate({payload:' '.repeat(2097153),signature:'AA=='},trust.releaseKey));
 for(const inputs of [[new Blob(['junk'])],await Promise.all(['base.apk','split_config.xhdpi.apk'].map(async n=>new Blob([await fs.readFile(E+'/signed/'+n)])))])
  await assert.rejects(validateSelection(inputs,r));
});
test('no implicit production mode, unrelated identity file or unchecked delta',async()=>{
 // Flipping either state flag yields a mixed state for development and production alike.
 const edits=[v=>v.released=!v.released,v=>v.developmentOnly=!v.developmentOnly,v=>v.identity.files.base['classes.dex']=v.identity.files.base['classes4.dex']];
 if(r.released)edits.push(v=>v.signingProfile='rehearsal',v=>{delete v.signingProfile;});
 for(const edit of edits){
  const c=structuredClone(r);edit(c);assert.throws(()=>checkIdentityPlan(c));
 }
 const spec=r.identity.files.base['classes4.dex'];
 await assert.rejects(transformIdentity(new Uint8Array(spec.sourceSize),spec));
 assert.equal(spec.encoding,'copy-add-zlib-v1');assert.ok(spec.expandedSize<=16*1024*1024);
});

const originals=process.env.DRTV_ORIGINAL_DIR;
test('one-byte changed original is rejected before transformation',{skip:!originals},async()=>{
 const base=new Uint8Array(await fs.readFile(originals+'/base.apk'));base[base.length-1]^=1;
 const split=await fs.readFile(originals+'/split_config.xhdpi.apk');
 await assert.rejects(validateSelection([new Blob([base]),new Blob([split])],r));
});
