// Narrow, audited compiled-manifest integration. No original class is rewritten.
import {need,u16,u32,put16,put32,cat,le32,enc,sha,hex} from './binary.mjs';
import {parseXml,chunks,strings} from './xml.mjs';
const ANDROID='http://schemas.android.com/apk/res/android';
export async function normalizeManifest(source,spec){
 need(await sha(source)===spec.source,'Manifest normalization source');const parsed=parseXml(source),nodes=parsed.nodes.filter(n=>n.path==='manifest/application/meta-data'&&n.attrs.some(a=>a.attribute_name==='name'&&a.type===3&&parsed.pool[a.data]==='com.android.vending.derived.apk.id'));
 need(nodes.length===1,'Derived metadata owner missing/ambiguous');const value=nodes[0].attrs.filter(a=>a.attribute_name==='value');need(value.length===1&&value[0].type===16&&value[0].data===spec.expected,'Derived metadata expected value');const result=source.slice();put32(result,value[0].offset+4,spec.replacement);need(await sha(result)===spec.target,'Canonical manifest oracle');return {bytes:result,audit:{kind:'source-normalization',offset:value[0].offset+4,expected:spec.expected,observed:spec.expected,replacement:spec.replacement,verified:true}};
}
export async function injectProvider(source,spec){
 need(await sha(source)===spec.source,'Notifier manifest source');const parsed=parseXml(source),parts=chunks(source).map(c=>({...c,b:source.slice(c.p,c.p+c.size)})),pools=parts.filter(p=>p.kind===1),maps=parts.filter(p=>p.kind===0x180);need(pools.length===1&&maps.length===1,'Manifest pool/map count');const pool=pools[0].b,map=maps[0].b,str=parsed.pool.slice(),resources=parsed.map.slice(),oldCount=str.length,start=u32(pool,20),utf8=!!(u32(pool,16)&256);
 need(u16(pool,2)===28&&!u32(pool,12)&&!u32(pool,24)&&start===28+oldCount*4&&u16(map,2)===8,'Unsupported manifest pool layout');need(!parsed.values.some(a=>a.type===3&&[spec.className,spec.authority].includes(parsed.pool[a.data])),'Notifier component already exists');const offsets=Array.from({length:oldCount},(_,i)=>u32(pool,28+4*i));let data=pool.slice(start);const addedStrings=[];
 function length(n){need(n<32768,'Manifest string limit');return utf8?(n<128?new Uint8Array([n]):new Uint8Array([128|(n>>>8),n&255])):new Uint8Array([n&255,n>>>8]);}
 function add(name,rid=null){let index=str.findIndex((s,i)=>s===name&&(rid===null||resources[i]===rid));if(index>=0)return index;index=str.length;const raw=utf8?enc.encode(name):Uint8Array.from([...name].flatMap(c=>[c.charCodeAt(0)&255,c.charCodeAt(0)>>>8]));offsets.push(data.length);data=cat(data,length(name.length),...(utf8?[length(raw.length)]:[]),raw,new Uint8Array(utf8?1:2));str.push(name);if(rid!==null){while(resources.length<=index)resources.push(0);resources[index]=rid;}addedStrings.push({index,value:name,resourceId:rid});return index;}
 const ns=str.indexOf(ANDROID);need(ns>=0,'Manifest Android namespace');
 const inserted=[],addedComponents=[];
 function component(tag,className,attrs){
  attrs=[...attrs].sort((a,b)=>a.rid-b.rid);
  need(!parsed.values.some(a=>a.type===3&&parsed.pool[a.data]===className),'Notifier component already exists');
  const name=add(tag),attributes=attrs.map(a=>{const b=new Uint8Array(20);put32(b,0,ns);put32(b,4,add(a.name,a.rid));const value=a.type===3?add(a.value):a.value;put32(b,8,a.type===3?value:0xffffffff);put16(b,12,8);b[15]=a.type;put32(b,16,value);return b;});
  const begin=new Uint8Array(36);put16(begin,0,0x102);put16(begin,2,16);put32(begin,4,36+20*attributes.length);put32(begin,12,0xffffffff);put32(begin,16,0xffffffff);put32(begin,20,name);put16(begin,24,20);put16(begin,26,20);put16(begin,28,attributes.length);
  const end=new Uint8Array(24);put16(end,0,0x103);put16(end,2,16);put32(end,4,24);put32(end,12,0xffffffff);put32(end,16,0xffffffff);put32(end,20,name);
  inserted.push(begin,...attributes,end);addedComponents.push({tag,className,attributes:attrs});
 }
 const attrs=[{name:'name',rid:0x1010003,type:3,value:spec.className},{name:'exported',rid:0x1010010,type:18,value:0},{name:'authorities',rid:0x1010018,type:3,value:spec.authority}];
 component('provider',spec.className,attrs);
 if(spec.activities!==undefined){
  need(Array.isArray(spec.activities)&&spec.activities.length===1&&spec.activities[0]==='org.drtvdark.watchdog.UpdateActivity','Unapproved authored activity');
  component('activity',spec.activities[0],[{name:'name',rid:0x1010003,type:3,value:spec.activities[0]},{name:'exported',rid:0x1010010,type:18,value:0},{name:'excludeFromRecents',rid:0x1010017,type:18,value:1},{name:'theme',rid:0x1010000,type:1,value:16974374}]);
 }
 data=cat(data,new Uint8Array((4-data.length%4)%4));const newPool=cat(pool.subarray(0,28),...offsets.map(le32),data);put32(newPool,4,newPool.length);put32(newPool,8,str.length);put32(newPool,16,u32(pool,16)&~1);put32(newPool,20,28+4*str.length);need(JSON.stringify(strings(newPool).slice(0,oldCount))===JSON.stringify(parsed.pool),'Existing manifest strings changed');const newMap=cat(map.subarray(0,8),...resources.map(le32));put32(newMap,4,newMap.length);
 const output=[],stack=[];let owners=0;for(const part of parts){if(part.kind===0x102)stack.push(str[u32(part.b,20)]);if(part.kind===0x103){const element=str[u32(part.b,20)];need(stack.at(-1)===element,'Manifest nesting');if(stack.join('/')==='manifest/application'){output.push(...inserted);owners++;}stack.pop();}output.push(part.kind===1?newPool:part.kind===0x180?newMap:part.b);}need(owners===1&&!stack.length,'Application owner missing/ambiguous');const result=cat(source.subarray(0,u16(source,2)),...output);put32(result,4,result.length);
 const after=parseXml(result),originalSemantic=a=>JSON.stringify([a.path,a.attribute,a.attribute_name,a.type,a.type===3?parsed.pool[a.data]:a.data]),afterSemantic=a=>JSON.stringify([a.path,a.attribute,a.attribute_name,a.type,a.type===3?after.pool[a.data]:a.data]);const count=new Map();for(const a of after.values)count.set(afterSemantic(a),(count.get(afterSemantic(a))||0)+1);for(const a of parsed.values){const k=originalSemantic(a);need(count.get(k)>0,'Existing manifest attribute changed');count.set(k,count.get(k)-1);}need([...count.values()].reduce((a,b)=>a+b,0)===addedComponents.reduce((n,c)=>n+c.attributes.length,0),'Unexpected notifier manifest mutation');need(!spec.target||await sha(result)===spec.target,'Notifier manifest target oracle');
 return {bytes:result,audit:{kind:'notifier-provider',sourceSha256:await sha(source),targetSha256:await sha(result),className:spec.className,authority:spec.authority,exported:false,addedStrings,addedAttributes:attrs,addedComponents,existingAttributesPreserved:true,verified:true}};
}
