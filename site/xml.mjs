// Port of tools/xml_colors.py; original indices and attributes are retained.
import {need,u16,u32,put16,put32,cat,le32,enc,dec,hex,sha,range} from './binary.mjs';
export function chunks(b,start=u16(b,2),end=b.length){const out=[];for(let p=start;p<end;){const kind=u16(b,p),header=u16(b,p+2),size=u32(b,p+4);need(header>=8&&size>=header&&size%4===0&&p+size<=end,'Chunk bounds');out.push({p,kind,header,size});p+=size;}return out;}
export function strings(b,p=0){
 need(u16(b,p)===1&&u16(b,p+2)>=28,'String pool');const h=u16(b,p+2),size=u32(b,p+4),count=u32(b,p+8),styles=u32(b,p+12),flags=u32(b,p+16),start=u32(b,p+20),styleStart=u32(b,p+24),end=p+(styleStart||size);
 need(count<=100000&&h+4*(count+styles)<=start&&start<=size&&p+size<=b.length,'String pool bounds');const result=[];
 function length(q,wide){const n=wide?u16(b,q):b[q];q+=wide?2:1;if(n&(wide?0x8000:0x80))return [((n&(wide?0x7fff:0x7f))*(wide?32768:256))+(wide?u16(b,q):b[q]),q+(wide?2:1)];return [n,q];}
 for(let i=0;i<count;i++){let q=p+start+u32(b,p+h+4*i);need(q>=p+start&&q<end,'String offset');let n;[n,q]=length(q,!(flags&256));if(flags&256)[n,q]=length(q,false);const width=flags&256?1:2;need(q+n*width+width<=end,'String length');need(range(b,q+n*width,width).every(x=>x===0),'String terminator');result.push(new TextDecoder(width===1?'utf-8':'utf-16le',{fatal:true}).decode(range(b,q,n*width)));}
 return result;
}
export function parseXml(b){
 need(u16(b,0)===3&&u32(b,4)===b.length,'Binary XML header');let pool,map=[],stack=[],nodes=[],values=[];
 for(const ch of chunks(b)){
  const p=ch.p;if(ch.kind===1){need(!pool,'Duplicate string pool');pool=strings(b,p);}
  else if(ch.kind===0x180){need(map.length===0,'Duplicate resource map');map=Array.from({length:(ch.size-ch.header)/4},(_,i)=>u32(b,p+ch.header+i*4));}
  else if(ch.kind===0x102){
   need(pool&&ch.header===16&&ch.size>=36,'XML element');const name=u32(b,p+20),start=u16(b,p+24),width=u16(b,p+26),n=u16(b,p+28);need(name<pool.length&&start>=20&&width===20&&16+start+width*n<=ch.size,'XML attribute bounds');stack.push(pool[name]);const node={p,path:stack.join('/'),attrs:[],ch};nodes.push(node);const seen=new Set();
   for(let i=0;i<n;i++){const at=p+16+start+i*20,attr=u32(b,at+4),typ=b[at+15],data=u32(b,at+16);need(attr<pool.length&&u16(b,at+12)===8&&b[at+14]===0,'XML typed value');const rid=map[attr]||0,key=rid?String(rid):pool[attr];need(!seen.has(key),'Duplicate XML attribute');seen.add(key);const v={path:node.path,attribute:rid,attribute_name:pool[attr],type:typ,data,offset:at+12,node:p,raw:b.slice(at,at+20)};node.attrs.push(v);values.push(v);}
  }else if(ch.kind===0x103){const name=u32(b,p+20);need(pool&&name<pool.length&&stack.pop()===pool[name],'XML nesting');}
 }
 need(pool&&!stack.length,'Incomplete XML');return {pool,map,nodes,values};
}
export async function addAttributes(source,specs){
 if(!specs.length)return source.slice();need(specs.every(s=>s.source_sha256===specs[0].source_sha256)&&await sha(source)===specs[0].source_sha256,'XML addition source hash');const parsed=parseXml(source),parts=chunks(source).map(c=>({...c,b:source.slice(c.p,c.p+c.size)})),poolPart=parts.filter(x=>x.kind===1),mapPart=parts.filter(x=>x.kind===0x180);need(poolPart.length===1&&mapPart.length===1,'XML pool/map count');
 const pool=poolPart[0].b,map=mapPart[0].b,oldStrings=parsed.pool.slice(),str=parsed.pool.slice(),resources=parsed.map.slice(),count=str.length,flags=u32(pool,16),start=u32(pool,20),utf8=!!(flags&256);need(u16(pool,2)===28&&!u32(pool,12)&&!u32(pool,24)&&start===28+count*4&&u16(map,2)===8,'Unsupported styled XML pool');const namespace=str.indexOf('http://schemas.android.com/apk/res/android');need(namespace>=0,'Android namespace');
 const offsets=Array.from({length:count},(_,i)=>u32(pool,28+4*i));let stringData=pool.slice(start);
 function nameIndex(name,attr){let i=str.findIndex((x,i)=>x===name&&resources[i]===attr);if(i>=0)return i;i=str.length;offsets.push(stringData.length);const raw=utf8?enc.encode(name):Uint8Array.from([...name].flatMap(c=>[c.charCodeAt(0)&255,c.charCodeAt(0)>>>8]));need(name.length<128&&raw.length<128,'Attribute name length');const len=utf8?new Uint8Array([name.length,raw.length]):new Uint8Array([name.length,0]);stringData=cat(stringData,len,raw,new Uint8Array(utf8?1:2));str.push(name);while(resources.length<=i)resources.push(0);resources[i]=attr;return i;}
 const found=new Set();
 for(const part of parts.filter(x=>x.kind===0x102)){
  const node=parsed.nodes.find(x=>x.p===part.p),selected=specs.map((s,i)=>[s,i]).filter(([s])=>s.path===node.path&&node.attrs.some(a=>a.attribute===0x10100d0&&a.data===Number(s.element_id)));
  if(!selected.length)continue;const old=part.b,n=node.attrs.length,start=u16(old,24);need(start===20,'XML attribute layout');const attrs=node.attrs.map((a,i)=>({b:a.raw,old:i,rid:a.attribute}));
  for(const [s,i] of selected){need(!found.has(i),'Ambiguous XML addition owner');found.add(i);const rid=Number(s.attribute);need(({[0x1010098]:'textColor',[0x10100d4]:'background'})[rid]===s.attribute_name&&!attrs.some(a=>a.rid===rid),'Duplicate/noncolor XML addition');const typ=Number(s.replacement[0]),val=Number(s.replacement[1]);need(typ===1||(typ===28&&val>>>24===255),'Color addition');const a=new Uint8Array(20);put32(a,0,namespace);put32(a,4,nameIndex(s.attribute_name,rid));put32(a,8,0xffffffff);put16(a,12,8);a[15]=typ;put32(a,16,val);attrs.push({b:a,old:null,rid});}
  attrs.sort((a,b)=>(a.rid||0x100000000)-(b.rid||0x100000000));need(attrs.filter(a=>a.old!==null).every((a,i)=>a.old===i),'Original XML order');part.b=cat(old.subarray(0,36),...attrs.map(a=>a.b),old.subarray(36+n*20));put32(part.b,4,part.b.length);put16(part.b,28,attrs.length);
  for(const at of [30,32,34]){const index=u16(old,at);put16(part.b,at,index?attrs.findIndex(a=>a.old===index-1)+1:0);}
 }
 need(found.size===specs.length,'Missing XML addition owner');stringData=cat(stringData,new Uint8Array((4-stringData.length%4)%4));const newPool=cat(pool.subarray(0,28),...offsets.map(le32),stringData);put32(newPool,4,newPool.length);put32(newPool,8,str.length);put32(newPool,20,28+4*str.length);need(JSON.stringify(strings(newPool).slice(0,count))===JSON.stringify(oldStrings),'Original XML strings changed');const newMap=cat(map.subarray(0,8),...resources.map(le32));put32(newMap,4,newMap.length);
 const result=cat(source.subarray(0,u16(source,2)),...parts.map(x=>x.kind===1?newPool:x.kind===0x180?newMap:x.b));put32(result,4,result.length);
 const after=parseXml(result);const semantic=a=>JSON.stringify([a.path,a.attribute,a.attribute_name,a.type,a.data]);const inventory=new Map();for(const a of after.values)inventory.set(semantic(a),(inventory.get(semantic(a))||0)+1);for(const a of parsed.values){const k=semantic(a),n=inventory.get(k)||0;need(n>0,'Original XML attribute changed');inventory.set(k,n-1);}need([...inventory.values()].reduce((a,b)=>a+b,0)===specs.length,'Unexpected XML additions');return result;
}
