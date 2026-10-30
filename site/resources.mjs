// Strict table selectors mirror tools/resources.py. Sparse/16-bit offsets fail closed.
import {need,u16,u32,hex,range} from './binary.mjs';
import {chunks,strings} from './xml.mjs';
export function tableValues(b){
 need(u16(b,0)===2&&u16(b,2)>=12&&u32(b,4)===b.length,'Resource table header');const result=[],owners=new Set();let packages=0,globals;
 for(const part of chunks(b)){
  const p=part.p;
  if(part.kind===1){need(!globals,'Duplicate global pool');globals=strings(b,p);}
  if(part.kind!==0x200)continue;packages++;need(part.header>=284,'Package header');const pkg=u32(b,p+8),types=strings(b,p+u32(b,p+268)),keys=strings(b,p+u32(b,p+276)),typeOffset=part.header>=288?u32(b,p+284):0,specs=new Map(),configs=new Set();
  for(const ch of chunks(b,p+part.header,p+part.size)){
   const q=ch.p;if(ch.kind===0x202){const tid=b[q+8],n=u32(b,q+12);need(!specs.has(tid)&&ch.header+n*4<=ch.size,'Type spec');specs.set(tid,n);}
   if(ch.kind!==0x201)continue;const tid=b[q+8],flags=b[q+9],n=u32(b,q+12),start=u32(b,q+16),configSize=u32(b,q+20);need(flags===0&&configSize>=4&&20+configSize<=ch.header,'Unsupported resource configuration');const config=hex(range(b,q+20,configSize)),ck=tid+':'+config;need(!configs.has(ck),'Duplicate type/config');configs.add(ck);need(specs.has(tid)&&n<=specs.get(tid)&&tid>0&&tid<=types.length&&ch.header+n*4<=start&&start<=ch.size,'Resource entry index');const indexed=[];
   for(let i=0;i<n;i++){const off=u32(b,q+ch.header+4*i);if(off!==0xffffffff){need(off%4===0&&q+start+off+8<=q+ch.size,'Resource offset');indexed.push([off,i]);}}
   indexed.sort((a,b)=>a[0]-b[0]);need(new Set(indexed.map(a=>a[0])).size===indexed.length,'Aliased entries');
   for(let j=0;j<indexed.length;j++){
    const [off,index]=indexed[j],e=q+start+off,boundary=j+1<indexed.length?q+start+indexed[j+1][0]:q+ch.size,es=u16(b,e),ef=u16(b,e+2),key=u32(b,e+4),rid=((pkg<<24)|((tid+typeOffset)<<16)|index)>>>0,name=types[tid-1]+'/'+keys[key];need(!(ef&~7)&&es>=(ef&1?16:8)&&e+es<=boundary&&key<keys.length,'Resource entry');const owner=rid+':'+config;need(!owners.has(owner),'Duplicate resource owner');owners.add(owner);
    function value(pos,attribute){need(pos+8<=boundary&&u16(b,pos)===8&&b[pos+2]===0,'Resource typed value');result.push({resource_id:rid,name,config,attribute,offset:pos,type:b[pos+3],data:u32(b,pos+4)});}
    if(ef&1){const maps=u32(b,e+12),seen=new Set();need(e+es+maps*12<=boundary,'Complex map bounds');for(let m=0;m<maps;m++){const pos=e+es+m*12,attr=u32(b,pos);need(!seen.has(attr),'Duplicate complex attribute');seen.add(attr);value(pos+4,attr);}}
    else value(e+es,null);
   }
  }
 }
 need(packages===u32(b,8)&&globals,'Package/global pool count');for(const v of result)if(v.type===3)need(v.data<globals.length,'Global string reference');return result;
}
