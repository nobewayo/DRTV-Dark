import {need,u16,u32,read,sha,digest,hex,adler,put32,dec,range} from './binary.mjs';
function leb(b,state){let n=0;for(let i=0;i<5;i++){const x=range(b,state.p++,1)[0];need(i<4||x<16,'ULEB overflow');n+=(x&127)*2**(7*i);if(!(x&128))return n;}throw new Error('ULEB length');}
export async function dexHeader(b){need(['dex\n035\0','dex\n037\0','dex\n038\0','dex\n039\0'].includes(dec.decode(b.subarray(0,8)))&&u32(b,32)===b.length&&u32(b,36)===112&&u32(b,40)===0x12345678,'DEX header');need(hex(await digest(b.subarray(32),'SHA-1'))===hex(b.subarray(12,32))&&adler(b.subarray(12))===u32(b,8),'DEX checksums');}
export function methodOwners(b,wanted){
 const stringsN=u32(b,56),stringsAt=u32(b,60),typesN=u32(b,64),typesAt=u32(b,68),protosN=u32(b,72),protosAt=u32(b,76),methodsN=u32(b,88),methodsAt=u32(b,92),classesN=u32(b,96),classesAt=u32(b,100);range(b,stringsAt,stringsN*4);range(b,typesAt,typesN*4);range(b,protosAt,protosN*12);range(b,methodsAt,methodsN*8);range(b,classesAt,classesN*32);
 const cache=new Map();function string(i){need(i<stringsN,'DEX string index');if(cache.has(i))return cache.get(i);const st={p:u32(b,stringsAt+i*4)};leb(b,st);let end=st.p;while(end<b.length&&b[end]!==0)end++;need(end<b.length&&end-st.p<16384,'DEX string bounds');const raw=b.subarray(st.p,end);need(raw.every(x=>x<128),'Selected DEX identifier must be ASCII');const s=dec.decode(raw);cache.set(i,s);return s;}
 function type(i){need(i<typesN,'DEX type');return string(u32(b,typesAt+i*4));}
 function signature(i){need(i<methodsN,'DEX method');const p=methodsAt+i*8,proto=u16(b,p+2);need(proto<protosN,'DEX prototype');const q=protosAt+proto*12,at=u32(b,q+8);let parameters='';if(at){const count=u32(b,at);need(count<256,'DEX parameter count');for(let k=0;k<count;k++)parameters+=type(u16(b,at+4+2*k));}return type(u16(b,p))+'->'+string(u32(b,p+4))+'('+parameters+')'+type(u32(b,q+4));}
 const selected=new Map();for(let i=0;i<methodsN;i++){const s=signature(i);if(wanted.has(s)){need(!selected.has(s),'Duplicate DEX signature');selected.set(s,{index:i,signature:s});}}
 const result=new Map();for(let c=0;c<classesN;c++){
  const at=u32(b,classesAt+c*32+24);if(!at)continue;const st={p:at},sf=leb(b,st),inf=leb(b,st),direct=leb(b,st),virtual=leb(b,st);need(sf+inf+direct+virtual<1000000,'DEX class quota');for(let i=0;i<sf+inf;i++){leb(b,st);leb(b,st);}
  for(const count of [direct,virtual]){let index=0;for(let i=0;i<count;i++){index+=leb(b,st);const access=leb(b,st),code=leb(b,st);need(index<methodsN,'DEX encoded method index');const s=signature(index);if(wanted.has(s)){need(!result.has(s),'Duplicate DEX method implementation');let units=0,tries=0;if(code){range(b,code,16);units=u32(b,code+12);tries=u16(b,code+6);range(b,code+16,units*2);}result.set(s,{...selected.get(s),code,units,tries,access});}}}
 }
 need([...wanted].every(s=>selected.has(s)),'Missing DEX method reference');return {owners:result,references:selected};
}
export async function repairDex(b){b.set(await digest(b.subarray(32),'SHA-1'),12);put32(b,8,adler(b.subarray(12)));await dexHeader(b);return b;}
