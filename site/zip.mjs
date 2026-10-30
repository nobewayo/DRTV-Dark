import {need,read,u16,u32,u64,put16,put32,enc,dec,crc,crcBytes,safeName,abort} from './binary.mjs';
export const LIMITS=Object.freeze({archive:128*1024*1024,entries:6000,entry:64*1024*1024,expanded:160*1024*1024,directory:2*1024*1024});
export async function parts(blob){
 need(blob instanceof Blob&&blob.size>=22&&blob.size<=LIMITS.archive,'Empty or oversized archive');
 const tail=await read(blob,Math.max(0,blob.size-65557));let p=tail.length-22;
 for(;p>=0;p--)if(u32(tail,p)===0x06054b50&&p+22+u16(tail,p+20)===tail.length)break;
 need(p>=0,'Missing ZIP directory');const end=tail.slice(p),offset=u32(end,16),size=u32(end,12),count=u16(end,10);
 need(!u16(end,4)&&!u16(end,6)&&u16(end,8)===count&&count>0&&count<=LIMITS.entries&&size<=LIMITS.directory&&offset+size+end.length===blob.size,'ZIP directory bounds/ZIP64');
 return {offset,size,count,end,cd:await read(blob,offset,offset+size)};
}
export async function openZip(blob,{apk=false,signal}={}){
 abort(signal);const z=await parts(blob),entries=new Map();let p=0,total=0;const spans=[];
 for(let i=0;i<z.count;i++){
  abort(signal);need(u32(z.cd,p)===0x02014b50,'Central header');const flags=u16(z.cd,p+8),method=u16(z.cd,p+10),checksum=u32(z.cd,p+16),packed=u32(z.cd,p+20),size=u32(z.cd,p+24),nl=u16(z.cd,p+28),el=u16(z.cd,p+30),cl=u16(z.cd,p+32),at=u32(z.cd,p+42);
  need(!(flags&~0x808)&&[0,8].includes(method)&&!u16(z.cd,p+34)&&packed<=LIMITS.entry&&size<=LIMITS.entry,'Unsupported flags, compression or entry quota');
  need(((u32(z.cd,p+38)>>>16)&0xf000)!==0xa000,'Symlink rejected');
  need(p+46+nl+el+cl<=z.cd.length,'Directory entry bounds');const name=safeName(dec.decode(z.cd.subarray(p+46,p+46+nl)));need(!entries.has(name),'Duplicate ZIP entry');
  total+=size;need(total<=LIMITS.expanded&&size<=Math.max(1048576,packed*200),'Decompression quota');
  need(at+30<=z.offset,'Local header bounds');const local=await read(blob,at,at+30),ln=u16(local,26),le=u16(local,28),start=at+30+ln+le,finish=start+packed;
  need(u32(local,0)===0x04034b50&&u16(local,6)===flags&&u16(local,8)===method&&ln===nl&&finish<=z.offset,'Local/central header mismatch');
  need(dec.decode(await read(blob,at+30,at+30+ln))===name,'Local name mismatch');
  if(!(flags&8))need(u32(local,14)===checksum&&u32(local,18)===packed&&u32(local,22)===size,'Local size/CRC mismatch');
  let end=finish;
  if(flags&8){const d=await read(blob,finish,Math.min(finish+16,z.offset)),q=u32(d,0)===0x08074b50?4:0;need(u32(d,q)===checksum&&u32(d,q+4)===packed&&u32(d,q+8)===size,'Descriptor mismatch');end+=q+12;}
  spans.push([at,end]);entries.set(name,{name,method,size,packed,checksum,start,data:blob.slice(start,finish)});p+=46+nl+el+cl;
 }
 need(p===z.cd.length,'Trailing central directory');spans.sort((a,b)=>a[0]-b[0]);let last=0;for(const [a,b] of spans){need(a===last&&b<=z.offset,'ZIP gap or overlap');last=b;}
 if(apk){
  const footer=await read(blob,z.offset-24,z.offset);need(dec.decode(footer.subarray(8))==='APK Sig Block 42','Missing APK signature block');const n=u64(footer,0),at=z.offset-n-8;
  need(n>=24&&n<=1024*1024&&at>=last&&at-last<=4096,'APK block bounds');need(u64(await read(blob,at,at+8),0)===n,'APK block size mismatch');
  if(at>last)need((await read(blob,last,at)).every(x=>x===0),'APK padding');z.signingStart=at;
 }else need(last===z.offset,'Unexpected ZIP gap');
 return {...z,blob,entries};
}
export async function unpack(entry,signal){
 abort(signal);let b;
 if(entry.method===0){need(entry.size===entry.packed,'STORE size mismatch');b=entry.data;}
 else {
  let stream;try{stream=entry.data.stream().pipeThrough(new DecompressionStream('deflate-raw'));}catch{throw new Error('Browseren understøtter ikke lokal udpakning. Brug en opdateret desktopbrowser.');}
  const reader=stream.getReader(),chunks=[];let total=0;
  try{while(true){abort(signal);const {done,value}=await reader.read();if(done)break;total+=value.length;need(total<=entry.size,'Inflated size quota');chunks.push(value);}}catch(e){await reader.cancel().catch(()=>{});throw e;}
  need(total===entry.size,'Inflated size mismatch');b=new Blob(chunks);
 }
 need(await crc(b,signal)===entry.checksum,'ZIP CRC mismatch');return b;
}
export async function writeZip(entries,{signal,apkAlignment=false}={}){
 need(entries.length>0&&entries.length<=LIMITS.entries,'ZIP entry count');let offset=0;const local=[],central=[],seen=new Set();
 for(const {name,data,checksum:knownChecksum} of entries){
  abort(signal);safeName(name);need(!seen.has(name),'Duplicate output entry');seen.add(name);need(data instanceof Blob&&data.size<=LIMITS.entry,'Output entry quota');
  const n=enc.encode(name),checksum=knownChecksum===undefined?await crc(data,signal):knownChecksum,pad=(4-(offset+30+n.length+4)%4)%4,extra=new Uint8Array(4+pad),h=new Uint8Array(30),c=new Uint8Array(46);
  put16(extra,0,0xcafe);put16(extra,2,pad);put32(h,0,0x04034b50);put16(h,4,20);put16(h,6,0x800);put16(h,12,0x21);put32(h,14,checksum);put32(h,18,data.size);put32(h,22,data.size);put16(h,26,n.length);put16(h,28,extra.length);
  put32(c,0,0x02014b50);put16(c,4,20);put16(c,6,20);put16(c,8,0x800);put16(c,14,0x21);put32(c,16,checksum);put32(c,20,data.size);put32(c,24,data.size);put16(c,28,n.length);put32(c,42,offset);
  local.push(h,n,extra,data);central.push(c,n);offset+=30+n.length+extra.length+data.size;need(offset<LIMITS.archive,'Output quota');
 }
 // SDK apksigner aligns the signing-block start to 4096 bytes. Make that
 // padding part of the canonical unsigned input, so it rewrites no content.
 if(apkAlignment){const pad=(4096-offset%4096)%4096;if(pad){local.push(new Uint8Array(pad));offset+=pad;}}
 const cd=new Blob(central),end=new Uint8Array(22);put32(end,0,0x06054b50);put16(end,8,entries.length);put16(end,10,entries.length);put32(end,12,cd.size);put32(end,16,offset);
 const result=new Blob([...local,cd,end]);need(result.size<=LIMITS.archive,'Archive output quota');return result;
}
