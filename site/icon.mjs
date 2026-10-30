// Deterministic color-only extension of the existing launcher icon system.
// Geometry, resolution and all neutral foreground pixels are preserved.
import {need,range,cat,crcBytes,adler,abort} from './binary.mjs';
const be=(b,p)=>new DataView(b.buffer,b.byteOffset,b.byteLength).getUint32(p,false);
function word(n){const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,false);return b;}
function chunk(name,b){const type=new TextEncoder().encode(name),data=cat(type,b);return cat(word(b.length),data,word((crcBytes(data)^0xffffffff)>>>0));}
function paeth(a,b,c){const p=a+b-c,pa=Math.abs(p-a),pb=Math.abs(p-b),pc=Math.abs(p-c);return pa<=pb&&pa<=pc?a:pb<=pc?b:c;}
export async function recolorIcon(png,{signal}={}){
 need(png.length<1024*1024&&[137,80,78,71,13,10,26,10].every((n,i)=>png[i]===n),'Icon PNG signature/size');
 let header,packed=[],ended=false;
 for(let p=8;p<png.length;){const n=be(png,p),type=new TextDecoder().decode(range(png,p+4,4)),data=range(png,p+8,n);need(be(png,p+8+n)===((crcBytes(range(png,p+4,n+4))^0xffffffff)>>>0),'Icon PNG CRC');
  if(type==='IHDR'){need(!header,'Icon duplicate header');header=data.slice();}
  else if(type==='IDAT')packed.push(data);
  else if(type==='IEND'){ended=true;need(p+12===png.length,'Icon PNG trailer');}
  else need((type.charCodeAt(0)&32)!==0,'Unknown critical PNG chunk');
  p+=n+12;
 }
 need(header?.length===13&&ended&&packed.length>0,'Icon PNG structure');
 const width=be(header,0),height=be(header,4);need(width===320&&height===180&&header[8]===8&&header[9]===2&&header[10]===0&&header[11]===0&&header[12]===0,'Pinned RGB TV banner format');
 const stride=width*3,size=(stride+1)*height,reader=new Blob(packed).stream().pipeThrough(new DecompressionStream('deflate')).getReader(),raw=new Uint8Array(size);let at=0;
 try{for(;;){abort(signal);const r=await reader.read();if(r.done)break;need(at+r.value.length<=size,'PNG expansion bound');raw.set(r.value,at);at+=r.value.length;}}
 finally{await reader.cancel().catch(()=>{});reader.releaseLock();}need(at===size,'PNG scanline size');
 const pixels=new Uint8Array(stride*height);
 for(let y=0;y<height;y++){const filter=raw[y*(stride+1)];need(filter<=4,'PNG row filter');for(let x=0;x<stride;x++){const p=y*stride+x,a=x>=3?pixels[p-3]:0,b=y?pixels[p-stride]:0,c=y&&x>=3?pixels[p-stride-3]:0;pixels[p]=(raw[y*(stride+1)+1+x]+([0,a,b,Math.floor((a+b)/2),paeth(a,b,c)][filter]))&255;}}
 let changed=0;
 for(let p=0;p<pixels.length;p+=3){const r=pixels[p],g=pixels[p+1],b=pixels[p+2];if(r>g&&r>b){const v=Math.round(g+(r-g)*36/255);pixels[p]=pixels[p+1]=pixels[p+2]=v;changed++;}else need(Math.max(r,g,b)-Math.min(r,g,b)<=2,'Unexpected non-neutral/non-red icon artwork');}
 need(changed>49000,'Pinned red icon background missing');
 const output=new Uint8Array(size);for(let y=0;y<height;y++)output.set(pixels.subarray(y*stride,(y+1)*stride),y*(stride+1)+1);
 // Stored DEFLATE avoids browser/SDK compressor differences and keeps output exact.
 const blocks=[];for(let p=0;p<output.length;p+=65535){const b=output.subarray(p,Math.min(p+65535,output.length)),n=b.length;blocks.push(new Uint8Array([p+n===output.length?1:0,n&255,n>>>8,(~n)&255,((~n)>>>8)&255]),b);}
 const zlib=cat(new Uint8Array([0x78,0x01]),...blocks,word(adler(output)));
 return cat(png.subarray(0,8),chunk('IHDR',header),chunk('IDAT',zlib),chunk('IEND',new Uint8Array()));
}
