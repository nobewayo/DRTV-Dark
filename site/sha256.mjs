// Incremental SHA-256, FIPS 180-4. Avoids whole-APK WebCrypto allocations.
// Independent oracle tests compare chunk boundaries and large data with SDK/Node.
import {need,read,abort,hex} from './binary.mjs';
const K=new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
const rotate=(x,n)=>(x>>>n)|(x<<(32-n));
export class Sha256{
 constructor(){this.h=new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);this.w=new Uint32Array(64);this.tail=new Uint8Array(64);this.used=0;this.length=0;this.finished=false;}
 block(b,p){const w=this.w;for(let i=0;i<16;i++)w[i]=((b[p++]<<24)|(b[p++]<<16)|(b[p++]<<8)|b[p++])>>>0;
  for(let i=16;i<64;i++){const x=w[i-15],y=w[i-2];w[i]=(w[i-16]+(rotate(x,7)^rotate(x,18)^(x>>>3))+w[i-7]+(rotate(y,17)^rotate(y,19)^(y>>>10)))>>>0;}
  let[a,b0,c,d,e,f,g,h]=this.h;for(let i=0;i<64;i++){const t1=(h+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+K[i]+w[i])>>>0,t2=((rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b0)^(a&c)^(b0&c)))>>>0;h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b0;b0=a;a=(t1+t2)>>>0;}const v=[a,b0,c,d,e,f,g,h];for(let i=0;i<8;i++)this.h[i]=(this.h[i]+v[i])>>>0;
 }
 update(b){need(!this.finished&&b instanceof Uint8Array,'SHA state');this.length+=b.length;need(Number.isSafeInteger(this.length),'SHA length');let p=0;if(this.used){const n=Math.min(64-this.used,b.length);this.tail.set(b.subarray(0,n),this.used);this.used+=n;p=n;if(this.used===64){this.block(this.tail,0);this.used=0;}}while(p+64<=b.length){this.block(b,p);p+=64;}if(p<b.length){this.tail.set(b.subarray(p),0);this.used=b.length-p;}return this;}
 finish(){need(!this.finished,'SHA already finished');const b=new Uint8Array(this.used<56?64:128);b.set(this.tail.subarray(0,this.used));b[this.used]=128;const v=new DataView(b.buffer),bits=this.length*8;v.setUint32(b.length-8,Math.floor(bits/4294967296));v.setUint32(b.length-4,bits>>>0);for(let p=0;p<b.length;p+=64)this.block(b,p);this.finished=true;const out=new Uint8Array(32),view=new DataView(out.buffer);for(let i=0;i<8;i++)view.setUint32(4*i,this.h[i]);return out;}
}
export async function shaBlob(blob,signal){const h=new Sha256();for(let p=0;p<blob.size;p+=262144){abort(signal);h.update(await read(blob,p,Math.min(p+262144,blob.size)));}abort(signal);return hex(h.finish());}
