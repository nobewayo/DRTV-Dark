// Bounded binary helpers shared by the local engine. No network or filesystem APIs.
export const enc=new TextEncoder(), dec=new TextDecoder('utf-8',{fatal:true});
export function need(ok,message){if(!ok)throw new Error(message);}
export function view(b){return new DataView(b.buffer,b.byteOffset,b.byteLength);}
export function range(b,p,n){need(Number.isSafeInteger(p)&&Number.isSafeInteger(n)&&p>=0&&n>=0&&p+n<=b.length,'Binary bounds');return b.subarray(p,p+n);}
export function u16(b,p){range(b,p,2);return view(b).getUint16(p,true);}
export function u32(b,p){range(b,p,4);return view(b).getUint32(p,true);}
export function u64(b,p){need(u32(b,p+4)===0,'ZIP64/large integer unsupported');return u32(b,p);}
export function put16(b,p,n){range(b,p,2);view(b).setUint16(p,n,true);}
export function put32(b,p,n){range(b,p,4);view(b).setUint32(p,n,true);}
export function le32(n){const b=new Uint8Array(4);put32(b,0,n);return b;}
export const le64=n=>cat(le32(n),le32(0));
export function cat(...parts){const n=parts.reduce((a,b)=>a+b.length,0);need(n<256*1024*1024,'Allocation budget');const out=new Uint8Array(n);let p=0;for(const b of parts){out.set(b,p);p+=b.length;}return out;}
export const lp=b=>cat(le32(b.length),b);
export function field(b,p){const n=u32(b,p);return [range(b,p+4,n),p+4+n];}
export const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
export function unhex(s){need(typeof s==='string'&&/^(?:[0-9a-f]{2})*$/.test(s),'Invalid hexadecimal');return Uint8Array.from(s.match(/../g)||[],x=>parseInt(x,16));}
export const digest=async(b,algorithm='SHA-256')=>new Uint8Array(await crypto.subtle.digest(algorithm,b));
export const sha=async b=>hex(await digest(b));
export async function read(blob,a=0,b=blob.size){need(a>=0&&b>=a&&b<=blob.size,'Blob bounds');return new Uint8Array(await blob.slice(a,b).arrayBuffer());}
export function abort(signal){if(signal?.aborted)throw new DOMException('Annulleret. Ingen pakke gemt.','AbortError');}
const table=new Uint32Array(256);
for(let n=0;n<256;n++){let c=n;for(let j=0;j<8;j++)c=c&1?0xedb88320^(c>>>1):c>>>1;table[n]=c>>>0;}
export function crcBytes(b,c=0xffffffff){for(const x of b)c=table[(c^x)&255]^(c>>>8);return c>>>0;}
export async function crc(blob,signal){let c=0xffffffff;for(let p=0;p<blob.size;p+=1048576){abort(signal);c=crcBytes(await read(blob,p,Math.min(p+1048576,blob.size)),c);}return (c^0xffffffff)>>>0;}
export function adler(b){let a=1,c=0;for(let p=0;p<b.length;p+=5552){for(const x of b.subarray(p,p+5552)){a+=x;c+=a;}a%=65521;c%=65521;}return ((c<<16)|a)>>>0;}
export function safeName(n){need(typeof n==='string'&&n.length>0&&n.length<=240&&/^[A-Za-z0-9_+.$@() /-]+$/.test(n)&&!n.startsWith('/')&&!n.split('/').some(x=>!x||x==='.'||x==='..'),'Unsafe archive path');return n;}
