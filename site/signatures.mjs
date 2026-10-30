// Single RSA/SHA-256 signer, APK Signature Scheme v2 (Android API 24+).
import {need,cat,lp,le32,le64,field,u32,u64,read,enc,dec,digest,hex,put32,abort,range} from './binary.mjs';
import {parts} from './zip.mjs';
export function der(tag,...parts){const b=cat(...parts),n=b.length;need(n<65536,'DER limit');return cat(new Uint8Array([tag]),n<128?new Uint8Array([n]):n<256?new Uint8Array([0x81,n]):new Uint8Array([0x82,n>>>8,n&255]),b);}
const seq=(...x)=>der(0x30,...x),algorithm=seq(der(6,new Uint8Array([42,134,72,134,247,13,1,1,11])),der(5));
export function tlv(b,p=0){const tag=b[p++];let n=b[p++];if(n&128){const width=n&127;need(width>0&&width<=3,'DER length');n=0;for(let i=0;i<width;i++)n=n*256+b[p++];}range(b,p,n);return {tag,start:p,end:p+n,body:b.subarray(p,p+n)};}
export function certificateParts(cert){
 const outer=tlv(cert);need(outer.tag===48&&outer.end===cert.length,'Certificate sequence');const tbs=tlv(cert,outer.start);let p=tbs.start;
 let x=tlv(cert,p);if(x.tag===160)p=x.end;
 for(let i=0;i<5;i++)p=tlv(cert,p).end;
 const key=tlv(cert,p);need(key.tag===48&&key.end<=tbs.end,'Certificate SPKI');
 return {spki:cert.subarray(p,key.end),tbs:cert.subarray(outer.start,tbs.end),signature:tlv(cert,tlv(cert,tbs.end).end).body.subarray(1)};
}
export async function contentDigest(sections,signal){
 const chunks=[];
 for(const s of sections)for(let p=0;p<s.size;p+=1048576){abort(signal);const b=await read(s,p,Math.min(p+1048576,s.size));chunks.push(await digest(cat(new Uint8Array([0xa5]),le32(b.length),b)));}
 return digest(cat(new Uint8Array([0x5a]),le32(chunks.length),...chunks));
}
export async function verifyV2(blob,{certificate,signal,allowSdkPadding=true}={}){
 const z=await parts(blob);need(z.offset>=32,'Signing offset');const footer=await read(blob,z.offset-24,z.offset);need(dec.decode(footer.subarray(8))==='APK Sig Block 42','APK signing magic');
 const size=u64(footer,0),start=z.offset-size-8;need(size>=24&&size<=1048576&&start>=0,'APK signing bounds');const block=await read(blob,start,z.offset);need(u64(block,0)===size,'APK signing sizes');
 let p=8,v2;const ids=new Set();while(p<block.length-24){const n=u64(block,p),id=u32(block,p+8);need(n>=4&&p+8+n<=block.length-24&&!ids.has(id),'Signing pair bounds/duplicate');ids.add(id);if(id===0x7109871a)v2=range(block,p+12,n-4);p+=8+n;}
 need(p===block.length-24&&v2,'APK v2 missing');
 const exact=(b)=>{const [v,e]=field(b,0);need(e===b.length,'Trailing signature data');return v;};
 const signer=exact(exact(v2)),[sd,q]=field(signer,0),[signatures,r]=field(signer,q),[spki,end]=field(signer,r);need(end===signer.length,'Signer trailing data');
 const sigRecord=exact(signatures);need(u32(sigRecord,0)===0x103,'Only RSA PKCS1 SHA256 supported');const [sig,se]=field(sigRecord,4);need(se===sigRecord.length,'Signature record');
 // The installed SDK emits one authenticated zero uint32 after attributes.
 // It is covered by the RSA signature, not an unauthenticated ZIP exception.
 const [digests,cp]=field(sd,0),[certs,ap]=field(sd,cp),[attributes,ae]=field(sd,ap);need(ae===sd.length||(allowSdkPadding&&sd.length-ae===4&&sd.subarray(ae).every(x=>x===0)),'Signed data bounds');
 // Original may have authenticated attributes; exact source hash pins their interpretation.
 const cert=exact(certs),record=exact(digests);need(u32(record,0)===0x103,'Digest algorithm');const [expected,de]=field(record,4);need(de===record.length&&expected.length===32,'Digest record');
 if(certificate)need(hex(await digest(cert))===certificate,'Certificate fingerprint mismatch');
 need(hex(certificateParts(cert).spki)===hex(spki),'Certificate/public key mismatch');
 const key=await crypto.subtle.importKey('spki',spki,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 need(await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,sig,sd),'APK cryptographic signature mismatch');
 const adjusted=z.end.slice();put32(adjusted,16,start);const actual=await contentDigest([blob.slice(0,start),new Blob([z.cd]),new Blob([adjusted])],signal);need(hex(actual)===hex(expected),'APK content digest mismatch');abort(signal);
 return {cert,spki,fingerprint:hex(await digest(cert))};
}
