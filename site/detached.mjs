// Public precomputed signatures finalize exactly one canonical APK. No private key.
import {need,read,dec,put32,u64,hex} from './binary.mjs';
import {parts} from './zip.mjs';
import {verifyV2} from './signatures.mjs';
import {shaBlob} from './sha256.mjs';
export async function finalize(unsigned,material,{signal}={}){
 need(material.schema===1&&material.scheme==='APK-v2-RSA-SHA256'&&material.unsignedSize===unsigned.size,'Detached signature schema/size');need(await shaBlob(unsigned,signal)===material.unsignedSha256,'Canonical APK bytes do not match signed release');const z=await parts(unsigned);need(z.offset===material.centralDirectoryOffset,'Canonical ZIP layout mismatch');need(typeof material.block==='string'&&material.block.length<=1400000&&/^[A-Za-z0-9+/]+={0,2}$/.test(material.block),'Detached block encoding');
 const block=Uint8Array.from(atob(material.block),x=>x.charCodeAt(0));need(block.length>=32&&block.length<=1048576&&u64(block,0)===block.length-8&&u64(block,block.length-24)===block.length-8&&dec.decode(block.subarray(block.length-16))==='APK Sig Block 42','Detached block bounds');const end=z.end.slice();put32(end,16,z.offset+block.length);const signed=new Blob([unsigned.slice(0,z.offset),block,new Blob([z.cd]),end]);need(signed.size===material.signedSize,'Final APK size');const cert=await verifyV2(signed,{certificate:material.certificateSha256,signal});need(await shaBlob(signed,signal)===material.signedSha256,'Final APK release hash mismatch');return {blob:signed,certificate:cert.fingerprint};
}
