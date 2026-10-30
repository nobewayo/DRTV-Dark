import {need,sha,hex,unhex,read,u16,u32,put32,abort,enc} from './binary.mjs';
import {openZip,unpack,writeZip} from './zip.mjs';

import {tableValues} from './resources.mjs';
import {parseXml,addAttributes} from './xml.mjs';
import {dexHeader,methodOwners,repairDex} from './dex.mjs';
const obsolete=n=>n.toUpperCase()==='META-INF/MANIFEST.MF'||n==='stamp-cert-sha256'||/^META-INF\/[^/]+\.(SF|RSA|DSA|EC)$/i.test(n);
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function selectValue(values,site){const s=site.selector;
 if(site.kind==='resource'){const rows=values.filter(v=>v.resource_id===Number(s.id)&&v.config===s.config&&v.attribute===(s.attribute?Number(s.attribute):null));need(rows.length===1&&rows[0].name===s.name,'Resource selector missing/ambiguous');return rows[0];}
 const rows=values.filter(v=>v.path===s.path&&v.attribute===Number(s.attribute)&&v.attribute_name===s.attribute_name);need(rows.length===s.matches&&Number.isInteger(s.occurrence)&&s.occurrence>=0&&s.occurrence<rows.length,'XML selector missing/ambiguous');return rows[s.occurrence];
}
function additionValue(parsed,site){const s=site.selector,nodes=parsed.nodes.filter(n=>n.path===s.path&&n.attrs.some(a=>a.attribute===0x10100d0&&a.data===Number(s.element_id)));need(nodes.length===1,'XML addition owner missing/ambiguous');const rows=nodes[0].attrs.filter(a=>a.attribute===Number(s.attribute)&&a.attribute_name===s.attribute_name);need(rows.length<=1,'Duplicate XML addition');return rows[0];}
export async function patchFile(source,name,recipe,{signal}={}){
 abort(signal);const config=recipe.files[name],sites=recipe.sites.filter(s=>s.file===name);need(config&&await sha(source)===config.source&&source.length===config.sourceSize,'Patch payload source mismatch: '+name);need(new Set(sites.map(s=>s.id)).size===sites.length,'Duplicate site');
 const additions=sites.filter(s=>s.kind==='addition'),beforeXml=additions.length?parseXml(source):null;for(const s of additions)need(!additionValue(beforeXml,s),'Addition already present');
 let result=await addAttributes(source,config.additions),values=name==='resources.arsc'?tableValues(result):name.endsWith('.xml')?parseXml(result).values:null;
 let methods;
 if(name.endsWith('.dex')){
  await dexHeader(source);const wanted=new Set(Object.keys(config.methods));methods=methodOwners(source,wanted);
  for(const [signature,proof] of Object.entries(config.methods)){
   const owner=methods.owners.get(signature);need(owner&&['code','units','tries','index'].every(k=>owner[k]===proof[k]),'DEX method ownership: '+signature);let p=proof.code+16;for(const i of proof.instructions){need(i.offset===p&&source[p]===i.opcode&&i.units>0,'DEX instruction boundary');p+=2*i.units;}need(p===proof.code+16+2*proof.units,'DEX instruction extent');
  }
  for(const s of sites){const owner=methods.owners.get(s.selector.method);need(owner&&await sha(source.subarray(owner.code+16,owner.code+16+2*owner.units))===s.selector.code_sha256,'DEX method instruction hash');}
 }
 const touched=new Set(),report=[];
 for(const site of sites){
  abort(signal);let observed,offset=site.offset;
  if(site.kind==='addition'){observed=null;report.push({...site,observedOriginal:observed,applied:true});continue;}
  let replacement;
  if(site.kind==='dex'){
   const s=site.selector,owner=methods.owners.get(s.method),proof=config.methods[s.method],old=unhex(site.expected);need(offset>=owner.code+16&&offset+old.length<=owner.code+16+owner.units*2,'DEX site outside owner');observed=hex(source.subarray(offset,offset+old.length));need(observed===site.expected,'DEX expected operand');replacement=unhex(site.replacement);
   if(s.action==='skip_color_override')need(s.method.endsWith(')V')&&owner.tries===0&&offset===owner.code+16&&old.length===proof.instructions[0].units*2,'Unsafe skip method');
   else if(s.action==='invoke_reference'){
    const expected=methods.references.get(s.expected),desired=methods.references.get(s.replacement);need(expected&&desired&&s.expected.split('(')[1]===s.replacement.split('(')[1],'DEX getter signature');const matches=proof.instructions.filter(i=>i.opcode===0x71&&u16(source,i.offset+2)===expected.index);need(matches.length===s.matches&&matches.some(i=>i.offset+2===offset)&&u16(replacement,0)===desired.index,'DEX getter match count');
   }else{
    const c=s.constant||s,expected=Number(c.expected),desired=Number(c.replacement),matches=proof.instructions.filter(i=>i.opcode===0x14&&i.units===3&&u32(source,i.offset+2)===expected);need(matches.length===1&&matches[0].offset+2===offset&&u32(replacement,0)===desired,'DEX constant match count');
   }
  }else{
   const v=selectValue(values,site);need(v.offset===offset,'Compiled selector offset mismatch');observed=[v.type,v.data];need(same(observed,site.expected)&&u16(result,offset)===8&&result[offset+2]===0,'Unexpected original typed value');need(site.replacement[0]===1||(site.replacement[0]===28&&site.replacement[1]>>>24===255),'Invalid replacement');replacement=result.slice(offset,offset+8);replacement[3]=site.replacement[0];put32(replacement,4,site.replacement[1]);
  }
  for(let j=0;j<replacement.length;j++){need(!touched.has(offset+j),'Overlapping mutation');touched.add(offset+j);}result.set(replacement,offset);report.push({...site,observedOriginal:observed,applied:true});
 }
 if(name.endsWith('.dex'))await repairDex(result);
 // Independent selectors are evaluated again on the completed bytes, then the whole
 // payload is compared with the immutable accepted-v0.14 digest.
 const afterValues=name==='resources.arsc'?tableValues(result):name.endsWith('.xml')?parseXml(result).values:null,afterXml=additions.length?parseXml(result):null;
 for(const row of report){let observed;if(row.kind==='addition'){const v=additionValue(afterXml,row);need(v,'Added attribute missing');observed=[v.type,v.data];}else if(row.kind==='dex')observed=hex(result.subarray(row.offset,row.offset+unhex(row.replacement).length));else{const v=selectValue(afterValues,row);observed=[v.type,v.data];}need(same(observed,row.replacement),'Post-patch site mismatch');row.postPatch={observed,verified:true};}
 need(result.length===config.targetSize&&await sha(result)===config.target,'Accepted v0.14 payload oracle mismatch: '+name);abort(signal);return {bytes:result,report};
}
