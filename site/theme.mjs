// B13's optional signed extension leaves the accepted 110-site recipe immutable.
import {need,sha,hex} from './binary.mjs';
import {tableValues} from './resources.mjs';
import {parseXml} from './xml.mjs';
import {methodOwners} from './dex.mjs';
const DIALOG=['b14-dialog-control','b14-dialog-text'];
const B14=['b14-dialog','b14-sports-0','b14-sports-1','b14-sports-2','b14-window'];
const IDS=['b13-header-1','b13-promotion-1','b13-sport-subtext','b13-sport-text'];
export function themePlan(release){
 const p=release.themeCorrections;if(p===undefined)return null;
 need(release.identity&&((release.developmentOnly===true&&release.released===false)||(release.developmentOnly===false&&release.released===true&&release.signingProfile==='production'))&&p.schema===1&&p.baselineSites===110&&[114,119,121].includes(p.totalSites),'Theme extension identity/gates');
 const ids=p.totalSites===121?[...IDS,...B14,...DIALOG].sort():p.totalSites===119?[...IDS,...B14].sort():IDS;
 need(Array.isArray(p.sites)&&p.sites.length===ids.length&&p.sites.map(s=>s.id).sort().join('|')===ids.join('|'),'Exact theme sites');
 for(const s of p.sites){
  const sports=s.id.startsWith('b14-sports-'),dialog=DIALOG.includes(s.id);
  const file=sports?['res/layout/fragment_sports_detail.xml','res/layout/drshe1_view_holder.xml','res/layout-v22/drshe1_view_holder.xml'][Number(s.id.slice(-1))]:dialog?'res/layout/custom_dialog_fragment_item_simple_layout.xml':s.kind==='resource'?'resources.arsc':'classes4.dex';
  need(s.file===file&&s.kind===(sports?'xml-background':dialog?'xml-reference':s.id.includes('header')||s.id.includes('promotion')?'dex-hook':'resource'),'Theme file/kind');
 }

 return p;
}
export async function verifyThemeFile(bytes,name,release){
 const plan=themePlan(release);if(!plan)return [];
 const sites=plan.sites.filter(s=>s.file===name);if(!sites.length)return [];
 const resources=name==='resources.arsc'?tableValues(bytes):null;
 const methods=name==='classes4.dex'?methodOwners(bytes,new Set(sites.map(s=>s.method))):null;
 for(const s of sites){
  if(resources){
   const rows=resources.filter(v=>v.resource_id===s.resourceId&&v.config===s.config&&v.attribute===(s.id.startsWith('b14-')?s.attribute:0x1010098));
   need(rows.length===1&&rows[0].name===s.name&&rows[0].type===28&&rows[0].data===s.color,'B13 exact sports style');
  }else if(s.kind==='xml-background'||s.kind==='xml-reference'){
   const rows=parseXml(bytes).nodes.filter(n=>n.path===s.path).flatMap(n=>n.attrs).filter(a=>a.offset===s.offset&&a.attribute===s.attribute);
   if(s.kind==='xml-background')need(s.attribute===0x10100d4&&rows.length===1&&rows[0].type===28&&rows[0].data===s.color,'Exact structural XML background');
   else need(rows.length===1&&rows[0].type===1&&rows[0].data===s.reference&&s.attribute===(s.id==='b14-dialog-text'?0x1010098:0x10100d4)&&s.reference===(s.id==='b14-dialog-text'?0x7f060609:0x7f08009d),'Exact scoped dialog selector');
  }else{
   const m=methods.owners.get(s.method);need(m&&m.code===s.code&&m.units===s.units,'B13 presentation method owner');
   need(await sha(bytes.subarray(m.code+16,m.code+16+2*m.units))===s.methodSha256,'B13 complete method digest');
   need(s.offset>=m.code+16&&s.offset+6<=m.code+16+2*m.units&&hex(bytes.subarray(s.offset,s.offset+6))===s.instruction,'B13 hook instruction');
  }
 }
 return sites.map(s=>({id:s.id,file:name,kind:s.kind,applied:true,postPatch:{verified:true}}));
}
