import {authenticate} from './envelope.mjs';
import {sha,enc,need} from './binary.mjs';
import {validateSelection,makeProduct} from './engine.mjs';
let context;
self.onmessage=async({data})=>{try{
 if(data.operation==='validate'){
  const release=await authenticate(data.envelope,data.trust.releaseKey);need(release.commonCertificate===data.trust.commonCertificate,'Forkert udgivelse.');need(release.recipeSha256===await sha(enc.encode(JSON.stringify(data.recipe))),'Forkert opskrift.');
  context={...data,prepared:await validateSelection(data.files,release)};self.postMessage({kind:'validated',variant:context.prepared.variant});
 }else if(data.operation==='build'){
  need(context,'Vælg originalen igen.');const result=await makeProduct(context.files,context.recipe,context.envelope,context.trust,{prepared:context.prepared,progress:label=>self.postMessage({kind:'progress',label})});context=null;self.postMessage({kind:'ready',...result});self.close();
 }
}catch(error){context=null;self.postMessage({kind:'error',message:error instanceof RangeError?'Der er ikke nok hukommelse. Luk andre faner og prøv igen.':error.message});self.close();}};
