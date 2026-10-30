// Offline and browser tests use the same authenticated, local-only product transaction.
import fs from 'node:fs/promises';
import {makeProduct} from '../site/engine.mjs';
const [folder,...inputs]=process.argv.slice(2);
const json=async p=>JSON.parse(await fs.readFile(p,'utf8'));
const result=await makeProduct(await Promise.all(inputs.map(async p=>new Blob([await fs.readFile(p)]))),await json('site/recipe.json'),await json(folder+'/release.json'),await json(folder+'/trust.json').catch(()=>json('site/trust.json')));
await fs.writeFile(folder+'/drtv-dark.apks',new Uint8Array(await result.blob.arrayBuffer()));
await fs.writeFile(folder+'/browser-transaction.json',JSON.stringify({...result,blob:undefined},null,2)+'\n');
console.log(JSON.stringify({sha256:result.hash,bytes:result.blob.size,darkSites:result.darkSites.length,identityChanges:result.additional.filter(x=>x.kind==='coexistence-identity').length}));
