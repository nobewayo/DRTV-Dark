// Offline canonical builder uses the exact browser implementation; no private key.
import fs from 'node:fs/promises';import path from 'node:path';
import {validateSelection,canonicalize} from '../site/engine.mjs';
import {read,sha} from '../site/binary.mjs';import {shaBlob} from '../site/sha256.mjs';
const [seedPath,recipePath,outPath,...inputPaths]=process.argv.slice(2),seed=JSON.parse(await fs.readFile(seedPath)),recipe=recipePath==='null'?null:JSON.parse(await fs.readFile(recipePath)),files=await Promise.all(inputPaths.map(async p=>new Blob([await fs.readFile(p)])));await fs.mkdir(outPath,{recursive:false});
const prepared=await validateSelection(files,seed),result=await canonicalize(prepared,recipe,seed);const summary={variant:prepared.variant,darkSites:result.darkSites,additional:result.additional,apks:[]};
for(const apk of result.apks){const p=path.join(outPath,apk.name);await fs.writeFile(p,await read(apk.blob));summary.apks.push({role:apk.role,name:apk.name,size:apk.blob.size,sha256:await shaBlob(apk.blob)});}
await fs.writeFile(path.join(outPath,'canonical-report.json'),JSON.stringify(summary,null,2));console.log(summary.apks);
