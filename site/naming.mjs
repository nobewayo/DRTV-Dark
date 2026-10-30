// Release naming from authenticated release metadata only. Renaming never touches bytes.
// A public name such as drtv-dark-v1.apks requires an explicitly released,
// non-development release with a plain DRTV Dark version (1, 1.1, 2 ...).
const VERSION=/^[1-9]\d{0,3}(\.\d{1,4}){0,2}$/;
export function publicVersion(release){return release&&release.released===true&&release.developmentOnly===false&&typeof release.darkVersion==='string'&&VERSION.test(release.darkVersion)?release.darkVersion:null;}
export function outputFilename(release){
 const version=publicVersion(release);if(version)return 'drtv-dark-v'+version+'.apks';
 const id=String(release?.id??'').toLowerCase().replace(/[^a-z0-9.-]+/g,'-').replace(/^[.-]+|[.-]+$/g,'')||'drtv-dark';
 return (id.includes('development')?id:id+'-development')+'.apks';
}
