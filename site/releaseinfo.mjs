// Every version-dependent text and link on the page comes from here, derived only from
// the authenticated release envelope. No page file may hardcode a DRTV or DRTV Dark
// version: a new release is a new signed envelope, never a copy edit.
import {need} from './binary.mjs';
import {publicVersion,outputFilename} from './naming.mjs';
import {checkIdentityPlan} from './identity.mjs';

export const DR_PACKAGE = 'dk.dr.tvplayer';
const SOURCE = 'https://d.apkpure.net/b/XAPK/';
const CONFIG = 'assets/drtv-dark-release.json';
const TEXT = /^[A-Za-z0-9.-]{1,64}$/;
const MONTHS = ['januar', 'februar', 'marts', 'april', 'maj', 'juni', 'juli', 'august', 'september', 'oktober', 'november', 'december'];

export function danishDate(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso || ''), d = m && new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  return d && d.getUTCMonth() === Number(m[2]) - 1 && d.getUTCDate() === Number(m[3]) ? d.getUTCDate() + '. ' + MONTHS[d.getUTCMonth()] + ' ' + m[1] : '';
}

// The notifier configuration that ends up inside the APK this release produces.
function embedded(release) {
  const assets = (release.notifier?.assets || []).filter(a => a.name === CONFIG);
  if (!assets.length) return null;
  need(assets.length === 1, 'Forkert udgivelse.');
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(assets[0].base64), c => c.charCodeAt(0))));
}

// Fails closed when the signed facts disagree with each other, so the page can never
// show a version other than the one inside the file it produces.
export function describeRelease(release) {
  checkIdentityPlan(release);
  need(release && typeof release.package === 'string' && TEXT.test(release.versionName) && Number.isSafeInteger(release.versionCode) && release.versionCode > 0, 'Forkert udgivelse.');
  const inside = embedded(release);
  if (inside) {
    need(inside.original?.package === (release.sourcePackage??release.package) && (inside.applicationPackage??inside.original?.package) === release.package && inside.original?.versionName === release.versionName && inside.original?.versionCode === release.versionCode, 'Forkert udgivelse.');
    need(release.darkVersion === undefined || release.darkVersion === inside.darkVersion, 'Forkert udgivelse.');
  }
  const darkVersion = publicVersion(release);
  // A public release must state what the APK states; development envelopes may predate the field.
  need(!darkVersion || inside?.darkVersion === darkVersion, 'Forkert udgivelse.');
  const changes = Array.isArray(release.changes) ? release.changes.filter(c => c && TEXT.test(c.version) && typeof c.text === 'string' && c.text.length <= 400) : [];
  return {
    drVersion: release.versionName,
    drVersionCode: release.versionCode,
    darkVersion,
    releaseDate: darkVersion ? danishDate(release.releaseDate) : '',
    changes: darkVersion ? changes.map(c => ({version: c.version, date: danishDate(c.date), text: c.text})) : [],
    filename: outputFilename(release),
    coexistence: release.sourcePackage === DR_PACKAGE && release.package !== DR_PACKAGE,
    sourceUrl: (release.sourcePackage??release.package) === DR_PACKAGE ? SOURCE + DR_PACKAGE + '?versionCode=' + release.versionCode : null
  };
}

// Keep the approved nine-step layout. Only the first installation instruction
// changes for the authenticated independent package; the old model stays intact.
export function guideForRelease(info, steps) {
  if (!info?.coexistence) return steps;
  return steps.map((step, i) => i === 7 ? {...step,
    text: 'TV’et spørger, om DRTV Dark skal installeres. Cancel er valgt fra start. Tryk til venstre og derefter OK for at vælge Install.'
  } : i ? step : {...step,
    title: 'Behold DRTV',
    text: 'Den almindelige DRTV-app kan blive installeret som reserve, hvis DRTV Dark en dag ikke virker. Fortsæt til næste trin.',
    src: '', alt: '', caption: ''});
}

// The Danish copy that names a version. Without an authenticated release it names none.
export function versionCopy(info, processingEnabled) {
  const v = info?.drVersion;
  return {
    header: info?.darkVersion && processingEnabled ? 'Version ' + info.darkVersion + (info.releaseDate ? ', ' + info.releaseDate : '') : processingEnabled ? 'Prøveudgave, ikke udgivet' : 'Ikke udgivet endnu',
    download: v ? 'Hent DRTV ' + v : 'Hent DRTV',
    rejected: v ? 'Filen passer ikke. Brug DRTV ' + v + ' fra linket i trin 1.' : 'Filen passer ikke. Brug DRTV fra linket i trin 1.',
    faqWrongFile: v ? 'Kun DRTV ' + v + ' til Android TV virker. Hent den fra linket i trin 1.' : 'Kun den version af DRTV, som linket i trin 1 henter, virker.'
  };
}
