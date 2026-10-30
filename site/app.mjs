// Website UI. Layout and interaction follow the approved prototype; file checks,
// processing and the download come from the verified worker/engine only.
import {sha,need} from './binary.mjs';
import {authenticate} from './envelope.mjs';
import {describeRelease,versionCopy,guideForRelease} from './releaseinfo.mjs';

const $ = id => document.getElementById(id);

// ---------- content ----------
const PLAY_DOWNLOADER = 'https://play.google.com/store/apps/details?id=com.downloader.tv.installer.xapk';
const FAQ = [
  {q: 'Hvilke TV virker det på?', a: 'Det kræver Google TV eller Android TV 7 eller nyere, fx en Chromecast med Google TV. Apple TV kan ikke bruges. Ikke alle TV er afprøvet.'},
  {q: 'Kan en telefon bruges?', a: 'Ja, men det er lettest fra en computer.'},
  {q: 'Skal den almindelige DRTV-app fjernes?', a: 'Nej. DRTV Dark er en selvstændig app og kan installeres ved siden af DRTV.'},
  {q: 'Downloader kan ikke findes', a: 'Søg efter Downloader TV: APK Installer fra Smartago i Google Play på TV’et. Du kan også se den på {link}.', link: {text: 'Google Play', href: PLAY_DOWNLOADER}},
  {q: 'Siden siger, at filen ikke passer', a: () => copy.faqWrongFile},
  {q: 'Er hele appen mørk?', a: 'Næsten. Enkelte skærme kan stadig være lyse.'},
  {q: 'Hvordan opdateres DRTV Dark?', a: 'Appen giver besked, når der er en ny version. Der kan også søges manuelt via knappen DRTV Dark nederst på forsiden i appen.'}
];
// Engine stage labels shown with the prototype's three user-facing words.
const STAGE = {'Validerer': 'Kontrollerer filen', 'Gør den mørk': 'Gør den mørk', 'Færdiggør': 'Færdiggør', 'Pakker': 'Færdiggør', 'Slutkontrol': 'Færdiggør', 'Færdig': 'Færdiggør'};

// ---------- state ----------
// step: 0 home, 1-3 make the file, 4..3+guide.length TV guide, last = done.
// check: none | checking | ok | bad.  stage: idle | run | done | err.
const S = {step: 0, files: null, check: 'none', stage: 'idle', label: '', error: '', detail: '', dl1: false, dl3: false, outName: '', outSize: 0};
let guide = [], config = null, trust, recipe, envelope, worker = null, token = 0, outputUrl = null, auditUrl = null, startupError = '';
// Version-dependent copy; it names no version until a release is authenticated.
let copy = versionCopy(null, false);
const last = () => guide.length + 4;

// ---------- FAQ ----------
const chevron = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#8b8e95" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>';
FAQ.forEach((f, i) => {
  const item = document.createElement('div'), btn = document.createElement('button'), ans = document.createElement('p');
  item.className = 'faq-item';
  btn.className = 'q'; btn.type = 'button'; btn.id = 'q' + i;
  btn.setAttribute('aria-expanded', 'false'); btn.setAttribute('aria-controls', 'a' + i);
  btn.innerHTML = '<span></span>' + chevron;
  btn.firstChild.textContent = f.q;
  ans.className = 'a'; ans.id = 'a' + i; ans.hidden = true;
  fillAnswer(f, ans);
  btn.addEventListener('click', () => openFaq(i, btn.getAttribute('aria-expanded') !== 'true'));
  item.append(btn, ans);
  $('faqList').append(item);
});
function fillAnswer(f, ans) {
  const [head, ...rest] = (typeof f.a === 'function' ? f.a() : f.a).split('{link}');
  ans.replaceChildren(head);
  if (f.link) {
    const a = document.createElement('a');
    a.href = f.link.href; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = f.link.text;
    ans.append(a, rest.join(''));
  }
}
function openFaq(i, open) {
  FAQ.forEach((_, j) => {
    const o = open && j === i;
    $('q' + j).setAttribute('aria-expanded', String(o));
    $('a' + j).hidden = !o;
  });
}

// ---------- progress ----------
function segs(el, n) {
  el.replaceChildren();
  for (let i = 0; i < n; i++) { const d = document.createElement('div'); d.className = 'seg'; el.append(d); }
  el.style.gridTemplateColumns = 'repeat(' + n + ',minmax(0,1fr))';
}
function buildProgress() {
  segs($('segA'), 3); segs($('segB'), guide.length);
  // Keep the prototype's per-segment proportions when the guide has another length.
  $('segB').parentElement.style.flex = guide.length + ' 1 220px';
}

// ---------- navigation ----------
function scrollToTopIfNeeded() {
  const el = S.step === 0 ? $('top') : $('flowTop'), r = el.getBoundingClientRect();
  if (r.top < 0 || r.top > window.innerHeight * 0.6) el.scrollIntoView({behavior: 'smooth', block: 'start'});
}
function goTo(n) {
  S.step = Math.max(0, Math.min(last(), n));
  render();
  requestAnimationFrame(scrollToTopIfNeeded);
  const h = document.querySelector(S.step === 0 ? '#home h1' : '#flow .step:not([hidden]) h1');
  if (h) { h.setAttribute('tabindex', '-1'); h.focus({preventScroll: true}); }
}

function render() {
  const n = S.step, G = guide.length;
  $('home').hidden = n !== 0;
  $('flow').hidden = n === 0;
  if (n === 0) return;

  // progress
  const a = $('segA').children, b = $('segB').children;
  for (let i = 0; i < 3; i++) a[i].classList.toggle('on', n >= i + 1);
  for (let j = 0; j < G; j++) b[j].classList.toggle('on', n >= j + 4);
  $('p1lbl').classList.toggle('on', n <= 3);
  $('p2lbl').classList.toggle('on', n >= 4);

  // which step section
  document.querySelectorAll('#flow .step').forEach(sec => {
    const k = sec.getAttribute('data-step');
    sec.hidden = !((k === 'guide' && n >= 4 && n <= G + 3) || (k === 'done' && n === last()) || k === String(n));
  });

  // step 2
  const off = !!startupError || !config;
  $('fileInput').disabled = off;
  $('pick').classList.toggle('off', off);
  $('pick').hidden = !!S.files;
  $('fileChip').hidden = !S.files;
  $('pickError').hidden = !startupError;
  $('pickError').textContent = startupError;
  if (S.files) {
    $('fileName').textContent = S.files.map(f => f.name).join(' + ');
    $('fileStatus').textContent = S.check === 'checking' ? 'Kontrollerer filen…' : S.check === 'ok' ? 'Filen er godkendt.' : S.check === 'bad' ? S.error : '';
    $('fileChip').classList.toggle('wait', S.check === 'checking');
    $('fileChip').classList.toggle('bad', S.check === 'bad');
    $('fileChip').title = S.check === 'bad' && S.detail !== S.error ? 'Teknisk: ' + S.detail : '';
  }

  // step 3
  const enabled = !!config?.processingEnabled;
  $('s3idle').hidden = S.stage !== 'idle';
  $('s3run').hidden = S.stage !== 'run';
  $('s3done').hidden = S.stage !== 'done';
  $('s3err').hidden = S.stage !== 'err';
  $('runBtn').disabled = !enabled || S.check !== 'ok';
  $('gateText').hidden = enabled;
  $('statusText').textContent = S.label;
  $('errText').textContent = S.error;
  $('errDetail').textContent = S.detail && S.detail !== S.error ? 'Teknisk: ' + S.detail : '';
  $('dl3Text').textContent = S.dl3 ? 'Gemt.' : S.outName + ', ' + (S.outSize >= 1048576 ? Math.round(S.outSize / 1048576) + ' MB' : Math.ceil(S.outSize / 1024) + ' kB');

  // guide
  if (n >= 4 && n <= G + 3) {
    const g = guide[n - 4];
    $('gKicker').textContent = (g.where === 'device' ? 'På telefonen eller computeren' : 'På TV’et') + ', trin ' + (n - 3) + ' af ' + G;
    $('gTitle').textContent = g.title;
    $('gText').textContent = g.text.replaceAll('{fil}', S.outName || 'DRTV Dark-filen');
    $('gApp').hidden = !g.app;
    // A step may deliberately have no screenshot.
    $('gShot').parentElement.hidden = !g.src;
    $('gCaption').hidden = !g.caption;
    if (g.src && $('gShot').getAttribute('src') !== g.src) $('gShot').src = g.src;
    $('gShot').alt = g.alt;
    $('gCaption').textContent = g.caption;
  }

  // nav bar
  const next = $('nextBtn');
  next.hidden = n === last();
  $('homeEndBtn').hidden = n !== last();
  next.textContent = n === 1 ? 'Filen er hentet' : n === 3 ? 'Installer den på TV’et' : n === G + 3 ? 'Færdig' : 'Videre';
  next.disabled = (n === 2 && S.check !== 'ok') || (n === 3 && S.stage !== 'done');
  const quiet = (n === 1 && !S.dl1) || (n === 3 && !S.dl3);
  next.className = quiet ? 'out' : 'go';
}

// ---------- real processing ----------
// The engine's own Danish messages are shown as they are; its English technical
// messages are replaced by plain Danish and kept as detail.
const DANISH = /^(Vælg|Ukendt|Denne|Filen|For mange|Forkert|Originalens|Der er|Behandlingen|Din browser)/;
const SPECIFIC = /hukommelse|afbrudt|browser/i;
function friendly(message) {
  return DANISH.test(message) ? message : 'Filen kunne ikke behandles. Vælg den originale fil igen.';
}
// A rejected source always reads like the FAQ answer, unless the browser itself failed.
function rejected(message) {
  return SPECIFIC.test(message) ? message : copy.rejected;
}
function revoke() {
  for (const u of [outputUrl, auditUrl]) if (u) URL.revokeObjectURL(u);
  outputUrl = auditUrl = null;
  $('dl3').removeAttribute('href'); $('audit').removeAttribute('href');
}
function stopWorker() { ++token; worker?.terminate(); worker = null; }

// Starts a worker for the chosen files. With build=true it continues straight
// into processing after the source is admitted again (retry or after cancel).
function startWorker(build) {
  stopWorker();
  const own = token, files = S.files;
  worker = new Worker(new URL('./worker.mjs', import.meta.url), {type: 'module'});
  const failed = message => {
    if (own !== token) return;
    worker?.terminate(); worker = null;
    if (S.stage === 'run') { S.stage = 'err'; S.error = friendly(message); S.detail = message; }
    else { S.check = 'bad'; S.error = rejected(message); S.detail = message; }
    render();
  };
  worker.onerror = () => failed('Behandlingen blev afbrudt. Vælg filen igen.');
  worker.onmessage = ({data}) => {
    if (own !== token) return;
    if (data.kind === 'validated') {
      S.check = 'ok';
      if (build && config.processingEnabled) { S.label = STAGE['Gør den mørk']; worker.postMessage({operation: 'build'}); }
      render();
    } else if (data.kind === 'progress') {
      S.label = STAGE[data.label] ?? S.label; render();
    } else if (data.kind === 'error') {
      failed(data.message);
    } else if (data.kind === 'ready') {
      worker = null;
      revoke();
      outputUrl = URL.createObjectURL(data.blob);
      $('dl3').href = outputUrl; $('dl3').download = data.filename;
      const audit = {sha256: data.hash, filename: data.filename, certificate: data.certificate, variant: data.variant, darkSites: data.darkSites, additional: data.additional, metrics: data.metrics};
      auditUrl = URL.createObjectURL(new Blob([JSON.stringify(audit, null, 2)], {type: 'application/json'}));
      $('audit').href = auditUrl;
      S.outName = data.filename; S.outSize = data.blob.size; S.stage = 'done'; S.dl3 = false;
      render();
    }
  };
  worker.postMessage({operation: 'validate', files, recipe, envelope, trust});
}
function choose(list) {
  const files = [...(list || [])];
  if (!files.length || !config || startupError) return;
  revoke();
  S.files = files; S.check = 'checking'; S.stage = 'idle'; S.dl3 = false; S.outName = ''; S.error = S.detail = '';
  startWorker(false);
  render();
}
function runBuild() {
  if (!config?.processingEnabled || S.check !== 'ok' || S.stage === 'run') return;
  S.stage = 'run'; S.label = STAGE['Validerer']; S.error = S.detail = '';
  // The validating worker holds the admitted source; reuse it, otherwise admit again.
  if (worker) { S.label = STAGE['Gør den mørk']; worker.postMessage({operation: 'build'}); } else startWorker(true);
  render();
}
function resetFlow() {
  stopWorker(); revoke();
  S.files = null; S.check = 'none'; S.stage = 'idle'; S.dl1 = S.dl3 = false; S.outName = ''; S.error = S.detail = '';
  $('fileInput').value = '';
}

// ---------- events ----------
$('homeBtn').addEventListener('click', () => goTo(0));
$('startBtn').addEventListener('click', () => goTo(1));
$('nextBtn').addEventListener('click', () => goTo(S.step + 1));
$('backBtn').addEventListener('click', () => goTo(S.step - 1));
$('homeEndBtn').addEventListener('click', () => { resetFlow(); goTo(0); });
$('askTvBtn').addEventListener('click', () => { openFaq(0, true); $('faq').scrollIntoView({behavior: 'smooth', block: 'start'}); });
$('logBtn').addEventListener('click', function () {
  const open = $('changelog').hidden;
  $('changelog').hidden = !open;
  this.setAttribute('aria-expanded', String(open));
});
$('dl1').addEventListener('click', () => { S.dl1 = true; render(); });
$('dl3').addEventListener('click', e => { if (!outputUrl) { e.preventDefault(); return; } S.dl3 = true; render(); });
$('audit').addEventListener('click', e => { if (!auditUrl) e.preventDefault(); });
$('runBtn').addEventListener('click', runBuild);
$('retryBtn').addEventListener('click', () => { S.stage = 'idle'; runBuild(); if (S.stage !== 'run') render(); });
$('cancelBtn').addEventListener('click', () => { stopWorker(); S.stage = 'idle'; render(); });
$('fileInput').addEventListener('change', function () { choose(this.files); });
$('unpick').addEventListener('click', () => {
  stopWorker(); revoke();
  S.files = null; S.check = 'none'; S.stage = 'idle'; S.dl3 = false; S.outName = '';
  $('fileInput').value = ''; render();
  $('fileInput').focus();
});
const pick = $('pick');
['dragenter', 'dragover'].forEach(ev => pick.addEventListener(ev, e => { e.preventDefault(); if (!$('fileInput').disabled) pick.classList.add('drag'); }));
['dragleave', 'drop'].forEach(ev => pick.addEventListener(ev, e => { e.preventDefault(); pick.classList.remove('drag'); }));
pick.addEventListener('drop', e => { if (!$('fileInput').disabled) choose(e.dataTransfer.files); });
// A file dropped beside the target must not make the browser open it and lose the flow.
['dragover', 'drop'].forEach(ev => window.addEventListener(ev, e => { if (!pick.contains(e.target)) e.preventDefault(); }));
window.addEventListener('pagehide', () => { stopWorker(); revoke(); });

// ---------- before/after sliders ----------
// All sliders share one position. Phone: one frame alternates between two pairs.
const frames = [...document.querySelectorAll('[data-cmp]')];
const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const PERIOD = 8;
let t = 0, pos = 86, pauseUntil = 0, lastTime = performance.now(), pair = 0;
function paint() {
  frames.forEach(f => {
    f.querySelectorAll('[data-after]').forEach(img => { img.style.clipPath = 'inset(0 0 0 ' + pos + '%)'; });
    f.querySelector('.line').style.left = pos + '%';
    f.querySelector('.knob').style.left = pos + '%';
    const inp = f.querySelector('input'); if (document.activeElement !== inp) inp.value = pos;
  });
  document.querySelectorAll('.mob [data-pair]').forEach(p => {
    p.style.opacity = String(Number(p.getAttribute('data-pair')) === pair ? 1 : 0);
  });
}
frames.forEach(f => {
  f.querySelector('input').addEventListener('input', function () {
    pos = Number(this.value); pauseUntil = performance.now() + 3500; paint();
  });
});
function tick(now) {
  const dt = Math.min(0.1, (now - lastTime) / 1000); lastTime = now;
  if (!reduce && S.step === 0 && now > pauseUntil && !document.hidden) {
    t += dt;
    const target = 50 + 36 * Math.cos(t * 2 * Math.PI / PERIOD);
    pos += (target - pos) * Math.min(1, dt * 4);
    pair = Math.floor(t / PERIOD) % 2;
    paint();
  }
  requestAnimationFrame(tick);
}
paint();
requestAnimationFrame(tick);

// ---------- release information ----------
// Header, change log, the step 1 source link and every version in the copy come only
// from the authenticated release envelope (releaseinfo.mjs).
function showRelease(info) {
  if (info.coexistence) {
    guide = guideForRelease(info, guide);
    FAQ.forEach((f, i) => { $('q' + i).firstChild.textContent = f.q; fillAnswer(f, $('a' + i)); });
  }
  copy = versionCopy(info, config.processingEnabled);
  $('versionText').textContent = copy.header;
  $('dl1').textContent = copy.download;
  if (info.sourceUrl) $('dl1').href = info.sourceUrl;
  FAQ.forEach((f, i) => { if (typeof f.a === 'function') fillAnswer(f, $('a' + i)); });
  if (!config.processingEnabled) return;
  for (const c of info.changes) {
    const p = document.createElement('p'), strong = document.createElement('strong');
    strong.textContent = 'Version ' + c.version;
    p.append(strong, (c.date ? ', ' + c.date : '') + '. ' + c.text);
    $('changelog').append(p);
  }
  $('logBtn').hidden = !info.changes.length;
}

// ---------- start ----------
async function start() {
  need(isSecureContext && crypto.subtle && globalThis.Worker && globalThis.DecompressionStream, 'Din browser kan ikke bruges. Brug en opdateret browser via HTTPS.');
  new DecompressionStream('deflate-raw');
  const inventory = await (await fetch('./integrity.json', {cache: 'no-store'})).json();
  const checked = async name => {
    const response = await fetch('./' + name, {cache: 'no-store'});
    need(response.ok, 'Siden kunne ikke indlæses. Genindlæs siden.');
    const bytes = new Uint8Array(await response.arrayBuffer());
    need(bytes.length <= 2 * 1024 * 1024 && await sha(bytes) === inventory.files[name], 'Sidefilerne matcher ikke. Genindlæs siden.');
    return JSON.parse(new TextDecoder().decode(bytes));
  };
  const [cfg, trusted] = await Promise.all([checked('config.json'), checked('trust.json')]);
  const query = new URL(location.href).searchParams.get('release'), id = cfg.processingEnabled && query ? query : cfg.defaultRelease;
  need(Object.hasOwn(cfg.releases, id), 'Ukendt udgivelse.');
  const selected = cfg.releases[id];
  [recipe, envelope] = await Promise.all([selected.recipe ? checked(selected.recipe) : null, checked(selected.envelope)]);
  const release = await authenticate(envelope, trusted.releaseKey);
  need(release.commonCertificate === trusted.commonCertificate, 'Forkert udgivelse.');
  const info = describeRelease(release);
  trust = trusted; config = cfg; guide = cfg.guide;
  showRelease(info);
}
start().catch(e => { startupError = e?.message?.startsWith('Din browser') || /Genindlæs/.test(e?.message) ? e.message : 'Siden kunne ikke starte. Genindlæs siden, eller brug en opdateret browser.'; })
  .finally(() => {
    // Without a guide the TV steps cannot be shown; the file steps still explain the problem.
    buildProgress(); render();
    document.documentElement.dataset.state = startupError ? 'error' : 'ready';
  });
