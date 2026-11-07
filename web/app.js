const API = '/api/v1';
let currentMode = 'url';
let pendingScan = () => {};
let privacySeen = localStorage.getItem('lg-consent') === 'yes';
let language = 'en';
let csrfToken = '';
let authUser = null;
let createAccountMode = false;

const translations = {
  en: {home:'Home',check:'Check content',guide:'Scam guide',emergency:'Emergency help',history:'History',empty:'No checks yet. Your reports will appear here.',unavailable:'Checks unavailable',evidence:'Signals found',next:'What you can do',go:'Check now',checking:'Checking…',camera:'Use camera'},
  ta: {home:'முகப்பு',check:'உள்ளடக்கத்தைச் சரிபார்',guide:'மோசடி வழிகாட்டி',emergency:'அவசர உதவி',history:'வரலாறு',empty:'இதுவரை சோதனைகள் இல்லை.',unavailable:'கிடைக்காத சோதனைகள்',evidence:'கண்டறிந்த அறிகுறிகள்',next:'நீங்கள் செய்யக்கூடியவை',go:'இப்போது சரிபார்',checking:'சரிபார்க்கிறது…',camera:'கேமராவைப் பயன்படுத்து'},
  hi: {home:'होम',check:'सामग्री जाँचें',guide:'घोटाला मार्गदर्शिका',emergency:'आपातकालीन मदद',history:'इतिहास',empty:'अभी कोई जाँच नहीं हुई।',unavailable:'उपलब्ध नहीं जाँच',evidence:'मिले संकेत',next:'आप क्या कर सकते हैं',go:'अभी जाँचें',checking:'जाँच हो रही है…',camera:'कैमरा इस्तेमाल करें'}
};
const $ = selector => document.querySelector(selector);
const tr = key => translations[language]?.[key] || translations.en[key] || key;
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const method = (options.method || 'GET').toUpperCase();
  if (['POST','PUT','PATCH','DELETE'].includes(method) && csrfToken && !path.startsWith('/auth/login') && !path.startsWith('/auth/register')) headers.set('X-CSRF-Token', csrfToken);
  const response = await fetch(API + path, {...options, headers, credentials:'same-origin'});
  const data = await response.json().catch(() => ({detail:'The server returned an unreadable response.'}));
  if (!response.ok) throw Error(data.detail || `Request failed (${response.status})`);
  return data;
}

function toast(message) {
  const element = $('#toast');
  element.textContent = message;
  element.classList.add('show');
  setTimeout(() => element.classList.remove('show'), 2500);
}

function view(name) {
  document.querySelectorAll('.view').forEach(element => element.classList.add('hidden'));
  $(`#${name}View`).classList.remove('hidden');
  document.querySelectorAll('.nav-item').forEach(element => element.classList.toggle('active', element.dataset.view === name));
  if (name === 'history') loadHistory();
  if (name === 'learn') loadScams();
  if (name === 'emergency') loadEmergencyGuides();
  window.scrollTo({top:0, behavior:'smooth'});
}

document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => view(button.dataset.view)));
document.querySelectorAll('[data-mode]').forEach(button => button.addEventListener('click', () => {
  setMode(button.dataset.mode);
  if (button.classList.contains('quick-card')) view('scan');
}));

function setMode(mode) {
  currentMode = mode;
  document.querySelectorAll('.mode').forEach(button => button.classList.toggle('active', button.dataset.mode === mode));
  $('#report').classList.add('hidden');
  renderForm();
}

function renderForm() {
  const titles = {url:'Check a link', message:'Check a message', qr:'Check a QR code', file:'Check a file', bulk:'Check multiple links'};
  let html = `<h2 class="scan-title">${titles[currentMode]}</h2>`;
  if (currentMode === 'url') html += `<p class="muted">LinkGuard will not open this address. Local checks run first.</p><div id="providerConsent" class="provider-consent"></div><label class="field-label" for="urlInput">Web address</label><input id="urlInput" class="input" type="text" inputmode="url" maxlength="4096" placeholder="https://example.com"><div class="scan-controls"><span class="hint">Query values are removed from saved history.</span><button class="button primary" id="submitScan">${tr('go')} →</button></div>`;
  if (currentMode === 'message') html += `<p class="muted">Your text is analysed in memory and is not saved in scan history.</p><label class="field-label" for="messageInput">Paste the message you received</label><textarea id="messageInput" class="textarea" maxlength="20000" placeholder="Paste message text here…"></textarea><div class="scan-controls"><span class="hint">Up to 20,000 characters · not saved</span><button class="button primary" id="submitScan">${tr('go')} →</button></div>`;
  if (currentMode === 'qr') html += `<p class="muted">Decoded content is previewed first. Nothing is opened or paid automatically.</p><div id="providerConsent" class="provider-consent"></div><label class="field-label" for="qrFile">Choose a QR image</label><input id="qrFile" class="file-input" type="file" accept="image/*"><div class="scan-controls"><button class="button quiet" id="cameraBtn">${tr('camera')}</button><span class="hint">Camera access is optional.</span></div><div id="qrPreview"></div>`;
  if (currentMode === 'file') html += `<p class="muted">File bytes are processed in memory. Maximum size: 10 MB. No malware engine is connected.</p><label class="field-label" for="fileInput">Choose a file</label><input id="fileInput" class="file-input" type="file"><div class="scan-controls"><span class="hint">Archives are inspected without extraction.</span><button class="button primary" id="submitScan">${tr('go')} →</button></div>`;
  if (currentMode === 'bulk') html += `<p class="muted">Check up to 25 links separately. No links are opened or sent to external providers in bulk mode.</p><label class="field-label" for="bulkInput">One link per line</label><textarea id="bulkInput" class="textarea" placeholder="example.com&#10;https://another.example" maxlength="15000"></textarea><div class="scan-controls"><span class="hint">Results include individual errors.</span><button class="button primary" id="submitScan">${tr('go')} →</button></div>`;
  $('#scanForm').innerHTML = html;
  $('#report').classList.add('hidden');
  $('#submitScan')?.addEventListener('click', submitScan);
  $('#qrFile')?.addEventListener('change', decodeQR);
  $('#cameraBtn')?.addEventListener('click', cameraQR);
  if (currentMode === 'url' || currentMode === 'qr') loadProviderChoice();
}

async function loadProviderChoice() {
  const element = $('#providerConsent');
  try {
    const config = await api('/config');
    if (currentMode !== 'url' && currentMode !== 'qr') return;
    const available=Object.values(config.providers).filter(provider=>provider.configured);
    if (available.length) {
      element.innerHTML = `<label class="provider-choice"><input type="checkbox" id="allowExternal"><span><b>Optional external reputation checks: ${available.map(provider=>esc(provider.name)).join(', ')}</b><small>${available.map(provider=>esc(provider.data_shared)).join(' ')} These services receive the URL when enabled.</small></span></label>`;
    } else {
      element.innerHTML = `<p class="hint provider-state">URLhaus reputation is not configured. This scan will use local checks only.</p>`;
    }
  } catch {
    element.innerHTML = '<p class="hint provider-state">Provider configuration could not be loaded; only local checks will run.</p>';
  }
}

function privacyThen(callback) {
  pendingScan = callback;
  if (privacySeen) { callback(); return; }
  $('#privacyDialog').showModal();
}

$('#continueScan').addEventListener('click', event => {
  event.preventDefault();
  if ($('#rememberConsent').checked) {
    localStorage.setItem('lg-consent', 'yes');
    privacySeen = true;
  }
  $('#privacyDialog').close();
  pendingScan();
});

async function submitScan() {
  privacyThen(async () => {
    const button = $('#submitScan');
    if (button) { button.disabled = true; button.textContent = tr('checking'); }
    try {
      let result;
      if (currentMode === 'url') result = await api('/scan/url', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({url:$('#urlInput').value, consent_external:$('#allowExternal')?.checked || false})});
      if (currentMode === 'message') result = await api('/scan/message', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({message:$('#messageInput').value})});
      if (currentMode === 'file') {
        const file = $('#fileInput').files[0];
        if (!file) throw Error('Choose a file first.');
        const form = new FormData(); form.append('file', file);
        result = await api('/scan/file', {method:'POST', body:form});
      }
      if (currentMode === 'bulk') {
        const urls = $('#bulkInput').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
        if (!urls.length) throw Error('Enter at least one link.');
        if (urls.length > 25) throw Error('There are more than 25 links. Remove some and try again.');
        result = await api('/scan/bulk', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({urls})});
        renderBulk(result); return;
      }
      renderReport(result);
    } catch (error) { showError(error.message); }
    finally { if (button) { button.disabled = false; button.textContent = tr('go') + ' →'; } }
  });
}

function renderReport(report) {
  const element = $('#report'); element.classList.remove('hidden');
  const icon = report.verdict === 'Suspicious' || report.verdict === 'High risk' ? '!' : report.verdict === 'Confirmed malicious' ? '×' : 'i';
  const evidence = (report.evidence || []).map(item => `<div class="evidence"><b>${esc(item.title)}</b><p>${esc(item.detail)}</p><small>${esc(item.source || '')}</small></div>`).join('') || '<p class="hint">No warning signal was found in the checks that ran.</p>';
  const actions = (report.recommended_actions || []).map(item => `<li>${esc(item)}</li>`).join('');
  const completed = (report.checks_completed || []).map(item => `<span class="pill">✓ ${esc(item)}</span>`).join('');
  const unavailable = (report.checks_unavailable || []).map(item => `<span class="pill">○ ${esc(item)}</span>`).join('');
  const checkStatuses = (report.check_statuses || []).map(item => `<span class="pill">${esc(item.status)} · ${esc(item.check)}</span>`).join('');
  const providerChecks = (report.provider_checks || []).map(item => `<div class="evidence"><b>${esc(item.provider)} · ${esc(item.status)}</b><p>${esc(item.reason || (item.status === 'no_match' ? 'No matching entry returned. This does not mean the item is safe.' : item.status === 'not_configured' ? 'Provider credentials are not configured.' : 'Provider result as returned; see status and timestamp.'))}</p><small>${esc(item.checked_at || 'Not queried')}</small>${item.reference && item.reference.startsWith('https://urlhaus.abuse.ch/') ? `<p><a href="${esc(item.reference)}" target="_blank" rel="noopener noreferrer">View URLhaus record ↗</a></p>` : ''}</div>`).join('');
  const timeline = (report.timeline || []).map(item => `<li><b>${esc(item.step)}</b><span class="pill">${esc(item.status)}</span><small>${esc(item.time)}</small></li>`).join('');
  const graph = report.investigation_graph;
  const graphHtml = graph ? `<h4>Observed connections</h4><p class="hint">${esc(graph.note)}</p><div class="graph-list">${graph.edges.map(edge => {const from=graph.nodes.find(node=>node.id===edge.from)?.label||edge.from;const to=graph.nodes.find(node=>node.id===edge.to)?.label||edge.to;return `<div class="graph-edge"><span>${esc(from)}</span><b>→ ${esc(edge.label)} →</b><span>${esc(to)}</span></div>`}).join('') || '<p class="hint">No extracted relationships to show.</p>'}</div>` : '';
  element.innerHTML = `<div class="verdict"><div class="verdict-icon">${icon}</div><div><h3>${esc(report.verdict)}</h3><p>Internal rule indicator: ${report.risk_score ?? 0}/100 · not a probability of fraud</p><small>${esc(report.scan_status || 'status unavailable')} · ${esc(report.confidence || 'Not calibrated')}</small></div></div><div class="report-summary">${esc(report.summary)}</div><p class="hint">${esc(report.risk_score_label || 'This indicator is not a calibrated probability.')}</p>${report.payment_preview ? `<div class="report-summary">Payee: ${esc(report.payment_preview.payee)} · Name: ${esc(report.payment_preview.name)} · Amount: ${esc(report.payment_preview.amount)} ${esc(report.payment_preview.currency)}</div>` : ''}${report.sha256 ? `<div class="report-summary">SHA-256: <code>${esc(report.sha256)}</code></div>` : ''}<h4>Check execution status</h4><div class="report-meta">${checkStatuses || '<span class="pill">No checks reported</span>'}</div><div class="report-meta">${completed}</div><h4>${tr('unavailable')}</h4><div class="report-meta">${unavailable || '<span class="pill">None reported</span>'}</div><h4>${tr('evidence')}</h4>${evidence}${providerChecks ? `<h4>Provider checks</h4>${providerChecks}` : ''}${graphHtml}<h4>${tr('next')}</h4><ul>${actions}</ul><details class="timeline"><summary>Investigation timeline</summary><ol>${timeline}</ol></details><p class="hint">${(report.limitations || []).map(esc).join(' ')}</p><p class="hint">Report time: ${esc(report.created_at || 'now')} · ${report.external_data_shared ? 'External data was shared with the selected provider.' : 'No external data was shared for this scan.'}</p><button class="button quiet" id="exportReportJson">Download report JSON</button>`;
  $('#exportReportJson').onclick = () => download(`linkguard-report-${report.id || 'scan'}.json`, JSON.stringify(report, null, 2), 'application/json');
  element.scrollIntoView({behavior:'smooth', block:'nearest'});
}

function renderBulk(result) {
  const element = $('#report'); element.classList.remove('hidden');
  element.innerHTML = `<h3 class="scan-title">${result.count} link result(s)</h3>` + result.results.map(item => `<div class="evidence"><b>${esc(item.input)}</b><p>${item.report ? `${esc(item.report.verdict)} · internal rule indicator ${item.report.risk_score}/100 (not a probability)` : esc(item.error)}</p></div>`).join('') + '<button class="button quiet" id="exportCsv">Download CSV</button>';
  $('#exportCsv').onclick = () => download('linkguard-results.csv', 'input,verdict,uncalibrated_rule_indicator_not_probability,error\n' + result.results.map(item => [item.input, item.report?.verdict || '', item.report?.risk_score ?? '', item.error || ''].map(csv).join(',')).join('\n'), 'text/csv');
}

function csv(value) { return '"' + String(value).replaceAll('"', '""') + '"'; }
function download(filename, text, type='text/plain') {
  const anchor = document.createElement('a');
  anchor.href = URL.createObjectURL(new Blob([text], {type}));
  anchor.download = filename; anchor.click();
  setTimeout(() => URL.revokeObjectURL(anchor.href), 1000);
}
function showError(message) { const element=$('#report'); element.classList.remove('hidden'); element.innerHTML=`<div class="error">${esc(message)}</div>`; }

async function decodeQR(event) {
  const file=event.target.files[0]; if (!file) return;
  const preview=$('#qrPreview');
  if (!('BarcodeDetector' in window)) { preview.innerHTML='<p class="error">This browser does not support the QR decoder. Try a browser with BarcodeDetector support.</p>'; return; }
  try {
    const detector=new BarcodeDetector({formats:['qr_code']});
    const bitmap=await createImageBitmap(file); const found=await detector.detect(bitmap); bitmap.close();
    if (!found.length) throw Error('No QR code was found in this image.');
    showQRPreview(found[0].rawValue);
  } catch (error) { preview.innerHTML=`<p class="error">${esc(error.message)}</p>`; }
}

async function cameraQR() {
  const preview=$('#qrPreview');
  if (!('BarcodeDetector' in window) || !navigator.mediaDevices?.getUserMedia) { preview.innerHTML='<p class="error">Camera QR scanning is unavailable in this browser. Upload an image if QR decoding is supported.</p>'; return; }
  let stream;
  try {
    stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:'environment'}});
    const video=document.createElement('video'); video.autoplay=true; video.playsInline=true; video.srcObject=stream; preview.innerHTML=''; preview.append(video);
    const detector=new BarcodeDetector({formats:['qr_code']}); await video.play(); let active=true;
    const stop=()=>{active=false;stream?.getTracks().forEach(track=>track.stop());};
    const loop=async()=>{if(!active)return;try{const found=await detector.detect(video);if(found.length){stop();showQRPreview(found[0].rawValue);return;}}catch{}requestAnimationFrame(loop);};
    loop();
    setTimeout(()=>{if(active){stop();preview.insertAdjacentHTML('beforeend','<p class="hint">No code detected yet. Try better lighting or upload an image.</p>');}},30000);
  } catch (error) { stream?.getTracks().forEach(track=>track.stop()); preview.innerHTML=`<p class="error">Camera unavailable or permission denied: ${esc(error.message)}</p>`; }
}

function showQRPreview(value) {
  const preview=$('#qrPreview');
  preview.innerHTML=`<div class="qr-box"><div class="eyebrow">DECODED CONTENT PREVIEW</div><p class="hint" style="overflow-wrap:anywhere">${esc(value)}</p><p class="hint">Nothing will be opened automatically.</p><button class="button primary" id="analyseQR">Analyse this destination</button></div>`;
  $('#analyseQR').onclick=()=>privacyThen(async()=>{
    try { const report=await api('/scan/qr',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:value,consent_external:$('#allowExternal')?.checked||false})}); renderReport(report); }
    catch(error){showError(error.message);}
  });
}

async function loadScams() {
  const box=$('#scamList');
  try { const data=await api('/scam-categories'); box.innerHTML=`<p class="hint">Scam coverage taxonomy v${esc(data.version)}. Coverage labels describe implemented checks, not how common or dangerous a scam is.</p>` + data.categories.map(category=>`<article class="scam-card glass"><h3>${esc(category.name)}</h3><p>${esc((category.items || []).join(' · '))}</p><p class="action"><b>Detection status:</b> ${esc(category.detection_status || 'not_implemented')}</p><small>${esc(category.limitations || category.warning || '')}</small></article>`).join(''); }
  catch(error){box.innerHTML=`<p class="error">${esc(error.message)}</p>`;}
}

async function loadEmergencyGuides() {
  const box=$('#emergencyList');
  try {
    const data=await api('/emergency-guides');
    box.innerHTML=data.guides.map(guide=>`<article class="emergency-card glass"><div class="eyebrow">${esc(guide.urgency)}</div><h2>${esc(guide.title)}</h2><ol>${guide.steps.map(step=>`<li>${esc(step)}</li>`).join('')}</ol><small>Reviewed ${esc(data.reviewed_on)}</small></article>`).join('');
  } catch(error){box.innerHTML=`<p class="error">${esc(error.message)}</p>`;}
}

$('#quizButton').onclick=()=>{$('#quizResult').textContent='Correct safety choice: do not share an OTP. Contact your bank through its official app or the number printed on your card.'};

async function loadHistory() {
  const box=$('#historyList');
  try {
    const data=await api('/history');
    if(!data.items.length){box.innerHTML=`<div class="empty">${tr('empty')}</div>`;return;}
    box.innerHTML=data.items.map(item=>`<article class="history-item glass"><span class="tile-icon blue">${item.kind==='url'?'↗':item.kind==='file'?'⌑':item.kind==='message'?'☷':'▦'}</span><div class="history-info"><b>${esc(item.verdict)} · ${esc(item.subject)}</b><small>${esc(item.kind)} · ${new Date(item.created_at).toLocaleString()}</small></div><button class="view-report" data-report="${esc(item.id)}">View</button><button data-delete="${esc(item.id)}" aria-label="Delete report">Delete</button></article>`).join('');
    box.querySelectorAll('[data-delete]').forEach(button=>button.onclick=async()=>{try{await api('/history/'+button.dataset.delete,{method:'DELETE'});loadHistory();}catch(error){toast(error.message);}});
    box.querySelectorAll('[data-report]').forEach(button=>button.onclick=async()=>{try{view('scan');setMode('url');renderReport(await api('/reports/'+button.dataset.report));}catch(error){toast(error.message);}});
  } catch(error){box.innerHTML=`<p class="error">${esc(error.message)}</p>`;}
}

$('#clearHistory').onclick=async()=>{if(confirm('Delete all saved scan reports on this device?')){try{await api('/history',{method:'DELETE'});loadHistory();toast('History cleared');}catch(error){toast(error.message);}}};
$('#theme').onclick=()=>{document.body.classList.toggle('light');localStorage.setItem('lg-theme',document.body.classList.contains('light')?'light':'dark');};
if(localStorage.getItem('lg-theme')==='light')document.body.classList.add('light');
$('#language').onchange=event=>{
  language=event.target.value; document.documentElement.lang=language;
  document.querySelectorAll('.nav-item').forEach(button=>{const keys={home:'home',scan:'check',learn:'guide',emergency:'emergency',history:'history'};button.textContent=tr(keys[button.dataset.view]);});
  renderForm(); toast(language==='ta'?'மொழி மாற்றப்பட்டது':language==='hi'?'भाषा बदल दी गई':'Language changed');
};

function applyAuthState(user, csrf) {
  authUser = user; csrfToken = csrf || '';
  document.body.classList.remove('auth-required');
  $('#authGate').classList.add('hidden');
  $('#accountName').textContent = user.username;
  $('#accountName').classList.remove('hidden');
  $('#accountButton').classList.remove('hidden');
  $('#accountDialogName').textContent = `Signed in as ${user.username}`;
}

function showAuthGate() {
  authUser = null; csrfToken = '';
  document.body.classList.add('auth-required');
  $('#authGate').classList.remove('hidden');
  $('#accountName').classList.add('hidden');
  $('#accountButton').classList.add('hidden');
}

$('#authMode').onclick=()=>{
  createAccountMode=!createAccountMode;
  $('#authTitle').textContent=createAccountMode?'Create your LinkGuard account':'Sign in to LinkGuard';
  $('#authSubmit').textContent=createAccountMode?'Create account':'Sign in';
  $('#authMode').textContent=createAccountMode?'I already have an account':'Create an account';
  $('#authPassword').autocomplete=createAccountMode?'new-password':'current-password';
  $('#authError').textContent='';
};

$('#authForm').addEventListener('submit',async event=>{
  event.preventDefault();
  const button=$('#authSubmit'); button.disabled=true; $('#authError').textContent='';
  try {
    const response=await api(createAccountMode?'/auth/register':'/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('#authUsername').value,password:$('#authPassword').value})});
    applyAuthState(response.user,response.csrf_token); $('#authPassword').value=''; renderForm();
  } catch(error) { $('#authError').textContent=error.message; }
  finally { button.disabled=false; }
});

$('#accountButton').onclick=()=>$('#accountDialog').showModal();
$('#logoutButton').onclick=async()=>{
  try { await api('/auth/logout',{method:'POST'}); $('#accountDialog').close(); showAuthGate(); }
  catch(error) { toast(error.message); }
};
$('#deleteAccountButton').onclick=async()=>{
  if(!confirm('Permanently delete this account and all reports saved to it?')) return;
  try { await api('/auth/account',{method:'DELETE'}); $('#accountDialog').close(); showAuthGate(); toast('Account and reports deleted'); }
  catch(error) { toast(error.message); }
};

async function initializeAuth() {
  try {
    const response=await api('/auth/me');
    applyAuthState(response.user,response.csrf_token);
  } catch { showAuthGate(); }
}

renderForm();
initializeAuth();
