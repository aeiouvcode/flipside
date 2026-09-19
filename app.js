'use strict';
/* ============================================================
   FLIPSIDE - local-first Depop seller workspace.
   No backend. No accounts. Data is session-only until the user
   sets a passphrase; then AES-GCM encrypted in localStorage.
   ============================================================ */

/* ---------------- utils ---------------- */
const $  = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
const todayStr = () => { const d = new Date(); return d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0') + '-' + String(d.getDate()).padStart(2,'0'); };
const dayKey = d => { const x = new Date(d); return x.getFullYear() + '-' + String(x.getMonth()+1).padStart(2,'0') + '-' + String(x.getDate()).padStart(2,'0'); };
const addDays = (key, n) => { const d = new Date(key + 'T12:00:00'); d.setDate(d.getDate() + n); return dayKey(d); };
const niceDay = key => new Date(key + 'T12:00:00').toLocaleDateString(undefined, { weekday:'short', month:'short', day:'numeric' });

function money(n, cur) {
  cur = cur || (S && S.settings.currency) || 'USD';
  try { return new Intl.NumberFormat(undefined, { style:'currency', currency:cur }).format(n || 0); }
  catch (e) { return (cur + ' ' + (n || 0).toFixed(2)); }
}
const num = v => { const n = parseFloat(v); return isFinite(n) ? n : 0; };

function toast(msg) {
  const t = document.createElement('div');
  t.className = 'toast'; t.textContent = msg;
  $('#toast-root').appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; }, 2400);
  setTimeout(() => t.remove(), 2800);
}

function confirmModal(title, body, okLabel, danger) {
  return new Promise(resolve => {
    const root = $('#modal-root');
    root.innerHTML = '<div class="modal-wrap"><div class="modal" role="dialog" aria-modal="true">' +
      '<h3>' + esc(title) + '</h3><p>' + body + '</p>' +
      '<div class="row-actions"><button class="btn ghost" id="m-no" type="button">Cancel</button>' +
      '<button class="btn ' + (danger ? 'danger' : 'primary') + '" id="m-yes" type="button">' + esc(okLabel || 'Confirm') + '</button></div></div></div>';
    $('#m-no').onclick = () => { root.innerHTML = ''; resolve(false); };
    $('#m-yes').onclick = () => { root.innerHTML = ''; resolve(true); };
  });
}

function passModal(title, body) {
  return new Promise(resolve => {
    const root = $('#modal-root');
    root.innerHTML = '<div class="modal-wrap"><div class="modal" role="dialog" aria-modal="true">' +
      '<h3>' + esc(title) + '</h3><p>' + esc(body) + '</p>' +
      '<label class="field"><span>Passphrase</span><input id="m-pass" type="password" autocomplete="off"></label>' +
      '<label class="field"><span>Again</span><input id="m-pass2" type="password" autocomplete="off"></label>' +
      '<p class="fine" id="m-err" style="color:var(--red)"></p>' +
      '<div class="row-actions"><button class="btn ghost" id="m-no" type="button">Cancel</button>' +
      '<button class="btn primary" id="m-yes" type="button">Save</button></div></div></div>';
    const close = v => { root.innerHTML = ''; resolve(v); };
    $('#m-no').onclick = () => close(null);
    $('#m-yes').onclick = () => {
      const a = $('#m-pass').value, b = $('#m-pass2').value;
      if (a.length < 8) { $('#m-err').textContent = 'At least 8 characters.'; return; }
      if (a !== b) { $('#m-err').textContent = 'Those two do not match.'; return; }
      close(a);
    };
    $('#m-pass').focus();
  });
}

async function copyText(txt, label) {
  try { await navigator.clipboard.writeText(txt); toast((label || 'Copied') + ' - ready to paste into Depop'); }
  catch (e) {
    const ta = document.createElement('textarea');
    ta.value = txt; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); toast(label || 'Copied'); } catch (e2) { toast('Copy failed - select the text and copy it by hand'); }
    ta.remove();
  }
}

/* ---------------- crypto vault ---------------- */
const Vault = {
  KEY: 'flipside.vault.v1',
  async derive(pass, salt) {
    const enc = new TextEncoder();
    const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name:'PBKDF2', salt, iterations:250000, hash:'SHA-256' },
      base, { name:'AES-GCM', length:256 }, false, ['encrypt', 'decrypt']);
  },
  b64: buf => btoa(String.fromCharCode.apply(null, new Uint8Array(buf))),
  unb64: s => Uint8Array.from(atob(s), c => c.charCodeAt(0)),
  has() { return !!localStorage.getItem(this.KEY); },
  async save(pass, plainText) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this.derive(pass, salt);
    const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, new TextEncoder().encode(plainText));
    localStorage.setItem(this.KEY, JSON.stringify({ salt:this.b64(salt), iv:this.b64(iv), data:this.b64(ct) }));
  },
  async load(pass) {
    const raw = localStorage.getItem(this.KEY);
    if (!raw) return null;
    const rec = JSON.parse(raw);
    const key = await this.derive(pass, this.unb64(rec.salt));
    const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv:this.unb64(rec.iv) }, key, this.unb64(rec.data));
    return new TextDecoder().decode(pt);
  },
  clear() { localStorage.removeItem(this.KEY); }
};

/* ---------------- store ---------------- */
const Blank = () => ({
  v: 1,
  settings: { currency:'USD', feePreset:'us', feePct:3.3, feeFixed:0.45, goal:51 },
  listings: [], orders: [], niches: [], checks: {},
  sample: false
});
let S = Blank();          // live state (in memory)
let PASS = null;          // passphrase held only in memory while unlocked
let dirty = false;

function markDirty() {
  dirty = true;
  if (PASS) {
    clearTimeout(markDirty._t);
    markDirty._t = setTimeout(persist, 600);
  }
}
async function persist() {
  if (!PASS) { dirty = false; return; }
  try { await Vault.save(PASS, JSON.stringify(S)); dirty = false; }
  catch (e) { console.error(e); toast('Could not save - encryption failed'); }
}
window.addEventListener('beforeunload', () => {
  if (dirty && PASS) persist();
  if (!PASS && (S.orders.length || S.listings.length || S.niches.length)) {
    // session-only data would be lost
    return 'Your data is session-only. Set a passphrase in Settings to keep it.';
  }
});

/* ---------------- fees ---------------- */
const FEE_PRESETS = {
  us:  { pct:3.3, fixed:0.45, cur:'USD', label:'US processing (3.3% + $0.45)' },
  uk:  { pct:2.9, fixed:0.30, cur:'GBP', label:'UK processing (2.9% + £0.30)' },
  au:  { pct:2.9, fixed:0.30, cur:'AUD', label:'AU processing (2.9% + A$0.30)' },
  row: { pct:10,  fixed:0,    cur:null,  label:'Rest of world (10% + processing)' }
};
function feeFor(price, shipCharged) {
  const base = num(price) + num(shipCharged);
  return base * S.settings.feePct / 100 + S.settings.feeFixed;
}
function orderMath(o) {
  const gross = num(o.price) + num(o.shipCharged);
  const fees = o.fees != null ? num(o.fees) : feeFor(o.price, o.shipCharged);
  const profit = gross - fees - num(o.shipCost) - num(o.cost);
  return { gross, fees, profit, margin: gross > 0 ? profit / gross * 100 : 0 };
}

/* ---------------- router ---------------- */
const VIEWS = {
  board:    ['Board', 'What you actually keep - today and this week.'],
  listings: ['Listings', 'Draft Depop-ready titles, descriptions and hashtags.'],
  photos:   ['Photos', 'Square, clean, Depop-ready. Processed on this device.'],
  orders:   ['Orders', 'Every sale in, fees and shipping out, real profit left.'],
  niche:    ['Niche lab', 'Pick what to sell with evidence, not vibes.'],
  settings: ['Settings', 'Fees, vault and your data.']
};
function route() {
  const name = (location.hash.replace('#/', '') || 'board');
  const view = VIEWS[name] ? name : 'board';
  $$('.view').forEach(v => { v.hidden = v.id !== 'view-' + view; });
  $$('[data-nav]').forEach(a => a.classList.toggle('on', a.dataset.nav === view));
  $('#view-title').textContent = VIEWS[view][0];
  $('#view-sub').textContent = VIEWS[view][1];
  if (view === 'board') renderBoard();
  if (view === 'listings') renderListingList();
  if (view === 'orders') { renderOrders(); }
  if (view === 'niche') { renderChecklist(); renderNicheList(); }
  if (view === 'settings') renderSettings();
  updateBadges();
  window.scrollTo(0, 0);
}
function updateBadges() {
  const drafts = S.listings.filter(l => l.status === 'draft').length;
  const nb = $('#nav-listing-count');
  nb.hidden = !drafts; nb.textContent = drafts;
  const ob = $('#nav-order-count');
  ob.hidden = !S.orders.length; ob.textContent = S.orders.length;
}
function updateVaultChips() {
  const txt = PASS ? 'Encrypted on this device' : 'Session only';
  [$('#vault-chip'), $('#vault-chip-top')].forEach(c => {
    c.textContent = txt;
    c.classList.toggle('locked', !!PASS);
    c.title = PASS ? 'Your data is AES-GCM encrypted in this browser with your passphrase.'
                   : 'Nothing is saved when this tab closes. Set a passphrase in Settings to keep your data.';
  });
}

/* ---------------- board ---------------- */
function weekStats() {
  const today = todayStr();
  let rev = 0, profit = 0, count = 0, todayProfit = 0;
  const days = {};
  for (let i = 13; i >= 0; i--) days[addDays(today, -i)] = 0;
  S.orders.forEach(o => {
    const m = orderMath(o);
    if (days[o.date] !== undefined) days[o.date] += m.profit;
    if (o.date >= addDays(today, -6) && o.date <= today) { rev += m.gross; profit += m.profit; count++; }
    if (o.date === today) todayProfit += m.profit;
  });
  return { rev, profit, count, todayProfit, days };
}

function renderBoard() {
  const has = S.orders.length > 0;
  $('#board-empty').hidden = has;
  $('#board-content').hidden = !has;
  if (!has) return;
  const w = weekStats();
  const goal = num(S.settings.goal);
  const avg = w.profit / 7;
  const best = Math.max.apply(null, Object.values(w.days).concat([0]));
  const cards = [
    ['Revenue · 7d', money(w.rev), w.count + (w.count === 1 ? ' sale' : ' sales')],
    ['Profit · 7d', money(w.profit), 'after fees, shipping + cost', w.profit >= 0 ? 'pos' : 'neg'],
    ['Avg / day · 7d', money(avg), 'best day ' + money(best)],
    ['Today', money(w.todayProfit), goal > 0 ? 'goal ' + money(goal) : 'no goal set', w.todayProfit >= goal && goal > 0 ? 'pos' : '']
  ];
  $('#stat-grid').innerHTML = cards.map(c =>
    '<div class="stat"><div class="k">' + c[0] + '</div><div class="v ' + (c[3] || '') + '">' + c[1] + '</div><div class="d">' + c[2] + '</div></div>').join('');
  drawChart(w.days);
  drawGoal(w.todayProfit, goal);
  $('#chart-total').textContent = '14-day total ' + money(Object.values(w.days).reduce((a, b) => a + b, 0));
  const recent = S.orders.slice().sort((a, b) => (b.date + b.id).localeCompare(a.date + a.id)).slice(0, 5);
  $('#recent-orders').innerHTML = recent.map(o => {
    const m = orderMath(o);
    return '<div class="mini-row"><span class="t">' + esc(o.item) + '</span><span class="d">' + niceDay(o.date) +
      '</span><span class="p ' + (m.profit >= 0 ? 'pos' : 'neg') + '">' + money(m.profit) + '</span></div>';
  }).join('') || '<p class="empty-note">No sales yet.</p>';
}

function drawChart(days) {
  const cv = $('#chart-14'), ctx = cv.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const W = cv.clientWidth || 600, H = 180;
  cv.width = W * dpr; cv.height = H * dpr; cv.style.height = H + 'px';
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);
  const keys = Object.keys(days), vals = keys.map(k => days[k]);
  const max = Math.max.apply(null, vals.map(Math.abs).concat([num(S.settings.goal), 1]));
  const pad = { l: 6, r: 6, t: 14, b: 22 };
  const bw = (W - pad.l - pad.r) / keys.length;
  const zeroY = pad.t + (max / (max + Math.max(0, Math.min.apply(null, vals.concat([0]))) * -1 || 0)) * 0; // computed below
  const minV = Math.min.apply(null, vals.concat([0])), maxV = Math.max.apply(null, vals.concat([0]));
  const span = (maxV - minV) || 1;
  const y = v => pad.t + (maxV - v) / span * (H - pad.t - pad.b);
  // goal line
  const goal = num(S.settings.goal);
  if (goal > 0 && goal <= maxV) {
    ctx.strokeStyle = 'rgba(240,169,80,.45)'; ctx.setLineDash([4, 4]); ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(pad.l, y(goal)); ctx.lineTo(W - pad.r, y(goal)); ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = 'rgba(240,169,80,.7)'; ctx.font = '10px ' + getComputedStyle(document.body).fontFamily;
    ctx.fillText('goal', pad.l + 2, y(goal) - 3);
  }
  if (minV < 0) {
    ctx.strokeStyle = '#2c303a'; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(pad.l, y(0)); ctx.lineTo(W - pad.r, y(0)); ctx.stroke();
  }
  keys.forEach((k, i) => {
    const v = days[k];
    const x = pad.l + i * bw + bw * 0.18;
    const wBar = bw * 0.64;
    ctx.fillStyle = v >= 0 ? '#f0a950' : '#e0665a';
    const top = y(Math.max(0, v)), bot = y(Math.min(0, v));
    const h = Math.max(1.5, bot - top);
    ctx.beginPath();
    ctx.roundRect(x, top, wBar, h, 2);
    ctx.fill();
    if (i % 2 === 0 || keys.length <= 7) {
      ctx.fillStyle = '#5c6069'; ctx.font = '9.5px ' + getComputedStyle(document.body).fontFamily;
      ctx.textAlign = 'center';
      ctx.fillText(new Date(k + 'T12:00:00').getDate(), x + wBar / 2, H - 8);
      ctx.textAlign = 'left';
    }
  });
}

function drawGoal(todayProfit, goal) {
  const cv = $('#goal-ring'), ctx = cv.getContext('2d');
  const dpr = window.devicePixelRatio || 1, Sz = 140;
  cv.width = Sz * dpr; cv.height = Sz * dpr; ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, Sz, Sz);
  const cx = Sz / 2, cy = Sz / 2, r = 56;
  const pct = goal > 0 ? clamp(todayProfit / goal, 0, 1) : 0;
  ctx.lineWidth = 11; ctx.lineCap = 'round';
  ctx.strokeStyle = '#23262e';
  ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.stroke();
  if (pct > 0) {
    ctx.strokeStyle = pct >= 1 ? '#7ec97f' : '#f0a950';
    ctx.beginPath(); ctx.arc(cx, cy, r, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * pct); ctx.stroke();
  }
  ctx.fillStyle = '#ece8e0'; ctx.font = '700 20px ' + getComputedStyle(document.body).fontFamily;
  ctx.textAlign = 'center';
  ctx.fillText(goal > 0 ? Math.round(todayProfit / goal * 100) + '%' : '—', cx, cy + 2);
  ctx.fillStyle = '#848893'; ctx.font = '10.5px ' + getComputedStyle(document.body).fontFamily;
  ctx.fillText('of daily goal', cx, cy + 18);
  const copy = $('#goal-copy');
  if (goal > 0) {
    const left = goal - todayProfit;
    copy.innerHTML = left <= 0
      ? '<b>Goal hit.</b><br>Today is paid for - everything from here is extra.'
      : '<b>' + esc(money(todayProfit)) + '</b> so far today.<br>' + esc(money(left)) + ' to go against your ' + esc(money(goal)) + ' goal.';
  } else {
    copy.innerHTML = 'No daily goal set. Add one in Settings - even ' + esc(money(20)) + ' a day is ' + esc(money(600)) + ' a month.';
  }
}

/* ---------------- orders ---------------- */
let editingOrder = null;

function prefillOrder(item, price, cost) {
  editingOrder = null;
  $('#order-form-title').textContent = 'Log a sale';
  $('#btn-order-cancel').hidden = true;
  $('#or-item').value = item || '';
  $('#or-date').value = todayStr();
  $('#or-price').value = price || '';
  $('#or-ship-charged').value = '';
  $('#or-ship-cost').value = '';
  $('#or-cost').value = cost || '';
  $('#or-notes').value = '';
  updateOrderPreview();
}
function updateOrderPreview() {
  const o = readOrderForm();
  const el = $('#or-preview');
  if (!o.price) { el.textContent = ''; return; }
  const m = orderMath(o);
  el.textContent = 'Depop takes ' + money(m.fees) + ' · you keep ' + money(m.profit) +
    (o.cost ? ' · margin ' + m.margin.toFixed(0) + '%' : '') +
    (m.profit < 0 ? ' · that sale loses money' : '');
  $('#or-fee-note').textContent = 'Fee preset: ' + (FEE_PRESETS[S.settings.feePreset] ? FEE_PRESETS[S.settings.feePreset].label : 'custom');
}
function readOrderForm() {
  return {
    item: $('#or-item').value.trim(),
    date: $('#or-date').value || todayStr(),
    price: num($('#or-price').value),
    shipCharged: num($('#or-ship-charged').value),
    shipCost: num($('#or-ship-cost').value),
    cost: num($('#or-cost').value),
    notes: $('#or-notes').value.trim()
  };
}
function saveOrder() {
  const o = readOrderForm();
  if (!o.item) { toast('Give the sale an item name'); $('#or-item').focus(); return; }
  if (!o.price) { toast('What did it sell for?'); $('#or-price').focus(); return; }
  if (editingOrder) {
    Object.assign(editingOrder, o);
    editingOrder = null;
    $('#order-form-title').textContent = 'Log a sale';
    $('#btn-order-cancel').hidden = true;
    toast('Sale updated');
  } else {
    S.orders.push(Object.assign({ id: uid() }, o));
    toast('Sale logged - ' + money(orderMath(o).profit) + ' profit');
  }
  prefillOrder('', '', '');
  markDirty(); renderOrders(); updateBadges();
}
function renderOrders() {
  const tb = $('#order-tbody');
  const rows = S.orders.slice().sort((a, b) => (b.date + b.id).localeCompare(a.date + a.id));
  $('#orders-empty').style.display = rows.length ? 'none' : '';
  $('#order-table').style.display = rows.length ? '' : 'none';
  let tg = 0, tf = 0, tp = 0;
  tb.innerHTML = rows.map(o => {
    const m = orderMath(o);
    tg += m.gross; tf += m.fees; tp += m.profit;
    const shipNet = num(o.shipCharged) - num(o.shipCost);
    return '<tr data-id="' + o.id + '"><td>' + esc(niceDay(o.date)) + '<span class="sub">' + esc(o.date) + '</span></td>' +
      '<td>' + esc(o.item) + (o.notes ? '<span class="sub">' + esc(o.notes) + '</span>' : '') + '</td>' +
      '<td class="num">' + esc(money(o.price)) + (o.shipCharged ? '<span class="sub">+' + esc(money(o.shipCharged)) + ' ship</span>' : '') + '</td>' +
      '<td class="num">−' + esc(money(m.fees)) + '</td>' +
      '<td class="num">' + (shipNet >= 0 ? '+' : '−') + esc(money(Math.abs(shipNet))) + '</td>' +
      '<td class="num">−' + esc(money(o.cost)) + '</td>' +
      '<td class="num ' + (m.profit >= 0 ? 'p-pos' : 'p-neg') + '">' + esc(money(m.profit)) + '</td>' +
      '<td class="num">' + m.margin.toFixed(0) + '%</td>' +
      '<td><div class="row-btns">' +
      '<button class="icon-btn" data-act="edit" title="Edit" type="button"><svg viewBox="0 0 20 20"><path d="m4 16 .8-3.2L13 4.5a1.7 1.7 0 0 1 2.4 2.4L7.2 15.2 4 16z"/></svg></button>' +
      '<button class="icon-btn" data-act="del" title="Delete" type="button"><svg viewBox="0 0 20 20"><path d="M4 6h12M8 6V4h4v2M6 6l1 10h6l1-10"/></svg></button>' +
      '</div></td></tr>';
  }).join('');
  $('#order-totals').textContent = rows.length
    ? rows.length + (rows.length === 1 ? ' sale' : ' sales') + ' · ' + money(tg) + ' in · ' + money(tp) + ' kept'
    : '';
}
function exportCSV() {
  if (!S.orders.length) { toast('Nothing to export yet'); return; }
  const head = 'date,item,sold_price,shipping_charged,depop_fee,shipping_cost,item_cost,profit,margin_pct,notes';
  const lines = S.orders.slice().sort((a, b) => a.date.localeCompare(b.date)).map(o => {
    const m = orderMath(o);
    return [o.date, o.item, o.price, o.shipCharged, m.fees.toFixed(2), o.shipCost, o.cost,
      m.profit.toFixed(2), m.margin.toFixed(1), o.notes || '']
      .map(v => '"' + String(v).replace(/"/g, '""') + '"').join(',');
  });
  download('flipside-sales.csv', [head].concat(lines).join('\n'), 'text/csv');
  toast('CSV downloaded - opens in Sheets or Excel');
}
function download(name, content, type) {
  const blob = content instanceof Blob ? content : new Blob([content], { type: type || 'application/octet-stream' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = name;
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 800);
}

/* ---------------- listings ---------------- */
const CATEGORIES = ['T-shirt','Shirt / top','Hoodie / sweatshirt','Jacket / coat','Jeans','Trousers','Shorts',
  'Dress','Skirt','Sneakers','Boots / shoes','Bag','Accessories','Vintage other','Other'];
const CONDITIONS = ['New with tags','Like new','Used - excellent','Used - good','Used - fair','Distressed / repaired'];
const CAT_TAGS = {
  'T-shirt':['#tee','#tshirt','#graphictee'], 'Shirt / top':['#shirt','#top'],
  'Hoodie / sweatshirt':['#hoodie','#sweatshirt','#streetwear'], 'Jacket / coat':['#jacket','#coat','#outerwear'],
  'Jeans':['#jeans','#denim'], 'Trousers':['#trousers','#pants'], 'Shorts':['#shorts'],
  'Dress':['#dress'], 'Skirt':['#skirt'], 'Sneakers':['#sneakers','#kicks','#shoes'],
  'Boots / shoes':['#boots','#shoes'], 'Bag':['#bag'], 'Accessories':['#accessories'],
  'Vintage other':['#vintage','#retro'], 'Other':['#fashion']
};
const AESTHETIC_TAGS = ['#depop','#depopseller','#depopfashion','#vintage','#thrifted','#secondhand',
  '#sustainablefashion','#y2k','#90s','#streetwear','#preloved','#vintagestyle'];

let currentListing = null;
function normCondition(c) {
  if (!c) return CONDITIONS[0];
  c = String(c).replace(/\u2014|\u2013/g, '-');
  return CONDITIONS.includes(c) ? c : CONDITIONS[0];
}
function migrateState() {
  S.listings.forEach(l => { l.condition = normCondition(l.condition); });
}

function initListingSelects() {
  $('#li-category').innerHTML = CATEGORIES.map(c => '<option>' + esc(c) + '</option>').join('');
  $('#li-condition').innerHTML = CONDITIONS.map(c => '<option>' + esc(c) + '</option>').join('');
}
function listingFromForm() {
  return {
    name: $('#li-name').value.trim(), brand: $('#li-brand').value.trim(),
    category: $('#li-category').value, size: $('#li-size').value.trim(),
    color: $('#li-color').value.trim(), condition: normCondition($('#li-condition').value),
    era: $('#li-era').value.trim(), flaws: $('#li-flaws').value.trim(),
    measure: $('#li-measure').value.trim(),
    tags: $('#li-tags').value.split(',').map(t => t.trim()).filter(Boolean),
    cost: num($('#li-cost').value), price: num($('#li-price').value)
  };
}
function fillListingForm(l) {
  $('#li-name').value = l.name || ''; $('#li-brand').value = l.brand || '';
  $('#li-category').value = l.category || CATEGORIES[0];
  $('#li-size').value = l.size || ''; $('#li-color').value = l.color || '';
  $('#li-condition').value = normCondition(l.condition);
  $('#li-era').value = l.era || ''; $('#li-flaws').value = l.flaws || '';
  $('#li-measure').value = l.measure || ''; $('#li-tags').value = (l.tags || []).join(', ');
  $('#li-cost').value = l.cost || ''; $('#li-price').value = l.price || '';
  updateTakehome();
  if (l.generated) showGenerated(l.generated); else $('#listing-output').hidden = true;
}
function updateTakehome() {
  const price = num($('#li-price').value), cost = num($('#li-cost').value);
  const el = $('#li-takehome');
  if (!price) { el.textContent = ''; return; }
  const fee = feeFor(price, 0);
  const keep = price - fee - cost;
  el.textContent = 'At ' + money(price) + ' before shipping: Depop takes ' + money(fee) +
    ', you keep about ' + money(keep) + (cost ? ' after your ' + money(cost) + ' cost' : '') + '.';
}

function renderListingList() {
  const wrap = $('#listing-list');
  const items = S.listings.slice().sort((a, b) => b.updated - a.updated);
  wrap.innerHTML = items.map(l =>
    '<button class="card-item' + (currentListing && currentListing.id === l.id ? ' on' : '') +
    '" data-id="' + l.id + '" type="button"><div class="t">' + esc(l.name || 'Untitled item') + '</div>' +
    '<div class="m"><span class="chip ' + l.status + '">' + l.status + '</span>' +
    (l.price ? '<span>' + esc(money(l.price)) + '</span>' : '') + '</div></button>').join('');
  $('#listing-empty').hidden = !!currentListing;
  $('#listing-editor').hidden = !currentListing;
  updateBadges();
}

function newListing() {
  currentListing = { id: uid(), status:'draft', updated:Date.now() };
  fillListingForm(currentListing);
  renderListingList();
  $('#li-name').focus();
}
function openListing(id) {
  const l = S.listings.find(x => x.id === id);
  if (!l) return;
  currentListing = l;
  fillListingForm(l);
  renderListingList();
}
function saveCurrentListing(silent) {
  if (!currentListing) return;
  const f = listingFromForm();
  Object.assign(currentListing, f, { updated: Date.now() });
  const i = S.listings.findIndex(x => x.id === currentListing.id);
  if (i >= 0) S.listings[i] = currentListing; else S.listings.push(currentListing);
  markDirty();
  if (!silent) toast('Listing saved');
  renderListingList();
}

/* ---------- the drafter ---------- */
function generateCopy() {
  const f = listingFromForm();
  if (!f.name) { toast('Name the item first'); $('#li-name').focus(); return; }
  const tone = $('#li-tone').value;
  const brand = f.brand;
  const desc = f.name.toLowerCase().startsWith((brand || '§').toLowerCase()) || !brand
    ? f.name : brand + ' ' + f.name;

  // ---- title (Depop truncates around 80 chars)
  let title = [desc, f.color, f.size ? '· size ' + f.size : '', f.era ? '· ' + f.era : ''].filter(Boolean).join(' ');
  title = title.charAt(0).toUpperCase() + title.slice(1);
  if (title.length > 80) title = [desc, f.size ? '· ' + f.size : ''].filter(Boolean).join(' ');
  if (title.length > 80) title = title.slice(0, 79).trimEnd() + '…';

  // ---- condition line
  const condLine = f.condition + (f.flaws ? ' · ' + f.flaws : (f.condition.startsWith('Used') ? ' · no flaws to note, check the photos' : ''));

  let body = '';
  if (tone === 'classic') {
    body += '✦ ' + desc + (f.color ? ' in ' + f.color : '') + (f.era ? ' · ' + f.era : '') + '\n\n';
    body += sentenceFor(f);
    body += '\n· Condition: ' + condLine + '\n';
    if (f.size) body += '· Size: ' + f.size + '\n';
    if (f.measure) body += '· Measurements: ' + f.measure + '\n';
    body += '· Ships within 24–48h, tracked\n';
    body += '· Open to reasonable offers - message me ♡\n';
  } else if (tone === 'clean') {
    body += sentenceFor(f) + '\n\n';
    body += 'Condition: ' + condLine + '\n';
    if (f.size) body += 'Size: ' + f.size + '\n';
    if (f.measure) body += 'Measurements: ' + f.measure + '\n';
    body += 'Ships within 1–2 working days with tracking. Reasonable offers welcome.\n';
  } else {
    body += desc + (f.color ? ' · ' + f.color : '') + '\n';
    body += condLine + '\n';
    if (f.size) body += 'Size ' + f.size + '\n';
    if (f.measure) body += f.measure + '\n';
    body += 'Tracked shipping in 24–48h.\n';
  }

  // ---- hashtags
  const tags = [];
  const push = t => { t = t.toLowerCase().replace(/[^a-z0-9]/g, ''); if (t && !tags.includes('#' + t)) tags.push('#' + t); };
  push('depop'); push('depopseller');
  if (brand) push(brand);
  (CAT_TAGS[f.category] || []).forEach(push);
  f.tags.forEach(push);
  if (/vintage|retro|90s|y2k|80s|70s/i.test((f.era || '') + ' ' + f.tags.join(' '))) { push('vintage'); push('retro'); }
  for (const t of AESTHETIC_TAGS) { if (tags.length >= 15) break; push(t); }
  const tagLine = tags.slice(0, 15).join(' ');

  const gen = { title, body, tags: tagLine };
  if (currentListing) { currentListing.generated = gen; saveCurrentListing(true); }
  showGenerated(gen);
}
function sentenceFor(f) {
  const bits = [];
  const what = (f.brand && !f.name.toLowerCase().startsWith(f.brand.toLowerCase()) ? f.brand + ' ' : '') + f.name;
  if (f.era) bits.push('Genuine ' + f.era + ' ' + what);
  else bits.push(what.charAt(0).toUpperCase() + what.slice(1));
  let s = bits[0] + (f.color ? ' in ' + f.color : '') + '.';
  if (f.condition === 'New with tags') s += ' Brand new, tags still on.';
  else if (f.condition === 'Like new') s += ' Worn once or twice at most - you would struggle to tell it from new.';
  return s + ' ';
}
function showGenerated(gen) {
  $('#listing-output').hidden = false;
  $('#out-title').textContent = gen.title;
  $('#out-title-len').textContent = gen.title.length + ' / 80';
  $('#out-desc').textContent = gen.body;
  $('#out-tags').textContent = gen.tags;
  $('#out-tag-len').textContent = gen.tags.split(' ').length + ' tags';
}

/* ---------------- photos ---------------- */
const Photos = {
  items: [], current: null, SZ: 1280,
  add(files) {
    let added = 0;
    Array.from(files).forEach(f => {
      if (!f.type.startsWith('image/')) return;
      const url = URL.createObjectURL(f);
      const img = new Image();
      const ph = { id: uid(), name: f.name.replace(/\.[^.]+$/, ''), url, img, fit: this.current ? this.current.fit : 'fill',
        padColor: '#f4f1ea', adj: { bright: 0, contrast: 0, sat: 0, warm: 0 }, rot: 0, mask: null, tol: 26, ready: false };
      img.onload = () => { ph.ready = true; this.items.push(ph); this.renderStrip(); if (!this.current) this.select(ph.id); else if (this.current === ph) this.render(); };
      img.onerror = () => { URL.revokeObjectURL(url); toast('Could not read ' + f.name); };
      img.src = url;
      added++;
    });
    if (added) toast(added === 1 ? 'Photo added' : added + ' photos added');
  },
  select(id) {
    const ph = this.items.find(x => x.id === id);
    if (!ph || !ph.ready) return;
    this.current = ph;
    $('#photo-editor').hidden = false;
    this.syncTools();
    this.renderStrip();
    this.render();
  },
  remove(id) {
    const i = this.items.findIndex(x => x.id === id);
    if (i < 0) return;
    URL.revokeObjectURL(this.items[i].url);
    this.items.splice(i, 1);
    if (this.current && this.current.id === id) {
      this.current = this.items[0] || null;
      $('#photo-editor').hidden = !this.current;
      if (this.current) { this.syncTools(); this.render(); }
    }
    this.renderStrip();
  },
  syncTools() {
    const ph = this.current; if (!ph) return;
    $$('#fit-seg button').forEach(b => b.classList.toggle('on', b.dataset.fit === ph.fit));
    $('#pad-color-row').hidden = ph.fit !== 'color';
    $('#pad-color').value = ph.padColor;
    $('#adj-bright').value = ph.adj.bright; $('#adj-bright').nextElementSibling.textContent = ph.adj.bright;
    $('#adj-contrast').value = ph.adj.contrast; $('#adj-contrast').nextElementSibling.textContent = ph.adj.contrast;
    $('#adj-sat').value = ph.adj.sat; $('#adj-sat').nextElementSibling.textContent = ph.adj.sat;
    $('#adj-warm').value = ph.adj.warm; $('#adj-warm').nextElementSibling.textContent = ph.adj.warm;
    $('#bg-tol').value = ph.tol; $('#bg-tol').nextElementSibling.textContent = ph.tol;
    $('#canvas-hint').textContent = ph.mask ? 'Backdrop mask active - use the brush to touch it up.' : '';
  },
  renderStrip() {
    const strip = $('#thumb-strip');
    strip.innerHTML = '';
    this.items.forEach(ph => {
      const im = document.createElement('img');
      im.src = ph.url; im.className = 'thumb' + (this.current && this.current.id === ph.id ? ' on' : '');
      im.title = ph.name + ' - double-click to remove';
      im.onclick = () => this.select(ph.id);
      im.ondblclick = () => this.remove(ph.id);
      strip.appendChild(im);
    });
  },

  /* --- compositing --- */
  dims(ph) { return ph.rot % 2 ? { w: ph.img.naturalHeight, h: ph.img.naturalWidth } : { w: ph.img.naturalWidth, h: ph.img.naturalHeight }; },
  drawRotated(ctx, ph, dx, dy, dw, dh) {
    ctx.save();
    ctx.translate(dx + dw / 2, dy + dh / 2);
    ctx.rotate(ph.rot * Math.PI / 2);
    const w = ph.img.naturalWidth, h = ph.img.naturalHeight;
    const rw = ph.rot % 2 ? dh : dw, rh = ph.rot % 2 ? dw : dh;
    ctx.drawImage(ph.img, -rw / 2, -rh / 2, rw, rh);
    ctx.restore();
  },
  composeBase(ph, Sz) {
    const cv = document.createElement('canvas'); cv.width = Sz; cv.height = Sz;
    const ctx = cv.getContext('2d');
    const d = this.dims(ph);
    if (ph.fit === 'fill') {
      const sc = Math.max(Sz / d.w, Sz / d.h);
      this.drawRotated(ctx, ph, (Sz - d.w * sc) / 2, (Sz - d.h * sc) / 2, d.w * sc, d.h * sc);
    } else {
      if (ph.fit === 'blur') {
        const small = document.createElement('canvas'); small.width = 96; small.height = 96;
        const sctx = small.getContext('2d');
        const sc = Math.max(96 / d.w, 96 / d.h);
        this.drawRotated(sctx, ph, (96 - d.w * sc) / 2, (96 - d.h * sc) / 2, d.w * sc, d.h * sc);
        ctx.imageSmoothingEnabled = true;
        ctx.filter = 'blur(14px) brightness(.92)';
        ctx.drawImage(small, 0, 0, 96, 96, 0, 0, Sz, Sz);
        ctx.filter = 'none';
      } else {
        ctx.fillStyle = ph.padColor; ctx.fillRect(0, 0, Sz, Sz);
      }
      const sc = Math.min(Sz / d.w, Sz / d.h) * 0.96;
      this.drawRotated(ctx, ph, (Sz - d.w * sc) / 2, (Sz - d.h * sc) / 2, d.w * sc, d.h * sc);
    }
    return cv;
  },
  adjust(id, a) {
    const d = id.data;
    const b = a.bright * 2.2;
    const c = 1 + a.contrast / 100 * 1.4;
    const sat = 1 + a.sat / 100;
    const warm = a.warm;
    for (let i = 0; i < d.length; i += 4) {
      let r = d[i], g = d[i + 1], bl = d[i + 2];
      r += b; g += b; bl += b;
      r = (r - 128) * c + 128; g = (g - 128) * c + 128; bl = (bl - 128) * c + 128;
      const lum = 0.299 * r + 0.587 * g + 0.114 * bl;
      r = lum + (r - lum) * sat; g = lum + (g - lum) * sat; bl = lum + (bl - lum) * sat;
      r += warm; bl -= warm;
      d[i] = r; d[i + 1] = g; d[i + 2] = bl;
    }
    return id;
  },
  render() {
    const ph = this.current; if (!ph || !ph.ready) return;
    const base = this.composeBase(ph, this.SZ);
    const bctx = base.getContext('2d');
    let id = bctx.getImageData(0, 0, this.SZ, this.SZ);
    this.adjust(id, ph.adj);
    ph.baseData = new Uint8ClampedArray(id.data);
    if (ph.mask) this.applyMask(id, ph.mask);
    const cv = $('#edit-canvas');
    cv.width = this.SZ; cv.height = this.SZ;
    cv.getContext('2d').putImageData(id, 0, 0);
  },
  renderFromBase() {
    const ph = this.current; if (!ph || !ph.baseData) return;
    const cv = $('#edit-canvas');
    const ctx = cv.getContext('2d');
    const id = ctx.createImageData(this.SZ, this.SZ);
    id.data.set(ph.baseData);
    if (ph.mask) this.applyMask(id, ph.mask);
    ctx.putImageData(id, 0, 0);
  },
  applyMask(id, mask) {
    const d = id.data;
    for (let i = 0; i < mask.length; i++) if (mask[i] < d[i * 4 + 3]) d[i * 4 + 3] = mask[i];
  },
  removeBg() {
    const ph = this.current; if (!ph || !ph.baseData) return;
    toast('Scanning the backdrop…');
    setTimeout(() => {
      const Sz = this.SZ, data = ph.baseData;
      const corner = (x0, y0) => {
        let r = 0, g = 0, b = 0, n = 0;
        for (let y = y0; y < y0 + 22; y++) for (let x = x0; x < x0 + 22; x++) {
          const i = (y * Sz + x) * 4; r += data[i]; g += data[i + 1]; b += data[i + 2]; n++;
        }
        return [r / n, g / n, b / n];
      };
      const cs = [corner(2, 2), corner(Sz - 24, 2), corner(2, Sz - 24), corner(Sz - 24, Sz - 24)];
      const bg = [0, 1, 2].map(k => (cs[0][k] + cs[1][k] + cs[2][k] + cs[3][k]) / 4);
      const tol2 = ph.tol * ph.tol * 3;
      const close = i => {
        const dr = data[i] - bg[0], dg = data[i + 1] - bg[1], db = data[i + 2] - bg[2];
        return dr * dr + dg * dg + db * db <= tol2;
      };
      const mask = new Uint8Array(Sz * Sz).fill(255);
      const stack = new Int32Array(Sz * Sz); let sp = 0;
      const seen = new Uint8Array(Sz * Sz);
      for (let x = 0; x < Sz; x++) {
        [x, (Sz - 1) * Sz + x, x * Sz, x * Sz + Sz - 1].forEach(p => {
          if (!seen[p] && close(p * 4)) { seen[p] = 1; stack[sp++] = p; }
        });
      }
      while (sp > 0) {
        const p = stack[--sp];
        mask[p] = 0;
        const x = p % Sz, y = (p / Sz) | 0;
        if (x > 0 && !seen[p - 1] && close((p - 1) * 4)) { seen[p - 1] = 1; stack[sp++] = p - 1; }
        if (x < Sz - 1 && !seen[p + 1] && close((p + 1) * 4)) { seen[p + 1] = 1; stack[sp++] = p + 1; }
        if (y > 0 && !seen[p - Sz] && close((p - Sz) * 4)) { seen[p - Sz] = 1; stack[sp++] = p - Sz; }
        if (y < Sz - 1 && !seen[p + Sz] && close((p + Sz) * 4)) { seen[p + Sz] = 1; stack[sp++] = p + Sz; }
      }
      // feather the edge
      for (let pass = 0; pass < 2; pass++) {
        const src = mask.slice();
        for (let y = 1; y < Sz - 1; y++) for (let x = 1; x < Sz - 1; x++) {
          const p = y * Sz + x;
          const sum = src[p - Sz - 1] + src[p - Sz] + src[p - Sz + 1] + src[p - 1] + src[p] + src[p + 1] + src[p + Sz - 1] + src[p + Sz] + src[p + Sz + 1];
          mask[p] = sum / 9;
        }
      }
      ph.mask = mask;
      this.renderFromBase();
      this.syncTools();
      toast('Backdrop removed - brush anything it missed');
    }, 30);
  },
  brushAt(clientX, clientY, mode) {
    const ph = this.current; if (!ph) return;
    if (!ph.mask) ph.mask = new Uint8Array(this.SZ * this.SZ).fill(255);
    const cv = $('#edit-canvas');
    const rect = cv.getBoundingClientRect();
    const x = (clientX - rect.left) / rect.width * this.SZ;
    const y = (clientY - rect.top) / rect.height * this.SZ;
    const r = num($('#brush-size').value) / 2 * (this.SZ / rect.width);
    const val = mode === 'erase' ? 0 : 255;
    const x0 = clamp(Math.floor(x - r), 0, this.SZ - 1), x1 = clamp(Math.ceil(x + r), 0, this.SZ - 1);
    const y0 = clamp(Math.floor(y - r), 0, this.SZ - 1), y1 = clamp(Math.ceil(y + r), 0, this.SZ - 1);
    for (let yy = y0; yy <= y1; yy++) for (let xx = x0; xx <= x1; xx++) {
      const dd = (xx - x) * (xx - x) + (yy - y) * (yy - y);
      if (dd <= r * r) ph.mask[yy * this.SZ + xx] = val;
    }
    this.renderFromBase();
  },
  exportOne(ph) {
    return new Promise(resolve => {
      const prev = this.current;
      const base = this.composeBase(ph, this.SZ);
      const bctx = base.getContext('2d');
      let id = bctx.getImageData(0, 0, this.SZ, this.SZ);
      this.adjust(id, ph.adj);
      if (ph.mask) this.applyMask(id, ph.mask);
      bctx.putImageData(id, 0, 0);
      const fmt = $$('#fmt-seg button').find(b => b.classList.contains('on')).dataset.fmt;
      let out = base;
      if (fmt === 'jpeg' && ph.mask) {
        out = document.createElement('canvas'); out.width = this.SZ; out.height = this.SZ;
        const octx = out.getContext('2d');
        octx.fillStyle = '#ffffff'; octx.fillRect(0, 0, this.SZ, this.SZ);
        octx.drawImage(base, 0, 0);
      }
      out.toBlob(blob => {
        download(ph.name + '-flipside.' + (fmt === 'png' ? 'png' : 'jpg'), blob);
        resolve();
      }, fmt === 'png' ? 'image/png' : 'image/jpeg', 0.92);
    });
  }
};

/* ---------------- niche lab ---------------- */
const CHECK_PHASES = [
  { name: 'Pick the niche', items: [
    ['Write down 3 niches you actually know', 'You spot fakes and underpriced grails faster in things you already wear or collect.'],
    ['Search each niche on Depop, filter to SOLD', 'Asking prices are wishes. Sold prices are the market.'],
    ['Note how long sold items took to move', 'Same-day sales mean demand; items sitting for weeks mean a slow niche.'],
    ['Score the survivors in the scorecard', 'Five sliders, one honest number. Compare niches side by side.']
  ]},
  { name: 'Source stock', items: [
    ['Find 2 repeatable sources', 'Thrift stores, car boots, wholesale lots, family closets. One lucky find is not a source.'],
    ['Set a hard max cost per item', 'If you cannot make 2.5–3x after fees, walk away.'],
    ['Buy 5–10 starter pieces, no more', 'Prove the niche sells before you sink real money into it.']
  ]},
  { name: 'Photograph', items: [
    ['Plain backdrop + daylight', 'A wall, a sheet, a clean floor. The Photos tab can strip a plain backdrop for you.'],
    ['Shoot 4+ photos per item', 'Front, back, label/tag, and any flaw - buyers ask for these anyway.'],
    ['Square-prep every photo here', 'Depop displays square. Fill-crop or blur-pad in the Photos tab.']
  ]},
  { name: 'List it', items: [
    ['Draft the listing in the Listings tab', 'Title, description and hashtags from the details you enter.'],
    ['Price from sold comps, not asking prices', 'Check 5+ sold listings and price inside that range.'],
    ['Post when your buyers scroll', 'Evenings and weekends move youth fashion fastest - test and watch your own numbers.']
  ]},
  { name: 'Ship + learn', items: [
    ['Know your shipping cost before you list', 'Weigh a packed item once. Guessing wrong eats your margin.'],
    ['Ship within 48 hours', 'Fast shipping is the cheapest way to get 5-star reviews and repeat buyers.'],
    ['Log every sale in Orders', 'The point of all this: see what you actually keep per sale, per day, per week.']
  ]}
];
function renderChecklist() {
  let done = 0, total = 0;
  $('#checklist').innerHTML = CHECK_PHASES.map((ph, pi) => {
    const items = ph.items.map((it, ii) => {
      const key = pi + '_' + ii;
      const on = !!S.checks[key];
      total++; if (on) done++;
      return '<label class="check-item' + (on ? ' done' : '') + '"><input type="checkbox" data-key="' + key + '"' + (on ? ' checked' : '') + '>' +
        '<span><span class="ct">' + esc(it[0]) + '</span><span class="ch" style="display:block">' + esc(it[1]) + '</span></span></label>';
    }).join('');
    const pd = ph.items.filter((it, ii) => S.checks[pi + '_' + ii]).length;
    return '<div class="check-phase"><h4>' + esc(ph.name) + '<span class="phase-bar"><i style="width:' +
      Math.round(pd / ph.items.length * 100) + '%"></i></span></h4>' + items + '</div>';
  }).join('');
  $('#check-progress').textContent = done + ' / ' + total + ' done';
}
function nicheScore() {
  const d = num($('#ni-demand').value), r = num($('#ni-room').value), m = num($('#ni-margin').value),
        s = num($('#ni-source').value), k = num($('#ni-know').value);
  return Math.round(d * 3 + r * 2 + m * 2 + s * 2 + k * 1);
}
function nicheVerdict(score) {
  if (score < 40) return 'Pass - the numbers do not back this one.';
  if (score < 60) return 'Risky - it needs a clear angle or a cheaper source.';
  if (score < 75) return 'Promising - start small and let sold items prove it.';
  return 'Strong - go build stock before someone else does.';
}
function updateNicheScore() {
  const sc = nicheScore();
  $('#ni-score').textContent = sc;
  $('#ni-verdict').textContent = nicheVerdict(sc);
}
function renderNicheList() {
  const wrap = $('#niche-list');
  const items = S.niches.slice().sort((a, b) => b.score - a.score);
  wrap.innerHTML = items.map(n =>
    '<div class="card-item" style="cursor:default"><div class="t">' + esc(n.name) + '</div>' +
    '<div class="m"><span class="chip ' + (n.score >= 60 ? 'listed' : (n.score >= 40 ? 'draft' : 'sold')) + '">' + n.score + ' / 100</span>' +
    '<span>' + esc(nicheVerdict(n.score).split(' - ')[0].trim()) + '</span>' +
    '<button class="icon-btn" data-niche-del="' + n.id + '" title="Delete" type="button" style="margin-left:auto"><svg viewBox="0 0 20 20"><path d="M4 6h12M8 6V4h4v2M6 6l1 10h6l1-10"/></svg></button></div></div>'
  ).join('') || '<p class="empty-note">No scorecards saved yet.</p>';
}

/* ---------------- settings ---------------- */
function renderSettings() {
  $('#set-fee-preset').value = S.settings.feePreset;
  $('#set-currency').value = S.settings.currency;
  $('#set-goal').value = S.settings.goal;
  $('#set-fee-pct').value = S.settings.feePct;
  $('#set-fee-fixed').value = S.settings.feeFixed;
  $('#custom-fees').hidden = S.settings.feePreset !== 'custom';
  $('#vault-setup').hidden = !!PASS || Vault.has();
  $('#vault-manage').hidden = !PASS && !Vault.has();
  $('#data-explainer').textContent = PASS
    ? 'Backups download encrypted with your passphrase - safe to keep anywhere. Restoring needs the same passphrase.'
    : 'Session mode: this backup is a plain, readable JSON file. Anyone who opens it can read it. Set a passphrase first if you want backups encrypted.';
}
function applyFeePreset() {
  const p = $('#set-fee-preset').value;
  S.settings.feePreset = p;
  if (FEE_PRESETS[p]) {
    S.settings.feePct = FEE_PRESETS[p].pct;
    S.settings.feeFixed = FEE_PRESETS[p].fixed;
    if (FEE_PRESETS[p].cur) S.settings.currency = FEE_PRESETS[p].cur;
  }
  markDirty(); renderSettings(); updateOrderPreview();
}

/* ---------------- data backup ---------------- */
async function exportData() {
  const payload = JSON.stringify(S, null, 1);
  if (PASS) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await Vault.derive(PASS, salt);
    const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, new TextEncoder().encode(payload));
    download('flipside-backup.json', JSON.stringify({ flipside:1, enc:true, salt:Vault.b64(salt), iv:Vault.b64(iv), data:Vault.b64(ct) }), 'application/json');
    toast('Encrypted backup downloaded');
  } else {
    const ok = await confirmModal('Plain backup', 'No passphrase is set, so this file will be <strong>readable by anyone</strong> who gets it. Download anyway?', 'Download anyway', true);
    if (!ok) return;
    download('flipside-backup.json', JSON.stringify({ flipside:1, enc:false, data:S }, null, 1), 'application/json');
    toast('Backup downloaded');
  }
}
async function importData(file) {
  try {
    const rec = JSON.parse(await file.text());
    if (!rec || rec.flipside !== 1) throw new Error('bad file');
    let data;
    if (rec.enc) {
      const pass = prompt('This backup is encrypted. Enter its passphrase:');
      if (!pass) return;
      const key = await Vault.derive(pass, Vault.unb64(rec.salt));
      const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv:Vault.unb64(rec.iv) }, key, Vault.unb64(rec.data));
      data = JSON.parse(new TextDecoder().decode(pt));
      if (!PASS) {
        const keep = await confirmModal('Keep it encrypted?', 'This backup is encrypted. Set the same passphrase now so your restored data stays protected on this device?', 'Set passphrase + keep');
        if (keep) { PASS = pass; await persist(); }
      }
    } else {
      data = rec.data;
    }
    if (!data || !Array.isArray(data.orders)) throw new Error('bad file');
    S = Object.assign(Blank(), data);
    migrateState();
    markDirty();
    route();
    toast('Backup restored');
  } catch (e) {
    console.error(e);
    toast('That file did not restore - wrong passphrase or not a Flipside backup');
  }
}

/* ---------------- gate / lock ---------------- */
let lockTimer = null;
function bumpLockTimer() {
  if (!PASS) return;
  clearTimeout(lockTimer);
  lockTimer = setTimeout(lockNow, 10 * 60 * 1000);
}
function lockNow() {
  if (dirty && PASS) persist();
  PASS = null;
  S = Blank();
  Photos.items.forEach(p => URL.revokeObjectURL(p.url));
  Photos.items = []; Photos.current = null;
  currentListing = null; editingOrder = null;
  showGate();
}
function showGate() {
  $('#app').hidden = true;
  $('#gate').hidden = false;
  const hasVault = Vault.has();
  $('#gate-unlock').hidden = !hasVault;
  $('#gate-fresh').hidden = hasVault;
  $('#gate-error').textContent = '';
  if (hasVault) setTimeout(() => $('#gate-pass').focus(), 50);
}
async function enterApp() {
  migrateState();
  $('#gate').hidden = true;
  $('#app').hidden = false;
  updateVaultChips();
  bumpLockTimer();
  route();
}

/* ---------------- sample data ---------------- */
function loadSample() {
  const t = todayStr();
  const mk = (daysAgo, item, price, shipC, shipCost, cost, notes) => ({
    id: uid(), date: addDays(t, -daysAgo), item, price, shipCharged: shipC, shipCost, cost, notes: notes || ''
  });
  S.orders = [
    mk(0, 'Carhartt detroit jacket', 48, 4.99, 3.6, 9, 'sold in 2 days'),
    mk(0, 'Nike vintage crewneck', 32, 3.5, 3.2, 6),
    mk(1, 'Levi 501s w32', 38, 4.5, 3.8, 7),
    mk(2, 'Ralph lauren quarter zip', 42, 4.2, 3.6, 8, 'bundle with tee'),
    mk(4, 'Adidas samba OG', 65, 5.5, 4.9, 22),
    mk(6, 'Y2K diesel tee', 24, 3.2, 2.9, 3),
    mk(8, 'North face nuptse', 95, 6.5, 5.8, 30, 'grail piece'),
    mk(11, 'Dickies 874 work pants', 28, 4, 3.4, 5)
  ];
  S.listings = [
    { id: uid(), status: 'listed', updated: Date.now(), name: 'Stussy 8-ball fleece', brand: 'Stussy',
      category: 'Hoodie / sweatshirt', size: 'L', color: 'washed black', condition: 'Used - excellent',
      era: '', flaws: '', measure: 'pit to pit 24in, length 27in', tags: ['streetwear', 'fleece'], cost: 12, price: 55 },
    { id: uid(), status: 'draft', updated: Date.now() - 3600e3, name: 'Harley davidson tee', brand: 'Harley Davidson',
      category: 'T-shirt', size: 'M', color: 'faded grey', condition: 'Used - good',
      era: '90s', flaws: 'light fade throughout, single stitch', measure: 'pit to pit 20in', tags: ['vintage', '90s', 'americana'], cost: 4, price: 26 }
  ];
  S.niches = [{ id: uid(), name: '90s workwear jackets', score: 78, created: Date.now() }];
  S.checks = { '0_0': true, '0_1': true, '1_0': true };
  S.sample = true;
  markDirty();
  route();
  toast('Sample data loaded - wipe it any time in Settings');
}

/* ---------------- wiring ---------------- */
function wire() {
  window.addEventListener('hashchange', route);
  ['pointerdown', 'keydown'].forEach(ev => window.addEventListener(ev, bumpLockTimer, { passive: true }));

  // gate
  $('#btn-fresh').onclick = enterApp;
  $('#btn-unlock').onclick = async () => {
    const pass = $('#gate-pass').value;
    if (!pass) return;
    try {
      const pt = await Vault.load(pass);
      S = Object.assign(Blank(), JSON.parse(pt));
      PASS = pass;
      $('#gate-pass').value = '';
      enterApp();
      toast('Unlocked - welcome back');
    } catch (e) {
      $('#gate-error').textContent = 'That passphrase did not open the vault. Try again.';
    }
  };
  $('#gate-pass').addEventListener('keydown', e => { if (e.key === 'Enter') $('#btn-unlock').click(); });

  // lock buttons
  ['#btn-lock-side', '#btn-lock-top', '#btn-lock-now'].forEach(sel => $(sel).onclick = () => {
    if (!PASS) { toast('Session mode - nothing to lock. Set a passphrase in Settings.'); return; }
    lockNow(); toast('Locked');
  });

  // board
  $('#hero-add-order').onclick = () => { location.hash = '#/orders'; setTimeout(() => $('#or-item').focus(), 60); };
  $('#hero-sample').onclick = loadSample;
  $('#btn-edit-goal').onclick = () => { location.hash = '#/settings'; setTimeout(() => $('#set-goal').focus(), 60); };

  // listings
  initListingSelects();
  $('#btn-new-listing').onclick = newListing;
  $('#listing-list').addEventListener('click', e => {
    const card = e.target.closest('[data-id]');
    if (card) openListing(card.dataset.id);
  });
  ['#li-name','#li-brand','#li-category','#li-size','#li-color','#li-condition','#li-era','#li-flaws','#li-measure','#li-tags','#li-cost','#li-price']
    .forEach(sel => $(sel).addEventListener('input', () => { if (currentListing) { saveCurrentListing(true); } if (sel === '#li-price' || sel === '#li-cost') updateTakehome(); }));
  $('#btn-generate').onclick = generateCopy;
  $$('.copy').forEach(b => b.onclick = () => copyText($('#' + b.dataset.copy).textContent, 'Copied'));
  $('#btn-copy-all').onclick = () => {
    const t = $('#out-title').textContent + '\n\n' + $('#out-desc').textContent + '\n' + $('#out-tags').textContent;
    copyText(t, 'Whole listing copied');
  };
  $('#btn-mark-listed').onclick = () => { if (!currentListing) return; saveCurrentListing(true); currentListing.status = 'listed'; markDirty(); renderListingList(); toast('Marked as listed - nice'); };
  $('#btn-mark-sold').onclick = () => {
    if (!currentListing) return;
    saveCurrentListing(true);
    currentListing.status = 'sold'; markDirty(); renderListingList();
    prefillOrder(currentListing.name, currentListing.price || '', currentListing.cost || '');
    location.hash = '#/orders';
    toast('Marked sold - finish logging the sale');
  };
  $('#btn-del-listing').onclick = async () => {
    if (!currentListing) return;
    const ok = await confirmModal('Delete listing?', 'Remove <strong>' + esc(currentListing.name || 'this listing') + '</strong> for good?', 'Delete', true);
    if (!ok) return;
    S.listings = S.listings.filter(x => x.id !== currentListing.id);
    currentListing = null; markDirty(); renderListingList();
  };

  // photos
  const dz = $('#dropzone');
  const fi = document.createElement('input');
  fi.type = 'file'; fi.accept = 'image/*'; fi.multiple = true; fi.hidden = true;
  document.body.appendChild(fi);
  dz.onclick = () => fi.click();
  dz.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fi.click(); } };
  fi.onchange = () => { Photos.add(fi.files); fi.value = ''; };
  ['dragover', 'dragenter'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('drag'); }));
  dz.addEventListener('drop', e => Photos.add(e.dataTransfer.files));
  $$('#fit-seg button').forEach(b => b.onclick = () => {
    const ph = Photos.current;
    ph.fit = b.dataset.fit;
    if (ph.mask) { ph.mask = null; toast('Framing changed - backdrop mask reset'); }
    $('#pad-color-row').hidden = b.dataset.fit !== 'color';
    $$('#fit-seg button').forEach(x => x.classList.toggle('on', x === b));
    Photos.render(); Photos.syncTools();
  });
  $('#pad-color').oninput = e => { Photos.current.padColor = e.target.value; Photos.render(); };
  $('#btn-rotate').onclick = () => { const ph = Photos.current; ph.rot = (ph.rot + 1) % 4; ph.mask = null; Photos.render(); Photos.syncTools(); toast('Rotated - backdrop mask reset'); };
  const adjBind = (sel, key) => {
    $(sel).addEventListener('input', e => {
      const v = num(e.target.value);
      e.target.nextElementSibling.textContent = v;
      if (!Photos.current) return;
      Photos.current.adj[key] = v;
      clearTimeout(adjBind._t);
      adjBind._t = setTimeout(() => Photos.render(), 40);
    });
  };
  adjBind('#adj-bright', 'bright'); adjBind('#adj-contrast', 'contrast'); adjBind('#adj-sat', 'sat'); adjBind('#adj-warm', 'warm');
  $('#bg-tol').addEventListener('input', e => { const v = num(e.target.value); e.target.nextElementSibling.textContent = v; if (Photos.current) Photos.current.tol = v; });
  $('#btn-bg-auto').onclick = () => Photos.removeBg();
  $('#btn-bg-reset').onclick = () => { if (Photos.current) { Photos.current.mask = null; Photos.renderFromBase(); Photos.syncTools(); } };
  let brushMode = 'off', brushing = false;
  $$('#brush-seg button').forEach(b => b.onclick = () => {
    brushMode = b.dataset.brush;
    $$('#brush-seg button').forEach(x => x.classList.toggle('on', x === b));
    $('#canvas-hint').textContent = brushMode === 'off' ? '' : (brushMode === 'erase' ? 'Drag on the photo to erase.' : 'Drag to bring back what was erased.');
  });
  const ecv = $('#edit-canvas');
  ecv.addEventListener('pointerdown', e => { if (brushMode === 'off') return; brushing = true; ecv.setPointerCapture(e.pointerId); Photos.brushAt(e.clientX, e.clientY, brushMode); });
  ecv.addEventListener('pointermove', e => { if (brushing && brushMode !== 'off') Photos.brushAt(e.clientX, e.clientY, brushMode); });
  ['pointerup', 'pointercancel'].forEach(ev => ecv.addEventListener(ev, () => { brushing = false; }));
  $$('#fmt-seg button').forEach(b => b.onclick = () => $$('#fmt-seg button').forEach(x => x.classList.toggle('on', x === b)));
  $('#btn-export').onclick = () => { if (Photos.current) Photos.exportOne(Photos.current).then(() => toast('Downloaded - Depop-ready square')); };
  $('#btn-export-all').onclick = async () => {
    if (!Photos.items.length) return;
    $('#export-status').textContent = 'Preparing ' + Photos.items.length + ' photos…';
    for (const ph of Photos.items) await Photos.exportOne(ph);
    $('#export-status').textContent = 'All downloaded. Your browser may have asked to allow multiple downloads.';
    toast('All photos exported');
  };

  // orders
  $('#or-date').value = todayStr();
  ['#or-item','#or-price','#or-ship-charged','#or-ship-cost','#or-cost'].forEach(sel => $(sel).addEventListener('input', updateOrderPreview));
  $('#btn-save-order').onclick = saveOrder;
  $('#btn-order-cancel').onclick = () => prefillOrder('', '', '');
  $('#btn-export-csv').onclick = exportCSV;
  $('#order-tbody').addEventListener('click', async e => {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const tr = btn.closest('tr');
    const o = S.orders.find(x => x.id === tr.dataset.id);
    if (!o) return;
    if (btn.dataset.act === 'del') {
      const ok = await confirmModal('Delete sale?', 'Remove the sale of <strong>' + esc(o.item) + '</strong> from your records?', 'Delete', true);
      if (!ok) return;
      S.orders = S.orders.filter(x => x.id !== o.id);
      markDirty(); renderOrders(); updateBadges();
    } else {
      editingOrder = o;
      $('#order-form-title').textContent = 'Edit sale';
      $('#btn-order-cancel').hidden = false;
      $('#or-item').value = o.item; $('#or-date').value = o.date;
      $('#or-price').value = o.price; $('#or-ship-charged').value = o.shipCharged;
      $('#or-ship-cost').value = o.shipCost; $('#or-cost').value = o.cost;
      $('#or-notes').value = o.notes || '';
      updateOrderPreview();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  });

  // niche
  ['#ni-demand','#ni-room','#ni-margin','#ni-source','#ni-know'].forEach(sel =>
    $(sel).addEventListener('input', e => { e.target.nextElementSibling.textContent = e.target.value; updateNicheScore(); }));
  $('#btn-save-niche').onclick = () => {
    const name = $('#ni-name').value.trim();
    if (!name) { toast('Name the niche first'); $('#ni-name').focus(); return; }
    S.niches.push({ id: uid(), name, score: nicheScore(), created: Date.now() });
    $('#ni-name').value = '';
    markDirty(); renderNicheList();
    toast('Scorecard saved');
  };
  $('#checklist').addEventListener('change', e => {
    const cb = e.target.closest('input[type=checkbox][data-key]');
    if (!cb) return;
    S.checks[cb.dataset.key] = cb.checked;
    if (!cb.checked) delete S.checks[cb.dataset.key];
    markDirty(); renderChecklist();
  });
  $('#niche-list').addEventListener('click', async e => {
    const btn = e.target.closest('[data-niche-del]');
    if (!btn) return;
    S.niches = S.niches.filter(n => n.id !== btn.dataset.nicheDel);
    markDirty(); renderNicheList();
  });

  // settings
  $('#set-fee-preset').addEventListener('change', applyFeePreset);
  $('#set-currency').addEventListener('change', () => { S.settings.currency = $('#set-currency').value; markDirty(); renderSettings(); });
  $('#set-goal').addEventListener('input', () => { S.settings.goal = num($('#set-goal').value); markDirty(); });
  $('#set-fee-pct').addEventListener('input', () => { S.settings.feePct = num($('#set-fee-pct').value); markDirty(); });
  $('#set-fee-fixed').addEventListener('input', () => { S.settings.feeFixed = num($('#set-fee-fixed').value); markDirty(); });
  $('#btn-set-pass').onclick = async () => {
    const a = $('#set-pass-1').value, b = $('#set-pass-2').value;
    if (a.length < 8) { toast('Passphrase needs at least 8 characters'); return; }
    if (a !== b) { toast('Those two passphrases do not match'); return; }
    PASS = a;
    await persist();
    $('#set-pass-1').value = ''; $('#set-pass-2').value = '';
    updateVaultChips(); renderSettings(); bumpLockTimer();
    toast('Vault on - your data now stays on this device, encrypted');
  };
  $('#btn-change-pass').onclick = async () => {
    const p = await passModal('Change passphrase', 'Your data will be re-encrypted with the new passphrase.');
    if (!p) return;
    PASS = p;
    await persist();
    toast('Passphrase changed');
  };
  $('#btn-remove-vault').onclick = async () => {
    const ok = await confirmModal('Stop storing + wipe?', 'This deletes the encrypted copy on this device <strong>and</strong> clears everything in the app. Download a backup first if you want to keep anything.', 'Wipe it', true);
    if (!ok) return;
    Vault.clear(); lockNow(); toast('Wiped');
  };
  $('#btn-export-data').onclick = exportData;
  $('#btn-import-data').onclick = () => $('#import-file').click();
  $('#import-file').addEventListener('change', e => { if (e.target.files[0]) importData(e.target.files[0]); e.target.value = ''; });
  $('#btn-wipe').onclick = async () => {
    const ok = await confirmModal('Wipe everything?', 'Every listing, sale, scorecard and tick is gone' + (S.sample ? ' - including the sample data' : '') + '. There is no undo.', 'Wipe it all', true);
    if (!ok) return;
    Vault.clear();
    lockNow();
    toast('Everything wiped');
  };

  window.addEventListener('resize', () => { if (location.hash.replace('#/', '') === 'board' || !location.hash) renderBoard(); });
}

/* ---------------- boot ---------------- */
wire();
updateNicheScore();
updateVaultChips();
showGate();
