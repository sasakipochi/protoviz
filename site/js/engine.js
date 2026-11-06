// 画面の描画とアニメーション。プロトコルの中身は js/protocols/*.js にデータとして書く。
'use strict';
(() => {
const PV = window.PV;
const $ = (s, el = document) => el.querySelector(s);
const NS = 'http://www.w3.org/2000/svg';
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const svg = (tag, attrs = {}, text) => {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined) el.setAttribute(k, v);
  if (text !== undefined) el.textContent = text;
  return el;
};
// 空行で段落、1 つの改行は <br>
const paras = (t) => String(t || '').split('\n\n').filter(Boolean).map((x) => `<p>${esc(x).replace(/\n/g, '<br>')}</p>`).join('');
const toArr = (x) => (Array.isArray(x) ? x : [x]);
const CIRCLED = '①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳';

const st = { proto: null, step: -1, sel: null, speed: 1, anim: null, auto: false };

/* ---------- ルーティング ---------- */
function parseHash() {
  const [id, step] = location.hash.replace(/^#\/?/, '').split('/');
  const proto = PV.protocols.find((p) => p.id === id) || PV.protocols[0];
  return { proto, step: step === undefined ? -1 : Math.max(-1, Math.min(+step, proto.steps.length)) };
}
function go(protoId, step, push = true) {
  const h = `#/${protoId}` + (step >= 0 ? `/${step}` : '');
  if (location.hash !== h) (push ? history.pushState : history.replaceState).call(history, null, '', h);
  render();
}
window.addEventListener('popstate', render);

/* ---------- サイドバー ---------- */
function renderNav() {
  const nav = $('#nav');
  nav.innerHTML = '';
  const groups = {};
  for (const p of PV.protocols) (groups[p.group] ||= []).push(p);
  for (const [g, list] of Object.entries(groups)) {
    nav.insertAdjacentHTML('beforeend', `<div class="nav-group">${esc(g)}</div>`);
    for (const p of list) {
      const a = document.createElement('a');
      a.href = `#/${p.id}`;
      a.className = 'nav-item' + (p === st.proto ? ' active' : '');
      a.innerHTML = `<span class="nav-name">${esc(p.name)}</span><span class="nav-title">${esc(p.title)}</span>`;
      a.onclick = (e) => { e.preventDefault(); stopAuto(); go(p.id, -1); document.body.classList.remove('nav-open'); };
      nav.appendChild(a);
    }
  }
}

/* ---------- 経路 (リンクのグラフ上の最短経路) ---------- */
function route(p, a, b) {
  if (a === b) return [a];
  const adj = {};
  for (const [x, y] of p.links) { (adj[x] ||= []).push(y); (adj[y] ||= []).push(x); }
  const prev = { [a]: null };
  const q = [a];
  while (q.length) {
    const n = q.shift();
    if (n === b) break;
    for (const m of adj[n] || []) if (!(m in prev)) { prev[m] = n; q.push(m); }
  }
  if (!(b in prev)) return [a, b];
  const path = [];
  for (let n = b; n !== null; n = prev[n]) path.unshift(n);
  return path;
}

/* ---------- ノードの状態 (ステップごとに積み上がる) ---------- */
function nodeStates(p, upto) {
  const s = {};
  p.steps.slice(0, upto + 1).forEach((step) => Object.assign(s, step.state || {}));
  return s;
}

/* ---------- トポロジ図 ---------- */
const ICON = {
  pc: 'M-13 -9h26v15h-26z M-17 9h34', server: 'M-11 -13h22v8h-22z M-11 -3h22v8h-22z M-11 7h22v6h-22z',
  router: 'M-12 0h24 M0 -12v24 M-12 0l5 -4 M-12 0l5 4 M12 0l-5 -4 M12 0l-5 4',
  cloud: 'M-14 6a7 7 0 0 1 2 -13a9 9 0 0 1 17 2a6 6 0 0 1 -1 11z', key: 'M-4 -4a7 7 0 1 1 0.1 0 M2 2l11 11 M8 8l-3 3 M11 11l-3 3',
  nat: 'M-12 -6h24 M8 -10l4 4l-4 4 M12 6h-24 M-8 2l-4 4l4 4', relay: 'M-12 0h24 M-4 -8l8 8l-8 8',
  attacker: 'M-10 6a10 10 0 0 1 20 0z M-6 -6a6 6 0 1 0 12 0a6 6 0 1 0 -12 0',
};
function renderTopo(p) {
  const el = $('#topo');
  el.innerHTML = '';
  const H = p.height || 380;
  el.setAttribute('viewBox', `0 0 1000 ${H}`);
  for (const g of p.groups || []) {
    el.append(svg('rect', { x: g.x, y: g.y, width: g.w, height: g.h, rx: 14, class: 'grp' }));
    el.append(svg('text', { x: g.x + 12, y: g.y + 20, class: 'grp-label' }, g.label));
  }
  for (const [a, b] of p.links) {
    const A = p.nodes[a], B = p.nodes[b];
    el.append(svg('line', { x1: A.x, y1: A.y, x2: B.x, y2: B.y, class: 'link' }));
  }
  const states = nodeStates(p, st.step);
  for (const [id, n] of Object.entries(p.nodes)) {
    const g = svg('g', { class: 'node', 'data-id': id, transform: `translate(${n.x},${n.y})` });
    g.append(svg('rect', { x: -30, y: -26, width: 60, height: 52, rx: n.icon === 'router' || n.icon === 'nat' ? 26 : 10, class: 'node-box' }));
    g.append(svg('path', { d: ICON[n.icon] || ICON.pc, class: 'node-icon' }));
    g.append(svg('text', { y: 44, class: 'node-label' }, n.label));
    if (n.sub) g.append(svg('text', { y: 60, class: 'node-sub' }, n.sub));
    if (states[id]) {
      const t = svg('text', { y: n.sub ? 80 : 64, class: 'node-state' }, states[id]);
      g.append(t);
    }
    el.append(g);
  }
  el.append(svg('g', { id: 'packets' }));
}

/* ---------- アニメーション ---------- */
function stopAnim() {
  if (st.anim) st.anim.cancelled = true;
  st.anim = null;
  const layer = $('#packets');
  if (layer) layer.innerHTML = '';
}
function sleep(ms, token) {
  return new Promise((res) => setTimeout(() => res(!token.cancelled), ms / st.speed));
}
function moveDot(p, ev, path, token) {
  return new Promise((resolve) => {
    const layer = $('#packets');
    const pts = path.map((id) => p.nodes[id]);
    const seg = pts.slice(1).map((b, i) => Math.hypot(b.x - pts[i].x, b.y - pts[i].y));
    const total = seg.reduce((a, b) => a + b, 0) || 1;
    const dur = (380 + total * 2.2) / st.speed;
    const g = svg('g', { class: `pkt c-${ev.color}` });
    g.append(svg('circle', { r: 9 }));
    g.append(svg('text', { y: -15, class: 'pkt-label' }, ev.label));
    g.style.cursor = 'pointer';
    g.onclick = () => select(ev);
    layer.append(g);
    const t0 = performance.now();
    const tick = (now) => {
      if (token.cancelled) { g.remove(); return resolve(); }
      let d = Math.min(1, (now - t0) / dur) * total;
      let i = 0;
      while (i < seg.length - 1 && d > seg[i]) { d -= seg[i]; i++; }
      const a = pts[i], b = pts[i + 1] || a, r = seg[i] ? Math.min(1, d / seg[i]) : 1;
      g.setAttribute('transform', `translate(${a.x + (b.x - a.x) * r},${a.y + (b.y - a.y) * r})`);
      if (now - t0 < dur) requestAnimationFrame(tick);
      else { flash(path.at(-1)); setTimeout(() => g.remove(), 900 / st.speed); resolve(); }
    };
    requestAnimationFrame(tick);
  });
}
function flash(id) {
  const n = $(`#topo .node[data-id="${id}"]`);
  if (!n) return;
  n.classList.remove('hit'); void n.getBBox(); n.classList.add('hit');
}
async function localBubble(p, ev, token) {
  const n = p.nodes[ev.from];
  const layer = $('#packets');
  const g = svg('g', { class: 'bubble', transform: `translate(${n.x},${n.y - 40})` });
  const t = svg('text', { y: 0 }, ev.label);
  g.append(svg('rect', { class: 'bubble-bg' }), t);
  layer.append(g);
  const bb = t.getBBox();
  const r = g.firstChild;
  Object.entries({ x: bb.x - 8, y: bb.y - 4, width: bb.width + 16, height: bb.height + 8, rx: 6 }).forEach(([k, v]) => r.setAttribute(k, v));
  flash(ev.from);
  await sleep(1100, token);
  g.remove();
}
async function playStep(p, idx) {
  stopAnim();
  const step = p.steps[idx];
  if (!step) return;
  const token = { cancelled: false };
  st.anim = token;
  let running = [];
  for (const ev of step.events) {
    if (!ev.with) { await Promise.all(running); running = []; if (token.cancelled) return; await sleep(120, token); }
    if (token.cancelled) return;
    markCurrent(ev);
    const job = ev.kind === 'local'
      ? localBubble(p, ev, token)
      : Promise.all(toArr(ev.to).map((to) => moveDot(p, ev, route(p, ev.from, to), token)));
    running.push(job);
  }
  await Promise.all(running);
  markCurrent(null);
  if (!token.cancelled && st.auto) {
    await sleep(1400, token);
    if (!token.cancelled && st.auto) {
      if (st.step < p.steps.length - 1) go(p.id, st.step + 1);
      else stopAuto();
    }
  }
}
function markCurrent(ev) {
  document.querySelectorAll('.seq-ev.playing, .chip.playing').forEach((e) => e.classList.remove('playing'));
  if (!ev) return;
  document.querySelectorAll(`[data-ev="${ev._id}"]`).forEach((e) => e.classList.add('playing'));
}
function stopAuto() { st.auto = false; const b = $('#btn-auto'); if (b) b.textContent = '▶ 通しで再生'; }

/* ---------- ステップの説明 ---------- */
function factsTable(facts) {
  if (!facts || !facts.length) return '';
  return `<dl class="facts">${facts.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>`;
}
function renderPanel(p) {
  const el = $('#panel');
  const n = p.steps.length;
  if (st.step < 0) {
    el.innerHTML = `
      <div class="eyebrow">概要</div>
      <h2>${esc(p.overview.full)}</h2>
      <p>${esc(p.overview.description)}</p>
      ${factsTable(p.overview.facts)}
      <button class="primary" id="btn-start">はじめる →</button>`;
    $('#btn-start').onclick = () => go(p.id, 0);
    return;
  }
  if (st.step >= n) {
    const o = p.outro;
    el.innerHTML = `
      <div class="eyebrow">まとめ</div>
      <h2>${esc(o.title)}</h2>
      ${paras(o.text)}
      ${o.points ? `<ul class="points">${o.points.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}
      ${o.next ? `<p class="muted">${esc(o.next)}</p>` : ''}`;
    return;
  }
  const s = p.steps[st.step];
  el.innerHTML = `
    <div class="eyebrow">ステップ ${st.step + 1} / ${n}</div>
    <h2>${esc(s.title)}</h2>
    <p class="lead">${esc(s.desc)}</p>
    ${paras(s.detail)}
    ${factsTable(s.facts)}
    <div class="chips">${s.events.map((ev) => `<button class="chip c-${ev.color}" data-ev="${ev._id}">${ev.kind === 'local' ? '⚙ ' : ''}${esc(ev.label)}</button>`).join('')}</div>`;
  el.querySelectorAll('.chip').forEach((b) => (b.onclick = () => select(p.evById[b.dataset.ev])));
}

function renderControls(p) {
  const n = p.steps.length;
  const dots = [`<button class="dot ${st.step < 0 ? 'on' : ''}" data-i="-1" title="概要">概要</button>`]
    .concat(p.steps.map((s, i) => `<button class="dot ${i === st.step ? 'on' : ''} ${i < st.step ? 'done' : ''}" data-i="${i}" title="${esc(s.title)}">${CIRCLED[i] || i + 1}</button>`))
    .concat([`<button class="dot ${st.step >= n ? 'on' : ''}" data-i="${n}" title="まとめ">まとめ</button>`]);
  $('#dots').innerHTML = dots.join('');
  $('#dots').querySelectorAll('.dot').forEach((d) => (d.onclick = () => { stopAuto(); go(p.id, +d.dataset.i); }));
  $('#btn-prev').disabled = st.step < 0;
  $('#btn-next').disabled = st.step >= n;
  $('#btn-replay').disabled = st.step < 0 || st.step >= n;
}

/* ---------- 凡例 ---------- */
function renderLegend(p) {
  $('#legend').innerHTML = (p.legend || []).map(([c, t]) => `<span class="lg"><i class="sw c-${c}"></i>${esc(t)}</span>`).join('');
}

/* ---------- シーケンス図 ---------- */
function renderSeq(p) {
  const el = $('#seq');
  el.innerHTML = '';
  const L = p.lifelines;
  const W = Math.max(560, Math.round(el.parentElement.clientWidth || 1000)), top = 46, rowH = 30, stepH = 26, left = 20;
  const colX = (id) => left + ((W - left - 40) * (L.indexOf(id) + 0.5)) / L.length;
  let y = top + 8;
  const rows = [];
  p.steps.forEach((s, si) => {
    rows.push({ type: 'step', si, y }); y += stepH;
    s.events.forEach((ev) => { rows.push({ type: 'ev', si, ev, y }); y += rowH; });
    y += 6;
  });
  const H = y + 10;
  el.setAttribute('viewBox', `0 0 ${W} ${H}`);
  el.style.aspectRatio = `${W} / ${H}`;
  for (const id of L) {
    const x = colX(id);
    el.append(svg('line', { x1: x, y1: top - 8, x2: x, y2: H - 4, class: 'lifeline' }));
    el.append(svg('text', { x, y: 18, class: 'seq-head' }, p.nodes[id].label));
    if (p.nodes[id].sub) el.append(svg('text', { x, y: 34, class: 'seq-sub' }, p.nodes[id].sub));
  }
  for (const r of rows) {
    const cls = r.si < st.step ? 'past' : r.si === st.step ? 'now' : 'future';
    if (r.type === 'step') {
      const g = svg('g', { class: `seq-step ${cls}` });
      g.append(svg('rect', { x: 4, y: r.y, width: W - 8, height: stepH - 4, rx: 4 }));
      g.append(svg('text', { x: 12, y: r.y + 16 }, `${CIRCLED[r.si] || r.si + 1} ${p.steps[r.si].title}`));
      g.onclick = () => { stopAuto(); go(p.id, r.si); };
      el.append(g);
      continue;
    }
    const ev = r.ev;
    const g = svg('g', { class: `seq-ev ${cls} c-${ev.color} ${st.sel === ev ? 'sel' : ''}`, 'data-ev': ev._id });
    const yy = r.y + rowH / 2 + 4;
    g.append(svg('rect', { x: 4, y: r.y, width: W - 8, height: rowH, class: 'hit' }));
    if (ev.kind === 'local') {
      const x = colX(ev.from);
      const last = L.indexOf(ev.from) === L.length - 1;
      const t = svg('text', { x: last ? x - 14 : x + 14, y: yy + 4, class: 'seq-local', 'text-anchor': last ? 'end' : 'start' }, '⚙ ' + ev.label);
      g.append(svg('rect', { x: x - 6, y: yy - 9, width: 12, height: 18, rx: 3, class: 'seq-box' }), t);
    } else {
      const x1 = colX(ev.from);
      for (const to of toArr(ev.to)) {
        const x2 = colX(to);
        const dir = Math.sign(x2 - x1) || 1;
        g.append(svg('line', { x1, y1: yy, x2: x2 - dir * 6, y2: yy, class: 'arrow' + (Array.isArray(ev.to) ? ' multi' : '') }));
        g.append(svg('path', { d: `M${x2} ${yy} l${-dir * 9} -5 v10 z`, class: 'head' }));
      }
      const xs = toArr(ev.to).map(colX).concat(x1);
      const mid = (Math.min(...xs) + Math.max(...xs)) / 2;
      g.append(svg('text', { x: mid, y: yy - 6, class: 'seq-label' }, ev.label));
    }
    g.onclick = () => { if (r.si !== st.step) { stopAuto(); st.pendingSel = ev; go(p.id, r.si); } else select(ev); };
    el.append(g);
  }
}

/* ---------- パケットインスペクタ ---------- */
function select(ev) {
  st.sel = ev;
  document.querySelectorAll('.seq-ev.sel, .chip.sel').forEach((e) => e.classList.remove('sel'));
  if (ev) document.querySelectorAll(`[data-ev="${ev._id}"]`).forEach((e) => e.classList.add('sel'));
  renderInspector();
}
function renderInspector() {
  const el = $('#inspector');
  const ev = st.sel;
  if (!ev) { el.innerHTML = '<p class="muted">シーケンス図の矢印やステップのボタンを押すと、そのパケットの中身をここに表示します。</p>'; return; }
  const p = st.proto;
  const names = (ids) => toArr(ids).map((i) => p.nodes[i].label).join(', ');
  if (ev.kind === 'local') {
    el.innerHTML = `<div class="ins-head"><span class="sw c-${ev.color}"></span><b>${esc(ev.label)}</b></div>
      <div class="ins-route">${esc(names(ev.from))} の中での処理 (パケットは流れません)</div>
      ${paras(ev.text)}`;
    return;
  }
  const pk = ev.packet;
  if (!pk) { el.innerHTML = `<div class="ins-head"><b>${esc(ev.label)}</b></div><p>${esc(ev.text || '')}</p>`; return; }
  let off = 0;
  const wireBytes = [], decBytes = [];
  const allBasic = pk.layers.every((L) => L.meta.basic);
  const layerHtml = pk.layers.map((L, li) => {
    const target = L.decoded ? decBytes : wireBytes;
    const rows = L.fields.map((f, fi) => {
      const start = target.length;
      f.bytes.forEach((b) => target.push({ b, li, fi, dec: L.decoded }));
      return `<tr data-f="${li}:${fi}" title="${esc(f.desc || '')}">
        <td class="fn" style="padding-left:${8 + f.depth * 14}px">${esc(f.name.trim())}${f.desc ? '<i class="has-desc"></i>' : ''}</td>
        <td class="fv">${esc(f.value)}</td><td class="fo">${f.bytes.length ? `${start}–${start + f.bytes.length - 1}` : ''}</td></tr>`
        + (f.desc ? `<tr class="desc-row" data-f="${li}:${fi}"><td colspan="3" style="padding-left:${8 + f.depth * 14}px">${esc(f.desc)}</td></tr>` : '');
    }).join('');
    const size = L.fields.reduce((a, f) => a + f.bytes.length, 0);
    return `<details class="layer L${li % 6}"${L.meta.basic && !L.decoded && !allBasic ? '' : ' open'}>
      <summary><span class="lname">${L.decoded ? '🔓 ' : ''}${esc(L.name)}</span><span class="lsize">${size} バイト</span></summary>
      ${L.note ? `<p class="lnote">${esc(L.note)}</p>` : ''}
      <table class="fields">${rows}</table></details>`;
  }).join('');
  off = wireBytes.length;
  const dump = (arr) => {
    let h = '';
    for (let i = 0; i < arr.length; i += 16) {
      const row = arr.slice(i, i + 16);
      h += `<div class="hx-row"><span class="hx-off">${i.toString(16).padStart(4, '0')}</span><span class="hx-bytes">${row.map((x) => `<span class="L${x.li % 6}" data-f="${x.li}:${x.fi}">${x.b.toString(16).padStart(2, '0')}</span>`).join('')}</span><span class="hx-asc">${row.map((x) => `<span data-f="${x.li}:${x.fi}">${x.b >= 32 && x.b < 127 ? esc(String.fromCharCode(x.b)) : '·'}</span>`).join('')}</span></div>`;
    }
    return h;
  };
  el.innerHTML = `
    <div class="ins-head"><span class="sw c-${ev.color}"></span><b>${esc(pk.summary)}</b></div>
    <div class="ins-route">${esc(names(ev.from))} → ${esc(names(ev.to))} ・ 回線上 ${off} バイト</div>
    ${pk.note ? `<p class="ins-note">${esc(pk.note)}</p>` : ''}
    <div class="ins-layers">${layerHtml}</div>
    <div class="hexdump"><div class="hx-title">回線上のバイト列 (16進)</div>${dump(wireBytes)}
    ${decBytes.length ? `<div class="hx-title">🔓 復号・デコードした中身</div>${dump(decBytes)}` : ''}</div>`;
  el.querySelectorAll('[data-f]').forEach((e) => {
    e.onmouseenter = () => el.querySelectorAll(`[data-f="${e.dataset.f}"]`).forEach((x) => x.classList.add('hl'));
    e.onmouseleave = () => el.querySelectorAll('.hl').forEach((x) => x.classList.remove('hl'));
    e.onclick = () => {
      const row = el.querySelector(`tr[data-f="${e.dataset.f}"]`);
      if (row && e.tagName === 'SPAN') { row.closest('details').open = true; row.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); }
    };
  });
}

/* ---------- 全体 ---------- */
function prepare(p) {
  if (p.evById) return;
  p.evById = {};
  let k = 0;
  p.steps.forEach((s) => s.events.forEach((ev) => { ev._id = `${p.id}-${k++}`; p.evById[ev._id] = ev; }));
}
function render() {
  const { proto, step } = parseHash();
  const changed = proto !== st.proto;
  st.proto = proto; st.step = step;
  prepare(proto);
  stopAnim();
  document.title = `${proto.name} — ProtoViz`;
  renderNav();
  $('#p-name').textContent = proto.name;
  $('#p-title').textContent = proto.title;
  $('#p-layer').textContent = proto.layerLabel;
  renderLegend(proto);
  renderTopo(proto);
  renderPanel(proto);
  renderControls(proto);
  renderSeq(proto);
  const s = proto.steps[step];
  const want = st.pendingSel || (s ? s.events.find((e) => e.kind === 'pkt') || s.events[0] : changed ? null : st.sel);
  st.pendingSel = null;
  select(s && want && s.events.includes(want) ? want : s ? s.events[0] : null);
  if (s) {
    playStep(proto, step);
    const cur = $('#seq .seq-step.now');
    if (cur && st.auto) cur.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
}

function init() {
  $('#btn-prev').onclick = () => { stopAuto(); go(st.proto.id, st.step - 1); };
  $('#btn-next').onclick = () => { stopAuto(); go(st.proto.id, st.step + 1); };
  $('#btn-replay').onclick = () => playStep(st.proto, st.step);
  $('#btn-auto').onclick = () => {
    if (st.auto) return stopAuto();
    st.auto = true; $('#btn-auto').textContent = '■ 停止';
    go(st.proto.id, st.step >= 0 && st.step < st.proto.steps.length ? st.step : 0);
    if (st.step >= 0) playStep(st.proto, st.step);
  };
  $('#speed').onchange = (e) => (st.speed = +e.target.value);
  $('#btn-menu').onclick = () => document.body.classList.toggle('nav-open');
  $('#btn-theme').onclick = () => {
    const dark = document.documentElement.dataset.theme !== 'dark';
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    try { localStorage.setItem('protoviz:theme', dark ? 'dark' : 'light'); } catch (e) { /* 保存できなくてもよい */ }
  };
  document.addEventListener('keydown', (e) => {
    if (e.target.closest('input,select,textarea')) return;
    if (e.key === 'ArrowRight' && st.step < st.proto.steps.length) { stopAuto(); go(st.proto.id, st.step + 1); }
    if (e.key === 'ArrowLeft' && st.step >= 0) { stopAuto(); go(st.proto.id, st.step - 1); }
    if (e.key === ' ' && st.step >= 0) { e.preventDefault(); playStep(st.proto, st.step); }
  });
  render();
}
let resizeTimer;
window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => st.proto && renderSeq(st.proto), 150); });
document.addEventListener('DOMContentLoaded', init);
})();
