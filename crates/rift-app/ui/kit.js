/* Rift UI kit: компоненты слоя поверх страницы. Без зависимостей.
 *
 *   Kit.popover({ anchor, align, content })       дропдаун у элемента
 *   Kit.menu({ anchor, align, items })            меню; результат — id пункта
 *   Kit.modal({ title, body, footer })            модальное окно
 *   Kit.alert / confirm / prompt                  диалоги поверх модального окна
 *   Kit.toast({ title, text, tone })              уведомление
 *   Kit.ui.*                                      элементы форм (переключатель, сегменты, слайдер, цвет)
 *
 * Слой (`#root`) — отдельный прозрачный WebView поверх страницы. Размытие фона рисует система (см. Kit.host.blur),
 * компоненты лишь сообщают, какой прямоугольник должен быть размыт. */
(() => {
  const SVGNS = 'http://www.w3.org/2000/svg';
  const doc = document, rootEl = () => doc.getElementById('root');

  /* ---- мелкие помощники ---- */
  const h = (tag, attrs = {}, ...kids) => {
    const el = doc.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v == null) continue;
      if (k === 'class') el.className = v;
      else if (k === 'style' && typeof v === 'object') for (const [prop, val] of Object.entries(v)) el.style.setProperty(prop.startsWith('--') ? prop : prop.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`), String(val));
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k === 'value' || k === 'checked' || k === 'disabled') el[k] = v;
      else el.setAttribute(k, v === true ? '' : String(v));
    }
    el.append(...kids.flat(Infinity).filter((c) => c != null && c !== false).map((c) => (c instanceof Node ? c : doc.createTextNode(String(c)))));
    return el;
  };
  const icon = (name, cls = '') => {
    const s = doc.createElementNS(SVGNS, 'svg'); s.setAttribute('class', `i ${cls}`.trim()); s.setAttribute('aria-hidden', 'true');
    const u = doc.createElementNS(SVGNS, 'use'); u.setAttribute('href', `#i-${name}`); s.append(u); return s;
  };
  const cssNum = (name, fallback) => { const v = parseFloat(getComputedStyle(doc.documentElement).getPropertyValue(name)); return Number.isNaN(v) ? fallback : v; };
  const ms = (base) => Math.round(base * cssNum('--m', 1));
  const rectOf = (el) => ({ x: el.offsetLeft, y: el.offsetTop, w: el.offsetWidth, h: el.offsetHeight }); // без учёта transform

  /* ---- позиция дропдауна: чистая функция ---- */
  function position(anchor, size, o = {}) {
    const { align = 'start', side = 'bottom', gap = 8, margin = 8, vw = innerWidth, vh = innerHeight } = o;
    let x = align === 'end' ? anchor.x + anchor.w - size.w : align === 'center' ? anchor.x + (anchor.w - size.w) / 2 : anchor.x;
    x = Math.max(margin, Math.min(x, vw - size.w - margin));
    const below = anchor.y + anchor.h + gap, above = anchor.y - gap - size.h;
    let y, placement = side;
    if (side === 'bottom') { if (below + size.h <= vh - margin || above < margin) y = below; else { y = above; placement = 'top'; } }
    else if (above >= margin || below + size.h > vh - margin) y = above; else { y = below; placement = 'bottom'; }
    y = Math.max(margin, Math.min(y, vh - size.h - margin));
    return { x: Math.round(x), y: Math.round(y), placement };
  }

  /* ---- связь со средой: заполняет overlay.html ---- */
  const host = { blur() {}, hide() {}, full() {}, rect() {}, result() {}, shown() {} };
  const settings = { accent: 'blue', blur: 'soft', dim: 45, motion: 'system', rift_first: true };
  const caps = { blur: false };
  const PALETTE = [
    { id: 'blue', name: 'Синий', c: '#6aa5e8', fg: '#06101c' }, { id: 'teal', name: 'Бирюзовый', c: '#4cc3a0', fg: '#041510' },
    { id: 'amber', name: 'Янтарный', c: '#e0a84a', fg: '#1a1203' }, { id: 'red', name: 'Красный', c: '#e5645c', fg: '#190606' },
    { id: 'violet', name: 'Фиолетовый', c: '#b49bf0', fg: '#120a24' }, { id: 'white', name: 'Белый', c: '#f2f2f5', fg: '#0a0a0c' },
  ];

  function applySettings(s) {
    Object.assign(settings, s);
    const rootStyle = doc.documentElement.style, p = PALETTE.find((x) => x.id === settings.accent) || PALETTE[0];
    rootStyle.setProperty('--accent', p.c); rootStyle.setProperty('--accent-fg', p.fg);
    rootStyle.setProperty('--dim', String(Math.max(0, Math.min(100, settings.dim)) / 100));
    doc.documentElement.dataset.motion = settings.motion;
    doc.documentElement.dataset.blur = settings.blur !== 'off' && caps.blur ? 'on' : 'off';
    reportBlur();
  }

  /* ---- слои ---- */
  const layers = [];
  let seq = 0;

  function reportBlur() {
    const top = layers[layers.length - 1];
    if (!top || top.closing || settings.blur === 'off' || !caps.blur) { host.blur(null); return; }
    host.blur(top.modal ? { x: 0, y: 0, w: top.vp?.w ?? innerWidth, h: top.vp?.h ?? innerHeight, r: 0 } : { ...rectOf(top.surface), r: 14 });
  }

  function mount({ kind, node, modal = false, dismissible = true, anchor, align, side, gap, onClose }) {
    const shown = host.full();
    const layer = { id: ++seq, kind, modal, dismissible, closing: false, surface: node, restore: doc.activeElement, onClose };
    layer.scrim = h('div', { class: `scrim${modal ? '' : ' clear'}`, onpointerdown: (e) => { if (e.target === layer.scrim && dismissible) close(layer); } });
    node.classList.add('surface'); node.dataset.kind = kind;
    layer.promise = new Promise((resolve) => { layer.resolve = resolve; });
    rootEl().append(layer.scrim, node);
    layers.push(layer);
    // Анимация входа начинается, когда среда подтвердила показ слоя: у скрытого WebView нет кадров, и она бы прошла вхолостую.
    Promise.resolve(shown).then((vp) => {
      if (layer.closing) return;
      // Размер слоя сообщает среда: он мог только что поменяться (с плашки уведомлений на всё окно), а `innerWidth` ещё старый.
      layer.vp = vp && vp.w && vp.h ? vp : null;
      if (anchor) {
        const pos = position(anchor, { w: node.offsetWidth, h: node.offsetHeight }, { align, side, gap, vw: layer.vp?.w ?? innerWidth, vh: layer.vp?.h ?? innerHeight });
        node.style.left = `${pos.x}px`; node.style.top = `${pos.y}px`;
        node.style.setProperty('--origin', `${pos.placement === 'top' ? 'bottom' : 'top'} ${align === 'end' ? 'right' : 'left'}`);
      }
      void node.offsetWidth;   // зафиксировать начальное состояние, иначе переход не запустится
      layer.scrim.classList.add('in'); node.classList.add('in');
      reportBlur();
      host.shown();
      const first = node.querySelector('[data-autofocus]') || node.querySelector('button, input, [tabindex]');
      if (first) first.focus({ preventScroll: true });
    });
    return layer;
  }

  function close(layer, result) {
    if (layer.closing) return;
    layer.closing = true;
    layer.surface.classList.remove('in'); layer.surface.classList.add('out'); layer.scrim.classList.remove('in');
    const i = layers.indexOf(layer); if (i >= 0) layers.splice(i, 1);
    reportBlur();
    const done = () => {
      layer.surface.remove(); layer.scrim.remove();
      if (!layers.length) { if (toasts.length) syncToasts(); else host.hide(); }
      if (layer.restore && layer.restore.isConnected) layer.restore.focus({ preventScroll: true });
      layer.onClose && layer.onClose(result);
      layer.resolve(result);
    };
    const wait = ms(190);
    if (wait <= 0) done(); else setTimeout(done, wait + 30);
  }

  const closeTop = (result) => { const t = layers[layers.length - 1]; if (t && t.dismissible) close(t, result); };

  doc.addEventListener('keydown', (e) => {
    const top = layers[layers.length - 1];
    if (!top) return;
    if (e.key === 'Escape') { e.preventDefault(); closeTop(undefined); return; }
    if (e.key === 'Tab' && top.modal) {   // фокус не выходит за пределы модального окна
      const items = [...top.surface.querySelectorAll('button:not(:disabled), input:not(:disabled), [tabindex]:not([tabindex="-1"])')].filter((x) => x.offsetParent !== null);
      if (!items.length) return;
      const first = items[0], last = items[items.length - 1];
      if (e.shiftKey && doc.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && doc.activeElement === last) { e.preventDefault(); first.focus(); }
    }
    if (top.kind === 'menu' && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      e.preventDefault();
      const items = [...top.surface.querySelectorAll('.menu-item')];
      const at = items.indexOf(doc.activeElement);
      items[(at + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length].focus();
    }
  });

  /* ---- компоненты ---- */
  const popover = ({ anchor, align = 'start', content, width }) => {
    const node = h('div', { class: 'popover', role: 'dialog', style: width ? { width: `${width}px` } : null }, content);
    return mount({ kind: 'popover', node, anchor, align }).promise;
  };

  const menu = ({ anchor, align = 'end', items }) => {
    let layer;
    let n = 0;
    const node = h('div', { class: 'menu', role: 'menu' }, items.map((it) => {
      if (it.separator) return h('div', { class: 'menu-sep', role: 'separator' });
      return h('button', { class: `menu-item${it.danger ? ' danger' : ''}`, role: 'menuitem', style: { '--i': n++ }, onclick: () => close(layer, it.id) },
        it.icon ? icon(it.icon) : null, h('span', {}, it.label), it.hint ? h('span', { class: 'hint' }, [].concat(it.hint).map((k) => h('span', { class: 'kbd' }, k))) : null);
    }));
    layer = mount({ kind: 'menu', node, anchor, align, gap: 6 });
    return layer.promise;
  };

  const modal = ({ title, body, footer, width, dismissible = true, dialog = false, lead, onClose }) => {
    let layer;
    const node = h('div', { class: `modal${dialog ? ' dialog' : ''}`, role: dialog ? 'alertdialog' : 'dialog', 'aria-modal': 'true', 'aria-label': title, style: width ? { width: `min(${width}px, calc(100vw - 32px))` } : null },
      h('div', { class: 'modal-head' }, lead || null, h('h2', {}, title), dismissible ? h('button', { class: 'icon-btn', 'aria-label': 'Закрыть', onclick: () => close(layer) }, icon('x')) : null),
      h('div', { class: 'modal-body' }, body),
      footer ? h('div', { class: 'modal-foot' }, footer) : null);
    layer = mount({ kind: 'modal', node, modal: true, dismissible, onClose });
    layer.close = (r) => close(layer, r);
    return layer;
  };

  const tones = { info: ['info', 'tone-neutral'], ok: ['ok', 'tone-ok'], warn: ['error', 'tone-warn'], bad: ['blocked', 'tone-bad'] };
  const lead = (tone) => h('div', { class: `dlg-icon ${tones[tone || 'info'][1]}` }, icon(tones[tone || 'info'][0]));

  const alertDlg = ({ title, text, tone = 'info', okLabel = 'Понятно' }) => new Promise((resolve) => {
    let l;
    l = modal({ title, dialog: true, lead: lead(tone), body: h('p', {}, text), footer: h('button', { class: 'button primary', 'data-autofocus': true, onclick: () => l.close(true) }, okLabel), onClose: () => resolve(true) });
  });

  const confirmDlg = ({ title, text, confirmLabel = 'Подтвердить', cancelLabel = 'Отмена', danger = false, tone }) => new Promise((resolve) => {
    let l, answer = false;
    l = modal({
      title, dialog: true, lead: lead(tone || (danger ? 'bad' : 'info')), body: h('p', {}, text),
      footer: [h('button', { class: 'button ghost', onclick: () => l.close() }, cancelLabel),
        h('button', { class: `button ${danger ? 'danger' : 'primary'}`, 'data-autofocus': true, onclick: () => { answer = true; l.close(); } }, confirmLabel)],
      onClose: () => resolve(answer),
    });
  });

  const promptDlg = ({ title, text, label, value = '', placeholder = '', confirmLabel = 'Готово', validate }) => new Promise((resolve) => {
    let l, answer = null;
    const input = h('input', { class: 'field', value, placeholder, 'data-autofocus': true, spellcheck: 'false', 'aria-label': label || title });
    const error = h('div', { class: 'field-error', role: 'alert', hidden: true });
    const submit = () => {
      const v = input.value.trim(), problem = validate ? validate(v) : (v ? '' : 'Введите значение');
      if (problem) { error.textContent = problem; error.hidden = false; input.classList.add('invalid'); input.focus(); return; }
      answer = v; l.close();
    };
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } });
    input.addEventListener('input', () => { error.hidden = true; input.classList.remove('invalid'); });
    l = modal({
      title, dialog: true, body: [text ? h('p', {}, text) : null, label ? h('label', { class: 'field-label' }, label) : null, input, error],
      footer: [h('button', { class: 'button ghost', onclick: () => l.close() }, 'Отмена'), h('button', { class: 'button primary', onclick: submit }, confirmLabel)],
      onClose: () => resolve(answer),
    });
  });

  /* ---- уведомления ---- */
  const toasts = [];
  const toastBox = () => doc.getElementById('toasts');
  // Пока открыт большой слой, уведомления лежат в нём; иначе слой сжимается до стопки уведомлений.
  const syncToasts = () => (!layers.length && toasts.length ? host.rect({ w: 360, h: toastBox().scrollHeight }) : undefined);
  const toast = ({ title, text, tone = 'info', ms: life = 4200 }) => {
    const node = h('div', { class: 'surface toast', role: tone === 'bad' ? 'alert' : 'status', style: { position: 'relative', background: 'rgb(10 10 12 / .96)' } },
      h('span', { class: tones[tone][1] }, icon(tones[tone][0])),
      h('div', { class: 't-body' }, title ? h('div', { class: 't-title' }, title) : null, text ? h('div', { class: 't-text' }, text) : null),
      h('button', { class: 'icon-btn', style: { width: '24px', height: '24px' }, 'aria-label': 'Закрыть уведомление', onclick: () => dismiss() }, icon('x', 's')));
    const item = { node }; toasts.push(item);
    toastBox().append(node);
    Promise.resolve(syncToasts()).then(() => { void node.offsetWidth; node.classList.add('in'); syncToasts(); });   // сначала показать слой, потом анимировать
    let timer = life > 0 ? setTimeout(() => dismiss(), life) : null;
    function dismiss() {
      clearTimeout(timer);
      const i = toasts.indexOf(item); if (i < 0) return; toasts.splice(i, 1);
      node.classList.remove('in'); node.classList.add('out');
      setTimeout(() => { node.remove(); syncToasts(); if (!layers.length && !toasts.length) host.hide(); }, ms(190) + 30);
    }
    return dismiss;
  };

  /* ---- элементы форм ---- */
  const ui = {
    row: ({ label, desc, control, labelId }) => h('div', { class: 'row' }, h('div', {}, h('div', { class: 'label', id: labelId }, label), desc ? h('div', { class: 'desc' }, desc) : null), h('div', { class: 'ctl' }, control)),
    section: (t) => h('div', { class: 'sect' }, t),
    segmented: ({ options, value, onChange, label, disabled }) => {
      const box = h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': label });
      const set = (v) => box.querySelectorAll('button').forEach((b) => b.setAttribute('aria-checked', String(b.dataset.v === v)));
      for (const o of options) box.append(h('button', { type: 'button', role: 'radio', 'data-v': o.value, disabled: disabled || o.disabled, onclick: () => { set(o.value); onChange(o.value); } }, o.label));
      set(value); box.set = set; return box;
    },
    switch: ({ value, onChange, label }) => {
      const b = h('button', { type: 'button', class: 'switch', role: 'switch', 'aria-label': label, 'aria-checked': String(!!value), onclick: () => { const v = b.getAttribute('aria-checked') !== 'true'; b.setAttribute('aria-checked', String(v)); onChange(v); } });
      return b;
    },
    swatches: ({ value, onChange }) => {
      const box = h('div', { class: 'swatches', role: 'radiogroup', 'aria-label': 'Акцентный цвет' });
      const set = (v) => box.querySelectorAll('button').forEach((b) => b.setAttribute('aria-checked', String(b.dataset.v === v)));
      for (const p of PALETTE) box.append(h('button', { type: 'button', role: 'radio', 'data-v': p.id, title: p.name, 'aria-label': p.name, style: { '--c': p.c }, onclick: () => { set(p.id); onChange(p.id); } }));
      set(value); return box;
    },
    range: ({ value, min = 0, max = 100, step = 5, onChange, label, format = (v) => `${v}%` }) => {
      const out = h('span', { class: 'val' }, format(value));
      const input = h('input', { type: 'range', class: 'range', min, max, step, value, 'aria-label': label });
      const paint = () => input.style.setProperty('--fill', `${((input.value - min) / (max - min)) * 100}%`);
      input.addEventListener('input', () => { paint(); out.textContent = format(Number(input.value)); onChange(Number(input.value)); });
      paint();
      return [input, out];
    },
  };

  window.Kit = {
    clearToasts: () => { toasts.splice(0).forEach((t) => t.node.remove()); },
    h, icon, position, popover, menu, modal, alert: alertDlg, confirm: confirmDlg, prompt: promptDlg, toast, ui,
    host, caps, settings, PALETTE, applySettings, reportBlur, closeTop,
    state: () => ({ layers: layers.length, top: layers.length ? layers[layers.length - 1].kind : null, toasts: toasts.length }),
  };
})();
