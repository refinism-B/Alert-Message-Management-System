(function () {
  const root = document.getElementById('settings-root');
  const KEYS = [
    { kind: 'vt', title: 'VirusTotal 金鑰' },
    { kind: 'llm', title: 'LLM（Anthropic）金鑰' },
  ];
  const keyEls = {};
  let modelEls = null;

  // 使用者與伺服器回傳的文字一律用 textContent，不拼 innerHTML
  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    Object.entries(props || {}).forEach(([k, v]) => {
      if (k === 'className') node.className = v;
      else if (k === 'text') node.textContent = v;
      else node.setAttribute(k, v);
    });
    children.forEach((c) => node.append(c));
    return node;
  }

  // FastAPI 的 422 detail 是物件陣列，直接插值會變成 [object Object]
  function errorDetail(err) {
    const d = err && err.detail;
    return typeof d === 'string' ? d : JSON.stringify(d ?? '');
  }

  async function api(method, path, body) {
    const opts = { method };
    if (body !== undefined) {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`${res.status} ${errorDetail(data)}`);
    return data;
  }

  function setMsg(node, text, isErr) {
    node.textContent = text;
    node.className = 'settings-msg' + (isErr ? ' err' : '');
  }

  function buildKeyCard(spec) {
    const status = el('div', { className: 'settings-status', text: '載入中...' });
    const input = el('input', { type: 'password', autocomplete: 'off', placeholder: '貼上新的金鑰', spellcheck: 'false' });
    const saveBtn = el('button', { className: 'btn btn-primary btn-sm', text: '儲存' });
    const delBtn = el('button', { className: 'btn btn-danger btn-sm', text: '刪除' });
    const msg = el('div', { className: 'settings-msg' });
    const row = el('div', { className: 'settings-row' }, input, saveBtn, delBtn);
    const card = el('div', { className: 'settings-card' }, el('h3', { text: spec.title }), status, row, msg);
    saveBtn.addEventListener('click', () => saveKey(spec.kind));
    delBtn.addEventListener('click', () => deleteKey(spec.kind));
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') saveKey(spec.kind); });
    keyEls[spec.kind] = { status, input, saveBtn, delBtn, msg, spec };
    return card;
  }

  function renderKey(kind, s) {
    const e = keyEls[kind];
    const locked = s.source === 'env';
    e.status.className = 'settings-status' + (s.configured ? ' ok' : '');
    if (!s.configured) {
      e.status.textContent = '未設定';
    } else {
      const parts = ['已設定'];
      if (s.hint) parts.push(s.hint);
      parts.push(locked ? '來源：.env' : '來源：前端設定');
      if (s.updated_at) parts.push(s.updated_at);
      e.status.textContent = parts.join('｜');
    }
    e.input.disabled = locked;
    e.saveBtn.disabled = locked;
    e.delBtn.disabled = locked || !s.configured;
    e.input.placeholder = locked ? '由 .env 設定（唯讀）' : '貼上新的金鑰';
    if (locked) e.input.value = '';
  }

  function renderStatus(data) {
    KEYS.forEach((spec) => renderKey(spec.kind, data.keys[spec.kind]));
    if (data.keyring_error) setMsg(keyEls.vt.msg, data.keyring_error, true);
    const m = data.model;
    const locked = m.source === 'env';
    modelEls.select.replaceChildren();
    // .env 指定的模型可能不在清單內，仍要顯示出來（唯讀）
    const values = m.options.includes(m.value) ? m.options : [...m.options, m.value];
    values.forEach((v) => {
      const opt = el('option', { value: v, text: v });
      if (v === m.value) opt.selected = true;
      modelEls.select.append(opt);
    });
    modelEls.select.disabled = locked;
    modelEls.note.textContent = locked ? '由 .env 設定（唯讀）' : (m.source === 'ui' ? '前端設定' : '預設值');
  }

  async function refresh() {
    try {
      renderStatus(await api('GET', '/api/settings'));
    } catch (e) {
      setMsg(keyEls.vt.msg, `讀取設定失敗：${e.message}`, true);
    }
  }

  async function saveKey(kind) {
    const e = keyEls[kind];
    const value = e.input.value.trim();
    if (!value) { setMsg(e.msg, '請輸入金鑰', true); return; }
    e.saveBtn.disabled = true;
    setMsg(e.msg, '驗證中...', false);
    try {
      const s = await api('PUT', `/api/settings/keys/${kind}`, { value });
      e.input.value = '';
      renderKey(kind, s);
      setMsg(e.msg, '已驗證並儲存', false);
    } catch (err) {
      setMsg(e.msg, `儲存失敗：${err.message}`, true);
      e.saveBtn.disabled = false;
    }
  }

  async function deleteKey(kind) {
    const e = keyEls[kind];
    if (!confirm(`確定要刪除「${e.spec.title}」嗎？`)) return;
    try {
      const s = await api('DELETE', `/api/settings/keys/${kind}`);
      e.input.value = '';
      renderKey(kind, s);
      setMsg(e.msg, '已刪除', false);
    } catch (err) {
      setMsg(e.msg, `刪除失敗：${err.message}`, true);
    }
  }

  async function saveModel() {
    try {
      await api('PUT', '/api/settings/model', { model: modelEls.select.value });
      setMsg(modelEls.msg, '已儲存', false);
    } catch (err) {
      setMsg(modelEls.msg, `儲存失敗：${err.message}`, true);
    }
    refresh();
  }

  const modelSelect = el('select', {});
  modelSelect.addEventListener('change', saveModel);
  modelEls = {
    select: modelSelect,
    note: el('div', { className: 'settings-note' }),
    msg: el('div', { className: 'settings-msg' }),
  };

  root.append(el('div', { className: 'settings-wrap' },
    el('div', { className: 'settings-note', text: '金鑰只寫不讀：儲存後不會再顯示，只存在 Windows 認證管理員。.env 有值時以 .env 為準。' }),
    ...KEYS.map(buildKeyCard),
    el('div', { className: 'settings-card' }, el('h3', { text: 'LLM 模型' }),
      el('div', { className: 'settings-row' }, modelSelect), modelEls.note, modelEls.msg),
  ));

  window.settingsRefresh = refresh;
})();
