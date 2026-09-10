(function () {
  const root = document.getElementById('iplookup-root');

  root.innerHTML = `
    <div class="iplookup-bar">
      <input id="iplookup-input" type="text" placeholder="輸入 IP 或網域...">
      <button id="iplookup-query-btn" class="btn btn-primary" onclick="ipLookupQuery()">查詢</button>
      <button id="iplookup-analyze-btn" class="btn btn-secondary" disabled onclick="ipLookupAnalyze()">進階分析</button>
    </div>
    <div class="iplookup-tabs">
      <button class="iplookup-tab-btn active" data-tab="rdap" onclick="ipLookupSwitchTab('rdap')">RDAP／WHOIS</button>
      <button class="iplookup-tab-btn" data-tab="vt" onclick="ipLookupSwitchTab('vt')">VirusTotal</button>
      <button id="iplookup-tab-btn-analysis" class="iplookup-tab-btn" data-tab="analysis" disabled onclick="ipLookupSwitchTab('analysis')">進階分析</button>
    </div>
    <div id="iplookup-panel-rdap" class="iplookup-panel active"><div class="iplookup-empty">尚未查詢</div></div>
    <div id="iplookup-panel-vt" class="iplookup-panel"><div class="iplookup-empty">尚未查詢</div></div>
    <div id="iplookup-panel-analysis" class="iplookup-panel"><div class="iplookup-empty">尚未分析</div></div>
  `;

  let lastRdapResult = null;
  let lastVtResult = null;
  let rdapDone = false;
  let vtDone = false;

  window.ipLookupSwitchTab = function (tab) {
    document.querySelectorAll('.iplookup-tab-btn').forEach((btn) => btn.classList.toggle('active', btn.dataset.tab === tab));
    document.querySelectorAll('.iplookup-panel').forEach((panel) => panel.classList.remove('active'));
    document.getElementById(`iplookup-panel-${tab}`).classList.add('active');
  };

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function flattenForDisplay(data, prefix = '') {
    const out = {};
    for (const [key, value] of Object.entries(data || {})) {
      const label = prefix ? `${prefix}.${key}` : key;
      if (value === null || value === undefined) {
        out[label] = '';
      } else if (Array.isArray(value)) {
        out[label] = value.map((v) => (typeof v === 'object' && v !== null ? JSON.stringify(v) : v)).join('; ');
      } else if (typeof value === 'object') {
        Object.assign(out, flattenForDisplay(value, label));
      } else {
        out[label] = String(value);
      }
    }
    return out;
  }

  function renderLookupError(tab, message) {
    document.getElementById(`iplookup-panel-${tab}`).innerHTML = `<div class="iplookup-error">${escapeHtml(message)}</div>`;
  }

  function renderLookupResult(tab, result) {
    const panel = document.getElementById(`iplookup-panel-${tab}`);
    const meta = `
      <div class="iplookup-meta">
        <div><span class="field-label">資料來源</span>${escapeHtml(result.source)}</div>
        <div><span class="field-label">查詢日期時間</span>${escapeHtml(result.queried_at)}</div>
      </div>`;
    const rows = Object.entries(flattenForDisplay(result.data))
      .map(([k, v]) => `<div class="report-fields"><span class="field-label">${escapeHtml(k)}</span><span class="field-value">${escapeHtml(v)}</span></div>`)
      .join('');
    panel.innerHTML = meta + rows;
  }

  function setQueryButtonDisabled(disabled) {
    document.getElementById('iplookup-query-btn').disabled = disabled;
  }

  function checkQueryComplete() {
    if (rdapDone && vtDone) {
      setQueryButtonDisabled(false);
      document.getElementById('iplookup-analyze-btn').disabled = false;
    }
  }

  async function fetchRdap(target) {
    try {
      const res = await fetch(`/api/lookup/rdap?target=${encodeURIComponent(target)}`);
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        renderLookupError('rdap', `RDAP/WHOIS 查詢失敗：${res.status} ${err.detail || ''}`);
      } else {
        lastRdapResult = await res.json();
        renderLookupResult('rdap', lastRdapResult);
      }
    } catch (e) {
      renderLookupError('rdap', `RDAP/WHOIS 查詢失敗：${e.message}`);
    } finally {
      rdapDone = true;
      checkQueryComplete();
    }
  }

  async function fetchVt(target) {
    try {
      const res = await fetch(`/api/lookup/vt?target=${encodeURIComponent(target)}`);
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        renderLookupError('vt', `VirusTotal 查詢失敗：${res.status} ${err.detail || ''}`);
      } else {
        lastVtResult = await res.json();
        renderLookupResult('vt', lastVtResult);
      }
    } catch (e) {
      renderLookupError('vt', `VirusTotal 查詢失敗：${e.message}`);
    } finally {
      vtDone = true;
      checkQueryComplete();
    }
  }

  window.ipLookupQuery = function () {
    const target = document.getElementById('iplookup-input').value.trim();
    if (!target) {
      showToast('請輸入查詢目標', 'error');
      return;
    }
    lastRdapResult = null;
    lastVtResult = null;
    rdapDone = false;
    vtDone = false;
    setQueryButtonDisabled(true);
    document.getElementById('iplookup-analyze-btn').disabled = true;
    document.getElementById('iplookup-tab-btn-analysis').disabled = true;
    document.getElementById('iplookup-panel-analysis').innerHTML = '<div class="iplookup-empty">尚未分析</div>';
    document.getElementById('iplookup-panel-rdap').innerHTML = '<div class="iplookup-loading">查詢中...</div>';
    document.getElementById('iplookup-panel-vt').innerHTML = '<div class="iplookup-loading">查詢中...</div>';

    fetchRdap(target);
    fetchVt(target);
  };
})();
