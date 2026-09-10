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
    const exportBtns = `
      <div class="iplookup-export">
        <button class="btn btn-secondary btn-sm" onclick="ipLookupExportTxt('${tab}')">匯出 TXT</button>
        <button class="btn btn-secondary btn-sm" onclick="ipLookupExportCsv('${tab}')">匯出 CSV</button>
      </div>`;
    panel.innerHTML = meta + rows + exportBtns;
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

  let lastAnalysisResult = null;

  function renderAnalysis(result) {
    lastAnalysisResult = result;
    const panel = document.getElementById('iplookup-panel-analysis');
    panel.innerHTML = `
      <div class="iplookup-meta">
        <div><span class="field-label">分析日期時間</span>${escapeHtml(result.analyzed_at)}</div>
        <div><span class="field-label">分析對象</span>${escapeHtml(result.target)}</div>
        <div><span class="field-label">分析使用的廠牌與模型</span>Anthropic — ${escapeHtml(result.model)}</div>
      </div>
      <div class="iplookup-disclaimer">本分析僅供參考，非最終判斷，請自行核實原始資料</div>
      <pre class="iplookup-analysis-content">${escapeHtml(result.content)}</pre>
      <div class="iplookup-export">
        <button class="btn btn-secondary btn-sm" onclick="ipLookupExportAnalysisTxt()">匯出 TXT</button>
      </div>`;
  }

  window.ipLookupAnalyze = async function () {
    const target = document.getElementById('iplookup-input').value.trim();
    const btn = document.getElementById('iplookup-analyze-btn');
    btn.disabled = true;
    document.getElementById('iplookup-panel-analysis').innerHTML = '<div class="iplookup-loading">分析中...</div>';
    try {
      const res = await fetch('/api/lookup/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target,
          rdap: lastRdapResult ? lastRdapResult.data : null,
          vt: lastVtResult ? lastVtResult.data : null,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        document.getElementById('iplookup-panel-analysis').innerHTML =
          `<div class="iplookup-error">進階分析失敗：${res.status} ${escapeHtml(err.detail || '')}</div>`;
        return;
      }
      const result = await res.json();
      renderAnalysis(result);
      document.getElementById('iplookup-tab-btn-analysis').disabled = false;
      ipLookupSwitchTab('analysis');
    } catch (e) {
      document.getElementById('iplookup-panel-analysis').innerHTML =
        `<div class="iplookup-error">進階分析失敗：${escapeHtml(e.message)}</div>`;
    } finally {
      btn.disabled = false;
    }
  };

  function csvEscape(value) {
    const s = String(value ?? '');
    if (/[",\n]/.test(s)) {
      return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }

  function downloadBlob(filename, content, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function resultForTab(tab) {
    return tab === 'rdap' ? lastRdapResult : lastVtResult;
  }

  function sanitizeFilename(s) {
    return String(s).replace(/[\\/:*?"<>|]/g, '_');
  }

  window.ipLookupExportTxt = function (tab) {
    const result = resultForTab(tab);
    if (!result) return;
    const lines = [`資料來源：${result.source}`, `查詢日期時間：${result.queried_at}`, ''];
    const flat = flattenForDisplay(result.data);
    for (const [k, v] of Object.entries(flat)) {
      lines.push(`${k}：${v}`);
    }
    downloadBlob(`${tab}_${sanitizeFilename(result.target)}.txt`, lines.join('\n'), 'text/plain;charset=utf-8');
  };

  window.ipLookupExportCsv = function (tab) {
    const result = resultForTab(tab);
    if (!result) return;
    const rows = [['欄位', '值'], ['資料來源', result.source], ['查詢日期時間', result.queried_at]];
    const flat = flattenForDisplay(result.data);
    for (const [k, v] of Object.entries(flat)) {
      rows.push([k, v]);
    }
    const csv = rows.map((row) => row.map(csvEscape).join(',')).join('\r\n');
    downloadBlob(`${tab}_${sanitizeFilename(result.target)}.csv`, '﻿' + csv, 'text/csv;charset=utf-8');
  };

  window.ipLookupExportAnalysisTxt = function () {
    if (!lastAnalysisResult) return;
    const lines = [
      `分析日期時間：${lastAnalysisResult.analyzed_at}`,
      `分析對象：${lastAnalysisResult.target}`,
      `分析使用的廠牌與模型：Anthropic — ${lastAnalysisResult.model}`,
      '',
      lastAnalysisResult.content,
    ];
    downloadBlob(`analysis_${sanitizeFilename(lastAnalysisResult.target)}.txt`, lines.join('\n'), 'text/plain;charset=utf-8');
  };
})();
