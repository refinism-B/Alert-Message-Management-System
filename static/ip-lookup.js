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
      <button id="iplookup-tab-btn-compare" class="iplookup-tab-btn" data-tab="compare" disabled onclick="ipLookupSwitchTab('compare')">來源比對</button>
      <button id="iplookup-tab-btn-analysis" class="iplookup-tab-btn" data-tab="analysis" disabled onclick="ipLookupSwitchTab('analysis')">進階分析</button>
    </div>
    <div id="iplookup-panel-rdap" class="iplookup-panel active"><div class="iplookup-empty">尚未查詢</div></div>
    <div id="iplookup-panel-vt" class="iplookup-panel"><div class="iplookup-empty">尚未查詢</div></div>
    <div id="iplookup-panel-compare" class="iplookup-panel"><div class="iplookup-empty">尚未查詢</div></div>
    <div id="iplookup-panel-analysis" class="iplookup-panel"><div class="iplookup-empty">尚未分析</div></div>
  `;

  let lastRdapResult = null;
  let lastVtResult = null;
  let rdapDone = false;
  let vtDone = false;
  let lastQueryTarget = null;
  let lastCompareResult = null;

  window.ipLookupSwitchTab = function (tab) {
    document.querySelectorAll('.iplookup-tab-btn').forEach((btn) => btn.classList.toggle('active', btn.dataset.tab === tab));
    document.querySelectorAll('.iplookup-panel').forEach((panel) => panel.classList.remove('active'));
    document.getElementById(`iplookup-panel-${tab}`).classList.add('active');
  };

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // 純攤平，不做任何摘要或壓縮。摘要交給後端 view，這裡只負責
  // 「檢視原始資料」與 CSV 匯出——兩者都要求一欄不少。
  function flattenForDisplay(data, prefix = '') {
    const out = {};
    for (const [key, value] of Object.entries(data || {})) {
      const label = prefix ? `${prefix}.${key}` : key;
      if (value === null || value === undefined) {
        out[label] = '';
      } else if (Array.isArray(value)) {
        if (value.length === 0) {
          out[label] = '';
        } else {
          value.forEach((item, i) => {
            if (item !== null && typeof item === 'object') {
              Object.assign(out, flattenForDisplay(item, `${label}[${i}]`));
            } else {
              out[`${label}[${i}]`] = String(item);
            }
          });
        }
      } else if (typeof value === 'object') {
        if (Object.keys(value).length === 0) {
          out[label] = '';
        } else {
          Object.assign(out, flattenForDisplay(value, label));
        }
      } else {
        out[label] = String(value);
      }
    }
    return out;
  }

  function markdownToHtml(md) {
    const lines = String(md).replace(/\r\n/g, '\n').split('\n');
    const out = [];
    let para = [];
    let list = [];
    let quote = [];
    let table = [];

    function inline(text) {
      let s = escapeHtml(text);
      const codeSpans = [];
      s = s.replace(/`([^`]+?)`/g, (match, code) => {
        codeSpans.push(`<code>${code}</code>`);
        return `\x00CODE${codeSpans.length - 1}\x00`;
      });
      s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
      s = s.replace(/\x00CODE(\d+)\x00/g, (match, i) => codeSpans[Number(i)]);
      return s;
    }

    function flushPara() {
      if (para.length) {
        out.push(`<p>${para.join(' ')}</p>`);
        para = [];
      }
    }
    function flushList() {
      if (list.length) {
        out.push(`<ul>${list.map((item) => `<li>${item}</li>`).join('')}</ul>`);
        list = [];
      }
    }
    function flushQuote() {
      if (quote.length) {
        out.push(`<blockquote>${quote.join(' ')}</blockquote>`);
        quote = [];
      }
    }
    function flushTable() {
      if (table.length) {
        const [headerRow, ...bodyRows] = table;
        const thead = `<tr>${headerRow.map((c) => `<th>${inline(c)}</th>`).join('')}</tr>`;
        const tbody = bodyRows
          .map((row) => `<tr>${row.map((c) => `<td>${inline(c)}</td>`).join('')}</tr>`)
          .join('');
        out.push(`<table><thead>${thead}</thead><tbody>${tbody}</tbody></table>`);
        table = [];
      }
    }
    function flushAll() {
      flushPara();
      flushList();
      flushQuote();
      flushTable();
    }

    function isTableRow(line) {
      return line.startsWith('|') && line.endsWith('|') && line.length > 1;
    }
    function isTableSeparator(line) {
      return /^[-:|\s]+$/.test(line) && line.includes('-');
    }
    function parseTableRow(line) {
      return line.replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());
    }

    for (const rawLine of lines) {
      const line = rawLine.trim();

      if (line === '') {
        flushAll();
        continue;
      }

      const headerMatch = /^(#{1,3})\s+(.*)$/.exec(line);
      if (headerMatch) {
        flushAll();
        const level = headerMatch[1].length;
        out.push(`<h${level} class="iplookup-md-h${level}">${inline(headerMatch[2])}</h${level}>`);
        continue;
      }

      if (line === '---') {
        flushAll();
        out.push('<hr>');
        continue;
      }

      if (isTableRow(line)) {
        if (isTableSeparator(line)) {
          continue;
        }
        flushPara();
        flushList();
        flushQuote();
        table.push(parseTableRow(line));
        continue;
      } else if (table.length) {
        flushTable();
      }

      const bulletMatch = /^[-*]\s+(.*)$/.exec(line);
      if (bulletMatch) {
        flushPara();
        flushQuote();
        flushTable();
        list.push(inline(bulletMatch[1]));
        continue;
      } else if (list.length) {
        flushList();
      }

      const quoteMatch = /^>\s*(.*)$/.exec(line);
      if (quoteMatch) {
        flushPara();
        flushList();
        flushTable();
        quote.push(inline(quoteMatch[1]));
        continue;
      } else if (quote.length) {
        flushQuote();
      }

      flushList();
      flushQuote();
      flushTable();
      para.push(inline(line));
    }

    flushAll();
    return out.join('');
  }

  const TONE_CLASS = { risk: 'tone-risk', warn: 'tone-warn', ok: 'tone-ok' };

  function valueText(value) {
    if (value === null || value === undefined) return '';
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  }

  function pathAttr(path) {
    return path ? ` title="原始欄位：${escapeHtml(path)}"` : '';
  }

  // 翻譯只加不取代：欄位顯示中文名，原始路徑保留在 title 供分析師回頭核對
  function renderFieldRows(rows) {
    if (!rows || !rows.length) return '';
    return '<div class="report-fields">' + rows.map((r) =>
      `<span class="field-label"${pathAttr(r.path)}>${escapeHtml(r.label)}</span>` +
      `<span class="field-value">${escapeHtml(valueText(r.value))}</span>`).join('') + '</div>';
  }

  function renderSummary(summary) {
    if (!summary || !summary.length) return '';
    const rows = summary.map((item) => {
      const cls = ['iplookup-sum-value'];
      if (item.missing) cls.push('is-missing');
      if (item.tone && TONE_CLASS[item.tone]) cls.push(TONE_CLASS[item.tone]);
      const note = item.note ? `<div class="iplookup-sum-note">${escapeHtml(item.note)}</div>` : '';
      return `<div class="iplookup-sum-label"${pathAttr(item.path)}>${escapeHtml(item.label)}</div>` +
             `<div class="${cls.join(' ')}">${escapeHtml(item.value)}${note}</div>`;
    }).join('');
    return `<div class="iplookup-summary"><div class="iplookup-summary-title">摘要</div>` +
           `<div class="iplookup-summary-grid">${rows}</div></div>`;
  }

  function renderEngines(engines) {
    if (!engines) return '';
    // 「尚無掃描結果」與「掃過且無異常」必須看起來完全不同
    if (!engines.available) {
      return `<div class="iplookup-callout tone-warn">${escapeHtml(engines.reason)}</div>`;
    }
    const stats = engines.stats || {};
    const chipDefs = [['惡意', stats.malicious, 'tone-risk'], ['可疑', stats.suspicious, 'tone-warn'],
                      ['無害', stats.harmless, 'tone-ok'], ['未偵測', stats.undetected, ''],
                      ['逾時', stats.timeout, '']];
    const chips = chipDefs.filter(([, v]) => v !== undefined && v !== null)
      .map(([k, v, c]) => `<span class="iplookup-chip ${c}">${k} ${v}</span>`).join('');
    let body = `<div class="iplookup-chips">${chips}` +
               `<span class="iplookup-chip">共 ${engines.total} 家引擎</span></div>`;
    if (engines.mismatch) {
      body += `<div class="iplookup-callout tone-warn">${escapeHtml(engines.mismatch)}</div>`;
    }
    if (engines.abnormal && engines.abnormal.length) {
      body += '<table class="iplookup-table"><thead><tr><th>引擎</th><th>判定</th><th>結果</th><th>方法</th></tr></thead><tbody>' +
        engines.abnormal.map((x) => {
          const tone = x.category === 'malicious' ? 'tone-risk' : 'tone-warn';
          return `<tr><td>${escapeHtml(x.engine)}</td><td class="${tone}">${escapeHtml(x.category)}</td>` +
                 `<td>${escapeHtml(x.result)}</td><td>${escapeHtml(x.method)}</td></tr>`;
        }).join('') + '</tbody></table>';
    } else if (engines.all_clear_text) {
      body += `<div class="iplookup-callout tone-ok">${escapeHtml(engines.all_clear_text)}</div>`;
    }
    if (engines.inconclusive && engines.inconclusive.length) {
      const names = engines.inconclusive.map((x) => `${x.engine}（${x.category}）`).join('、');
      body += `<details class="iplookup-sub"><summary>${engines.inconclusive.length} 家引擎未取得結論（逾時／不支援等），不計入異常</summary>` +
              `<div class="iplookup-note">${escapeHtml(names)}</div></details>`;
    }
    return body;
  }

  function renderTable(table, count) {
    if (!table) return '';
    let out = '';
    const constants = Object.entries(table.constant || {});
    if (constants.length) {
      out += `<div class="iplookup-note">以下 ${count} 筆的這些欄位值全部相同：` +
        constants.map(([k, v]) => `<code>${escapeHtml(k)}</code> = ${escapeHtml(valueText(v))}`).join('、') + '</div>';
    }
    if (table.empty_columns && table.empty_columns.length) {
      out += `<div class="iplookup-note">已隱藏在所有筆數中皆為空的欄位：${escapeHtml(table.empty_columns.join('、'))}</div>`;
    }
    if (!table.columns || !table.columns.length) return out;
    out += '<div class="iplookup-table-wrap"><table class="iplookup-table"><thead><tr>' +
      table.columns.map((c) => `<th>${escapeHtml(c)}</th>`).join('') + '</tr></thead><tbody>' +
      table.rows.map((row) => `<tr>${row.map((c) => `<td>${escapeHtml(valueText(c))}</td>`).join('')}</tr>`).join('') +
      '</tbody></table></div>';
    return out;
  }

  function renderSection(section) {
    let inner;
    if (section.kind === 'engines') inner = renderEngines(section.engines);
    else if (section.kind === 'table') inner = renderTable(section.table, section.count);
    else if (section.kind === 'text') inner = `<pre class="iplookup-pre">${escapeHtml(section.text || '')}</pre>`;
    else inner = renderFieldRows(section.rows || []);
    const note = section.note ? `<div class="iplookup-note">${escapeHtml(section.note)}</div>` : '';
    const open = section.collapsed ? '' : ' open';
    return `<details class="iplookup-section"${open}><summary>${escapeHtml(section.title)}</summary>` +
           `${note}${inner}</details>`;
  }

  function renderHidden(hidden) {
    if (!hidden || !hidden.count) return '';
    const rows = hidden.fields.map((f) => ({ label: f.label, path: f.path, value: `（${f.reason}）` }));
    return `<details class="iplookup-section"><summary>已隱藏 ${hidden.count} 個欄位` +
           `（其中 ${hidden.empty_count} 個為空值）</summary>` +
           '<div class="iplookup-note">「欄位存在但未填寫」與「來源根本沒有這個欄位」的判讀意義不同，' +
           '因此空欄位只收合、不刪除。</div>' + renderFieldRows(rows) + '</details>';
  }

  function renderRaw(data) {
    const flat = flattenForDisplay(data);
    const rows = Object.entries(flat).map(([k, v]) => ({ label: k, path: k, value: v }));
    return `<details class="iplookup-section"><summary>檢視原始資料（${rows.length} 個欄位）</summary>` +
           '<div class="iplookup-note">未經任何摘要或摺疊處理的完整回應內容。</div>' +
           renderFieldRows(rows) + '</details>';
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
    const warnings = (result.warnings || [])
      .map((w) => `<div class="iplookup-callout tone-warn">${escapeHtml(w)}</div>`).join('');
    let body;
    if (result.view) {
      body = renderSummary(result.view.summary) +
             (result.view.sections || []).map(renderSection).join('') +
             renderHidden(result.view.hidden) +
             renderRaw(result.data);
    } else {
      // 後端未提供 view（舊版或後處理停用）時退回原本的全欄位攤平呈現
      body = renderFieldRows(Object.entries(flattenForDisplay(result.data))
        .map(([k, v]) => ({ label: k, path: k, value: v })));
    }
    const exportBtns = `
      <div class="iplookup-export">
        <button class="btn btn-secondary btn-sm" onclick="ipLookupExportTxt('${tab}')">匯出 TXT（摘要）</button>
        <button class="btn btn-secondary btn-sm" onclick="ipLookupExportCsv('${tab}')">匯出 CSV（完整）</button>
      </div>`;
    panel.innerHTML = meta + warnings + body + exportBtns;
  }

  const COMPARE_STATUS = {
    agree: { text: '一致', cls: 'tone-ok' },
    conflict: { text: '不一致', cls: 'tone-risk' },
    single: { text: '僅一個權威來源提供', cls: '' },
    reference_only: { text: '僅參考來源提供', cls: '' },
    missing: { text: '皆無資料', cls: '' },
  };

  function renderCompare(result) {
    lastCompareResult = result;
    const panel = document.getElementById('iplookup-panel-compare');
    const sources = result.sources || [];
    const labels = sources.map((s) => s.label);

    const headline = result.headline
      ? `<div class="iplookup-callout ${result.summary.conflict ? 'tone-warn' : 'tone-ok'}">` +
        `${escapeHtml(result.headline)}</div>`
      : '';
    const warnings = (result.warnings || [])
      .map((w) => `<div class="iplookup-callout tone-warn">${escapeHtml(w)}</div>`).join('');

    // 來源分層要講清楚，否則使用者會把「參考來源不同」誤讀成資料有錯
    const legend = sources.map((s) => {
      const tier = s.tier === 'primary' ? '權威來源' : '參考來源';
      const tierCls = s.tier === 'primary' ? 'tone-ok' : '';
      const note = s.note ? `<div class="iplookup-sum-note">${escapeHtml(s.note)}</div>` : '';
      return `<div class="iplookup-sum-label">${escapeHtml(s.label)}</div>` +
             `<div class="iplookup-sum-value"><span class="iplookup-chip ${tierCls}">${tier}</span>${note}</div>`;
    }).join('');

    const header = ['事實', ...labels, '判定']
      .map((c) => `<th>${escapeHtml(c)}</th>`).join('');
    const body = (result.rows || []).map((row) => {
      const status = COMPARE_STATUS[row.status] || { text: row.status, cls: '' };
      const cells = labels.map((label) => {
        const value = row.values[label];
        const missing = value === '資料未提供';
        const differs = (row.differing_references || []).includes(label);
        const cls = missing ? 'is-missing' : (differs ? 'tone-warn' : '');
        return `<td class="${cls}">${escapeHtml(value === undefined ? '' : value)}</td>`;
      }).join('');
      // 差異說明放表格上方講一次即可；每列各寫一遍反而把表格變成新的雜訊來源
      return `<tr><td>${escapeHtml(row.label)}</td>${cells}` +
             `<td class="${status.cls}">${escapeHtml(status.text)}</td></tr>`;
    }).join('');

    panel.innerHTML = headline + warnings +
      '<div class="iplookup-section" style="padding-bottom:4px">' +
      '<div class="iplookup-summary-title" style="margin:10px 14px">來源分層</div>' +
      `<div class="iplookup-summary-grid" style="margin:0 14px 12px">${legend}</div></div>` +
      '<div class="iplookup-note">一致性判定只看「權威來源」之間是否相符。' +
      '參考來源的值以黃色標示，代表與權威來源不同——這通常不是錯誤（例如 VirusTotal 回報的是路由聚合網段、' +
      'WHOIS 原文可能描述上層委派區塊），故不列入判定。</div>' +
      `<div class="iplookup-table-wrap"><table class="iplookup-table"><thead><tr>${header}</tr></thead>` +
      `<tbody>${body}</tbody></table></div>` +
      '<div class="iplookup-export">' +
      '<button class="btn btn-secondary btn-sm" onclick="ipLookupExportCompareTxt()">匯出 TXT</button></div>';
  }

  async function fetchCompare() {
    const panel = document.getElementById('iplookup-panel-compare');
    const btn = document.getElementById('iplookup-tab-btn-compare');
    if (!lastRdapResult && !lastVtResult) {
      panel.innerHTML = '<div class="iplookup-empty">RDAP 與 VirusTotal 皆未取得資料，無法比對</div>';
      return;
    }
    panel.innerHTML = '<div class="iplookup-loading">比對中...</div>';
    try {
      const res = await fetch('/api/lookup/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rdap: lastRdapResult, vt: lastVtResult }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        panel.innerHTML = `<div class="iplookup-error">來源比對失敗：${res.status} ${escapeHtml(err.detail || '')}</div>`;
        return;
      }
      renderCompare(await res.json());
      btn.disabled = false;
    } catch (e) {
      panel.innerHTML = `<div class="iplookup-error">來源比對失敗：${escapeHtml(e.message)}</div>`;
    }
  }

  window.ipLookupExportCompareTxt = function () {
    if (!lastCompareResult) return;
    const r = lastCompareResult;
    const labels = (r.sources || []).map((s) => s.label);
    const lines = [`比對目標：${r.target}`, ''];
    if (r.headline) lines.push(r.headline, '');
    (r.warnings || []).forEach((w) => lines.push(`[注意] ${w}`));
    lines.push('', '【來源分層】');
    (r.sources || []).forEach((s) => {
      lines.push(`${s.label}：${s.tier === 'primary' ? '權威來源' : '參考來源'}` +
                 (s.note ? `（${s.note}）` : ''));
    });
    lines.push('', '【事實比對】');
    lines.push(['事實', ...labels, '判定'].join(' | '));
    (r.rows || []).forEach((row) => {
      const status = (COMPARE_STATUS[row.status] || {}).text || row.status;
      lines.push([row.label, ...labels.map((l) => row.values[l] ?? ''), status].join(' | '));
      if ((row.differing_references || []).length) {
        lines.push(`  （參考來源 ${row.differing_references.join('、')} 的值不同，不列入判定）`);
      }
    });
    downloadBlob(`compare_${sanitizeFilename(r.target)}.txt`, lines.join('\n'), 'text/plain;charset=utf-8');
  };

  function setQueryButtonDisabled(disabled) {
    document.getElementById('iplookup-query-btn').disabled = disabled;
  }

  function checkQueryComplete() {
    if (rdapDone && vtDone) {
      setQueryButtonDisabled(false);
      if (lastRdapResult || lastVtResult) {
        document.getElementById('iplookup-analyze-btn').disabled = false;
      }
      // 跨來源比對需要兩邊的結果，只能等兩個查詢都結束才發動
      fetchCompare();
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
    lastQueryTarget = target;
    setQueryButtonDisabled(true);
    document.getElementById('iplookup-analyze-btn').disabled = true;
    document.getElementById('iplookup-tab-btn-analysis').disabled = true;
    document.getElementById('iplookup-tab-btn-compare').disabled = true;
    lastCompareResult = null;
    document.getElementById('iplookup-panel-analysis').innerHTML = '<div class="iplookup-empty">尚未分析</div>';
    document.getElementById('iplookup-panel-compare').innerHTML = '<div class="iplookup-loading">等待兩邊查詢完成...</div>';
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
      <div class="iplookup-analysis-content">${markdownToHtml(result.content)}</div>
      <div class="iplookup-export">
        <button class="btn btn-secondary btn-sm" onclick="ipLookupExportAnalysisTxt()">匯出 TXT</button>
      </div>`;
  }

  window.ipLookupAnalyze = async function () {
    const target = lastQueryTarget;
    const btn = document.getElementById('iplookup-analyze-btn');
    btn.disabled = true;
    document.getElementById('iplookup-panel-analysis').innerHTML = '<div class="iplookup-loading">分析中...</div>';
    try {
      const res = await fetch('/api/lookup/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // 送完整查詢結果而非只送 data：後端要靠 source 判斷是哪一套 schema
        // （whoisit / python-whois / VirusTotal），才能給 LLM 整理過的資料
        body: JSON.stringify({ target, rdap: lastRdapResult, vt: lastVtResult }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        document.getElementById('iplookup-panel-analysis').innerHTML =
          `<div class="iplookup-error">進階分析失敗：${res.status} ${escapeHtml(err.detail || '')}</div>`;
        document.getElementById('iplookup-tab-btn-analysis').disabled = false;
        ipLookupSwitchTab('analysis');
        return;
      }
      const result = await res.json();
      renderAnalysis(result);
      document.getElementById('iplookup-tab-btn-analysis').disabled = false;
      ipLookupSwitchTab('analysis');
    } catch (e) {
      document.getElementById('iplookup-panel-analysis').innerHTML =
        `<div class="iplookup-error">進階分析失敗：${escapeHtml(e.message)}</div>`;
      document.getElementById('iplookup-tab-btn-analysis').disabled = false;
      ipLookupSwitchTab('analysis');
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

  // 匯出分工：TXT 給人看（摘要視圖），CSV 給機器／存證（完整攤平，一欄不少）。
  // 匯出檔常被當成工單附件或證據保存，因此完整性優先於版面。
  const EXPORT_PII_NOTE = '※ 內容可能包含註冊人姓名、地址、電話等個人資料，請依所屬單位規定保管。';

  function viewToLines(view) {
    const lines = [];
    if (view.summary && view.summary.length) {
      lines.push('【摘要】');
      view.summary.forEach((item) => {
        lines.push(`${item.label}：${item.value}${item.note ? `（${item.note}）` : ''}`);
      });
    }
    (view.warnings || []).forEach((w) => lines.push(`[注意] ${w}`));
    (view.sections || []).forEach((section) => {
      lines.push('', `【${section.title}】`);
      if (section.note) lines.push(`（${section.note}）`);
      if (section.kind === 'engines') {
        const engines = section.engines || {};
        if (!engines.available) {
          lines.push(engines.reason || '');
          return;
        }
        lines.push(`共 ${engines.total} 家引擎；異常 ${engines.counts.abnormal} 家、` +
                   `正常 ${engines.counts.normal} 家、未取得結論 ${engines.counts.inconclusive} 家`);
        if (engines.mismatch) lines.push(`[注意] ${engines.mismatch}`);
        engines.abnormal.forEach((x) => lines.push(`  - ${x.engine}：${x.category} / ${x.result}`));
        if (!engines.abnormal.length && engines.all_clear_text) lines.push(engines.all_clear_text);
      } else if (section.kind === 'text') {
        lines.push(section.text || '');
      } else if (section.kind === 'table') {
        const table = section.table || {};
        Object.entries(table.constant || {}).forEach(([k, v]) => lines.push(`（全部相同）${k}：${valueText(v)}`));
        if (table.columns && table.columns.length) {
          lines.push(table.columns.join(' | '));
          (table.rows || []).forEach((row) => lines.push(row.map(valueText).join(' | ')));
        }
      } else {
        (section.rows || []).forEach((r) => lines.push(`${r.label}：${valueText(r.value)}`));
      }
    });
    if (view.hidden && view.hidden.count) {
      lines.push('', `【已隱藏欄位】共 ${view.hidden.count} 個（其中 ${view.hidden.empty_count} 個為空值）`);
      view.hidden.fields.forEach((f) => lines.push(`${f.label}（${f.path}）：${f.reason}`));
    }
    return lines;
  }

  window.ipLookupExportTxt = function (tab) {
    const result = resultForTab(tab);
    if (!result) return;
    const lines = [
      `查詢目標：${result.target}`,
      `資料來源：${result.source}`,
      `查詢日期時間：${result.queried_at}`,
      '',
      '※ 本檔為摘要視圖，欄位經整理與摺疊；完整內容請改用 CSV 匯出。',
      EXPORT_PII_NOTE,
      '',
    ];
    if (result.view) {
      lines.push(...viewToLines(result.view));
    } else {
      const flat = flattenForDisplay(result.data);
      for (const [k, v] of Object.entries(flat)) lines.push(`${k}：${v}`);
    }
    downloadBlob(`${tab}_${sanitizeFilename(result.target)}.txt`, lines.join('\n'), 'text/plain;charset=utf-8');
  };

  window.ipLookupExportCsv = function (tab) {
    const result = resultForTab(tab);
    if (!result) return;
    const rows = [
      ['欄位', '值'],
      ['# 說明', '完整原始欄位，未套用任何摘要或摺疊規則'],
      ['# 個資提醒', EXPORT_PII_NOTE.replace('※ ', '')],
      ['查詢目標', result.target],
      ['資料來源', result.source],
      ['查詢日期時間', result.queried_at],
    ];
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
