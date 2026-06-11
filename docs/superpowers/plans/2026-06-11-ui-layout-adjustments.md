# UI Layout Adjustments Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply 6 UI improvements to `static/index.html` — font sizes, sticky header, sidebar collapse, sort, select zone, and add-form modal.

**Architecture:** Single-file HTML/CSS/JS app. All changes are inline edits to `static/index.html`. No build system. No automated tests — verification is manual via browser (Playwright MCP available).

**Tech Stack:** Vanilla HTML5, CSS3, JavaScript (ES2020), Python FastAPI backend (not modified)

---

## File Structure

Only one file is modified:
- **Modify:** `static/index.html` — all CSS, HTML, and JS changes

---

## Task 1: Font Sizes +2px (excluding #topbar)

**Files:**
- Modify: `static/index.html` (CSS `<style>` block and JS `buildForm` inline style string)

- [ ] **Step 1: Update CSS font sizes in `<style>` block**

Make these exact replacements in the `<style>` block:

```
OLD: .btn-sm { padding: 3px 8px; font-size: 12px; }
NEW: .btn-sm { padding: 3px 8px; font-size: 14px; }
```

```
OLD: #sidebar .sidebar-label { font-size: 11px; text-transform: uppercase; color: #475569; padding: 0 6px; margin-bottom: 8px; letter-spacing: 0.05em; }
NEW: #sidebar .sidebar-label { font-size: 13px; text-transform: uppercase; color: #475569; padding: 0 6px; margin-bottom: 8px; letter-spacing: 0.05em; }
```

```
OLD: .date-item { padding: 7px 8px; border-radius: 4px; font-size: 13px; cursor: pointer; color: #94a3b8; margin-bottom: 2px; }
NEW: .date-item { padding: 7px 8px; border-radius: 4px; font-size: 15px; cursor: pointer; color: #94a3b8; margin-bottom: 2px; }
```

```
OLD: #main-title { font-size: 14px; color: #94a3b8; }
NEW: #main-title { font-size: 16px; color: #94a3b8; }
```

```
OLD: .report-fields { display: grid; grid-template-columns: 140px 1fr; gap: 4px 8px; font-size: 13px; margin-bottom: 10px; }
NEW: .report-fields { display: grid; grid-template-columns: 140px 1fr; gap: 4px 8px; font-size: 15px; margin-bottom: 10px; }
```

```
OLD: .field-input { width: 100%; padding: 4px 8px; background: #0f172a; border: 1px solid #334155; border-radius: 3px; color: #e2e8f0; font-size: 13px; }
NEW: .field-input { width: 100%; padding: 4px 8px; background: #0f172a; border: 1px solid #334155; border-radius: 3px; color: #e2e8f0; font-size: 15px; }
```

```
OLD: .edit-label { font-size: 11px; color: #3b82f6; margin-bottom: 8px; }
NEW: .edit-label { font-size: 13px; color: #3b82f6; margin-bottom: 8px; }
```

```
OLD: .search-date-tag { font-size: 11px; color: #3b82f6; margin-bottom: 4px; }
NEW: .search-date-tag { font-size: 13px; color: #3b82f6; margin-bottom: 4px; }
```

```
OLD: .toast { padding: 10px 16px; border-radius: 4px; font-size: 13px; opacity: 1; transition: opacity 0.3s ease; white-space: nowrap; }
NEW: .toast { padding: 10px 16px; border-radius: 4px; font-size: 15px; opacity: 1; transition: opacity 0.3s ease; white-space: nowrap; }
```

```
OLD: #schema-drawer-header {
  padding: 14px 16px;
  font-size: 13px;
NEW: #schema-drawer-header {
  padding: 14px 16px;
  font-size: 15px;
```

- [ ] **Step 2: Update font sizes inside `buildForm` JS inline `<style>` string**

Find this string inside the `buildForm` function:

```
OLD:       .key-label { font-size: 13px; color: #cbd5e1; padding: 4px 8px; }
NEW:       .key-label { font-size: 15px; color: #cbd5e1; padding: 4px 8px; }
```

```
OLD:       .preview-area { background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 10px; font-size: 12px; color: #94a3b8; white-space: pre; margin-bottom: 12px; min-height: 40px; }
NEW:       .preview-area { background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 10px; font-size: 14px; color: #94a3b8; white-space: pre; margin-bottom: 12px; min-height: 40px; }
```

```
OLD:       .form-container .form-label { font-size: 11px; color: #475569; margin-bottom: 4px; text-transform: uppercase; }
NEW:       .form-container .form-label { font-size: 13px; color: #475569; margin-bottom: 4px; text-transform: uppercase; }
```

- [ ] **Step 3: Verify in browser**

Open `http://localhost:8000`. Check:
- Card field text larger than topbar text
- Topbar search/buttons unchanged size
- Sidebar date items larger
- Toast messages larger when triggered

- [ ] **Step 4: Commit**

```
git add static/index.html
git commit -m "style: bump font sizes +2px outside topbar"
```

---

## Task 2: Sticky Main-Header

**Files:**
- Modify: `static/index.html` (CSS only)

- [ ] **Step 1: Make `#main-header` sticky**

```
OLD: #main-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
NEW: #main-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; position: sticky; top: 0; z-index: 10; background: #0f172a; padding: 12px 0; }
```

- [ ] **Step 2: Verify in browser**

Scroll down on a date with many reports. Header row (date, count, buttons) stays visible at top.

- [ ] **Step 3: Commit**

```
git add static/index.html
git commit -m "style: make main-header sticky on scroll"
```

---

## Task 3: Sort Default New→Old + Toggle Button

**Files:**
- Modify: `static/index.html` (HTML + JS)

- [ ] **Step 1: Add `sortOrder` global variable**

Find the global variable declarations at top of `<script>`:

```
OLD: let currentDate = null;
let currentReports = [];
let schemaFields = [];
let isSearchMode = false;
NEW: let currentDate = null;
let currentReports = [];
let schemaFields = [];
let isSearchMode = false;
let sortOrder = 'desc';
```

- [ ] **Step 2: Add `toggleSort` function and sorting logic to `renderReports`**

Find `renderReports` function:

```
OLD: function renderReports(reports, searchMode = false) {
  const container = document.getElementById('reports-container');
  container.innerHTML = '';
NEW: function sortedReports(reports) {
  return [...reports].sort((a, b) => sortOrder === 'desc' ? b.id - a.id : a.id - b.id);
}

function toggleSort() {
  sortOrder = sortOrder === 'desc' ? 'asc' : 'desc';
  document.getElementById('sort-btn').textContent = sortOrder === 'desc' ? '排序↓' : '排序↑';
  if (isSearchMode) {
    const container = document.getElementById('reports-container');
    const cards = Array.from(container.querySelectorAll('.report-card'));
    const sorted = sortedReports(cards.map(c => c._report));
    sorted.forEach(r => {
      const card = document.getElementById(`card-${r.id}`);
      container.appendChild(card);
    });
  } else {
    renderReports(currentReports);
  }
}

function renderReports(reports, searchMode = false) {
  const container = document.getElementById('reports-container');
  container.innerHTML = '';
```

Then find where reports are iterated in `renderReports`:

```
OLD:   reports.forEach(r => container.appendChild(buildCard(r, searchMode)));
NEW:   sortedReports(reports).forEach(r => container.appendChild(buildCard(r, searchMode)));
```

- [ ] **Step 3: Add sort button to HTML `#main-actions`**

```
OLD:         <button class="btn btn-primary btn-sm" onclick="openAddForm()">＋ 新增通報</button>
NEW:         <button class="btn btn-primary btn-sm" onclick="openAddForm()">＋ 新增通報</button>
        <button id="sort-btn" class="btn btn-secondary btn-sm" onclick="toggleSort()">排序↓</button>
```

- [ ] **Step 4: Verify in browser**

- Reports load newest-first by default
- Sort button toggles ↓/↑ and re-renders in correct order
- Works in both normal and search mode

- [ ] **Step 5: Commit**

```
git add static/index.html
git commit -m "feat: default sort new→old, add sort toggle button"
```

---

## Task 4: Sidebar — Toggle Button Repositioned + Hide Content When Collapsed

**Files:**
- Modify: `static/index.html` (CSS + HTML + JS)

- [ ] **Step 1: Update sidebar CSS**

Replace old sidebar toggle/inner styles:

```
OLD: #sidebar-toggle { width: 100%; background: none; border: none; border-bottom: 1px solid #1e293b; color: #475569; cursor: pointer; padding: 8px 0; font-size: 14px; text-align: center; }
#sidebar-toggle:hover { color: #e2e8f0; background: #1e293b; }
.sidebar-inner { padding: 12px 8px; white-space: nowrap; overflow-y: auto; max-height: calc(100vh - 40px); }
NEW: #sidebar-header { display: flex; align-items: center; justify-content: space-between; padding: 6px 8px; border-bottom: 1px solid #1e293b; flex-shrink: 0; }
#sidebar-header .sidebar-label { font-size: 13px; text-transform: uppercase; color: #475569; letter-spacing: 0.05em; transition: opacity 0.2s ease; }
#sidebar.collapsed #sidebar-header .sidebar-label { opacity: 0; pointer-events: none; }
#sidebar-toggle { background: none; border: 1px solid #334155; border-radius: 3px; color: #475569; cursor: pointer; width: 24px; height: 24px; font-size: 14px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
#sidebar-toggle:hover { color: #e2e8f0; background: #1e293b; }
.sidebar-inner { padding: 12px 8px; white-space: nowrap; overflow-y: auto; max-height: calc(100vh - 48px); transition: visibility 0.2s ease, opacity 0.2s ease; }
#sidebar.collapsed .sidebar-inner { visibility: hidden; opacity: 0; }
```

Also remove the old `#sidebar .sidebar-label` rule (it's now inside `#sidebar-header`):

```
OLD: #sidebar .sidebar-label { font-size: 13px; text-transform: uppercase; color: #475569; padding: 0 6px; margin-bottom: 8px; letter-spacing: 0.05em; }
NEW: 
```

(Delete that line — the label is now styled via `#sidebar-header .sidebar-label`)

- [ ] **Step 2: Update sidebar HTML structure**

```
OLD:   <div id="sidebar">
    <button id="sidebar-toggle" onclick="toggleSidebar()">‹</button>
    <div class="sidebar-inner">
      <div class="sidebar-label">日期</div>
      <div id="date-list"></div>
    </div>
  </div>
NEW:   <div id="sidebar">
    <div id="sidebar-header">
      <span class="sidebar-label">日期</span>
      <button id="sidebar-toggle" onclick="toggleSidebar()">‹</button>
    </div>
    <div class="sidebar-inner">
      <div id="date-list"></div>
    </div>
  </div>
```

- [ ] **Step 3: Update `toggleSidebar` JS function**

```
OLD: function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  sidebar.classList.toggle('collapsed');
  document.getElementById('sidebar-toggle').textContent =
    sidebar.classList.contains('collapsed') ? '›' : '‹';
}
NEW: function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  sidebar.classList.toggle('collapsed');
  document.getElementById('sidebar-toggle').textContent =
    sidebar.classList.contains('collapsed') ? '›' : '‹';
  document.getElementById('sidebar-toggle').title =
    sidebar.classList.contains('collapsed') ? '展開側邊欄' : '收合側邊欄';
}
```

- [ ] **Step 4: Verify in browser**

- Sidebar header shows「日期」on left, small toggle button on right
- Clicking toggle collapses sidebar to 32px — no text visible, only the `›` button
- Expanding restores all content

- [ ] **Step 5: Commit**

```
git add static/index.html
git commit -m "feat: reposition sidebar toggle, hide content when collapsed"
```

---

## Task 5: Select Zone (Replace Checkbox)

**Files:**
- Modify: `static/index.html` (CSS + HTML in `buildCard` + JS)

- [ ] **Step 1: Add select zone CSS, add elastic keyframe animation**

Add after the existing `.report-card` styles (after the `.card-actions` rule), in the `<style>` block:

```css
@keyframes elastic-select {
  0%   { transform: scale(1); }
  30%  { transform: scale(0.92); }
  70%  { transform: scale(1.04); }
  100% { transform: scale(1); }
}
.card-body { flex: 1; min-width: 0; }
.select-zone {
  width: 10%;
  min-width: 44px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-left: 1px solid #334155;
  cursor: pointer;
  border-radius: 0 6px 6px 0;
  background: #1e293b;
  color: #475569;
  font-size: 14px;
  user-select: none;
  transition: background 0.15s ease, color 0.15s ease;
  writing-mode: vertical-rl;
  text-orientation: mixed;
  letter-spacing: 0.1em;
}
.select-zone:hover { background: #273549; color: #94a3b8; }
.select-zone.selected { background: #1e3a8a; color: #93c5fd; border-left-color: #3b82f6; }
.select-zone.animating { animation: elastic-select 0.28s ease; }
.report-card { background: #1e293b; border: 1px solid #334155; border-radius: 6px; margin-bottom: 10px; display: flex; overflow: hidden; }
```

Note: The `.report-card` rule already exists — replace it:

```
OLD: .report-card { background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 14px; margin-bottom: 10px; }
NEW: .report-card { background: #1e293b; border: 1px solid #334155; border-radius: 6px; margin-bottom: 10px; display: flex; overflow: hidden; }
```

Also remove old checkbox styles:

```
OLD: .report-checkbox { width: 14px; height: 14px; cursor: pointer; accent-color: #3b82f6; }
.checkbox-row { display: flex; align-items: center; gap: 6px; margin-bottom: 8px; }
.checkbox-row label { font-size: 12px; color: #64748b; cursor: pointer; }
NEW: 
```

- [ ] **Step 2: Add `.card-body` padding CSS**

Add to the `<style>` block:

```css
.card-body { padding: 14px; flex: 1; min-width: 0; }
```

(This replaces the old `padding: 14px` that was on `.report-card`)

- [ ] **Step 3: Update `buildCard` function**

```
OLD: function buildCard(report, showDate = false) {
  const card = document.createElement('div');
  card.className = 'report-card';
  card.id = `card-${report.id}`;

  let html = '';
  if (!showDate) {
    html += `<div class="checkbox-row">
      <input type="checkbox" class="report-checkbox" id="chk-${report.id}" data-id="${report.id}" onchange="updateCopyBtn()">
      <label for="chk-${report.id}">選取</label>
    </div>`;
  }
  if (showDate) html += `<div class="search-date-tag">${report.date}</div>`;
  html += '<div class="report-fields">';
  report.field_order.forEach(k => {
    html += `<span class="field-label">${k}</span><span class="field-value">${report.fields[k] ?? ''}</span>`;
  });
  html += '</div>';
  html += `<div class="card-actions">
    <button class="btn btn-secondary btn-sm" onclick="copyReport(${report.id})">複製</button>
    <button class="btn btn-secondary btn-sm" onclick="editReport(${report.id})">編輯</button>
    <button class="btn btn-danger btn-sm" onclick="deleteReport(${report.id})">刪除</button>
  </div>`;
  card.innerHTML = html;
  card._report = report;
  return card;
}
NEW: function buildCard(report, showDate = false) {
  const card = document.createElement('div');
  card.className = 'report-card';
  card.id = `card-${report.id}`;

  let bodyHtml = '';
  if (showDate) bodyHtml += `<div class="search-date-tag">${report.date}</div>`;
  bodyHtml += '<div class="report-fields">';
  report.field_order.forEach(k => {
    bodyHtml += `<span class="field-label">${k}</span><span class="field-value">${report.fields[k] ?? ''}</span>`;
  });
  bodyHtml += '</div>';
  bodyHtml += `<div class="card-actions">
    <button class="btn btn-secondary btn-sm" onclick="copyReport(${report.id})">複製</button>
    <button class="btn btn-secondary btn-sm" onclick="editReport(${report.id})">編輯</button>
    <button class="btn btn-danger btn-sm" onclick="deleteReport(${report.id})">刪除</button>
  </div>`;

  card.innerHTML = `<div class="card-body">${bodyHtml}</div>`;

  if (!showDate) {
    const zone = document.createElement('div');
    zone.className = 'select-zone';
    zone.textContent = '選取';
    zone.dataset.id = report.id;
    zone.onclick = () => toggleSelectZone(zone);
    card.appendChild(zone);
  }

  card._report = report;
  return card;
}
```

- [ ] **Step 4: Add `toggleSelectZone` function, update selection helper functions**

Add `toggleSelectZone` function (place near `updateCopyBtn`):

```javascript
function toggleSelectZone(zone) {
  zone.classList.toggle('selected');
  zone.classList.add('animating');
  zone.addEventListener('animationend', () => zone.classList.remove('animating'), { once: true });
  updateCopyBtn();
}
```

Replace `updateCopyBtn`:

```
OLD: function updateCopyBtn() {
  const any = document.querySelectorAll('.report-checkbox:checked').length > 0;
  document.getElementById('copy-selected-btn').disabled = !any;
}
NEW: function updateCopyBtn() {
  const any = document.querySelectorAll('.select-zone.selected').length > 0;
  document.getElementById('copy-selected-btn').disabled = !any;
}
```

Replace `toggleSelectAll`:

```
OLD: function toggleSelectAll() {
  const checkboxes = Array.from(document.querySelectorAll('.report-checkbox'));
  const allChecked = checkboxes.length > 0 && checkboxes.every(cb => cb.checked);
  checkboxes.forEach(cb => { cb.checked = !allChecked; });
  updateCopyBtn();
}
NEW: function toggleSelectAll() {
  const zones = Array.from(document.querySelectorAll('.select-zone'));
  const allSelected = zones.length > 0 && zones.every(z => z.classList.contains('selected'));
  zones.forEach(z => z.classList.toggle('selected', !allSelected));
  updateCopyBtn();
}
```

Replace `copySelected`:

```
OLD: async function copySelected() {
  const checked = Array.from(document.querySelectorAll('.report-checkbox:checked'));
  if (!checked.length) return;
  const ids = new Set(checked.map(cb => parseInt(cb.dataset.id)));
  const reports = currentReports.filter(r => ids.has(r.id));
  const text = reports.map(r => formatReport(r)).join('\n\n\n');
  await navigator.clipboard.writeText(text);
  showToast('已成功複製');
}
NEW: async function copySelected() {
  const selected = Array.from(document.querySelectorAll('.select-zone.selected'));
  if (!selected.length) return;
  const ids = new Set(selected.map(z => parseInt(z.dataset.id)));
  const reports = currentReports.filter(r => ids.has(r.id));
  const text = reports.map(r => formatReport(r)).join('\n\n\n');
  await navigator.clipboard.writeText(text);
  showToast('已成功複製');
}
```

- [ ] **Step 5: Verify in browser**

- Report cards have right-side select zone with 「選取」text
- Clicking select zone toggles blue highlight + elastic bounce animation
- 全選 button toggles all zones
- 複製選取事件 button enables/disables based on selection
- Search mode cards have no select zone

- [ ] **Step 6: Commit**

```
git add static/index.html
git commit -m "feat: replace checkbox with right-side select zone with elastic animation"
```

---

## Task 6: Add-Form Modal (+ Remove Preview, + Slide-in Animation)

**Files:**
- Modify: `static/index.html` (CSS + HTML + JS)

- [ ] **Step 1: Add modal CSS to `<style>` block**

Add after the existing drawer styles (after `#schema-drawer-footer` rule):

```css
/* Add modal */
#add-modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  z-index: 200;
  background: rgba(0, 0, 0, 0.55);
  backdrop-filter: blur(4px);
  opacity: 0;
  transition: opacity 0.2s ease;
}
#add-modal-overlay.open { opacity: 1; }
#add-modal {
  position: fixed;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%) scale(1);
  width: 560px;
  max-width: 90vw;
  max-height: 85vh;
  overflow-y: auto;
  z-index: 201;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 20px;
  opacity: 1;
  transition: opacity 0.2s ease, transform 0.2s ease;
}
#add-modal.closing {
  opacity: 0;
  transform: translate(-50%, -50%) scale(0.85);
}
@keyframes card-slide-in {
  from { opacity: 0; transform: translateX(60px); }
  to   { opacity: 1; transform: translateX(0); }
}
.card-slide-in { animation: card-slide-in 0.8s ease-out; }
```

- [ ] **Step 2: Add modal HTML elements (before `#toast-container`)**

```
OLD: <div id="toast-container"></div>
NEW: <div id="add-modal-overlay" onclick="handleModalOverlayClick(event)"></div>
<div id="add-modal"></div>
<div id="toast-container"></div>
```

- [ ] **Step 3: Remove preview area from `buildForm`**

Find the `buildForm` function and remove the preview-related parts:

```
OLD:     <style>
      .field-row { display: grid; grid-template-columns: 32px 20px 1fr 3fr; gap: 6px; align-items: center; margin-bottom: 6px; }
      .key-label { font-size: 15px; color: #cbd5e1; padding: 4px 8px; }
      .drag-handle { cursor: grab; color: #475569; text-align: center; user-select: none; }
      .preview-area { background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 10px; font-size: 14px; color: #94a3b8; white-space: pre; margin-bottom: 12px; min-height: 40px; }
      .form-container .form-label { font-size: 13px; color: #475569; margin-bottom: 4px; text-transform: uppercase; }
    </style>
    <div class="field-rows">${buildFieldRows(fields, order, defaultKeys)}</div>
    <button class="btn btn-success btn-sm" style="margin-bottom:12px" onclick="addFieldRow(this.closest('.form-container'))">＋ 新增欄位</button>
    <div class="form-label">輸出預覽</div>
    <div class="preview-area"></div>
    <div class="card-actions">
NEW:     <style>
      .field-row { display: grid; grid-template-columns: 32px 20px 1fr 3fr; gap: 6px; align-items: center; margin-bottom: 6px; }
      .key-label { font-size: 15px; color: #cbd5e1; padding: 4px 8px; }
      .drag-handle { cursor: grab; color: #475569; text-align: center; user-select: none; }
      .form-container .form-label { font-size: 13px; color: #475569; margin-bottom: 4px; text-transform: uppercase; }
    </style>
    <div class="field-rows">${buildFieldRows(fields, order, defaultKeys)}</div>
    <button class="btn btn-success btn-sm" style="margin-bottom:12px" onclick="addFieldRow(this.closest('.form-container'))">＋ 新增欄位</button>
    <div class="card-actions">
```

- [ ] **Step 4: Remove `updatePreview` calls from `buildForm`, `addFieldRow`, `deleteFieldRow`, `bindDrag`**

In `buildForm`, remove the last two lines that call `updatePreview`:

```
OLD:   div.querySelector('.save-btn').onclick = () => onSave(div);
  div.querySelector('.cancel-btn').onclick = onCancel;
  bindDrag(div);
  updatePreview(div);
  div.querySelectorAll('.field-input').forEach(i => i.addEventListener('input', () => updatePreview(div)));
  return div;
NEW:   div.querySelector('.save-btn').onclick = () => onSave(div);
  div.querySelector('.cancel-btn').onclick = onCancel;
  bindDrag(div);
  return div;
```

In `deleteFieldRow`:

```
OLD: function deleteFieldRow(btn) {
  const fc = btn.closest('.form-container');
  btn.closest('.field-row').remove();
  updatePreview(fc);
}
NEW: function deleteFieldRow(btn) {
  btn.closest('.field-row').remove();
}
```

In `bindDrag` (ondrop handler):

```
OLD:       if (dragging && dragging !== row) {
        row.parentNode.insertBefore(dragging, row);
        updatePreview(container);
      }
NEW:       if (dragging && dragging !== row) {
        row.parentNode.insertBefore(dragging, row);
      }
```

- [ ] **Step 5: Rewrite `openAddForm` to use modal, add `closeAddModal` and `handleModalOverlayClick`**

```
OLD: function cancelForm() {
  document.getElementById('add-form-container').style.display = 'none';
  document.getElementById('add-form-container').innerHTML = '';
}

function openAddForm() {
  const container = document.getElementById('add-form-container');
  container.style.display = 'block';
  container.innerHTML = '';
  const now = new Date();
  const dateStr = `${now.getMonth() + 1}月${now.getDate()}日`;
  const initFields = Object.fromEntries(
    schemaFields.map(k => [k, k === '時間' ? dateStr : ''])
  );
  const form = buildForm(
    initFields,
    schemaFields,
    async (div) => {
      const { fields, field_order } = collectFormData(div);
      try {
        await api('POST', '/api/reports', { date: currentDate, fields, field_order });
        showToast('已成功儲存');
        await selectDate(currentDate);
      } catch (e) {
        showToast(`儲存失敗：${e.message}`, 'error');
      }
    },
    cancelForm,
    schemaFields
  );
  container.appendChild(form);
}
NEW: function cancelForm() {
  document.getElementById('add-form-container').style.display = 'none';
  document.getElementById('add-form-container').innerHTML = '';
}

function closeAddModal() {
  const overlay = document.getElementById('add-modal-overlay');
  const modal = document.getElementById('add-modal');
  modal.classList.add('closing');
  overlay.classList.remove('open');
  modal.addEventListener('transitionend', () => {
    overlay.style.display = 'none';
    modal.classList.remove('closing');
    modal.innerHTML = '';
  }, { once: true });
}

function handleModalOverlayClick(e) {
  if (e.target === e.currentTarget) closeAddModal();
}

function openAddForm() {
  const overlay = document.getElementById('add-modal-overlay');
  const modal = document.getElementById('add-modal');
  modal.innerHTML = '';
  const now = new Date();
  const dateStr = `${now.getMonth() + 1}月${now.getDate()}日`;
  const initFields = Object.fromEntries(
    schemaFields.map(k => [k, k === '時間' ? dateStr : ''])
  );
  const form = buildForm(
    initFields,
    schemaFields,
    async (div) => {
      const { fields, field_order } = collectFormData(div);
      try {
        await api('POST', '/api/reports', { date: currentDate, fields, field_order });
        closeAddModal();
        showToast('已成功儲存');
        await selectDate(currentDate);
        const newCard = document.querySelector(`#reports-container .report-card`);
        if (newCard) newCard.classList.add('card-slide-in');
      } catch (e) {
        showToast(`儲存失敗：${e.message}`, 'error');
      }
    },
    closeAddModal,
    schemaFields
  );
  modal.appendChild(form);
  overlay.style.display = 'block';
  requestAnimationFrame(() => overlay.classList.add('open'));
}
```

- [ ] **Step 6: Verify in browser**

- Click「＋ 新增通報」→ modal appears with dark blurred overlay
- Click overlay background → modal closes with fade+shrink
- Fill form and save → modal closes, new card slides in from right (0.8s ease-out)
- Edit (inline) still works normally

- [ ] **Step 7: Commit**

```
git add static/index.html
git commit -m "feat: add-form modal with overlay, remove preview, slide-in animation on add"
```

---

## Self-Review Checklist

- [x] Section 1 (Select zone) → Task 5
- [x] Section 2 (Sort default + toggle) → Task 3
- [x] Section 3 (Sidebar collapse hide content) → Task 4
- [x] Section 4 (Sticky header) → Task 2
- [x] Section 5 (Modal add form, remove preview, animations) → Task 6
- [x] Section 6 (Font +2px) → Task 1
- [x] No TBD/TODO placeholders
- [x] All function names consistent across tasks (`closeAddModal`, `toggleSelectZone`, `toggleSort`, `sortedReports`)
- [x] `.report-card` padding moved to `.card-body` — Task 5 Step 1 adds `.card-body { padding: 14px; }` and removes padding from `.report-card`
- [x] `deleteFieldRow` no longer needs `fc` variable after removing `updatePreview` call
- [x] `updatePreview` function stays (used by edit form inline — no, actually edit form also uses `buildForm`... but since we removed `updatePreview` call from `buildForm`, `updatePreview` itself is now dead code. Leave it — removing it is out of scope.)
