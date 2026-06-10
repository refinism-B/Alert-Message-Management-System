# Schema Management Drawer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the inline schema panel card with a right-side slide-in drawer backed by a full-viewport backdrop-filter overlay.

**Architecture:** Two new `fixed`-position elements (`#drawer-overlay`, `#schema-drawer`) are added to `<body>`. CSS transitions handle open/close animation. JS functions `openSchemaDrawer()` and `closeSchemaDrawer()` replace `toggleSchemaPanel()`. All existing schema logic (`schemaFields`, `schemaRowUp`, `addSchemaField`, `saveSchema` API call) is preserved unchanged.

**Tech Stack:** Vanilla HTML/CSS/JS — no build step, no dependencies.

---

### Task 1: Add CSS for overlay and drawer

**Files:**
- Modify: `static/index.html` — `<style>` block in `<head>` (append before closing `</style>`)

- [ ] **Step 1: Locate the closing `</style>` tag in `<head>`**

It is around line 70 in `static/index.html`, after the `.checkbox-row label` rule.

- [ ] **Step 2: Insert the new CSS rules before `</style>`**

```css
/* Drawer overlay */
#drawer-overlay {
  display: none;
  position: fixed;
  inset: 0;
  z-index: 100;
  background: rgba(0, 0, 0, 0.45);
  backdrop-filter: blur(4px);
  opacity: 0;
  transition: opacity 0.25s ease;
}
#drawer-overlay.open { opacity: 1; }

/* Schema drawer */
#schema-drawer {
  position: fixed;
  top: 0; right: 0; bottom: 0;
  width: 38%;
  max-width: 50%;
  min-width: 280px;
  background: #1e293b;
  border-left: 1px solid #334155;
  z-index: 101;
  display: flex;
  flex-direction: column;
  transform: translateX(100%);
  transition: transform 0.25s ease;
  overflow: hidden;
}
#schema-drawer.open { transform: translateX(0); }
#schema-drawer-header {
  padding: 14px 16px;
  font-size: 13px;
  font-weight: 600;
  color: #94a3b8;
  border-bottom: 1px solid #334155;
  flex-shrink: 0;
}
#schema-drawer-content {
  flex: 1;
  overflow-y: auto;
  padding: 14px 16px;
}
#schema-drawer-footer {
  padding: 12px 16px;
  border-top: 1px solid #334155;
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}
```

- [ ] **Step 3: Verify no syntax error**

Open `static/index.html` in browser — page loads, no console errors.

---

### Task 2: Add drawer and overlay HTML to `<body>`

**Files:**
- Modify: `static/index.html` — just before `<div id="toast-container">` near the bottom of `<body>`

- [ ] **Step 1: Locate `<div id="toast-container">` near the bottom of `<body>`**

It appears as:
```html
<div id="toast-container"></div>
```

- [ ] **Step 2: Insert the two new elements immediately before it**

```html
<div id="drawer-overlay" onclick="closeSchemaDrawer()"></div>
<div id="schema-drawer">
  <div id="schema-drawer-header">預設欄位管理</div>
  <div id="schema-drawer-content"></div>
  <div id="schema-drawer-footer">
    <button class="btn btn-primary btn-sm" onclick="saveSchema()">儲存</button>
    <button class="btn btn-secondary btn-sm" onclick="closeSchemaDrawer()">取消</button>
  </div>
</div>
<div id="toast-container"></div>
```

---

### Task 3: Remove old `#schema-panel` div

**Files:**
- Modify: `static/index.html` — inside `#main` div, around line 108

- [ ] **Step 1: Locate and delete this line inside `#main`**

```html
    <div id="schema-panel" style="display:none;margin-bottom:16px" class="report-card"></div>
```

Delete the entire line.

---

### Task 4: Update the 欄位管理 button onclick

**Files:**
- Modify: `static/index.html` — the toolbar button, around line 104

- [ ] **Step 1: Locate the button**

```html
        <button class="btn btn-secondary btn-sm" onclick="toggleSchemaPanel()">欄位管理</button>
```

- [ ] **Step 2: Change onclick to `openSchemaDrawer()`**

```html
        <button class="btn btn-secondary btn-sm" onclick="openSchemaDrawer()">欄位管理</button>
```

---

### Task 5: Rewrite `renderSchemaPanel()` to target drawer content

**Files:**
- Modify: `static/index.html` — `renderSchemaPanel()` function, around lines 224–243

- [ ] **Step 1: Locate the full current function**

```js
function renderSchemaPanel() {
  const panel = document.getElementById('schema-panel');
  const rows = schemaFields.map((f, i) => `
    <div class="schema-row" data-index="${i}" style="display:flex;gap:6px;align-items:center;margin-bottom:6px">
      <input class="field-input" value="${f}" style="flex:1" oninput="schemaFields[${i}]=this.value">
      <button class="btn btn-secondary btn-sm" onclick="schemaRowUp(${i})">↑</button>
      <button class="btn btn-danger btn-sm" onclick="schemaFields.splice(${i},1);renderSchemaPanel()">✕</button>
    </div>`).join('');
  panel.innerHTML = `
    <div style="font-size:13px;font-weight:600;margin-bottom:10px;color:#94a3b8">預設欄位管理</div>
    <div id="schema-rows">${rows}</div>
    <div style="display:flex;gap:8px;margin-top:8px">
      <input id="new-field-input" class="field-input" placeholder="新欄位名稱" style="flex:1">
      <button class="btn btn-success btn-sm" onclick="addSchemaField()">＋ 新增</button>
    </div>
    <div style="margin-top:12px;display:flex;gap:8px">
      <button class="btn btn-primary btn-sm" onclick="saveSchema()">儲存</button>
      <button class="btn btn-secondary btn-sm" onclick="document.getElementById('schema-panel').style.display='none'">取消</button>
    </div>`;
}
```

- [ ] **Step 2: Replace the entire function**

Target element changes to `#schema-drawer-content`. Title div and footer buttons are removed (they now live in the drawer's header and footer HTML).

```js
function renderSchemaPanel() {
  const panel = document.getElementById('schema-drawer-content');
  const rows = schemaFields.map((f, i) => `
    <div class="schema-row" data-index="${i}" style="display:flex;gap:6px;align-items:center;margin-bottom:6px">
      <input class="field-input" value="${f}" style="flex:1" oninput="schemaFields[${i}]=this.value">
      <button class="btn btn-secondary btn-sm" onclick="schemaRowUp(${i})">↑</button>
      <button class="btn btn-danger btn-sm" onclick="schemaFields.splice(${i},1);renderSchemaPanel()">✕</button>
    </div>`).join('');
  panel.innerHTML = `
    <div id="schema-rows">${rows}</div>
    <div style="display:flex;gap:8px;margin-top:8px">
      <input id="new-field-input" class="field-input" placeholder="新欄位名稱" style="flex:1">
      <button class="btn btn-success btn-sm" onclick="addSchemaField()">＋ 新增</button>
    </div>`;
}
```

---

### Task 6: Replace `toggleSchemaPanel()` with `openSchemaDrawer()` and `closeSchemaDrawer()`

**Files:**
- Modify: `static/index.html` — `toggleSchemaPanel()` function, around lines 217–222

- [ ] **Step 1: Locate the full current function**

```js
async function toggleSchemaPanel() {
  const panel = document.getElementById('schema-panel');
  if (panel.style.display !== 'none') { panel.style.display = 'none'; return; }
  panel.style.display = 'block';
  renderSchemaPanel();
}
```

- [ ] **Step 2: Replace with two new functions**

```js
function openSchemaDrawer() {
  renderSchemaPanel();
  const overlay = document.getElementById('drawer-overlay');
  const drawer = document.getElementById('schema-drawer');
  overlay.style.display = 'block';
  requestAnimationFrame(() => {
    overlay.classList.add('open');
    drawer.classList.add('open');
  });
}

function closeSchemaDrawer() {
  const overlay = document.getElementById('drawer-overlay');
  const drawer = document.getElementById('schema-drawer');
  overlay.classList.remove('open');
  drawer.classList.remove('open');
  drawer.addEventListener('transitionend', () => {
    overlay.style.display = 'none';
  }, { once: true });
}
```

---

### Task 7: Update `saveSchema()` to close drawer

**Files:**
- Modify: `static/index.html` — `saveSchema()` function, around lines 260–263

- [ ] **Step 1: Locate the full current function**

```js
async function saveSchema() {
  await api('PUT', '/api/schema', { fields: schemaFields });
  document.getElementById('schema-panel').style.display = 'none';
}
```

- [ ] **Step 2: Replace the last line**

```js
async function saveSchema() {
  await api('PUT', '/api/schema', { fields: schemaFields });
  closeSchemaDrawer();
}
```

---

### Task 8: Commit and manual verification

- [ ] **Step 1: Commit all changes so far**

```bash
git add static/index.html
git commit -m "feat: replace schema panel with right-side drawer and overlay"
```

- [ ] **Step 2: Start the server**

```bash
python main.py
```

Open `http://localhost:8000`.

- [ ] **Step 3: Verify drawer opens**

Click "欄位管理". Expected:
- Overlay fades in (dark + blurred background, full viewport including topbar)
- Drawer slides in from right (~38% width)
- Drawer shows "預設欄位管理" header, list of schema fields with ↑ and ✕ buttons, ＋ 新增欄位 input, and 儲存/取消 buttons at bottom

- [ ] **Step 4: Verify Cancel closes without saving**

Click "取消". Expected: drawer slides out, overlay fades out. No changes to schema.

- [ ] **Step 5: Verify overlay click closes without saving**

Reopen drawer. Click anywhere on the blurred background (not the drawer). Expected: same close behavior as Cancel.

- [ ] **Step 6: Verify Save works**

Add a new field, click "儲存". Expected: drawer closes, new field appears in add-form next time it's opened.

- [ ] **Step 7: Verify no leftover panel**

Confirm no schema card appears inline in the main content area when toggling.
