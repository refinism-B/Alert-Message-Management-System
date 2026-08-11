# WAF 事件模板 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增資料時可在「一般事件」與「WAF事件」兩套預設欄位模板間切換，其餘增刪欄位/排序/存檔功能不變。

**Architecture:** `field_schema` table 用固定 `id` 區分模板（1=一般事件，既有邏輯不動；2=WAF事件，新種子資料）。後端 `get_schema`/`update_schema` 與 `/api/schema` 端點加上 `template` 參數（預設 `general`，向下相容）。前端把單一全域 `schemaFields` 換成 `schemaByTemplate = {general, waf}`，新增視窗與欄位管理 drawer 各自加模板切換 UI。`reports` table 與既有紀錄完全不受影響。

**Tech Stack:** FastAPI + SQLite（後端），Vanilla JS 單頁 `static/index.html`（前端，無建置流程、無前端測試框架）。

## Global Constraints

- WAF 事件預設 13 欄，順序固定：`Offense ID, 觸發規則, 時間, 方向, 來源IP, 目的IP, 目的port, 防火牆action, response code, severity, 攻擊類型, 日誌總數, 事件描述`
- 一般事件模板（`id=1`）既有資料與遷移邏輯不可變動。
- `reports` table 不新增欄位，不記錄模板來源。
- 切換模板 = 直接清空重建表單欄位，不跳確認 dialog。
- 後端每個變更都要有對應 pytest（沿用 `tests/test_database.py`、`tests/test_api.py` 既有 fixture 模式）。
- 前端無自動化測試框架 — 每個前端 task 完成後用瀏覽器手動驗證，步驟寫在 task 內。

詳細設計見 `docs/superpowers/specs/2026-08-11-waf-template-design.md`。

---

### Task 1: `database.py` — WAF 模板常數與 schema 存取函式

**Files:**
- Modify: `database.py:8`（`DEFAULT_FIELDS` 常數區）
- Modify: `database.py:21-56`（`init_db()`）
- Modify: `database.py:59-74`（`get_schema()` / `update_schema()`）
- Test: `tests/test_database.py`

**Interfaces:**
- Produces: `database.DEFAULT_FIELDS_WAF: list[str]`、`database.TEMPLATE_IDS: dict[str, int]`、
  `database.get_schema(template: str = "general") -> dict`、
  `database.update_schema(fields: list[str], template: str = "general") -> dict`
  （回傳格式與既有 `{"fields": [...], "updated_at": str}` 不變）

- [ ] **Step 1: 寫失敗測試 — WAF 模板種子資料**

在 `tests/test_database.py` 新增（緊接 `test_update_schema` 之後）：

```python
def test_get_schema_waf_template_seeded_with_defaults():
    schema = database.get_schema("waf")
    assert schema["fields"] == database.DEFAULT_FIELDS_WAF

def test_get_schema_general_template_unaffected():
    schema = database.get_schema("general")
    assert schema["fields"] == database.DEFAULT_FIELDS

def test_update_schema_waf_template_isolated_from_general():
    database.update_schema(["自訂A", "自訂B"], template="waf")
    assert database.get_schema("waf")["fields"] == ["自訂A", "自訂B"]
    assert database.get_schema("general")["fields"] == database.DEFAULT_FIELDS

def test_init_db_does_not_overwrite_existing_waf_schema():
    database.update_schema(["使用者自訂"], template="waf")
    database.init_db()
    assert database.get_schema("waf")["fields"] == ["使用者自訂"]
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `pytest tests/test_database.py -k waf -v`
Expected: FAIL（`database.DEFAULT_FIELDS_WAF` 不存在 / `get_schema()` 不接受參數）

- [ ] **Step 3: 實作**

`database.py:8` 附近，`DEFAULT_FIELDS` 常數之後加：

```python
DEFAULT_FIELDS_WAF = [
    "Offense ID", "觸發規則", "時間", "方向", "來源IP", "目的IP", "目的port",
    "防火牆action", "response code", "severity", "攻擊類型", "日誌總數", "事件描述",
]

TEMPLATE_IDS = {"general": 1, "waf": 2}
```

`init_db()`（`database.py:41-56`）在既有一般事件遷移邏輯 `else:` 區塊結束後，於同一個 `with get_conn() as conn:` 區塊內追加 WAF 種子邏輯：

```python
        waf_exists = conn.execute("SELECT id FROM field_schema WHERE id = 2").fetchone()
        if not waf_exists:
            conn.execute(
                "INSERT INTO field_schema (id, fields, updated_at) VALUES (2, ?, ?)",
                (json.dumps(DEFAULT_FIELDS_WAF, ensure_ascii=False), _now()),
            )
```

`get_schema()` / `update_schema()`（`database.py:59-74`）改為：

```python
def get_schema(template: str = "general") -> dict:
    schema_id = TEMPLATE_IDS[template]
    with get_conn() as conn:
        row = conn.execute("SELECT fields, updated_at FROM field_schema WHERE id = ?", (schema_id,)).fetchone()
    if row is None:
        raise RuntimeError("Schema row missing — was init_db() called?")
    return {"fields": json.loads(row["fields"]), "updated_at": row["updated_at"]}


def update_schema(fields: list[str], template: str = "general") -> dict:
    schema_id = TEMPLATE_IDS[template]
    now = _now()
    with get_conn() as conn:
        conn.execute(
            "UPDATE field_schema SET fields = ?, updated_at = ? WHERE id = ?",
            (json.dumps(fields, ensure_ascii=False), now, schema_id),
        )
    return {"fields": fields, "updated_at": now}
```

- [ ] **Step 4: 執行測試確認通過**

Run: `pytest tests/test_database.py -v`
Expected: 全部 PASS（含既有測試，`get_schema()`/`update_schema()` 無參數呼叫仍走 `template="general"` 預設值）

- [ ] **Step 5: Commit**

```bash
git add database.py tests/test_database.py
git commit -m "feat: add WAF template schema storage in database layer"
```

---

### Task 2: `main.py` — `/api/schema` 加 `template` 參數

**Files:**
- Modify: `main.py:47-54`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `database.get_schema(template)`、`database.update_schema(fields, template)`（Task 1 產出）
- Produces: `GET /api/schema?template=general|waf`、`PUT /api/schema?template=general|waf`（`template` 省略時預設 `general`，向下相容）

- [ ] **Step 1: 寫失敗測試**

在 `tests/test_api.py` 新增（緊接 `test_put_schema` 之後）：

```python
def test_get_schema_waf_template(client):
    r = client.get("/api/schema?template=waf")
    assert r.status_code == 200
    fields = r.json()["fields"]
    assert "Offense ID" in fields
    assert "response code" in fields

def test_put_schema_waf_template_does_not_affect_general(client):
    r = client.put("/api/schema?template=waf", json={"fields": ["A", "B"]})
    assert r.status_code == 200
    assert r.json()["fields"] == ["A", "B"]
    general = client.get("/api/schema").json()
    assert general["fields"] != ["A", "B"]

def test_get_schema_invalid_template_rejected(client):
    r = client.get("/api/schema?template=bogus")
    assert r.status_code == 422
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `pytest tests/test_api.py -k template -v`
Expected: FAIL（目前 `/api/schema` 不接受 `template` query param，`?template=waf` 會被忽略，兩次呼叫回同一份資料）

- [ ] **Step 3: 實作**

`main.py` 頂部 import 區加 `from typing import Literal`（`Optional` 已存在同一行可合併）：

```python
from typing import Literal, Optional
```

`main.py:47-54` 改為：

```python
@app.get("/api/schema")
def get_schema(template: Literal["general", "waf"] = "general") -> models.SchemaResponse:
    return database.get_schema(template)


@app.put("/api/schema")
def update_schema(body: models.SchemaUpdate, template: Literal["general", "waf"] = "general") -> models.SchemaResponse:
    return database.update_schema(body.fields, template)
```

（FastAPI 對 `Literal` query 參數自動做 enum 驗證，非法值回 422，符合設計文件「白名單外拒絕」的要求。）

- [ ] **Step 4: 執行測試確認通過**

Run: `pytest tests/test_api.py -v`
Expected: 全部 PASS

- [ ] **Step 5: Commit**

```bash
git add main.py tests/test_api.py
git commit -m "feat: add template query param to /api/schema endpoints"
```

---

### Task 3: 前端 — `schemaByTemplate` 重構（行為不變，純資料結構替換）

**Files:**
- Modify: `static/index.html:245`（宣告）
- Modify: `static/index.html:368-406`（`renderSchemaPanel`, `schemaRowUp`, `addSchemaField`, `saveSchema`）
- Modify: `static/index.html:408-415`（`init()`）
- Modify: `static/index.html:647-679`（`openAddForm()`）

**Interfaces:**
- Produces: 全域 `schemaByTemplate = { general: string[], waf: string[] }`，取代 `schemaFields`。
  本 task 所有讀寫暫時固定操作 `schemaByTemplate.general`（行為對使用者 100% 不變），
  Task 4/5 才會讓 UI 實際切到 `waf`。

- [ ] **Step 1: 替換全域宣告**

`static/index.html:245`：

```js
let schemaByTemplate = { general: [], waf: [] };
```

（取代 `let schemaFields = [];`）

- [ ] **Step 2: 替換 `init()`**

`static/index.html:408-415` 改為：

```js
async function init() {
  schemaByTemplate.general = (await api('GET', '/api/schema?template=general')).fields;
  schemaByTemplate.waf = (await api('GET', '/api/schema?template=waf')).fields;
  await loadDates();
  await selectDate(today);
  document.getElementById('search-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') doSearch();
  });
}
```

- [ ] **Step 3: 替換 `renderSchemaPanel` / `schemaRowUp` / `addSchemaField` / `saveSchema`**

`static/index.html:368-406` 改為（`schemaFields` 全數替換為 `schemaByTemplate.general`）：

```js
function renderSchemaPanel() {
  const panel = document.getElementById('schema-drawer-content');
  const rows = schemaByTemplate.general.map((f, i) => `
    <div class="schema-row" data-index="${i}" style="display:flex;gap:6px;align-items:center;margin-bottom:6px">
      <input class="field-input" value="${f}" style="flex:1" oninput="schemaByTemplate.general[${i}]=this.value">
      <button class="btn btn-secondary btn-sm" onclick="schemaRowUp(${i})">↑</button>
      <button class="btn btn-danger btn-sm" onclick="schemaByTemplate.general.splice(${i},1);renderSchemaPanel()">✕</button>
    </div>`).join('');
  panel.innerHTML = `
    <div id="schema-rows">${rows}</div>
    <div style="display:flex;gap:8px;margin-top:8px">
      <input id="new-field-input" class="field-input" placeholder="新欄位名稱" style="flex:1">
      <button class="btn btn-success btn-sm" onclick="addSchemaField()">＋ 新增</button>
    </div>`;
}

function schemaRowUp(i) {
  if (i === 0) return;
  const arr = schemaByTemplate.general;
  [arr[i-1], arr[i]] = [arr[i], arr[i-1]];
  renderSchemaPanel();
}

function addSchemaField() {
  const input = document.getElementById('new-field-input');
  const val = input.value.trim();
  if (!val) return;
  schemaByTemplate.general.push(val);
  input.value = '';
  renderSchemaPanel();
}

async function saveSchema() {
  try {
    await api('PUT', '/api/schema?template=general', { fields: schemaByTemplate.general });
    closeSchemaDrawer();
  } catch (e) {
    showToast(`儲存失敗：${e.message}`, 'error');
  }
}
```

- [ ] **Step 4: 替換 `openAddForm()` 內三處 `schemaFields` 引用**

`static/index.html:647-679`，`initFields`／`buildForm` 呼叫改用 `schemaByTemplate.general`：

```js
function openAddForm() {
  const overlay = document.getElementById('add-modal-overlay');
  const modal = document.getElementById('add-modal');
  modal.innerHTML = '';
  const now = new Date();
  const dateStr = `${now.getMonth() + 1}月${now.getDate()}日`;
  const initFields = Object.fromEntries(
    schemaByTemplate.general.map(k => [k, k === '時間' ? dateStr : ''])
  );
  const form = buildForm(
    initFields,
    schemaByTemplate.general,
    async (div) => {
      const { fields, field_order } = collectFormData(div);
      try {
        await api('POST', '/api/reports', { date: currentDate, fields, field_order });
        closeAddModal();
        showToast('已成功儲存');
        await selectDate(currentDate);
        const newCard = document.querySelector('#reports-container .report-card');
        if (newCard) newCard.classList.add('card-slide-in');
      } catch (e) {
        showToast(`儲存失敗：${e.message}`, 'error');
      }
    },
    closeAddModal,
    schemaByTemplate.general
  );
  modal.appendChild(form);
  overlay.style.display = 'block';
  modal.style.display = 'block';
  requestAnimationFrame(() => overlay.classList.add('open'));
}
```

- [ ] **Step 5: 手動回歸驗證（無自動化前端測試）**

```bash
python main.py
```

瀏覽器開 `http://127.0.0.1:8000`，確認與變更前行為完全一致：
1. 「＋ 新增通報」開窗，欄位為原本 9 欄一般事件欄位，「時間」已預填。
2. 「欄位管理」開 drawer，可看到同 9 欄，增刪欄位、↑ 排序、儲存皆正常，重整頁面後仍保留。
3. 新增一筆通報成功送出，卡片正確顯示。

確認無誤後才進下一步（避免帶著壞掉的中間狀態做下一個 task）。

- [ ] **Step 6: Commit**

```bash
git add static/index.html
git commit -m "refactor: replace global schemaFields with schemaByTemplate map"
```

---

### Task 4: 前端 — 新增事件視窗模板切換按鈕

**Files:**
- Modify: `static/index.html`（`<style>` 區塊，`#add-modal` 相關樣式之後）
- Modify: `static/index.html:647-679`（`openAddForm()` 重構為可重建的 `renderAddForm(template)`）

**Interfaces:**
- Consumes: `schemaByTemplate.general` / `schemaByTemplate.waf`（Task 3 產出）
- Produces: `renderAddForm(template: 'general' | 'waf')`（重建整個新增表單，含切換按鈕）、
  全域 `currentAddTemplate: string`

- [ ] **Step 1: 加樣式**

在 `<style>` 區塊、`#add-modal .card-actions .btn-sm { ... }` 規則（約 `static/index.html:194`）之後加：

```css
.template-toggle-bar { display: flex; justify-content: flex-end; margin-bottom: 10px; }
.template-toggle-bar .btn-sm { font-size: 14px; padding: 6px 14px; }
```

- [ ] **Step 2: 重構 `openAddForm()` 為 `renderAddForm(template)` + 新 `openAddForm()`**

`static/index.html:647-679` 整段換成：

```js
const TEMPLATE_LABELS = { general: '一般事件', waf: 'WAF事件' };
let currentAddTemplate = 'general';

function renderAddForm(template) {
  currentAddTemplate = template;
  const modal = document.getElementById('add-modal');
  modal.innerHTML = '';

  const toggleBar = document.createElement('div');
  toggleBar.className = 'template-toggle-bar';
  const otherTemplate = template === 'general' ? 'waf' : 'general';
  toggleBar.innerHTML = `<button class="btn btn-secondary btn-sm" onclick="renderAddForm('${otherTemplate}')">目前：${TEMPLATE_LABELS[template]}（點擊切換為 ${TEMPLATE_LABELS[otherTemplate]}）</button>`;
  modal.appendChild(toggleBar);

  const now = new Date();
  const dateStr = `${now.getMonth() + 1}月${now.getDate()}日`;
  const schemaFields = schemaByTemplate[template];
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
        const newCard = document.querySelector('#reports-container .report-card');
        if (newCard) newCard.classList.add('card-slide-in');
      } catch (e) {
        showToast(`儲存失敗：${e.message}`, 'error');
      }
    },
    closeAddModal,
    schemaFields
  );
  modal.appendChild(form);
}

function openAddForm() {
  const overlay = document.getElementById('add-modal-overlay');
  const modal = document.getElementById('add-modal');
  renderAddForm('general');
  overlay.style.display = 'block';
  modal.style.display = 'block';
  requestAnimationFrame(() => overlay.classList.add('open'));
}
```

（`renderAddForm` 每次呼叫都整個重建 `#add-modal` 內容，等同「直接清空重建」——符合設計文件的切換行為，不需額外的 confirm 或狀態保留邏輯。）

- [ ] **Step 3: 手動驗證**

```bash
python main.py
```

瀏覽器開 `http://127.0.0.1:8000`，確認：
1. 「＋ 新增通報」預設顯示「一般事件」9 欄，按鈕文字顯示「目前：一般事件（點擊切換為 WAF事件）」。
2. 點按鈕 → 表單重建為 WAF 13 欄，順序為
   `Offense ID, 觸發規則, 時間, 方向, 來源IP, 目的IP, 目的port, 防火牆action, response code, severity, 攻擊類型, 日誌總數, 事件描述`，
   按鈕文字變成「目前：WAF事件（點擊切換為 一般事件）」。
3. 在 WAF 模板下手動填幾欄再點切換鈕 → 表單清空重建成一般事件，剛填的值消失（預期行為，非 bug）。
4. WAF 模板下可正常「＋ 新增欄位」、拖曳排序、刪除欄位。
5. WAF 模板下送出存檔成功，卡片正確顯示 13 欄內容與順序。
6. 關閉視窗再重開，永遠回到「一般事件」（每次開窗重設，符合設計文件）。

- [ ] **Step 4: Commit**

```bash
git add static/index.html
git commit -m "feat: add template toggle button to new-report modal"
```

---

### Task 5: 前端 — 欄位管理 drawer 模板分頁

**Files:**
- Modify: `static/index.html`（`<style>` 區塊，`#schema-drawer-footer` 規則附近，約 `static/index.html:153`）
- Modify: `static/index.html:715-717`（`#schema-drawer-header` markup）
- Modify: `static/index.html:347-406`（`openSchemaDrawer`, `renderSchemaPanel`, `schemaRowUp`, `addSchemaField`, `saveSchema`）

**Interfaces:**
- Consumes: `schemaByTemplate`（Task 3 產出，`renderAddForm` 依賴 `schemaByTemplate.waf` 需與此 task 編輯結果同步 —— 兩者共用同一份記憶體物件，drawer 存檔成功後 `schemaByTemplate` 已是最新值，`renderAddForm` 下次開窗自動拿到新內容）
- Produces: 全域 `schemaDrawerTemplate: 'general' | 'waf'`

- [ ] **Step 1: 加樣式**

`<style>` 區塊、`#schema-drawer-footer { ... }` 規則（約 `static/index.html:147-153`）之後加：

```css
.drawer-tabs { display: flex; gap: 6px; margin-top: 8px; }
.drawer-tab { padding: 6px 12px; border-radius: 4px; font-size: 14px; cursor: pointer; color: #94a3b8; border: 1px solid #334155; }
.drawer-tab.active { background: #1e40af; color: #fff; border-color: #1e40af; }
```

- [ ] **Step 2: 改 drawer header markup**

`static/index.html:715-717`：

```html
  <div id="schema-drawer-header">
    預設欄位管理
    <div class="drawer-tabs" id="schema-drawer-tabs"></div>
  </div>
```

- [ ] **Step 3: 改對應 JS**

`static/index.html:347-406` 整段（`openSchemaDrawer` 到 `saveSchema`）換成：

```js
let schemaDrawerTemplate = 'general';

function openSchemaDrawer() {
  schemaDrawerTemplate = 'general';
  renderSchemaDrawerTabs();
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
    if (!drawer.classList.contains('open')) overlay.style.display = 'none';
  }, { once: true });
}

function renderSchemaDrawerTabs() {
  const tabs = document.getElementById('schema-drawer-tabs');
  tabs.innerHTML = Object.entries(TEMPLATE_LABELS).map(([key, label]) =>
    `<div class="drawer-tab${key === schemaDrawerTemplate ? ' active' : ''}" onclick="switchSchemaDrawerTemplate('${key}')">${label}</div>`
  ).join('');
}

function switchSchemaDrawerTemplate(template) {
  schemaDrawerTemplate = template;
  renderSchemaDrawerTabs();
  renderSchemaPanel();
}

function renderSchemaPanel() {
  const panel = document.getElementById('schema-drawer-content');
  const fields = schemaByTemplate[schemaDrawerTemplate];
  const rows = fields.map((f, i) => `
    <div class="schema-row" data-index="${i}" style="display:flex;gap:6px;align-items:center;margin-bottom:6px">
      <input class="field-input" value="${f}" style="flex:1" oninput="schemaByTemplate['${schemaDrawerTemplate}'][${i}]=this.value">
      <button class="btn btn-secondary btn-sm" onclick="schemaRowUp(${i})">↑</button>
      <button class="btn btn-danger btn-sm" onclick="schemaByTemplate['${schemaDrawerTemplate}'].splice(${i},1);renderSchemaPanel()">✕</button>
    </div>`).join('');
  panel.innerHTML = `
    <div id="schema-rows">${rows}</div>
    <div style="display:flex;gap:8px;margin-top:8px">
      <input id="new-field-input" class="field-input" placeholder="新欄位名稱" style="flex:1">
      <button class="btn btn-success btn-sm" onclick="addSchemaField()">＋ 新增</button>
    </div>`;
}

function schemaRowUp(i) {
  if (i === 0) return;
  const arr = schemaByTemplate[schemaDrawerTemplate];
  [arr[i-1], arr[i]] = [arr[i], arr[i-1]];
  renderSchemaPanel();
}

function addSchemaField() {
  const input = document.getElementById('new-field-input');
  const val = input.value.trim();
  if (!val) return;
  schemaByTemplate[schemaDrawerTemplate].push(val);
  input.value = '';
  renderSchemaPanel();
}

async function saveSchema() {
  try {
    await api('PUT', `/api/schema?template=${schemaDrawerTemplate}`, { fields: schemaByTemplate[schemaDrawerTemplate] });
    closeSchemaDrawer();
  } catch (e) {
    showToast(`儲存失敗：${e.message}`, 'error');
  }
}
```

（`TEMPLATE_LABELS` 已在 Task 4 定義為全域常數，這裡直接複用，不重複宣告。）

- [ ] **Step 4: 手動驗證**

```bash
python main.py
```

瀏覽器開 `http://127.0.0.1:8000`，確認：
1. 「欄位管理」開 drawer，預設在「一般事件」分頁，內容為 9 欄。
2. 切到「WAF事件」分頁，顯示 13 欄，順序正確。
3. 在 WAF 分頁新增／刪除／↑ 排序一個欄位，點「儲存」→ drawer 關閉、無錯誤。
4. 重新整理頁面，再開「＋ 新增通報」切到 WAF 模板 → 剛才在 drawer 存的變更有生效。
5. 切回「一般事件」分頁，內容仍是原本 9 欄，未被 WAF 分頁的編輯影響。
6. 在其中一分頁編輯但未存檔、直接切分頁再切回來 → 未存檔的編輯還在（因為資料源是共用記憶體物件，僅未整批 reload），關閉 drawer 未存檔則遺失（與設計文件「未存檔關閉會遺失」一致，可接受）。

- [ ] **Step 5: Commit**

```bash
git add static/index.html
git commit -m "feat: add template tabs to schema management drawer"
```

---

## Self-Review Notes

- Spec 覆蓋：資料模型（Task 1）、API（Task 2）、新增視窗切換（Task 4）、欄位管理分頁（Task 5）、
  `schemaFields`→`schemaByTemplate` 重構（Task 3，設計文件隱含要求，前端資料源改變的必要前置步驟）
  皆有對應 task。`editReport()` 不變動 —— 設計文件明講不受影響，故無 task 觸碰它，符合 YAGNI。
- 型別一致性：`get_schema(template)` / `update_schema(fields, template)` 簽章、
  `TEMPLATE_LABELS` / `schemaByTemplate` / `schemaDrawerTemplate` / `currentAddTemplate` 命名
  在 Task 3～5 間一致使用。
- 無 placeholder：所有 step 附完整程式碼，無「add appropriate handling」之類空話。
