# UI 介面布局調整設計文件

**日期：** 2026-06-11  
**來源需求：** `docs/20260611_req.md`  
**實作範圍：** 單檔 `static/index.html`（無 build system）

---

## 1. 選取區域重設計

**目標：** 取代 checkbox，提供更大的點擊區域並快速辨識已選狀態。

**實作：**
- Card 改為 `display: flex`，主內容佔 90%，右側選取區佔 10%
- 選取區樣式：
  - 未選：背景 `#1e293b`，左邊框 `1px solid #334155`，文字「選取」`color: #475569`
  - 已選：背景 `#1e3a8a`（加深藍），文字 `color: #93c5fd`
  - 垂直置中文字
- Elastic 動畫：CSS `@keyframes`，`scale(1) → scale(0.92) → scale(1.04) → scale(1)`，duration 280ms
- 搜尋模式下隱藏選取區（與現有 checkbox 行為一致）
- `全選`、`updateCopyBtn()`、`copySelected()` 改用 `.select-zone.selected` 取代 checkbox 查詢

---

## 2. 排序：預設新→舊 + 切換按鈕

**目標：** 預設顯示最新事件在上方，可切換排序方向。

**實作：**
- 新增全域 `let sortOrder = 'desc'`（`desc` = 新→舊，`asc` = 舊→新）
- `renderReports()` 渲染前依 `report.id` 排序
- `#main-actions` 加排序按鈕：
  - `sortOrder === 'desc'` 時顯示「排序↓」
  - `sortOrder === 'asc'` 時顯示「排序↑」
  - 點擊切換 `sortOrder` 並重新渲染當前清單（含搜尋結果）
- 搜尋結果同樣套用排序

---

## 3. 側邊欄收合行為調整

**目標：** 收合後不露出文字殘影，toggle 按鈕與「日期」標題並排。

**實作：**
- Sidebar header 列：flex row，`justify-content: space-between`
  - 左：「日期」標題文字
  - 右：縮小 toggle 按鈕（約 24×24px，僅顯示 `‹` / `›`）
- 收合時（`width: 32px`）：
  - `.sidebar-inner` 設 `visibility: hidden`（保持結構佔位，不顯示內容）
  - Sidebar header 中「日期」文字 `opacity: 0`（隱藏），toggle 按鈕仍可見
- 展開時恢復 `visibility: visible` 及 `opacity: 1`
- Transition 配合現有 `width: 0.2s ease`

---

## 4. Main-header Fixed（Sticky）

**目標：** 日期、筆數、按鈕列不隨 scroll 消失。

**實作：**
- `#main-header` 改 `position: sticky; top: 0; z-index: 10`
- 背景設 `background: #0f172a`（與 `#main` 同色），避免 scroll 內容穿透
- `#main` 加 `padding-top` 補足 header 佔位（約 48px，視實際渲染高度調整）

---

## 5. 新增事件 Modal

**目標：** 取代 inline card，改用 modal 視窗 + 遮罩，並加入動畫。

**實作：**
- 新增 HTML 元素：
  - `#add-modal-overlay`：`position: fixed; inset: 0; z-index: 200; background: rgba(0,0,0,0.5); backdrop-filter: blur(4px)`
  - `#add-modal`：`position: fixed; 置中 (top 50% left 50% transform translate(-50%,-50%)); width: 560px; max-width: 90vw; max-height: 85vh; overflow-y: auto; z-index: 201`
- 移除 `buildForm()` 中的預覽區塊（`.preview-area`、`updatePreview()` 呼叫、`.form-label` 預覽標題）
- `openAddForm()` 改為開啟 modal（類似 `openSchemaDrawer()` 模式）
- 點擊 overlay 空白處關閉 modal（不儲存）
- 儲存成功動畫序列：
  1. Modal `transform: scale(0.85)` + `opacity: 0`，200ms ease-in
  2. Overlay `opacity: 0`，200ms（同步）
  3. 移除 modal/overlay DOM
  4. 新增的 card 從右側 slide in：`translateX(60px) → translateX(0)`，`ease-out`，800ms
- **Edit 功能維持 inline**（不改動 `editReport()`）
- `#add-form-container` 元素保留但不再用於新增（編輯仍使用）

---

## 6. 字級 +2px（排除 #topbar）

**目標：** 提升整體可讀性，topbar 維持原尺寸。

| 選擇器 | 現在 | 改後 |
|---|---|---|
| 一般文字、`.report-fields`、`.field-input`、`.date-item`、`.toast`、`#schema-drawer-header` | 13px | 15px |
| `.btn-sm`、`.search-date-tag` | 12px | 14px |
| `.sidebar-label`、`.edit-label`、`.form-label` | 11px | 13px |
| `#main-title` | 14px | 16px |

`#topbar` 內所有元素（`.brand`、`#search-input`、`.date-input`、`.btn`、`.sep`）font-size 不變。

---

## 不在本次範圍

- Edit form 不改為 modal
- 後端 API 不改動
- 搜尋模式下的選取功能不啟用（維持現狀）
