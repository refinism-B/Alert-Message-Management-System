# WAF 事件模板 — 設計文件

日期：2026-08-11

## 背景

新增通報時，欄位皆源自單一全域 `field_schema`。需求：新增第二套預設模板「WAF事件」，
與現有「一般事件」並存，新增資料時可切換使用。

## 資料模型

`field_schema` table 結構不變（`id`, `fields`, `updated_at`）。新增第二筆固定 id 列：

- `id=1`：一般事件（沿用現有資料與遷移邏輯，不變動）
- `id=2`：WAF事件，`init_db()` 時若不存在才插入以下預設欄位（依序）：

```
Offense ID, 觸發規則, 時間, 方向, 來源IP, 目的IP, 目的port,
防火牆action, response code, severity, 攻擊類型, 日誌總數, 事件描述
```

若 `id=2` 已存在（使用者已編輯過），不覆蓋。

`reports` table 不變。不新增欄位標記某筆記錄來自哪個模板 —— 模板只決定新增當下的初始欄位，
存檔後與現有資料結構完全相同（`fields` + `field_order`）。

## Backend API

`database.py`：
- 新增常數 `DEFAULT_FIELDS_WAF`（上列13欄）。
- `TEMPLATE_IDS = {"general": 1, "waf": 2}`。
- `get_schema(template: str = "general")`、`update_schema(template, fields)` 依 `TEMPLATE_IDS` 查對應列。
- `init_db()` 內，一般事件遷移邏輯不變；新增 WAF 種子邏輯（僅在 id=2 不存在時插入）。

`main.py`：
- `GET /api/schema?template=general|waf`（預設 `general`，向下相容舊呼叫）
- `PUT /api/schema?template=general|waf`
- `template` 不在白名單內回 400。

`models.py`：`SchemaUpdate`/`SchemaResponse` 不變。

## 前端 — 新增事件視窗（`openAddForm`）

- 全域 `schemaFields` 改為 `schemaByTemplate = { general: [], waf: [] }`，`init()` 時各拉一次。
- 新增 `currentAddTemplate` 狀態，每次開窗重設為 `'general'`。
- Modal 內新增一顆切換按鈕，顯示「目前：一般事件」／「目前：WAF事件」，點擊切換至另一模板。
- 切換行為：直接用對應模板的 `schemaByTemplate[template]` 重建整張表單（已填內容捨棄，
  不跳確認 dialog）。
- 存檔行為不變：`POST /api/reports`，`fields`/`field_order` 結構不變，不帶模板資訊。

## 前端 — 欄位管理 drawer（`renderSchemaPanel`）

- 新增兩個 tab：「一般事件」／「WAF事件」，`schemaDrawerTemplate` 狀態記錄目前編輯中的模板。
- 沿用現有增刪欄位、上移排序、存檔邏輯，資料源改為 `schemaByTemplate[schemaDrawerTemplate]`。
- 「儲存」按鈕 PUT 至 `/api/schema?template=${schemaDrawerTemplate}`，成功後關閉 drawer
  （行為與現況一致：一次只存目前分頁）。
- 切換 tab 不自動存檔；未存檔即關閉 drawer 會遺失編輯，與現況（單一 schema 時）風險一致。

## 邊界 / 不受影響範圍

- `editReport()`：完全沿用該筆記錄自身的 `field_order`/`fields`，與模板概念無關，不改動。
- 現有 reports 資料不受影響，不需要 migration。
- 欄位新增/刪除/拖曳排序功能對兩模板行為完全相同，只是初始資料源不同。

## 測試重點

- 新增事件視窗預設顯示一般事件欄位；切換後顯示 WAF 13 欄，順序正確。
- 切換模板會清空已填值、重建欄位列。
- WAF 模板下可正常增刪欄位、拖曳排序、存檔成功。
- 欄位管理 drawer 兩個 tab 各自存檔互不影響；重新整理頁面後兩模板皆持久化。
- 舊有一般事件資料、既有 report 編輯功能不受影響。
