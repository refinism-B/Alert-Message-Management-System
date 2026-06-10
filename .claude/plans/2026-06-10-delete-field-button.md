# Delete Field Button Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a ✕ delete button to every field row (including default/schema rows) in the add/edit report form, positioned at the far left (left of the drag handle), and remove the ↑ up-arrow reorder button from all rows.

**Architecture:** All changes are confined to `static/index.html`. The field row grid is unified to `32px 20px 1fr 1fr` (delete / drag / key / val). Default rows lose their separate CSS rule and gain a delete button; custom rows have their delete button moved left and their up-arrow removed. `moveRowUp()` is deleted entirely.

**Tech Stack:** Vanilla HTML/CSS/JS — no build step, no dependencies.

---

### Task 1: Update CSS grid in `buildForm()`

**Files:**
- Modify: `static/index.html` (inline `<style>` inside `buildForm()`, lines 439–446)

The current CSS defines two separate grid rules. Replace both with one unified rule.

- [ ] **Step 1: Open `static/index.html` and locate the `<style>` block inside `buildForm()`**

It starts around line 439 and contains:
```css
.field-row { display: grid; grid-template-columns: 20px 1fr 1fr 32px 32px; gap: 6px; align-items: center; margin-bottom: 6px; }
.field-row.default-row { grid-template-columns: 20px 1fr 1fr; }
```

- [ ] **Step 2: Replace those two lines with the unified rule**

```css
.field-row { display: grid; grid-template-columns: 32px 20px 1fr 1fr; gap: 6px; align-items: center; margin-bottom: 6px; }
```

Remove the `.field-row.default-row` line entirely.

- [ ] **Step 3: Verify file saves without syntax error**

Open `static/index.html` in a browser (or run the server). The page should load without JS errors in the console.

---

### Task 2: Update `buildFieldRows()` — default branch

**Files:**
- Modify: `static/index.html` (`buildFieldRows()`, default-row return, lines 357–362)

Default rows currently have no delete button and use class `default-row`. Add delete button as first child; remove `default-row` class.

- [ ] **Step 1: Locate the default branch inside `buildFieldRows()`**

```js
if (isDefault) {
  return `
    <div class="field-row default-row" data-key="${k}">
      <span class="drag-handle" draggable="true">⠿</span>
      <span class="key-label">${k}</span>
      <input class="field-input val-input" value="${fields[k] ?? ''}" placeholder="值">
    </div>`;
}
```

- [ ] **Step 2: Replace with the new default row template**

```js
if (isDefault) {
  return `
    <div class="field-row" data-key="${k}">
      <button class="btn btn-danger btn-sm" onclick="const fc=this.closest('.form-container'); this.closest('.field-row').remove(); updatePreview(fc)">✕</button>
      <span class="drag-handle" draggable="true">⠿</span>
      <span class="key-label">${k}</span>
      <input class="field-input val-input" value="${fields[k] ?? ''}" placeholder="值">
    </div>`;
}
```

---

### Task 3: Update `buildFieldRows()` — custom branch

**Files:**
- Modify: `static/index.html` (`buildFieldRows()`, custom-row return, lines 363–372)

Custom rows currently have drag + key-input + val + ↑ + ✕. Move ✕ to first position; remove ↑.

- [ ] **Step 1: Locate the custom branch return**

```js
return `
  <div class="field-row" data-key="${k}">
    <span class="drag-handle" draggable="true">⠿</span>
    <input class="field-input key-input" value="${k}" placeholder="欄位名稱">
    <input class="field-input val-input" value="${fields[k] ?? ''}" placeholder="值">
    <button class="btn btn-secondary btn-sm" onclick="moveRowUp(this)">↑</button>
    <button class="btn btn-danger btn-sm" onclick="const fc=this.closest('.form-container'); this.closest('.field-row').remove(); updatePreview(fc)">✕</button>
  </div>`;
```

- [ ] **Step 2: Replace with the new custom row template**

```js
return `
  <div class="field-row" data-key="${k}">
    <button class="btn btn-danger btn-sm" onclick="const fc=this.closest('.form-container'); this.closest('.field-row').remove(); updatePreview(fc)">✕</button>
    <span class="drag-handle" draggable="true">⠿</span>
    <input class="field-input key-input" value="${k}" placeholder="欄位名稱">
    <input class="field-input val-input" value="${fields[k] ?? ''}" placeholder="值">
  </div>`;
```

---

### Task 4: Update `addFieldRow()`

**Files:**
- Modify: `static/index.html` (`addFieldRow()`, lines 375–386)

Dynamically added rows also need the same layout: ✕ first, no ↑.

- [ ] **Step 1: Locate `addFieldRow()` and find `row.innerHTML`**

```js
row.innerHTML = `
  <span class="drag-handle" draggable="true">⠿</span>
  <input class="field-input key-input" placeholder="欄位名稱">
  <input class="field-input val-input" placeholder="值">
  <button class="btn btn-secondary btn-sm" onclick="moveRowUp(this)">↑</button>
  <button class="btn btn-danger btn-sm" onclick="const fc=this.closest('.form-container'); this.closest('.field-row').remove(); updatePreview(fc)">✕</button>`;
```

- [ ] **Step 2: Replace with updated template**

```js
row.innerHTML = `
  <button class="btn btn-danger btn-sm" onclick="const fc=this.closest('.form-container'); this.closest('.field-row').remove(); updatePreview(fc)">✕</button>
  <span class="drag-handle" draggable="true">⠿</span>
  <input class="field-input key-input" placeholder="欄位名稱">
  <input class="field-input val-input" placeholder="值">`;
```

---

### Task 5: Delete `moveRowUp()`

**Files:**
- Modify: `static/index.html` (`moveRowUp()`, lines 388–395)

No callers remain after Tasks 2–4. Delete the entire function.

- [ ] **Step 1: Locate `moveRowUp()`**

```js
function moveRowUp(btn) {
  const row = btn.closest('.field-row');
  const prev = row.previousElementSibling;
  if (prev && prev.classList.contains('field-row')) {
    row.parentNode.insertBefore(row, prev);
    updatePreview(row.closest('.form-container'));
  }
}
```

- [ ] **Step 2: Delete the entire function**

Remove all 7 lines. Confirm no other references to `moveRowUp` remain:

Search the file for `moveRowUp` — should return zero matches after deletion.

---

### Task 6: Manual verification and commit

- [ ] **Step 1: Start the server**

```bash
python main.py
```

Open `http://localhost:8000` in browser.

- [ ] **Step 2: Verify add form — default fields**

Click "＋ 新增通報". Each default (schema) field row should show:
- ✕ button at far left
- ⠿ drag handle next to it
- Field name label (read-only)
- Value input

- [ ] **Step 3: Verify add form — dynamically added fields**

Click "＋ 新增欄位". New row should show same layout: ✕ / ⠿ / key-input / val-input. No ↑ button anywhere.

- [ ] **Step 4: Verify delete behavior**

Click ✕ on a default field row → row disappears from form; preview updates. Schema not affected (re-open form: field returns).

Click ✕ on a custom field row → same behavior.

- [ ] **Step 5: Verify drag reorder still works**

Drag a row up/down → order changes, preview updates correctly.

- [ ] **Step 6: Verify edit form**

Click "編輯" on an existing report. Same layout applies (edit form shares `buildForm()`). Confirm ✕ works, no ↑ present.

- [ ] **Step 7: Commit**

```bash
git add static/index.html
git commit -m "feat: add delete button to all field rows, remove up-arrow reorder button"
```
