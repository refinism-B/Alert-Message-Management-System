# Schema Management Drawer Design

**Date:** 2026-06-11

## Summary

Replace the inline `#schema-panel` card (currently appears between the action buttons and the report list) with a right-side slide-in drawer. A full-viewport overlay provides darkening and blur when the drawer is open. Clicking the overlay closes the drawer without saving (equivalent to Cancel).

## Scope

File: `static/index.html` — HTML structure, inline CSS, and JavaScript only. No backend changes.

## Approach

Approach A: `backdrop-filter` overlay. Two new `fixed`-position elements handle everything:
- `#drawer-overlay` — covers full viewport, provides dark + blur via `backdrop-filter`
- `#schema-drawer` — right-side panel, slides in via CSS `transform` transition

No filters applied to existing elements. Drawer sits above overlay via z-index.

## HTML Structure

Add before `#toast-container` at the bottom of `<body>`:

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
```

The old `<div id="schema-panel">` in `#main` is removed.

## CSS

Add to the document `<head>` `<style>` block (or inline; follow existing pattern):

```css
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

## JavaScript Changes

### Open: `openSchemaDrawer()` (replaces `toggleSchemaPanel`)

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
```

The `requestAnimationFrame` ensures the `display:block` is painted before the transition class is added, so the CSS transition fires.

### Close: `closeSchemaDrawer()`

```js
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

### `renderSchemaPanel()` — target element change

Change `const panel = document.getElementById('schema-panel')` → `const panel = document.getElementById('schema-drawer-content')`.

Remove the title div and the footer buttons from the `panel.innerHTML` template — the header is now in `#schema-drawer-header` and buttons are in `#schema-drawer-footer`.

### `saveSchema()`

Replace `document.getElementById('schema-panel').style.display = 'none'` → `closeSchemaDrawer()`.

### Button `onclick`

`onclick="toggleSchemaPanel()"` → `onclick="openSchemaDrawer()"`.

The old `toggleSchemaPanel()` function is deleted.

## Removed

- `<div id="schema-panel">` from `#main`
- `toggleSchemaPanel()` function
- `style="display:none;margin-bottom:16px"` inline style on schema-panel

## Preserved

- All existing schema logic: `schemaFields` array, `schemaRowUp()`, `addSchemaField()`, `saveSchema()` API call, `renderSchemaPanel()` row template (↑ and ✕ buttons unchanged)
- Cancel closes without saving (overlay click = Cancel = no `saveSchema()` call)

## Out of Scope

- Schema panel ↑ reorder buttons (intentionally kept; schema panel was excluded from previous row-cleanup)
- Mobile/responsive breakpoints
- Keyboard accessibility (Esc to close)
