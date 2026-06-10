# Delete Field Button in Add/Edit Form

**Date:** 2026-06-10

## Summary

Add a delete button to every field row in the report add/edit form, including default (schema) fields. Simultaneously remove the up-arrow (↑) reorder button from all rows, leaving drag-and-drop as the sole reordering mechanism.

## Scope

File: `static/index.html` — JavaScript and inline CSS only. No backend changes.

## Layout Change

All field rows (default and custom) adopt a unified grid:

```
grid-template-columns: 32px 20px 1fr 1fr
```

Column order: `[✕ delete] [⠿ drag] [key] [val]`

- **Default row** — key column is `<span class="key-label">` (read-only label)
- **Custom row** — key column is `<input class="key-input">` (editable)

The separate `.field-row.default-row` CSS rule is removed; both row types share `.field-row`.

## Behavior

- Clicking ✕ removes the row from the current form DOM and refreshes the preview.
- Deletion is local to the form instance — `schemaFields` (global schema) is not modified.
- Deleted default fields are simply absent from that report's saved `field_order`/`fields`.
- Global schema edits remain in the 欄位管理 panel only.

## Changes Required

| Location | Change |
|---|---|
| `buildForm()` inline `<style>` | Update `.field-row` grid; remove `.field-row.default-row` rule |
| `buildFieldRows()` — default branch | Add `✕` button (leftmost); remove `default-row` class; remove separate grid |
| `buildFieldRows()` — custom branch | Move `✕` button to leftmost; remove `↑` button |
| `addFieldRow()` | Add `✕` button (leftmost); remove `↑` button |
| `moveRowUp()` | Delete entire function (no callers after change) |

## Out of Scope

- Schema panel (欄位管理) rows — not affected
- Edit form (`editReport`) — `buildForm` is shared, so it benefits automatically
- Any backend API changes
