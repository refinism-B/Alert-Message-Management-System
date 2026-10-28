// 通報截圖：卡片縮圖、放大檢視、新增／編輯時的貼上區。依賴 index.html 的 api()、showToast()。

const OFFENSE_ID_RE = /^[A-Za-z0-9_-]+$/;
const OFFENSE_ID_BAD_MSG = 'Offense ID 含不允許的字元（僅限英數字、-、_），無法存圖';

function seqOf(filename) {
  return parseInt(filename.match(/-(\d+)\.png$/)[1], 10);
}

function imageUrl(reportId, filename) {
  return `/api/reports/${reportId}/images/${seqOf(filename)}`;
}

function makeImg(src) {
  const img = document.createElement('img');
  img.src = src;
  img.alt = '';
  return img;
}

// ── 卡片縮圖 ──────────────────────────────────────────────

function buildThumbs(report) {
  const images = report.images || [];
  if (!images.length) return null;
  const wrap = document.createElement('div');
  wrap.className = 'thumbs';
  images.slice(0, 3).forEach((fn, i) => {
    const t = document.createElement('div');
    t.className = 'thumb';
    t.appendChild(makeImg(imageUrl(report.id, fn)));
    if (images.length > 3 && i === 2) {
      const more = document.createElement('div');
      more.className = 'more';
      more.textContent = `+${images.length - 2}`;
      t.appendChild(more);
    }
    t.onclick = () => openLightbox(report, i);
    wrap.appendChild(t);
  });
  return wrap;
}

// ── 放大檢視 ──────────────────────────────────────────────

let lightboxEl = null;

function closeLightbox() {
  lightboxEl?.remove();
  lightboxEl = null;
}

function openLightbox(report, startIndex) {
  closeLightbox();
  const images = report.images;
  let idx = startIndex;

  const overlay = document.createElement('div');
  overlay.className = 'lightbox';
  const title = document.createElement('span');
  const close = document.createElement('span');
  close.className = 'lb-close';
  close.textContent = '✕';
  const top = document.createElement('div');
  top.className = 'lb-top';
  top.append(title, close);
  const prev = document.createElement('div');
  prev.className = 'lb-arrow';
  prev.textContent = '‹';
  const next = document.createElement('div');
  next.className = 'lb-arrow';
  next.textContent = '›';
  const img = document.createElement('img');
  const stage = document.createElement('div');
  stage.className = 'lb-stage';
  stage.append(prev, img, next);
  overlay.append(top, stage);

  const show = (i) => {
    idx = (i + images.length) % images.length;
    img.src = imageUrl(report.id, images[idx]);
    title.textContent = `${images[idx]}　（${idx + 1} / ${images.length}）`;
  };
  prev.onclick = (e) => { e.stopPropagation(); show(idx - 1); };
  next.onclick = (e) => { e.stopPropagation(); show(idx + 1); };
  close.onclick = closeLightbox;
  overlay.onclick = (e) => {
    if (e.target === overlay || e.target === stage) closeLightbox();
  };
  overlay._onKey = (e) => {
    if (e.key === 'ArrowLeft') show(idx - 1);
    else if (e.key === 'ArrowRight') show(idx + 1);
    else if (e.key !== 'Escape') return;
    if (e.key === 'Escape') closeLightbox();
    e.stopImmediatePropagation();
  };
  show(idx);
  document.body.appendChild(overlay);
  lightboxEl = overlay;
}

// 捕獲階段先攔，開啟時 Esc 才不會同時觸發 index.html 的既有 Esc 行為
window.addEventListener('keydown', (e) => lightboxEl?._onKey(e), true);

// ── 貼上區與編輯器 ────────────────────────────────────────

function formOffenseId(formDiv) {
  for (const row of formDiv.querySelectorAll('.field-row')) {
    const keyEl = row.querySelector('.key-input');
    const key = keyEl ? keyEl.value.trim() : (row.querySelector('.key-label')?.textContent.trim() ?? '');
    if (key === 'Offense ID') return row.querySelector('.val-input').value.trim();
  }
  return '';
}

function readPngBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    // 去掉 data:image/png;base64, 前綴，後端只收純 base64
    reader.onload = () => resolve(String(reader.result).split(',')[1]);
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

function buildImageEditor(existing, reportId, getOffenseId) {
  const root = document.createElement('div');
  root.className = 'image-editor';
  const list = document.createElement('div');
  list.className = 'img-list';
  const zone = document.createElement('div');
  zone.className = 'paste-zone';
  zone.tabIndex = 0;
  zone.textContent = '點擊後貼上圖片';
  zone.onfocus = () => { zone.textContent = '貼上圖片'; };
  zone.onblur = () => { zone.textContent = '點擊後貼上圖片'; };
  root.append(list, zone);

  const removedSeqs = [];
  const added = [];
  let kept = existing.slice();

  function item(src, name, onRemove, isNew) {
    const el = document.createElement('div');
    el.className = 'img-item' + (isNew ? ' new' : '');
    const nameEl = document.createElement('div');
    nameEl.className = 'img-name';
    nameEl.textContent = name;
    const x = document.createElement('button');
    x.type = 'button';
    x.className = 'img-remove';
    x.textContent = '✕';
    x.onclick = onRemove;
    el.append(makeImg(src), nameEl, x);
    return el;
  }

  function render() {
    list.replaceChildren();
    kept.forEach(fn => {
      list.appendChild(item(imageUrl(reportId, fn), fn, () => {
        removedSeqs.push(seqOf(fn));
        kept = kept.filter(f => f !== fn);
        render();
      }, false));
    });
    const maxSeq = kept.reduce((m, fn) => Math.max(m, seqOf(fn)), 0);
    const id = getOffenseId();
    added.forEach((b64, i) => {
      list.appendChild(item(`data:image/png;base64,${b64}`, `新貼上（儲存後為 ${id}-${maxSeq + i + 1}.png）`, () => {
        added.splice(i, 1);
        render();
      }, true));
    });
  }

  zone._onPaste = async (e) => {
    e.preventDefault();
    const file = Array.from(e.clipboardData?.items ?? [])
      .find(it => it.kind === 'file' && it.type === 'image/png')?.getAsFile();
    if (!file) { showToast('剪貼簿沒有圖片', 'error'); return; }
    const id = getOffenseId();
    if (!id) { showToast('請先填寫 Offense ID', 'error'); return; }
    if (!OFFENSE_ID_RE.test(id)) { showToast(OFFENSE_ID_BAD_MSG, 'error'); return; }
    try {
      added.push(await readPngBase64(file));
    } catch (err) {
      showToast(`讀取圖片失敗：${err.message}`, 'error');
      return;
    }
    render();
  };

  root.getChanges = () => ({ removedSeqs: removedSeqs.slice(), added: added.slice() });
  root.refresh = render;
  render();
  return root;
}

// 只在貼上區自己有焦點時才收圖；其餘情況不碰事件，欄位照常貼文字
document.addEventListener('paste', (e) => {
  const el = document.activeElement;
  if (el?.classList?.contains('paste-zone')) el._onPaste(e);
});

// 把編輯器插在欄位列下方、儲存／取消按鈕上方；Offense ID 變動時同步預告檔名
function mountImageEditor(formDiv, existing, reportId) {
  const editor = buildImageEditor(existing, reportId, () => formOffenseId(formDiv));
  formDiv.insertBefore(editor, formDiv.querySelector('.card-actions'));
  formDiv.addEventListener('input', () => editor.refresh());
  return editor;
}

// ── 儲存時套用變更 ────────────────────────────────────────

async function applyImageChanges(reportId, changes, fallbackImages) {
  let images = fallbackImages;
  const errors = [];
  for (const seq of changes.removedSeqs) {
    try {
      images = (await api('DELETE', `/api/reports/${reportId}/images/${seq}`)).images;
    } catch (e) {
      errors.push(`刪除第 ${seq} 張失敗（${e.message}）`);
    }
  }
  for (const data of changes.added) {
    try {
      images = (await api('POST', `/api/reports/${reportId}/images`, { data })).images;
    } catch (e) {
      errors.push(`新增圖片失敗（${e.message}）`);
    }
  }
  return { images, errors };
}
