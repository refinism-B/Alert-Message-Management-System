"""通報截圖的磁碟儲存。不得 import database（database 會 import 本模組）。"""
import re
from pathlib import Path

IMAGE_DIR: Path = Path(__file__).resolve().parent / "image"
MAX_IMAGE_BYTES = 10 * 1024 * 1024
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class ImageError(ValueError):
    """訊息是給使用者看的中文。"""


def day_dir(date: str) -> Path:
    return IMAGE_DIR / date.replace("-", "")


def check_offense_id(offense_id: str) -> None:
    if not offense_id:
        raise ImageError("請先填寫 Offense ID")
    if not _ID_RE.fullmatch(offense_id):
        raise ImageError("Offense ID 含不允許的字元（僅限英數字、-、_），無法存圖")


def seq_of(filename: str) -> int:
    return int(filename.rsplit("-", 1)[1].removesuffix(".png"))


def list_images(date: str, offense_id: str) -> list[str]:
    if not _ID_RE.fullmatch(offense_id):
        return []
    d = day_dir(date)
    if not d.is_dir():
        return []
    # 完整比對，避免 8267 撈到 8267-1-1.png
    pat = re.compile(rf"^{re.escape(offense_id)}-(\d+)\.png$")
    names = [p.name for p in d.iterdir() if p.is_file() and pat.fullmatch(p.name)]
    return sorted(names, key=seq_of)


def image_path(date: str, offense_id: str, seq: int) -> Path | None:
    for name in list_images(date, offense_id):
        if seq_of(name) == seq:
            return day_dir(date) / name
    return None


def add_image(date: str, offense_id: str, data: bytes) -> str:
    check_offense_id(offense_id)
    if not data.startswith(_PNG_MAGIC):
        raise ImageError("只接受 PNG 圖片")
    if len(data) > MAX_IMAGE_BYTES:
        raise ImageError("圖片過大（上限 10 MB）")
    d = day_dir(date)
    d.mkdir(parents=True, exist_ok=True)
    existing = list_images(date, offense_id)
    seq = seq_of(existing[-1]) + 1 if existing else 1
    name = f"{offense_id}-{seq}.png"
    with open(d / name, "xb") as f:  # 排他建立，絕不覆蓋
        f.write(data)
    return name


def delete_image(date: str, offense_id: str, seq: int) -> bool:
    p = image_path(date, offense_id, seq)
    if p is None:
        return False
    p.unlink()
    return True


def delete_all(date: str, offense_id: str) -> None:
    for name in list_images(date, offense_id):
        try:
            (day_dir(date) / name).unlink()
        except OSError as e:
            raise ImageError(f"刪除截圖失敗：{name}") from e


def rename_all(date: str, old_id: str, new_id: str) -> None:
    names = list_images(date, old_id)
    if not names:
        return
    check_offense_id(new_id)
    d = day_dir(date)
    pairs = [(d / n, d / f"{new_id}-{seq_of(n)}.png") for n in names]
    for _, dst in pairs:
        if dst.exists():
            raise ImageError(f"目標檔名已存在：{dst.name}，無法改名")
    done: list[tuple[Path, Path]] = []
    try:
        for src, dst in pairs:
            src.rename(dst)
            done.append((src, dst))
    except OSError as e:
        for src, dst in reversed(done):
            dst.rename(src)
        raise ImageError(f"截圖改名失敗，已還原：{e}") from e
