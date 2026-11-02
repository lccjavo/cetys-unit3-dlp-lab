"""Reset the lab: delete practice/ and the files generated in output/.

It only operates inside the lab directory; any path outside it is rejected.

Usage:
  python scripts/reset_demo.py
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lab_utils import OUTPUT_DIR, PRACTICE_DIR, PROJECT_ROOT, configure_console, display_path  # noqa: E402

ALLOWED_ROOTS = (PRACTICE_DIR.resolve(), OUTPUT_DIR.resolve())
KEEP = {".gitkeep"}


def _make_writable_and_retry(func, path, _info):
    # On Windows, Git objects are read-only and rmtree cannot delete them directly.
    os.chmod(path, stat.S_IWRITE)
    func(path)


def safe_remove(path: Path) -> None:
    """Delete a file or directory only if it lives inside practice/ or output/."""
    resolved = Path(path).resolve()
    inside = any(resolved == root or root in resolved.parents for root in ALLOWED_ROOTS)
    if not inside or resolved == OUTPUT_DIR.resolve() or PROJECT_ROOT.resolve() not in resolved.parents:
        raise ValueError(f"Refusing to delete a path outside the lab workspace: {resolved}")

    if resolved.is_dir() and not resolved.is_symlink():
        if sys.version_info >= (3, 12):
            shutil.rmtree(resolved, onexc=_make_writable_and_retry)
        else:
            shutil.rmtree(resolved, onerror=_make_writable_and_retry)
    elif resolved.exists() or resolved.is_symlink():
        resolved.unlink()


def reset() -> list[Path]:
    removed = []
    if PRACTICE_DIR.exists():
        safe_remove(PRACTICE_DIR)
        removed.append(PRACTICE_DIR)
    if OUTPUT_DIR.exists():
        for item in OUTPUT_DIR.iterdir():
            if item.name not in KEEP:
                safe_remove(item)
                removed.append(item)
    return removed


def main() -> int:
    configure_console()
    removed = reset()
    if not removed:
        print("[OK] Nothing to clean: the lab was already in its initial state.")
    for path in removed:
        print(f"[OK] Removed: {display_path(path)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
