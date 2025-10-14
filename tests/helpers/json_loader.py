"""JSON読み込みユーティリティ (重複キー検出付き)。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


class JsonLoaderError(ValueError):
    """JSON読み込み関連の例外。"""


def _build_object_pairs_hook(path: Path):
    def object_pairs_hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise JsonLoaderError(
                    f"{path}: JSON内でキー '{key}' が重複しています。重複を削除してください。"
                )
            result[key] = value
        return result

    return object_pairs_hook


def load_json_strict(path: Path) -> Any:
    """UTF-8でJSONを読み込み、重複キーを検出する。"""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise JsonLoaderError(f"{path}: ファイルを読み込めませんでした: {exc}") from exc

    try:
        return json.loads(text, object_pairs_hook=_build_object_pairs_hook(path))
    except JsonLoaderError:
        raise
    except json.JSONDecodeError as exc:
        raise JsonLoaderError(
            f"{path}: JSONの構文エラー ({exc.msg})。行{exc.lineno}列{exc.colno}付近を修正してください。"
        ) from exc
