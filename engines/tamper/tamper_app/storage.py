from __future__ import annotations
import json
from pathlib import Path
from typing import Any


class JsonStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def path_for(self, item_id: str) -> Path:
        safe = "".join(c for c in item_id if c.isalnum() or c in "-_.")
        if not safe:
            raise ValueError("Invalid identifier")
        return self.directory / f"{safe}.json"

    def save(self, item_id: str, data: dict[str, Any]) -> Path:
        path = self.path_for(item_id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
        return path

    def load(self, item_id: str) -> dict[str, Any]:
        path = self.path_for(item_id)
        if not path.exists():
            raise FileNotFoundError(item_id)
        return json.loads(path.read_text(encoding="utf-8"))

    def exists(self, item_id: str) -> bool:
        return self.path_for(item_id).exists()
