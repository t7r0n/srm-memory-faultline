from __future__ import annotations

import json
from pathlib import Path

from srm_redteam.models import AttackCase


def load_suite(path: Path) -> list[AttackCase]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [AttackCase.model_validate(item) for item in raw["cases"]]
