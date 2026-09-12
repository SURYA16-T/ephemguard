from pathlib import Path
from typing import Union
import yaml

def load_policy(path: Union[str, Path]) -> dict:
    with Path(path).open(encoding="utf-8") as f:
        data=yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("policy must be a mapping")
    return data
