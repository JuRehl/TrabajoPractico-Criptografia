"""Almacenamiento JSON con escritura atómica y permisos restrictivos."""
import json
import os
import tempfile
from pathlib import Path

from .errors import ValidationError


def ensure_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


class JsonStore:
    """Un fichero JSON. Se escribe a un temporal (0600) y se renombra atómicamente."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def load(self, default):
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return default
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValidationError(f"Fichero corrupto: {self.path.name}") from exc

    def save(self, obj) -> None:
        ensure_dir(self.path.parent)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".tmp-")  # mkstemp crea con 0600
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(obj, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
