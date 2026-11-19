"""Almacenamiento JSON con escritura atómica, permisos restrictivos y separación de accesos.

Separación de accesos (quién puede escribir qué):

* Zona del estudiante (`data/users.json`, `data/planning.json`): la escribe el propio
  estudiante (registro, login, planning).
* Zona de la secretaría (`data/secretaria/`) y de la AC raíz (`data/pki/`): solo la
  escriben la secretaría y la raíz. Tras cada escritura los ficheros quedan en SOLO
  LECTURA (y, en Linux/macOS, también el directorio), de modo que el proceso del
  estudiante no puede borrarlos ni sobrescribirlos: el sistema operativo devuelve
  `PermissionError`. Solo el código de la secretaría, que además necesita su clave de
  firma para que lo escrito sea aceptado, levanta la protección un instante para escribir.

En un despliegue real cada zona pertenecería a un usuario distinto del sistema
(o a un servidor) y los estudiantes solo tendrían permiso de lectura; aquí todo se
ejecuta con el mismo usuario y se emula con el atributo de solo lectura.
"""
import json
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .errors import ValidationError

POSIX = os.name != "nt"
READ_ONLY_FILE = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH                       # r--r--r--
READ_ONLY_DIR = READ_ONLY_FILE | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH       # r-xr-xr-x
WRITABLE_FILE = stat.S_IRUSR | stat.S_IWUSR                                       # rw-------
WRITABLE_DIR = stat.S_IRWXU                                                       # rwx------


def ensure_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def is_protected(path: Path) -> bool:
    """True si el fichero está en solo lectura (no se puede escribir ni, en Windows, borrar)."""
    return Path(path).exists() and not os.stat(path).st_mode & stat.S_IWUSR


@contextmanager
def _unlocked(path: Path):
    """Levanta la protección de un fichero de la secretaría solo mientras se escribe."""
    directory = path.parent
    ensure_dir(directory)
    if POSIX:
        os.chmod(directory, WRITABLE_DIR)
    if path.exists():
        os.chmod(path, WRITABLE_FILE)
    try:
        yield
    finally:
        if path.exists():
            os.chmod(path, READ_ONLY_FILE)
        if POSIX:
            os.chmod(directory, READ_ONLY_DIR)


def _atomic_write(path: Path, data: bytes) -> None:
    ensure_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def write_bytes(path: Path, data: bytes, protect: bool = False) -> None:
    """Escritura atómica de un fichero binario (PEM). Con `protect`, queda en solo lectura."""
    path = Path(path)
    if protect:
        with _unlocked(path):
            _atomic_write(path, data)
    else:
        _atomic_write(path, data)


class JsonStore:
    """Un fichero JSON. Se escribe a un temporal (0600) y se renombra atómicamente.

    `protect=True` marca un fichero de la zona de la secretaría o de la raíz: tras
    guardarlo queda en solo lectura para que el estudiante no lo pueda borrar."""

    def __init__(self, path: Path, protect: bool = False):
        self.path = Path(path)
        self.protect = protect

    def load(self, default):
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return default
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValidationError(f"Fichero corrupto: {self.path.name}") from exc

    def save(self, obj) -> None:
        write_bytes(self.path, json.dumps(obj, indent=2, sort_keys=True).encode("utf-8"), self.protect)
