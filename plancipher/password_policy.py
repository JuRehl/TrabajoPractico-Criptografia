"""Rechazo de contraseñas demasiado comunes (ataques de diccionario).

No se compara solo la contraseña literal: se reduce a sus letras (sin tildes,
dígitos ni símbolos) y se busca en una lista de palabras habituales. Así se
rechazan variantes triviales como "Password12345678" o "Contraseña-2026!".
Tolera hasta tres letras añadidas ("bienvenidox"). Es un filtro corto y deliberadamente simple; no sustituye a una lista grande
(p. ej. las de HIBP) en un sistema real.
"""
import re
import unicodedata

COMMON_WORDS = frozenset("""
password passw contrasena contrasenasegura micontrasena miclave clave claveclave
mypassword secret secreto qwerty qwertyuiop qwertyuiopasdfghjkl asdfghjkl
asdfghjklzxcvbnm zxcvbnm abcdefgh abcdefghijkl letmein letmeinplease welcome
bienvenido admin administrator administrador root toor iloveyou teamo tequiero
football futbol baseball monkey dragon master shadow superman batman michael
ashley sunshine princess trustno trustnoone freedom whatever usuario estudiante
universidad madrid barcelona realmadrid atletico changeme cambiame
""".split())


def _letters_only(text: str) -> str:
    folded = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", text).lower())
    return re.sub(r"[^a-z]", "", folded)


MAX_EXTRA_LETTERS = 3  # "bienvenidox" sigue siendo "bienvenido"; "caballograpaverde" no es "clave"


def is_common_password(password: str) -> bool:
    """True si es solo dígitos o sus letras son una palabra habitual (con hasta 3 letras de más)."""
    if re.fullmatch(r"\d+", password):
        return True
    core = _letters_only(password)
    if core in COMMON_WORDS:
        return True
    return any(len(w) >= 5 and w in core and len(core) - len(w) <= MAX_EXTRA_LETTERS for w in COMMON_WORDS)
