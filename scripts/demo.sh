#!/usr/bin/env bash
# Demo reproducible: flujo normal + manipulaciones rechazadas. Usa un directorio temporal.
set -u
cd "$(dirname "$0")/.."
# Intérprete: $PYTHON, o el del venv si existe (Linux/Mac o Windows), o python3/python del sistema.
for c in "${PYTHON:-}" .venv/bin/python .venv/Scripts/python.exe python3 python; do
  if [ -n "$c" ] && command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
export PYTHONIOENCODING=utf-8 PLANCIPHER_DATA="$(mktemp -d)" PLANCIPHER_SECRETARIA_PASS="frase-secreta-larga-1" PLANCIPHER_ROOT_PASS="frase-ac-raiz-larga-2" PLANCIPHER_PASSWORD="clave-del-estudiante-99"
run() { echo; echo "\$ plancipher $*"; "$PY" -m plancipher "$@"; echo "(salida: $?)"; }

run init-secretaria
run register alice
run enroll alice
run issue-grade alice --subject CRIPTO --grade 8.5 --term 2026-1C
run issue-grade alice --subject REDES --grade 4.2 --term 2026-1C
run add-planning alice --date 2026-11-10 --time 09:00 --text "Clase de Cripto"
run planning alice
run grades alice
run pending alice
run --debug grades alice

echo; echo "=== ATAQUE 1: contraseña incorrecta ==="
PLANCIPHER_PASSWORD="contrasena-equivocada-1" "$PY" -m plancipher grades alice; echo "(salida: $?)"

echo; echo "=== ATAQUE 2: modificar un byte del cifrado de una nota ==="
"$PY" - <<'PY'
import base64, json, os
p = os.path.join(os.environ["PLANCIPHER_DATA"], "records.json")
d = json.load(open(p)); ct = bytearray(base64.b64decode(d[0]["ct"])); ct[20] ^= 1
d[0]["ct"] = base64.b64encode(bytes(ct)).decode(); json.dump(d, open(p, "w"))
PY
run grades alice

echo; echo "=== ATAQUE 3: modificar una entrada del planning ==="
"$PY" - <<'PY'
import base64, json, os
p = os.path.join(os.environ["PLANCIPHER_DATA"], "planning.json")
d = json.load(open(p)); raw = bytearray(base64.b64decode(d[0]["data"])); raw[15] ^= 1
d[0]["data"] = base64.b64encode(bytes(raw)).decode(); json.dump(d, open(p, "w"))
PY
run planning alice

echo; echo "=== ATAQUE 4: la AC raíz revoca la secretaría (clave comprometida) ==="
run revoke-secretaria
run pending alice
rm -rf "$PLANCIPHER_DATA"
