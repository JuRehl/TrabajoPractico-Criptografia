# PlanCipher

Aplicación de línea de comandos para que los estudiantes consulten su **planning**, sus **notas** y las
**asignaturas pendientes**, con criptografía moderna (práctica final de Criptografía y Seguridad Informática).

## Instalación y ejecución (entorno limpio)

Linux / macOS:

```bash
python3 -m venv .venv && source .venv/bin/activate   # Python >= 3.10
pip install -r requirements.txt                       # cryptography==50.0.2
python -m unittest discover -s tests -t .             # 138 pruebas, funcionales y de ataques
bash scripts/demo.sh                                  # demo completa con manipulaciones
```

Windows (PowerShell):

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1                           # si está bloqueado: Set-ExecutionPolicy -Scope Process Bypass
pip install -r requirements.txt
python -m unittest discover -s tests -t .
bash scripts/demo.sh                                  # con Git Bash; usa el Python de .venv automáticamente
```

En PowerShell las variables de entorno se fijan con `$env:PLANCIPHER_PASSWORD = "..."`.

Uso manual (los secretos se piden sin eco; `--debug` muestra algoritmos y longitudes, nunca secretos):

```bash
python -m plancipher init-secretaria                  # PKI (AC raíz -> secretaría + CRL) y plan firmado
python -m plancipher register alice
python -m plancipher enroll alice                     # [secretaría] emite su certificado X.509 (matrícula)
python -m plancipher issue-grade alice --subject CRIPTO --grade 8.5 --term 2026-1C
python -m plancipher add-planning alice --date 2026-11-10 --time 09:00 --text "Clase de Cripto"
python -m plancipher planning alice
python -m plancipher grades alice                     # verifica firma + descifra
python -m plancipher pending alice
python -m plancipher revoke-secretaria                # [AC raíz] revoca la secretaría (CRL)
```

Para scripts: `PLANCIPHER_PASSWORD`, `PLANCIPHER_SECRETARIA_PASS`, `PLANCIPHER_ROOT_PASS`, `PLANCIPHER_DATA`,
`PLANCIPHER_TRUST_FP` (huella SHA-256 de la **AC raíz**).
Códigos de salida: `0` OK, `1` error controlado, `3` datos **rechazados** por integridad.

## Interfaz web (opcional, Streamlit)

```bash
pip install -r requirements-web.txt
streamlit run app.py --server.address 127.0.0.1
```

Usa exactamente los mismos servicios y la misma criptografía que la CLI; `app.py` solo hace entrada/salida.
Pestaña **Estudiante** (registro, login, planning, notas verificadas, pendientes) y pestaña **Secretaría**
(inicializar, firmar matrículas, emitir notas). Las sesiones viven en la memoria del servidor y se descartan al
cerrar sesión. Es una demo **local**: Streamlit no aporta TLS, por lo que no debe exponerse en red
(limitación a mencionar en la memoria). Versión fijada: `streamlit==1.67.0`. Las pruebas de la web
(`tests/test_web.py`) se omiten automáticamente si Streamlit no está instalado.

## Estructura

```
plancipher/crypto/   solo criptografía: kdf, aead, hybrid, signing, keystore, certs, encoding
plancipher/          lógica: auth, planning, academic (matrícula/plan/notas), secretaria, storage (zonas y permisos)
plancipher/cli.py    solo entrada/salida (CLI)
app.py               solo entrada/salida (web Streamlit, opcional)
tests/               unittest: crypto, auth, planning, academic (ataques), functional (casos de uso),
                     cli y web (extremo a extremo; web se omite sin Streamlit)
```

## Decisiones criptográficas

| Función | Mecanismo | Parámetros / motivo |
|---|---|---|
| Contraseñas | scrypt + HKDF-SHA256 | n=2^17, r=8, p=1 (~128 MiB), sal de 128 bits por usuario. Una sola ejecución de scrypt; HKDF separa el **verificador** (se guarda) de la **KEK** (no se guarda). Comparación en tiempo constante. Política: mínimo 12 caracteres y rechazo de contraseñas de diccionario (también variantes como `Password12345678`). |
| Cifrado de datos | AES-256-GCM (AEAD) | Nonce aleatorio de 96 bits por cifrado; clave de contenido (CEK) aleatoria por registro; AAD con id y propietario/destinatario. |
| Claves de usuario | X25519 | La privada se guarda cifrada con la KEK (AES-GCM, AAD = usuario). |
| Entrega de CEK al estudiante | ECIES: X25519 efímero + HKDF-SHA256 + AES-256-GCM | La secretaría solo necesita la clave pública del estudiante. |
| Integridad | AES-GCM (tag) en datos privados; ECDSA en datos públicos | No se usa HMAC separado porque AEAD ya autentica. |
| Firma digital | ECDSA P-256 + SHA-256 | Firma certificados de estudiante, plan de estudios y notas (sobre cabecera + clave sellada + cifrado). Separación de dominios en el mensaje firmado. |
| Claves de firma | scrypt + AES-256-GCM con passphrase | La clave de la AC raíz y la de la secretaría se guardan cifradas, cada una con su passphrase (deben ser distintas). Nunca en claro en disco. |
| PKI X.509 | AC raíz → AC subordinada (secretaría) + CRL | **Raíz** autofirmada (10 años, `CA, pathLen=1`, `keyCertSign`+`cRLSign`): única ancla de confianza, solo firma certificados y la CRL. **Secretaría** emitida por la raíz (2 años, sin superar a la raíz, `CA, pathLen=0`, `digitalSignature`): emite los certificados de estudiante y firma plan y notas. **Estudiantes** (entidad final, 1 año, `CA=false`, solo `keyAgreement`): certificado X.509 emitido por la secretaría con `CN=usuario` y su clave pública X25519. Al cargar se validan autofirma de la raíz, emisor y firma de la subordinada, fechas, extensiones, curva P-256, **CRL** (firmada por la raíz y vigente) y huella opcional de la raíz. |

Aleatoriedad: siempre `os.urandom` (CSPRNG del sistema). No hay claves, IVs ni nonces constantes.

## Fallos seguros

Cualquier tag, firma o certificado inválidos **rechaza** el dato (no se muestra) y se informa;
la CLI devuelve código 3. Login con mensaje genérico, coste scrypt también para usuarios inexistentes
y bloqueo exponencial tras 5 fallos.

## Separación de accesos (borrado de datos)

Lo que escribe la secretaría no lo puede borrar ni sobrescribir un estudiante. Los datos se reparten en zonas según quién los escribe:

| Zona | Ficheros | Quién escribe | Protección |
|---|---|---|---|
| Estudiante | `data/users.json`, `data/planning.json` | El estudiante (registro, login, planning) | Escribible |
| Secretaría | `data/secretaria/`: `records.json` (notas), `plan.json`, `matriculas.json` (certificados de estudiante), `cert.pem`, `signing_key.json` | Solo la secretaría (con su clave de firma) | **Solo lectura** tras cada escritura |
| AC raíz | `data/pki/`: `root_cert.pem`, `root_key.json`, `crl.pem` | Solo la AC raíz | **Solo lectura** |

Tras cada escritura de la secretaría o de la raíz, los ficheros quedan en solo lectura (en Linux/macOS también el
directorio). Borrarlos o sobrescribirlos desde el lado del estudiante falla con `PermissionError` del sistema
operativo (`tests/test_access.py`, ATAQUE 2 de la demo). El código del estudiante nunca escribe en esas zonas. Los
certificados de matrícula ya no están en `users.json` (que escribe el estudiante), sino en la zona de la secretaría.

En un despliegue real cada zona pertenecería a un usuario distinto del sistema (o a un servidor) y los estudiantes
solo tendrían permiso de lectura. Aquí todo corre con el mismo usuario, así que se emula con el atributo de solo
lectura: alguien que lo quite a propósito se salta la separación. Aun así, cualquier **modificación** se sigue
detectando por la firma y el tag; solo el borrado deliberado quedaría sin detectar.

## Ataques mitigados (probados en `tests/`)

1. **Manipulación de datos en disco** (ciphertext, tag, firma, cabecera): AEAD + ECDSA → rechazo.
2. **Cambio de contexto** (copiar un registro a otro usuario/id): AAD y firma cubren propietario e id.
3. **Repetición / rollback de notas**: id único, `seq` creciente por estudiante, nota vigente = mayor `seq`.
4. **Sustitución de clave pública** del estudiante: su certificado X.509 (emitido por la secretaría) liga usuario↔clave; se comprueba emisor, firma, `CN` y que la clave coincida.
5. **Fuerza bruta de contraseñas**: scrypt costoso, sal única, bloqueo progresivo.
6. **Escalada de privilegios**: la secretaría no es un nombre de usuario; se prueba con su clave de firma.
7. **Secretaría falsa**: su certificado debe estar emitido por la AC raíz; sustituir toda la PKI se detecta fijando la huella de la raíz (`--trust-fingerprint`).
8. **Clave de la secretaría comprometida**: la AC raíz la revoca (`revoke-secretaria`) y la CRL hace que todas sus firmas se rechacen.
9. **Borrado de notas por el estudiante**: separación de accesos; la zona de la secretaría es de solo lectura para él.

## Limitaciones conocidas (para la memoria / defensa)

* PKI de dos niveles local: la clave de la AC raíz vive en el mismo disco (en producción estaría offline o en un HSM), no hay OCSP ni distribución de la CRL, y tras revocar no hay comando para emitir una secretaría nueva (re-certificación).
* Los certificados de estudiante no tienen CRL propia: para "revocar" a un estudiante se re-emite su certificado o se borra.
* Al revocar se rechaza todo lo firmado por la secretaría, también lo anterior a la revocación (no hay sellado de tiempo).
* La lista de contraseñas comunes es corta; en producción se usaría una lista grande de contraseñas filtradas.
* El borrado se impide por permisos (separación de accesos), no se detecta criptográficamente: alguien que se salte
  los permisos del sistema podría borrar el último registro sin que se note. Se resolvería además con un manifiesto
  firmado por la secretaría (número de notas por estudiante).
* Sin bloqueo de ficheros entre procesos concurrentes (escritura atómica, pero last-write-wins).
* Los metadatos (usuario, `seq`, fecha de emisión, nº de entradas) no están cifrados.
* El bloqueo por intentos revela que un usuario existe; es un compromiso explícito frente a la denegación de servicio.
* No hay recuperación de contraseña: la KEK se deriva de ella, así que perderla implica perder el planning y no poder leer las notas. Nadie, tampoco la secretaría, puede resetear la contraseña de un estudiante.
