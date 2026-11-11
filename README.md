# PlanCipher

Aplicación de línea de comandos para que los estudiantes consulten su **planning**, sus **notas** y las
**asignaturas pendientes**, con criptografía moderna (práctica final de Criptografía y Seguridad Informática).

## Instalación y ejecución (entorno limpio)

```bash
python3 -m venv .venv && source .venv/bin/activate   # Python >= 3.10
pip install -r requirements.txt                       # cryptography==50.0.2
python -m unittest discover -s tests -t .             # 71 pruebas, positivas y negativas
bash scripts/demo.sh                                  # demo completa con manipulaciones
```

Uso manual (los secretos se piden sin eco; `--debug` muestra algoritmos y longitudes, nunca secretos):

```bash
python -m plancipher init-secretaria                  # clave de firma, certificado y plan firmado
python -m plancipher register alice
python -m plancipher enroll alice                     # [secretaría] firma la matrícula
python -m plancipher issue-grade alice --subject CRIPTO --grade 8.5 --term 2026-1C
python -m plancipher add-planning alice --date 2026-11-10 --time 09:00 --text "Clase de Cripto"
python -m plancipher planning alice
python -m plancipher grades alice                     # verifica firma + descifra
python -m plancipher pending alice
```

Para scripts: `PLANCIPHER_PASSWORD`, `PLANCIPHER_SECRETARIA_PASS`, `PLANCIPHER_DATA`, `PLANCIPHER_TRUST_FP`.
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
(limitación a mencionar en la memoria). Tras instalar, fija la versión exacta con `pip freeze | grep -i streamlit`.

## Estructura

```
plancipher/crypto/   solo criptografía: kdf, aead, hybrid, signing, keystore, certs, encoding
plancipher/          lógica: auth, planning, academic (matrícula/plan/notas), secretaria, storage
plancipher/cli.py    solo entrada/salida (CLI)
app.py               solo entrada/salida (web Streamlit, opcional)
tests/               unittest: crypto, auth, planning, academic, cli (extremo a extremo)
```

## Decisiones criptográficas

| Función | Mecanismo | Parámetros / motivo |
|---|---|---|
| Contraseñas | scrypt + HKDF-SHA256 | n=2^17, r=8, p=1 (~128 MiB), sal de 128 bits por usuario. Una sola ejecución de scrypt; HKDF separa el **verificador** (se guarda) de la **KEK** (no se guarda). Comparación en tiempo constante. Política: mínimo 12 caracteres y rechazo de contraseñas de diccionario (también variantes como `Password12345678`). |
| Cifrado de datos | AES-256-GCM (AEAD) | Nonce aleatorio de 96 bits por cifrado; clave de contenido (CEK) aleatoria por registro; AAD con id y propietario/destinatario. |
| Claves de usuario | X25519 | La privada se guarda cifrada con la KEK (AES-GCM, AAD = usuario). |
| Entrega de CEK al estudiante | ECIES: X25519 efímero + HKDF-SHA256 + AES-256-GCM | La secretaría solo necesita la clave pública del estudiante. |
| Integridad | AES-GCM (tag) en datos privados; ECDSA en datos públicos | No se usa HMAC separado porque AEAD ya autentica. |
| Firma digital | ECDSA P-256 + SHA-256 | Firma matrículas, plan de estudios y notas (sobre cabecera + clave sellada + cifrado). Separación de dominios en el mensaje firmado. |
| Clave de firma | scrypt + AES-256-GCM con passphrase | Nunca en claro en disco; certificado X.509 autofirmado como ancla de confianza. Al cargarlo se validan fechas, autofirma, `basicConstraints` (CA), `keyUsage` (firma de datos y de certificados), curva y huella opcional. |

Aleatoriedad: siempre `os.urandom` (CSPRNG del sistema). No hay claves, IVs ni nonces constantes.

## Fallos seguros

Cualquier tag, firma, certificado o matrícula inválidos **rechaza** el dato (no se muestra) y se informa;
la CLI devuelve código 3. Login con mensaje genérico, coste scrypt también para usuarios inexistentes
y bloqueo exponencial tras 5 fallos.

## Ataques mitigados (probados en `tests/`)

1. **Manipulación de datos en disco** (ciphertext, tag, firma, cabecera): AEAD + ECDSA → rechazo.
2. **Cambio de contexto** (copiar un registro a otro usuario/id): AAD y firma cubren propietario e id.
3. **Repetición / rollback de notas**: id único, `seq` creciente por estudiante, nota vigente = mayor `seq`.
4. **Sustitución de clave pública** del estudiante: la matrícula firmada liga usuario↔clave.
5. **Fuerza bruta de contraseñas**: scrypt costoso, sal única, bloqueo progresivo.
6. **Escalada de privilegios**: la secretaría no es un nombre de usuario; se prueba con su clave de firma.
7. **Secretaría falsa**: las firmas se verifican contra el certificado fijado (huella opcional `--trust-fingerprint`).

## Limitaciones conocidas (para la memoria / defensa)

* Ancla de confianza autofirmada de un solo nivel y sin revocación (CRL/OCSP): en producción, una PKI con CA raíz e intermedias y consulta del estado del certificado.
* La lista de contraseñas comunes es corta; en producción se usaría una lista grande de contraseñas filtradas.
* Un atacante con escritura en disco puede **borrar** el último registro (rollback por borrado) sin que se detecte;
  se resolvería con un contador/manifiesto firmado.
* Sin bloqueo de ficheros entre procesos concurrentes (escritura atómica, pero last-write-wins).
* Los metadatos (usuario, `seq`, fecha de emisión, nº de entradas) no están cifrados.
* El bloqueo por intentos revela que un usuario existe; es un compromiso explícito frente a la denegación de servicio.
* No hay recuperación de contraseña: la KEK se deriva de ella, así que perderla implica perder el planning.
