#!/usr/bin/env bash
# ---------------------------------------------------------------------------
#  secops.sh — Escáner de seguridad interno, ejecutable en local y en CI.
#
#  Seis capas, todas defensivas:
#    1. secretos   -> gitleaks   (claves/tokens filtrados en el código y el historial)
#    2. deps       -> trivy fs   (CVEs en dependencias y ficheros de configuración)
#    3. malware    -> clamscan   (antivirus sobre el árbol del repositorio)
#    4. workflows  -> actionlint (errores y patrones peligrosos en GitHub Actions)
#    5. codigo     -> semgrep + bandit (fallos explotables en tu propio código)
#    6. iac        -> checkov    (infraestructura como código, Docker, K8s, Actions)
#
#  Uso:
#     ./scripts/secops.sh --install          # descarga los binarios (con SHA-256 fijado)
#     ./scripts/secops.sh                    # ejecuta las seis capas
#     ./scripts/secops.sh secretos malware   # ejecuta sólo las capas indicadas
#     ./scripts/secops.sh --soft             # informa pero siempre sale con 0
#     ./scripts/secops.sh --strict           # falla también si una capa no se pudo ejecutar
#
#  Códigos de salida:
#     0 = sin hallazgos   1 = hallazgos   2 = error de uso   3 = capas sin verificar (--strict)
#
#  Nada de lo que hace este script modifica el código: sólo lee y genera informes.
# ---------------------------------------------------------------------------
set -Eeuo pipefail

# --- Versiones fijadas (SHA-256 tomados del *_checksums.txt de cada release) -
#  Fuente primaria: el fichero de checksums publicado por el propio proyecto en
#  su release de GitHub. No se copia el hash de ningún tercero.
GITLEAKS_VERSION="8.28.0"
TRIVY_VERSION="0.70.0"
ACTIONLINT_VERSION="1.7.7"

# --- Plataforma ------------------------------------------------------------
#  Descargar el binario de Linux en Windows o macOS deja un fichero que no
#  ejecuta ("Exec format error") y la capa queda como NO VERIFICADO sin que se
#  vea el motivo. Se detecta el sistema y se pide el activo correcto.
case "$(uname -s)" in
  Linux*)               SECOPS_SO="linux"   ;;
  Darwin*)              SECOPS_SO="darwin"  ;;
  MINGW*|MSYS*|CYGWIN*) SECOPS_SO="windows" ;;
  *)                    SECOPS_SO="desconocido" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  SECOPS_ARCH="amd64" ;;
  arm64|aarch64) SECOPS_ARCH="arm64" ;;
  *)             SECOPS_ARCH="desconocido" ;;
esac
SECOPS_PLATAFORMA="${SECOPS_SO}_${SECOPS_ARCH}"
if [ "$SECOPS_SO" = "windows" ]; then EXE=".exe"; else EXE=""; fi

activo() { # herramienta -> "nombre_del_activo|sha256"   (falla si no hay activo)
  case "$1:$SECOPS_PLATAFORMA" in
    gitleaks:linux_amd64)    echo "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz|a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb" ;;
    gitleaks:linux_arm64)    echo "gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz|eff65261156100e5d94a6b3dec313d532fddfe19ae1590bf7a2b4f2699128356" ;;
    gitleaks:darwin_amd64)   echo "gitleaks_${GITLEAKS_VERSION}_darwin_x64.tar.gz|edf5a507008b0d2ef4959575772772770586409c1f6f74dabf19cbe7ec341ced" ;;
    gitleaks:darwin_arm64)   echo "gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz|d942f3ad147250c9edbaab3fed9e482f98d3b59ba10ae97b8d75647e3ade492c" ;;
    gitleaks:windows_amd64)  echo "gitleaks_${GITLEAKS_VERSION}_windows_x64.zip|da6458e8864af553807de1c46a7a8eac0880bd6b99ba56288e87e86a45af884f" ;;

    trivy:linux_amd64)       echo "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz|8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9" ;;
    trivy:linux_arm64)       echo "trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz|2f6bb988b553a1bbac6bdd1ce890f5e412439564e17522b88a4541b4f364fc8d" ;;
    trivy:darwin_amd64)      echo "trivy_${TRIVY_VERSION}_macOS-64bit.tar.gz|52d531452b19e7593da29366007d02a810e1e0080d02f9cf6a1afb46c35aaa93" ;;
    trivy:darwin_arm64)      echo "trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz|68e543c51dcc96e1c344053a4fde9660cf602c25565d9f09dc17dd41e13b838a" ;;
    trivy:windows_amd64)     echo "trivy_${TRIVY_VERSION}_windows-64bit.zip|eea5442eab86f9e26cd718d7618d43899e72a83767619e8bee47911bddbfb825" ;;

    actionlint:linux_amd64)  echo "actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz|023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757" ;;
    actionlint:linux_arm64)  echo "actionlint_${ACTIONLINT_VERSION}_linux_arm64.tar.gz|401942f9c24ed71e4fe71b76c7d638f66d8633575c4016efd2977ce7c28317d0" ;;
    actionlint:darwin_amd64) echo "actionlint_${ACTIONLINT_VERSION}_darwin_amd64.tar.gz|28e5de5a05fc558474f638323d736d822fff183d2d492f0aecb2b73cc44584f5" ;;
    actionlint:darwin_arm64) echo "actionlint_${ACTIONLINT_VERSION}_darwin_arm64.tar.gz|2693315b9093aeacb4ebd91a993fea54fc215057bf0da2659056b4bc033873db" ;;
    actionlint:windows_amd64) echo "actionlint_${ACTIONLINT_VERSION}_windows_amd64.zip|7f12f1801bca3d480d67aaf7774f4c2a6359a3ca8eebe382c95c10c9704aa731" ;;

    *) return 1 ;;
  esac
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${SECOPS_DIR:-$REPO_ROOT/.secops}"
BINDIR="$WORKDIR/bin"
REPORTS="$WORKDIR/reports"
SUMMARY="$REPORTS/resumen.txt"

SOFT=0
STRICT=0
HALLAZGOS=0
NO_VERIFICADO=()
CAPAS=()

# --- Utilidades ------------------------------------------------------------
c_red()  { printf '\033[31m%s\033[0m\n' "$*"; }
c_grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
c_yel()  { printf '\033[33m%s\033[0m\n' "$*"; }
log()    { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
anota()  { printf '%s\n' "$*" >> "$SUMMARY"; }

# Marca una capa como no ejecutada. NUNCA se convierte en "correcto":
# el informe final la lista aparte para que nadie la lea como verificada.
sin_verificar() {
  NO_VERIFICADO+=("$1: $2")
  c_yel "  [NO VERIFICADO] $1 — $2"
  anota "NO VERIFICADO | $1 | $2"
}

bin_path() { # devuelve la ruta del binario, del PATH o del directorio local
  if command -v "$1" >/dev/null 2>&1; then command -v "$1"
  elif [ -x "$BINDIR/$1$EXE" ]; then printf '%s\n' "$BINDIR/$1$EXE"
  elif [ -x "$BINDIR/$1" ]; then printf '%s\n' "$BINDIR/$1"
  else return 1; fi
}

# --- Intérprete de Python --------------------------------------------------
#  Las capas 1, 2, 5 y 6 cuentan los hallazgos leyendo el JSON/SARIF con Python.
#  Si no hay intérprete, el script NO debe abortar (antes moría con 127 a mitad
#  del análisis): tiene que degradar a NO VERIFICADO, que es su propio contrato.
PY=""
for _c in python3 python; do
  if command -v "$_c" >/dev/null 2>&1 \
     && "$_c" -c 'import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)' >/dev/null 2>&1; then
    PY="$_c"; break
  fi
done
if [ -z "$PY" ] && command -v py >/dev/null 2>&1 && py -3 -c 'pass' >/dev/null 2>&1; then
  PY="py -3"
fi
SIN_PY=""
[ -n "$PY" ] || SIN_PY=" · no hay ningún Python 3 en el PATH"

py_run() { # fragmento [args...] -> imprime el resultado, o -1 si no se puede contar
  if [ -z "$PY" ]; then printf '%s\n' -1; return 0; fi
  # shellcheck disable=SC2086
  $PY -c "$@" 2>/dev/null || printf '%s\n' -1
}

descargar() { # url destino sha256
  local url="$1" dest="$2" sha="$3" tmp
  tmp="$(mktemp)"
  curl -fsSL --retry 3 -o "$tmp" "$url" || { c_red "descarga fallida: $url"; rm -f "$tmp"; return 1; }
  local real; real="$(sha256sum "$tmp" | cut -d' ' -f1)"
  if [ "$real" != "$sha" ]; then
    c_red "CHECKSUM NO COINCIDE para $url"
    c_red "  esperado: $sha"
    c_red "  obtenido: $real"
    rm -f "$tmp"; return 1
  fi
  mv "$tmp" "$dest"
}

obtener() { # herramienta tmpdir  — descarga, verifica el SHA y comprueba que ARRANCA
  local nombre="$1" tmp="$2" datos paquete sha base version url
  if ! datos="$(activo "$nombre")"; then
    c_red "  $nombre: no hay binario publicado para $SECOPS_PLATAFORMA"
    return 1
  fi
  paquete="${datos%%|*}"; sha="${datos##*|}"
  case "$nombre" in
    gitleaks)   base="https://github.com/gitleaks/gitleaks/releases/download";  version="$GITLEAKS_VERSION" ;;
    trivy)      base="https://github.com/aquasecurity/trivy/releases/download"; version="$TRIVY_VERSION" ;;
    actionlint) base="https://github.com/rhysd/actionlint/releases/download";   version="$ACTIONLINT_VERSION" ;;
    *) return 1 ;;
  esac
  url="$base/v$version/$paquete"

  descargar "$url" "$tmp/$paquete" "$sha" || return 1
  case "$paquete" in
    *.zip)    unzip -oqj "$tmp/$paquete" "$nombre$EXE" -d "$BINDIR" || return 1 ;;
    *.tar.gz) tar -xzf "$tmp/$paquete" -C "$BINDIR" "$nombre$EXE"   || return 1 ;;
    *) c_red "  $nombre: formato de paquete no soportado ($paquete)"; return 1 ;;
  esac
  chmod +x "$BINDIR/$nombre$EXE" 2>/dev/null || true

  # Un binario descargado no es un binario utilizable: si es de otra
  # arquitectura, se extrae sin error y falla al ejecutarse. Se comprueba aquí,
  # no cuando ya se esté escaneando y el fallo se confunda con "sin hallazgos".
  if ! "$BINDIR/$nombre$EXE" --version >/dev/null 2>&1 \
     && ! "$BINDIR/$nombre$EXE" version   >/dev/null 2>&1; then
    c_red "  $nombre: descargado pero NO ejecuta en esta plataforma ($SECOPS_PLATAFORMA)"
    rm -f "$BINDIR/$nombre$EXE"
    return 1
  fi
  c_grn "  $nombre $version OK ($paquete)"
}

instalar() {
  mkdir -p "$BINDIR"
  log "Instalando escáneres en $BINDIR — plataforma $SECOPS_PLATAFORMA, verificación SHA-256"
  if [ "$SECOPS_SO" = "desconocido" ] || [ "$SECOPS_ARCH" = "desconocido" ]; then
    c_red "  Plataforma no reconocida ($(uname -s) / $(uname -m))."
    c_red "  Instala gitleaks, trivy y actionlint a mano y vuelve a ejecutar."
    return 1
  fi

  local t fallos=0 h
  t="$(mktemp -d)"
  for h in gitleaks trivy actionlint; do
    obtener "$h" "$t" || { fallos=$((fallos + 1)); c_yel "  -> la capa de $h quedará como NO VERIFICADO"; }
  done
  rm -rf "$t"

  c_yel "  ClamAV no se descarga: instálalo con el gestor del sistema"
  c_yel "    Debian/Ubuntu: sudo apt-get install -y clamav && sudo freshclam"
  c_yel "    macOS:         brew install clamav && freshclam"
  c_yel "    Windows:       https://www.clamav.net/downloads (clamav-*.win.x64.msi) y freshclam"
  [ "$fallos" -eq 0 ] || return 1
}

# --- Capa 1: secretos ------------------------------------------------------
capa_secretos() {
  log "Capa 1/6 — Secretos filtrados (gitleaks)"
  local bin; bin="$(bin_path gitleaks)" || { sin_verificar "secretos" "gitleaks no instalado (ejecuta --install)"; return; }

  local args=(dir "$REPO_ROOT" --no-banner --redact
              --report-format sarif --report-path "$REPORTS/gitleaks.sarif"
              --exit-code 0)
  # Si es un repositorio git, se analiza también el historial completo: un secreto
  # borrado en un commit posterior sigue siendo un secreto comprometido.
  if [ -d "$REPO_ROOT/.git" ]; then
    "$bin" git "$REPO_ROOT" --no-banner --redact \
      --report-format sarif --report-path "$REPORTS/gitleaks-historial.sarif" \
      --exit-code 0 >/dev/null 2>&1 || true
  fi
  "$bin" "${args[@]}" >"$REPORTS/gitleaks.log" 2>&1 || true

  local n; n="$(py_run "
import json,sys
try:
    d=json.load(open('$REPORTS/gitleaks.sarif'))
    print(sum(len(r.get('results',[])) for r in d.get('runs',[])))
except Exception: print(-1)")"
  if [ "$n" -lt 0 ]; then sin_verificar "secretos" "gitleaks no produjo un SARIF legible${SIN_PY}"; return; fi
  if [ "$n" -gt 0 ]; then
    c_red "  $n secreto(s) detectado(s) -> $REPORTS/gitleaks.sarif"
    anota "HALLAZGOS   | secretos | $n"
    HALLAZGOS=$((HALLAZGOS + n))
  else
    c_grn "  Sin secretos detectados"; anota "LIMPIO      | secretos | 0"
  fi
}

# --- Capa 2: dependencias / configuración ----------------------------------
capa_deps() {
  log "Capa 2/6 — Vulnerabilidades en dependencias y configuración (trivy)"
  local bin; bin="$(bin_path trivy)" || { sin_verificar "dependencias" "trivy no instalado (ejecuta --install)"; return; }

  # Se ejecutan por separado a propósito: el escáner de CVEs necesita descargar
  # la base de datos (red hacia un registro OCI) y el de malas configuraciones no.
  # Si cae la red, la segunda mitad sigue dando resultados reales en lugar de
  # que todo el bloque quede sin ejecutar.
  local contar='
import json,sys
try:
    d=json.load(open(sys.argv[1])) or {}
    print(sum(len(r.get("Vulnerabilities") or [])+len(r.get("Misconfigurations") or []) for r in (d.get("Results") or [])))
except Exception: print(-1)'

  "$bin" fs "$REPO_ROOT" --scanners vuln --severity HIGH,CRITICAL \
      --format json --output "$REPORTS/trivy-vuln.json" \
      ${TRIVY_DB_REPOSITORY:+--db-repository "$TRIVY_DB_REPOSITORY"} \
      --exit-code 0 --skip-dirs "$WORKDIR" >"$REPORTS/trivy-vuln.log" 2>&1 || true
  local nv; nv="$(py_run "$contar" "$REPORTS/trivy-vuln.json" 2>/dev/null || echo -1)"

  "$bin" fs "$REPO_ROOT" --scanners misconfig --severity HIGH,CRITICAL \
      --format json --output "$REPORTS/trivy-misconfig.json" \
      --exit-code 0 --skip-dirs "$WORKDIR" >"$REPORTS/trivy-misconfig.log" 2>&1 || true
  local nm; nm="$(py_run "$contar" "$REPORTS/trivy-misconfig.json" 2>/dev/null || echo -1)"

  if [ "$nv" -lt 0 ]; then
    sin_verificar "dependencias (CVE)" "trivy no pudo descargar la base de vulnerabilidades, o no se pudo leer el JSON${SIN_PY} (ver $REPORTS/trivy-vuln.log)"
  elif [ "$nv" -gt 0 ]; then
    c_red "  $nv vulnerabilidad(es) HIGH/CRITICAL -> $REPORTS/trivy-vuln.json"
    anota "HALLAZGOS   | dependencias (CVE) | $nv"; HALLAZGOS=$((HALLAZGOS + nv))
  else
    c_grn "  Sin vulnerabilidades HIGH/CRITICAL"; anota "LIMPIO      | dependencias (CVE) | 0"
  fi

  if [ "$nm" -lt 0 ]; then
    sin_verificar "configuración" "trivy no produjo un JSON legible${SIN_PY} (ver $REPORTS/trivy-misconfig.log)"
  elif [ "$nm" -gt 0 ]; then
    c_red "  $nm mala(s) configuración(es) HIGH/CRITICAL -> $REPORTS/trivy-misconfig.json"
    anota "HALLAZGOS   | configuración | $nm"; HALLAZGOS=$((HALLAZGOS + nm))
  else
    c_grn "  Sin malas configuraciones HIGH/CRITICAL"; anota "LIMPIO      | configuración | 0"
  fi
}

# --- Capa 3: antivirus -----------------------------------------------------
capa_malware() {
  log "Capa 3/6 — Antivirus sobre el árbol del repositorio (ClamAV)"
  local bin; bin="$(bin_path clamscan)" || { sin_verificar "malware" "clamscan no instalado"; return; }

  local dbargs=()
  if [ -n "${CLAMAV_DB:-}" ]; then
    dbargs=(--database "$CLAMAV_DB")
  else
    # Si no hay base de firmas, clamscan aborta: eso es un fallo de entorno,
    # no un "sin virus". Se detecta antes de ejecutar el escaneo completo.
    local d
    for d in /var/lib/clamav "$HOME/.clamav"; do
      if compgen -G "$d/*.c[vl]d" >/dev/null 2>&1 || compgen -G "$d/*.hdb" >/dev/null 2>&1; then
        dbargs=(--database "$d"); break
      fi
    done
    if [ ${#dbargs[@]} -eq 0 ]; then
      sin_verificar "malware" "no hay base de firmas ClamAV; ejecuta 'freshclam' o define CLAMAV_DB"
      return
    fi
  fi

  set +e
  "$bin" "${dbargs[@]}" --recursive --infected --no-summary \
        --exclude-dir="^${WORKDIR}" --exclude-dir="^${REPO_ROOT}/.git$" \
        "$REPO_ROOT" >"$REPORTS/clamav.log" 2>&1
  local rc=$?
  set -e

  case "$rc" in
    0) c_grn "  Sin malware detectado"; anota "LIMPIO      | malware | 0" ;;
    1) local n; n="$(wc -l < "$REPORTS/clamav.log")"
       c_red "  $n fichero(s) infectado(s) -> $REPORTS/clamav.log"
       sed 's/^/    /' "$REPORTS/clamav.log"
       anota "HALLAZGOS   | malware | $n"
       HALLAZGOS=$((HALLAZGOS + n)) ;;
    *) sin_verificar "malware" "clamscan terminó con error $rc (ver $REPORTS/clamav.log)" ;;
  esac
}

# --- Capa 5: código propio (SAST) ------------------------------------------
capa_codigo() {
  log "Capa 5/6 — Vulnerabilidades en tu propio código (semgrep + bandit)"
  local algo=0

  local sg; if sg="$(bin_path semgrep)"; then
    # Con red, el registro público aporta cientos de reglas mantenidas.
    # Sin red, las reglas locales del kit siguen cubriendo lo esencial.
    local cfg="$REPO_ROOT/scripts/reglas/semgrep-basico.yaml"
    [ -f "$cfg" ] || cfg="$(dirname "${BASH_SOURCE[0]}")/reglas/semgrep-basico.yaml"
    local usadas="reglas locales"
    if [ "${SEMGREP_REMOTO:-1}" = "1" ] && curl -fsS -m 8 -o /dev/null https://semgrep.dev 2>/dev/null; then
      cfg="p/security-audit"; usadas="registro p/security-audit"
    fi
    "$sg" scan --config "$cfg" --json --output "$REPORTS/semgrep.json" \
        --metrics=off --quiet "$REPO_ROOT" >"$REPORTS/semgrep.log" 2>&1 || true
    local ns; ns="$(py_run "
import json,sys
try:
    d=json.load(open('$REPORTS/semgrep.json'))
    print(len(d.get('errors',[])) and -1 or len(d['results']))
except Exception: print(-1)")"
    if [ "$ns" -lt 0 ]; then
      sin_verificar "código (semgrep)" "semgrep no produjo un JSON válido o alguna regla no compiló${SIN_PY} (ver $REPORTS/semgrep.log)"
    elif [ "$ns" -gt 0 ]; then
      c_red "  semgrep ($usadas): $ns hallazgo(s) -> $REPORTS/semgrep.json"
      anota "HALLAZGOS   | código (semgrep) | $ns"; HALLAZGOS=$((HALLAZGOS + ns)); algo=1
    else
      c_grn "  semgrep ($usadas): sin hallazgos"; anota "LIMPIO      | código (semgrep) | 0"; algo=1
    fi
  else
    sin_verificar "código (semgrep)" "semgrep no instalado (pip install semgrep)"
  fi

  # bandit sólo tiene sentido si hay Python en el repositorio.
  if compgen -G "$REPO_ROOT/**/*.py" >/dev/null 2>&1 || find "$REPO_ROOT" -name '*.py' -not -path '*/.secops/*' -print -quit | grep -q .; then
    local bd; if bd="$(bin_path bandit)"; then
      # -ll -ii = severidad y confianza MEDIA o superior. Sin este filtro bandit
      # marca cosas como "importa subprocess" o "usa assert", que en un
      # repositorio normal son cientos de avisos y entierran lo que importa.
      # Con BANDIT_TODO=1 se ven todos, incluidos los de severidad baja.
      local nivel=(-ll -ii); [ "${BANDIT_TODO:-0}" = "1" ] && nivel=()
      "$bd" -q -r "$REPO_ROOT" -x "$WORKDIR" "${nivel[@]+"${nivel[@]}"}" \
            -f json -o "$REPORTS/bandit.json" >/dev/null 2>&1 || true
      local nb; nb="$(py_run "
import json
try: print(len(json.load(open('$REPORTS/bandit.json'))['results']))
except Exception: print(-1)")"
      if [ "$nb" -lt 0 ]; then
        sin_verificar "código (bandit)" "bandit no produjo un JSON legible${SIN_PY}"
      elif [ "$nb" -gt 0 ]; then
        c_red "  bandit: $nb hallazgo(s) en Python -> $REPORTS/bandit.json"
        anota "HALLAZGOS   | código (bandit) | $nb"; HALLAZGOS=$((HALLAZGOS + nb)); algo=1
      else
        c_grn "  bandit: sin hallazgos en Python"; anota "LIMPIO      | código (bandit) | 0"; algo=1
      fi
    else
      sin_verificar "código (bandit)" "bandit no instalado (pip install bandit)"
    fi
  fi

  [ "$algo" -eq 1 ] || true
}

# --- Capa 6: infraestructura como código -----------------------------------
capa_iac() {
  log "Capa 6/6 — Infraestructura como código y workflows (checkov)"
  local bin; bin="$(bin_path checkov)" || { sin_verificar "infraestructura" "checkov no instalado (pip install checkov)"; return; }

  "$bin" -d "$REPO_ROOT" --quiet --compact -o json > "$REPORTS/checkov.json" 2>"$REPORTS/checkov.log" || true
  local n; n="$(py_run "
import json
try:
    d=json.load(open('$REPORTS/checkov.json'))
    d=d if isinstance(d,list) else [d]
    print(sum(len(x.get('results',{}).get('failed_checks',[])) for x in d))
except Exception: print(-1)")"
  if [ "$n" -lt 0 ]; then
    sin_verificar "infraestructura" "checkov no produjo un JSON legible${SIN_PY} (ver $REPORTS/checkov.log)"
  elif [ "$n" -gt 0 ]; then
    c_red "  $n comprobación(es) fallida(s) -> $REPORTS/checkov.json"
    anota "HALLAZGOS   | infraestructura | $n"; HALLAZGOS=$((HALLAZGOS + n))
  else
    c_grn "  Sin problemas de infraestructura"; anota "LIMPIO      | infraestructura | 0"
  fi
}

# --- Capa 4: workflows -----------------------------------------------------
capa_workflows() {
  log "Capa 4/6 — Auditoría de los propios workflows (actionlint)"
  if [ ! -d "$REPO_ROOT/.github/workflows" ]; then
    c_grn "  No hay workflows que auditar"; anota "LIMPIO      | workflows | 0"; return
  fi
  local bin; bin="$(bin_path actionlint)" || { sin_verificar "workflows" "actionlint no instalado (ejecuta --install)"; return; }

  set +e
  (cd "$REPO_ROOT" && "$bin" -no-color) >"$REPORTS/actionlint.log" 2>&1
  local rc=$?
  set -e
  local n; n="$(grep -cE '^\.github/workflows/' "$REPORTS/actionlint.log" || true)"
  if [ "$rc" -eq 0 ]; then
    c_grn "  Workflows correctos"; anota "LIMPIO      | workflows | 0"
  elif [ "$n" -gt 0 ]; then
    c_red "  $n problema(s) -> $REPORTS/actionlint.log"
    sed 's/^/    /' "$REPORTS/actionlint.log" | head -40
    anota "HALLAZGOS   | workflows | $n"
    HALLAZGOS=$((HALLAZGOS + n))
  else
    # Salida distinta de 0 pero sin hallazgos con formato de hallazgo:
    # es un error de la herramienta, no un repositorio correcto.
    sin_verificar "workflows" "actionlint terminó con error $rc (ver $REPORTS/actionlint.log)"
  fi
}

# --- Programa principal ----------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    --install) mkdir -p "$REPORTS"; instalar; exit 0 ;;
    --soft)    SOFT=1 ;;
    --strict)  STRICT=1 ;;
    -h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    secretos|deps|malware|workflows|codigo|iac) CAPAS+=("$arg") ;;
    *) c_red "Argumento desconocido: $arg"; exit 2 ;;
  esac
done
[ ${#CAPAS[@]} -eq 0 ] && CAPAS=(secretos deps malware workflows codigo iac)

mkdir -p "$REPORTS"
: > "$SUMMARY"
anota "Informe secops — $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
anota "Repositorio: $REPO_ROOT"
anota "----------------------------------------------------------"

for capa in "${CAPAS[@]}"; do
  case "$capa" in
    secretos)  capa_secretos ;;
    deps)      capa_deps ;;
    malware)   capa_malware ;;
    workflows) capa_workflows ;;
    codigo)    capa_codigo ;;
    iac)       capa_iac ;;
  esac
done

log "Resumen"
cat "$SUMMARY"
echo
if [ ${#NO_VERIFICADO[@]} -gt 0 ]; then
  c_yel "ATENCIÓN: ${#NO_VERIFICADO[@]} capa(s) NO se pudieron verificar en este entorno."
  printf '  - %s\n' "${NO_VERIFICADO[@]}"
  c_yel "Un resultado sin estas capas NO es un repositorio verificado como limpio."
  echo
fi

# Prioridad de códigos de salida: hallazgos (1) > capas sin verificar (3) > limpio (0).
# Un hallazgo confirmado siempre pesa más que una capa que no se pudo ejecutar.
if [ "$HALLAZGOS" -gt 0 ]; then
  c_red "RESULTADO: $HALLAZGOS hallazgo(s) de seguridad. Informes en $REPORTS"
  [ "$SOFT" -eq 1 ] && exit 0 || exit 1
fi
if [ ${#NO_VERIFICADO[@]} -gt 0 ] && [ "$STRICT" -eq 1 ] && [ "$SOFT" -eq 0 ]; then
  c_red "RESULTADO: modo --strict y ${#NO_VERIFICADO[@]} capa(s) sin verificar. No se declara limpio."
  exit 3
fi
c_grn "RESULTADO: sin hallazgos en las capas ejecutadas. Informes en $REPORTS"
exit 0
