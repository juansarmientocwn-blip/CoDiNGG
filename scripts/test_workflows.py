#!/usr/bin/env python3
"""
Pruebas de los workflows del agente de seguridad.

No se limita a comprobar que el YAML es válido: extrae el script de
`github-script` del job de informe y lo EJECUTA con una API de GitHub simulada,
para verificar que decide bien en cada escenario (crear / actualizar / cerrar
la issue) y, sobre todo, que una capa que no se ejecutó nunca se presenta como
"repositorio limpio".

Requisitos: python3 con PyYAML y node.
Uso: python3 scripts/test_workflows.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _localizar_workflows() -> tuple[str, str]:
    """Los workflows viven en assets/github/ dentro de la skill y en .github/
    dentro de un repositorio ya instalado. Se acepta cualquiera de los dos,
    y un tercer camino explícito por argumento."""
    if len(sys.argv) > 1:
        base = os.path.abspath(sys.argv[1])
    else:
        candidatos = [os.path.join(RAIZ, "assets", "github"),
                      os.path.join(RAIZ, ".github")]
        base = next((c for c in candidatos if os.path.isdir(os.path.join(c, "workflows"))), "")
        if not base:
            print("No encuentro los workflows ni en assets/github/ ni en .github/")
            raise SystemExit(2)
    return base, os.path.join(base, "workflows")

BASE, WF = _localizar_workflows()

try:
    import yaml
except ImportError:
    print("Falta PyYAML: pip install pyyaml")
    raise SystemExit(2)


def prueba_yaml() -> int:
    fallos = 0
    objetivos = [os.path.join(WF, f) for f in sorted(os.listdir(WF))]
    objetivos.append(os.path.join(BASE, "dependabot.yml"))
    for f in objetivos:
        try:
            doc = yaml.safe_load(open(f))
            assert isinstance(doc, dict) and doc, "documento vacío"
            print(f"[OK  ] YAML válido: {os.path.relpath(f, RAIZ)}")
        except Exception as e:  # noqa: BLE001
            print(f"[FALLA] YAML: {os.path.relpath(f, RAIZ)}: {e}")
            fallos += 1
    return fallos


# Los workflows que instala esta skill. El resto de workflows del repositorio
# se revisan igual, pero un incumplimiento suyo se reporta como AVISO en vez de
# como fallo: son del usuario, y romperle el banco de pruebas por un workflow
# preexistente sólo consigue que deje de ejecutarlo.
PROPIOS = {"agente-seguridad.yml", "codeql.yml", "scorecard.yml", "remediacion-claude.yml"}


def prueba_permisos() -> int:
    """Ningún workflow debe conceder permisos amplios por defecto,
    ni usar pull_request_target (vía habitual de escalada en Actions)."""
    fallos = 0
    avisos = 0
    for f in sorted(os.listdir(WF)):
        ruta = os.path.join(WF, f)
        try:
            doc = yaml.safe_load(open(ruta))
        except yaml.YAMLError as e:
            # Ya lo reportó prueba_yaml con detalle; aquí sólo se cuenta, sin
            # dejar que una traza de Python oculte el resto de comprobaciones.
            print(f"[FALLA] {f}: no se puede analizar el YAML ({type(e).__name__})")
            fallos += 1
            continue
        propio = f in PROPIOS
        etiqueta = "FALLA" if propio else "AVISO"

        problemas = []
        # PyYAML interpreta la clave `on:` como el booleano True.
        disparadores = doc.get("on", doc.get(True, {}))
        if isinstance(disparadores, dict) and "pull_request_target" in disparadores:
            problemas.append("usa pull_request_target (ejecuta código de un fork con tus secretos)")
        permisos = doc.get("permissions")
        if permisos != {"contents": "read"}:
            problemas.append(f"permisos globales = {permisos!r}; lo seguro es 'contents: read'")

        if not problemas:
            print(f"[OK  ] {f}: permisos globales mínimos y sin pull_request_target")
            continue
        for p in problemas:
            print(f"[{etiqueta}] {f}: {p}")
        if propio:
            fallos += len(problemas)
        else:
            avisos += len(problemas)

    if avisos:
        print(f"       ({avisos} aviso(s) en workflows que no instala esta skill: "
              f"conviene arreglarlos, pero no bloquean la instalación)")
    return fallos


ESCENARIOS = [
    # (nombre, issues existentes, [secretos, deps, antivirus, codigo], acción esperada)
    ("sin issue previa, todo correcto", [], ["success", "success", "success", "success"], "nada"),
    ("sin issue previa, hay hallazgos", [], ["failure", "success", "success", "success"], "create+open"),
    ("sin issue previa, capa cancelada", [], ["success", "cancelled", "success", "success"], "create+open"),
    ("issue previa, ya todo correcto", [{"number": 7, "title": "🔐 Estado del agente de seguridad"}],
     ["success", "success", "success", "success"], "update+closed"),
    ("issue previa, siguen hallazgos", [{"number": 7, "title": "🔐 Estado del agente de seguridad"}],
     ["failure", "failure", "success", "success"], "update+open"),
    ("issue previa, capa omitida", [{"number": 7, "title": "🔐 Estado del agente de seguridad"}],
     ["success", "skipped", "success", "success"], "update+open"),
]

ARNES = r"""
const ESCENARIOS = __ESCENARIOS__;
let fallos = 0;

for (const e of ESCENARIOS) {
  const acc = [];
  const github = { rest: { issues: {
    listForRepo: async () => ({ data: e.issues }),
    create: async (a) => { acc.push(['create', 'open', a.body]); },
    update: async (a) => { acc.push(['update', a.state, a.body]); },
  }}};
  const context = { repo: {owner:'o', repo:'r'}, serverUrl:'https://github.com',
                    runId: 1, sha: 'abcdef1234567890' };
  process.env.R_SECRETOS = e.r[0];
  process.env.R_DEPS     = e.r[1];
  process.env.R_AV       = e.r[2];
  process.env.R_CODIGO   = e.r[3];

  await (async function (github, context) {
__CUERPO__
  })(github, context);

  const got = acc.length === 0 ? 'nada' : acc[0][0] + '+' + acc[0][1];
  const ok = got === e.espera;
  if (!ok) fallos++;
  console.log(`[${ok ? 'OK  ' : 'FALLA'}] informe: ${e.n}: ${got} (esperado ${e.espera})`);

  // Invariante clave: si alguna capa no se ejecutó, el cuerpo debe decirlo.
  const sinVerificar = e.r.some(r => r !== 'success' && r !== 'failure');
  if (sinVerificar && acc.length) {
    const cuerpo = acc[0][2];
    const avisa = cuerpo.includes('NO VERIFICADO') && cuerpo.includes('no llegó a ejecutarse');
    if (!avisa) { fallos++; console.log('  [FALLA] una capa sin ejecutar no se advierte en el cuerpo'); }
    else console.log('  [OK  ] la capa sin ejecutar se marca como NO VERIFICADO');
  }
}
console.log(fallos === 0 ? 'INFORME: todas las pruebas pasan' : `INFORME: ${fallos} fallos`);
process.exit(fallos ? 1 : 0);
"""


def prueba_informe() -> int:
    doc = yaml.safe_load(open(os.path.join(WF, "agente-seguridad.yml")))
    js = doc["jobs"]["informe"]["steps"][0]["with"]["script"]

    datos = [{"n": n, "issues": i, "r": r, "espera": e} for n, i, r, e in ESCENARIOS]
    codigo = (
        ARNES.replace("__ESCENARIOS__", json.dumps(datos, ensure_ascii=False))
        .replace("__CUERPO__", textwrap.indent(js, "    "))
    )
    codigo = "(async () => {\n" + codigo + "\n})();"

    with tempfile.NamedTemporaryFile("w", suffix=".mjs", delete=False, encoding="utf-8") as f:
        f.write(codigo)
        ruta = f.name
    try:
        r = subprocess.run(["node", ruta], capture_output=True, text=True)
        print(r.stdout.strip() or r.stderr.strip()[:2000])
        return 0 if r.returncode == 0 else 1
    finally:
        os.unlink(ruta)


def main() -> int:
    fallos = prueba_yaml() + prueba_permisos() + prueba_informe()
    print()
    print("TODAS LAS PRUEBAS PASAN" if fallos == 0 else f"{fallos} PRUEBAS FALLAN")
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
