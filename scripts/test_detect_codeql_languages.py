#!/usr/bin/env python3
"""Pruebas reales de detect_codeql_languages.py, incluidos casos límite."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "detect_codeql_languages.py")


def build(root: str, files: list[str]) -> None:
    for f in files:
        p = os.path.join(root, f)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write("x\n")


def run(root: str) -> dict:
    out = subprocess.run(
        [sys.executable, SCRIPT, root], capture_output=True, text=True, check=True
    )
    return json.loads(out.stdout)


CASES: list[tuple[str, list[str], list[str]]] = [
    # (nombre, ficheros, lenguajes esperados)
    ("repo python + workflows", ["app/main.py", ".github/workflows/ci.yml"],
     ["actions", "python"]),
    ("repo poliglota", ["src/a.ts", "src/b.tsx", "api/s.go", "lib/x.rb"],
     ["go", "javascript-typescript", "ruby"]),
    # CASO LÍMITE 1: repo vacío -> empty=true, la matriz debe saltarse
    ("repo vacio", [], []),
    # CASO LÍMITE 2: sólo documentación -> ningún lenguaje
    ("solo docs", ["README.md", "docs/guia.txt", "LICENSE"], []),
    # CASO LÍMITE 3: dependencias de terceros NO deben contar como código propio
    ("node_modules ignorado", ["node_modules/left-pad/index.js", "vendor/x.go",
                               ".venv/lib/p.py", "README.md"], []),
    # CASO LÍMITE 4: sólo workflows -> únicamente "actions"
    ("solo workflows", [".github/workflows/deploy.yaml"], ["actions"]),
    # CASO LÍMITE 5: mayúsculas en la extensión
    ("extension en mayusculas", ["src/Main.PY"], ["python"]),
]


def main() -> int:
    fallos = 0
    for nombre, files, esperado in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            build(tmp, files)
            got = run(tmp)
            ok = sorted(got["languages"]) == sorted(esperado) and got["empty"] == (not esperado)
            print(f"[{'OK  ' if ok else 'FALLA'}] {nombre}: {got['languages']} (esperado {esperado})")
            if not ok:
                fallos += 1

    # CASO LÍMITE 6: ruta inexistente -> código de salida 1, sin traza
    r = subprocess.run([sys.executable, SCRIPT, "/no/existe/jamas"],
                       capture_output=True, text=True)
    ok = r.returncode == 1 and json.loads(r.stdout)["empty"] is True
    print(f"[{'OK  ' if ok else 'FALLA'}] ruta inexistente: rc={r.returncode}")
    if not ok:
        fallos += 1

    print(f"\n{'TODAS LAS PRUEBAS PASAN' if fallos == 0 else f'{fallos} PRUEBAS FALLAN'}")
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(main())
