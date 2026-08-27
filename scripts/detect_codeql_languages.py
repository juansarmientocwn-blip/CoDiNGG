#!/usr/bin/env python3
"""
Detecta qué lenguajes soporta CodeQL en un repositorio y emite la matriz
que consume el workflow .github/workflows/codeql.yml

Uso:
    python3 scripts/detect_codeql_languages.py [ruta_repo]

Salida (stdout): JSON  ->  {"languages": ["python", "actions"], "empty": false}

No depende de la API de GitHub ni de ningún token: sólo del árbol de ficheros.
Así el mismo script se puede ejecutar en local y en CI con idéntico resultado.
"""
from __future__ import annotations

import json
import os
import sys

# Extensión -> lenguaje CodeQL (nombres oficiales aceptados por codeql-action/init)
EXT_TO_LANG: dict[str, str] = {
    ".js": "javascript-typescript",
    ".jsx": "javascript-typescript",
    ".mjs": "javascript-typescript",
    ".cjs": "javascript-typescript",
    ".ts": "javascript-typescript",
    ".tsx": "javascript-typescript",
    ".vue": "javascript-typescript",
    ".py": "python",
    ".java": "java-kotlin",
    ".kt": "java-kotlin",
    ".kts": "java-kotlin",
    ".go": "go",
    ".rb": "ruby",
    ".cs": "csharp",
    ".c": "c-cpp",
    ".cc": "c-cpp",
    ".cpp": "c-cpp",
    ".cxx": "c-cpp",
    ".h": "c-cpp",
    ".hpp": "c-cpp",
    ".swift": "swift",
    ".rs": "rust",
}

# Directorios que nunca son código propio del repositorio.
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "out", "target",
    ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    ".next", ".nuxt", ".gradle", ".idea", ".secops", "third_party",
}

# Nº mínimo de ficheros de un lenguaje para incluirlo. Evita que un único
# script suelto dispare un análisis completo (y lento) de ese lenguaje.
MIN_FILES = 1


def detect(root: str) -> dict:
    counts: dict[str, int] = {}
    has_workflows = False

    for dirpath, dirnames, filenames in os.walk(root):
        # Ojo: filtrar por prefijo ".git" excluiría también ".github". Sólo el
        # directorio ".git" exacto se descarta (ya está en SKIP_DIRS).
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
        in_workflows = rel == ".github/workflows" or rel.endswith("/.github/workflows")

        for name in filenames:
            if in_workflows and name.endswith((".yml", ".yaml")):
                has_workflows = True
            ext = os.path.splitext(name)[1].lower()
            lang = EXT_TO_LANG.get(ext)
            if lang:
                counts[lang] = counts.get(lang, 0) + 1

    languages = sorted(l for l, n in counts.items() if n >= MIN_FILES)

    # "actions" analiza los propios workflows (inyección de comandos, pull_request_target
    # mal usado, expresiones ${{ }} peligrosas...). Es el lenguaje que protege al agente
    # de seguridad de sí mismo, así que se añade siempre que haya workflows.
    if has_workflows and "actions" not in languages:
        languages.append("actions")

    return {"languages": languages, "empty": len(languages) == 0}


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    if not os.path.isdir(root):
        print(json.dumps({"languages": [], "empty": True, "error": f"no existe: {root}"}))
        return 1
    print(json.dumps(detect(root)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
