#!/usr/bin/env bash
# Instalador do Goldani Scanner (web-vuln-scanner): cria o venv, instala tudo e, se você quiser,
# já abre o menu interativo. Idempotente — pode rodar de novo para atualizar dependências.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Erro: python3 não encontrado. Instale o Python 3.10+ e rode este script de novo." >&2
    exit 1
fi

if [ ! -f pyproject.toml ]; then
    echo "Erro: rode este script de dentro do repositório clonado (pyproject.toml não encontrado)." >&2
    exit 1
fi

if [ ! -d .venv ]; then
    echo "==> Criando o ambiente virtual (.venv)..."
    python3 -m venv .venv
fi

echo "==> Instalando dependências..."
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -e . -q

echo
echo "Pronto! Para usar a partir de agora:"
echo "    source .venv/bin/activate"
echo "    goldani              # menu interativo"
echo "    wvs --help           # linha de comando completa"
echo

read -r -p "Abrir o menu interativo agora? [S/n] " resp || resp="n"
case "$resp" in
    [nN]*) ;;
    *) exec .venv/bin/goldani ;;
esac
