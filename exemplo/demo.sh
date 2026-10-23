#!/usr/bin/env bash
# Demonstração: cria uma pasta de teste, tira o baseline, "ataca" a pasta e verifica.
# Uso: bash exemplo/demo.sh
set -u
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/site/config"
echo "ServerName exemplo.local"      > "$TMP/site/config/app.conf"
echo "<h1>Bem-vindo</h1>"            > "$TMP/site/index.html"
echo "admin:senha-forte"             > "$TMP/site/config/usuarios.txt"
chmod 600 "$TMP/site/config/usuarios.txt"

echo "### 1) Criando o baseline"
python3 "$RAIZ/monitor_integridade.py" init "$TMP/site" --baseline "$TMP/base.json"

echo; echo "### 2) Verificando sem mexer em nada"
python3 "$RAIZ/monitor_integridade.py" check --baseline "$TMP/base.json"
echo "(código de saída: $?)"

echo; echo "### 3) Simulando um incidente"
echo '<script src="http://malicioso.example/x.js"></script>' >> "$TMP/site/index.html"
echo '<?php system($_GET["c"]); ?>'                          > "$TMP/site/shell.php"
rm "$TMP/site/config/app.conf"
chmod 666 "$TMP/site/config/usuarios.txt"

echo; echo "### 4) Verificando de novo"
python3 "$RAIZ/monitor_integridade.py" check --baseline "$TMP/base.json"
echo "(código de saída: $?)"

echo; echo "### 5) Atacante tenta esconder a mudança editando o baseline"
sed -i "0,/\"sha256\": \"[0-9a-f]*\"/s//\"sha256\": \"$(printf '0%.0s' {1..64})\"/" "$TMP/base.json"
python3 "$RAIZ/monitor_integridade.py" check --baseline "$TMP/base.json"
echo "(código de saída: $?)"
