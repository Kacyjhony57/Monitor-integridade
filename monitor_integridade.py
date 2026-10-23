#!/usr/bin/env python3
"""
monitor_integridade.py
----------------------
Monitor de integridade de arquivos (FIM, "File Integrity Monitoring").

Ideia: tirar uma "foto" (baseline) de uma pasta, guardando o hash SHA-256 de cada
arquivo, e depois comparar o estado atual com essa foto. Qualquer arquivo novo,
removido, modificado ou com permissões alteradas é reportado. É assim que
ferramentas como Tripwire, AIDE e OSSEC detectam adulteração em arquivos de
configuração, binários de sistema, scripts e páginas web.

Comandos:
  init   cria o baseline de uma pasta
  check  compara a pasta com o baseline e mostra as diferenças

Códigos de saída (úteis para agendar no cron ou integrar a outros sistemas):
  0  nenhuma alteração
  1  alterações detectadas
  2  erro de uso (pasta/baseline inexistente, arquivo já existe etc.)
  3  baseline corrompido ou ADULTERADO (checksum não confere)

Exemplos:
  python3 monitor_integridade.py init /etc/nginx --baseline nginx.json
  python3 monitor_integridade.py check --baseline nginx.json
  python3 monitor_integridade.py check --baseline nginx.json --json

Somente biblioteca padrão do Python 3 (testado em 3.11 a 3.13).
"""

import argparse
import fnmatch
import hashlib
import json
import os
import stat
import sys
from datetime import datetime

VERSAO_BASELINE = 1
TAMANHO_BLOCO = 1024 * 1024  # lê arquivos grandes em blocos de 1 MiB

COD_OK, COD_MUDANCAS, COD_ERRO, COD_ADULTERADO = 0, 1, 2, 3


# ------------------------------------------------------------------ hashes
def sha256_arquivo(caminho):
    """SHA-256 de um arquivo, lido em blocos (não carrega tudo na memória)."""
    h = hashlib.sha256()
    with open(caminho, "rb") as arquivo:
        for bloco in iter(lambda: arquivo.read(TAMANHO_BLOCO), b""):
            h.update(bloco)
    return h.hexdigest()


def sha256_texto(texto):
    return hashlib.sha256(texto.encode("utf-8", errors="surrogateescape")).hexdigest()


def checksum_entradas(arquivos):
    """Checksum do conjunto de entradas do baseline.

    Serve para detectar edição acidental ou maliciosa do arquivo de baseline.
    Limitação: quem consegue reescrever o baseline INTEIRO também consegue
    recalcular este checksum. Veja docs/automacao.md (guarde o baseline fora
    do alcance de quem você quer monitorar).
    """
    canonico = json.dumps(arquivos, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonico.encode("utf-8", errors="surrogateescape")).hexdigest()


# ------------------------------------------------------------- varredura
def _juntar(rel_dir, nome):
    return nome if not rel_dir else rel_dir + "/" + nome


def deve_excluir(rel, padroes):
    """True se o caminho relativo casa com algum padrão (estilo shell: *.log, .git, tmp/*)."""
    partes = rel.split("/")
    for padrao in padroes:
        if fnmatch.fnmatch(rel, padrao) or any(fnmatch.fnmatch(p, padrao) for p in partes):
            return True
    return False


def _mesmo_arquivo(a, b):
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def _entrada_link(caminho):
    destino = os.readlink(caminho)
    info = os.lstat(caminho)
    return {"tipo": "link", "sha256": sha256_texto(destino), "tamanho": len(destino),
            "modo": format(stat.S_IMODE(info.st_mode), "04o"), "destino": destino}


def coletar(pasta, excluir=(), ignorar=()):
    """Percorre a pasta e devolve ({caminho_relativo: metadados}, [avisos]).

    - Não segue links simbólicos: o próprio link (e seu destino) é monitorado.
    - Só calcula hash de arquivos regulares (ignora sockets, FIFOs etc.).
    - Arquivos ilegíveis viram avisos em vez de derrubar a execução.
    - 'ignorar' lista arquivos a pular (ex.: o próprio baseline).
    """
    raiz = os.path.abspath(pasta)
    arquivos, avisos = {}, []

    for diretorio, subpastas, nomes in os.walk(raiz, followlinks=False):
        rel_dir = os.path.relpath(diretorio, raiz)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")

        # Links para pastas: monitora o link, mas não desce neles.
        for sub in list(subpastas):
            caminho = os.path.join(diretorio, sub)
            rel = _juntar(rel_dir, sub)
            if os.path.islink(caminho) and not deve_excluir(rel, excluir):
                arquivos[rel] = _entrada_link(caminho)
        subpastas[:] = sorted(s for s in subpastas
                              if not deve_excluir(_juntar(rel_dir, s), excluir))

        for nome in sorted(nomes):
            rel = _juntar(rel_dir, nome)
            caminho = os.path.join(diretorio, nome)
            if deve_excluir(rel, excluir) or any(_mesmo_arquivo(caminho, i) for i in ignorar):
                continue
            try:
                info = os.lstat(caminho)
                if stat.S_ISLNK(info.st_mode):
                    arquivos[rel] = _entrada_link(caminho)
                elif stat.S_ISREG(info.st_mode):
                    arquivos[rel] = {"tipo": "arquivo", "sha256": sha256_arquivo(caminho),
                                     "tamanho": info.st_size,
                                     "modo": format(stat.S_IMODE(info.st_mode), "04o"),
                                     "mtime": int(info.st_mtime)}
            except OSError as erro:
                avisos.append(f"{rel}: não foi possível ler ({erro.strerror})")

    return arquivos, avisos


# ------------------------------------------------------------ comparação
def comparar(base, atual):
    """Compara dois dicionários de entradas e classifica as diferenças."""
    novos = sorted(set(atual) - set(base))
    removidos = sorted(set(base) - set(atual))
    modificados, permissoes = [], []
    for rel in sorted(set(base) & set(atual)):
        antes, depois = base[rel], atual[rel]
        if antes["sha256"] != depois["sha256"] or antes["tipo"] != depois["tipo"]:
            modificados.append({"arquivo": rel,
                                "antes": antes["sha256"], "depois": depois["sha256"],
                                "tamanho_antes": antes["tamanho"], "tamanho_depois": depois["tamanho"]})
        elif antes["modo"] != depois["modo"]:
            permissoes.append({"arquivo": rel, "antes": antes["modo"], "depois": depois["modo"]})
    return {"novos": novos, "removidos": removidos,
            "modificados": modificados, "permissoes": permissoes}


def total_mudancas(diff):
    return sum(len(v) for v in diff.values())


# --------------------------------------------------------------- comandos
def cmd_init(args):
    if not os.path.isdir(args.pasta):
        print(f"Erro: '{args.pasta}' não é uma pasta.", file=sys.stderr)
        return COD_ERRO
    if os.path.exists(args.baseline) and not args.forcar:
        print(f"Erro: '{args.baseline}' já existe. Use --forcar para sobrescrever "
              "(isso aceita o estado atual como o novo normal).", file=sys.stderr)
        return COD_ERRO

    arquivos, avisos = coletar(args.pasta, args.excluir, ignorar=[args.baseline])
    dados = {
        "versao": VERSAO_BASELINE,
        "pasta": os.path.abspath(args.pasta),
        "criado_em": datetime.now().astimezone().isoformat(timespec="seconds"),
        "algoritmo": "sha256",
        "excluir": list(args.excluir),
        "arquivos": arquivos,
        "checksum": checksum_entradas(arquivos),
    }
    with open(args.baseline, "w", encoding="utf-8") as saida:
        json.dump(dados, saida, indent=2, ensure_ascii=False)

    print(f"Baseline criado: {args.baseline} ({len(arquivos)} arquivo(s) em {dados['pasta']})")
    for aviso in avisos:
        print(f"[AVISO] {aviso}")
    return COD_OK


def carregar_baseline(caminho):
    """Lê e valida o baseline. Lança ValueError se corrompido/adulterado."""
    with open(caminho, "r", encoding="utf-8") as arquivo:
        try:
            dados = json.load(arquivo)
        except json.JSONDecodeError as erro:
            raise ValueError(f"baseline não é um JSON válido ({erro})")
    if not isinstance(dados, dict) or not isinstance(dados.get("arquivos"), dict) or "checksum" not in dados:
        raise ValueError("baseline com formato inesperado")
    if checksum_entradas(dados["arquivos"]) != dados["checksum"]:
        raise ValueError("o checksum do baseline NÃO confere: o arquivo foi alterado depois de criado")
    return dados


def cmd_check(args):
    try:
        dados = carregar_baseline(args.baseline)
    except FileNotFoundError:
        print(f"Erro: baseline '{args.baseline}' não encontrado. Rode 'init' primeiro.", file=sys.stderr)
        return COD_ERRO
    except ValueError as erro:
        print(f"[ALERTA] {erro}.", file=sys.stderr)
        print("Não confie neste baseline: recrie-o a partir de um estado conhecido e íntegro.", file=sys.stderr)
        return COD_ADULTERADO

    pasta = args.pasta or dados["pasta"]
    if not os.path.isdir(pasta):
        print(f"Erro: '{pasta}' não é uma pasta.", file=sys.stderr)
        return COD_ERRO

    excluir = list(dados.get("excluir", [])) + list(args.excluir)
    atual, avisos = coletar(pasta, excluir, ignorar=[args.baseline])
    diff = comparar(dados["arquivos"], atual)
    n = total_mudancas(diff)

    if args.json:
        print(json.dumps({"pasta": os.path.abspath(pasta), "baseline_criado_em": dados.get("criado_em"),
                          "arquivos_no_baseline": len(dados["arquivos"]), "arquivos_atuais": len(atual),
                          "total_mudancas": n, "mudancas": diff, "avisos": avisos},
                         ensure_ascii=False, indent=2))
    else:
        imprimir_relatorio(pasta, dados, atual, diff, avisos)
    return COD_MUDANCAS if n else COD_OK


def imprimir_relatorio(pasta, dados, atual, diff, avisos):
    print(f"Verificando {os.path.abspath(pasta)}")
    print(f"Baseline de {dados.get('criado_em', '?')} com {len(dados['arquivos'])} arquivo(s)\n")

    for item in diff["modificados"]:
        print(f"[MODIFICADO] {item['arquivo']}")
        print(f"             sha256 {item['antes'][:12]} -> {item['depois'][:12]} "
              f"({item['tamanho_antes']} -> {item['tamanho_depois']} bytes)")
    for rel in diff["novos"]:
        print(f"[NOVO]       {rel}")
    for rel in diff["removidos"]:
        print(f"[REMOVIDO]   {rel}")
    for item in diff["permissoes"]:
        print(f"[PERMISSÃO]  {item['arquivo']} ({item['antes']} -> {item['depois']})")
    for aviso in avisos:
        print(f"[AVISO]      {aviso}")

    n = total_mudancas(diff)
    if n:
        print(f"\nResumo: {len(diff['modificados'])} modificado(s), {len(diff['novos'])} novo(s), "
              f"{len(diff['removidos'])} removido(s), {len(diff['permissoes'])} com permissão alterada.")
    else:
        print(f"Nenhuma alteração: {len(atual)} arquivo(s) íntegro(s).")


# ------------------------------------------------------------------- CLI
def montar_parser():
    parser = argparse.ArgumentParser(
        description="Monitor de integridade de arquivos: cria um baseline (SHA-256) e detecta alterações.")
    sub = parser.add_subparsers(dest="comando", required=True)

    p_init = sub.add_parser("init", help="cria o baseline de uma pasta")
    p_init.add_argument("pasta", help="pasta a monitorar")
    p_init.add_argument("--baseline", default="baseline_integridade.json",
                        help="arquivo de baseline (padrão: baseline_integridade.json)")
    p_init.add_argument("--excluir", action="append", default=[], metavar="PADRAO",
                        help="padrão a ignorar, ex.: '*.log' ou '.git' (pode repetir)")
    p_init.add_argument("--forcar", action="store_true", help="sobrescreve um baseline existente")
    p_init.set_defaults(funcao=cmd_init)

    p_check = sub.add_parser("check", help="compara a pasta com o baseline")
    p_check.add_argument("pasta", nargs="?", help="pasta a verificar (padrão: a do baseline)")
    p_check.add_argument("--baseline", default="baseline_integridade.json",
                         help="arquivo de baseline (padrão: baseline_integridade.json)")
    p_check.add_argument("--excluir", action="append", default=[], metavar="PADRAO",
                         help="padrões extras a ignorar nesta verificação")
    p_check.add_argument("--json", action="store_true", help="saída em JSON")
    p_check.set_defaults(funcao=cmd_check)
    return parser


def main(argv=None):
    args = montar_parser().parse_args(argv)
    return args.funcao(args)


if __name__ == "__main__":
    sys.exit(main())
