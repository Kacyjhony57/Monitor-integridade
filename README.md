# monitor-integridade

![Testes](https://github.com/Kacyjhony57/monitor-integridade/actions/workflows/testes.yml/badge.svg)

Monitor de integridade de arquivos (**FIM**, *File Integrity Monitoring*) em Python, sem dependências.
Tira uma "foto" de uma pasta (hash SHA-256 de cada arquivo) e depois aponta o que foi **modificado, criado, removido** ou teve as **permissões alteradas**.

É a mesma ideia de ferramentas como Tripwire, AIDE e OSSEC, que detectam, por exemplo, uma página web adulterada, um `sshd_config` alterado ou um webshell plantado.

## Por que isso importa em segurança

- Atacantes alteram arquivos de configuração, binários e scripts para manter acesso (persistência).
- Detectar essa mudança rápido reduz o tempo entre o comprometimento e a resposta.
- O monitor ainda **detecta a adulteração do próprio baseline**: se alguém editar o arquivo para esconder uma mudança, o checksum não confere e o resultado é um alerta.

## Uso

```bash
# 1) tirar a foto de uma pasta (em estado conhecido e limpo)
python3 monitor_integridade.py init /etc/nginx --baseline nginx.json --excluir "*.log"

# 2) comparar depois
python3 monitor_integridade.py check --baseline nginx.json

# saída em JSON, para integrar com outras ferramentas
python3 monitor_integridade.py check --baseline nginx.json --json
```

| Código de saída | Significado |
|---|---|
| `0` | nenhuma alteração |
| `1` | alterações detectadas |
| `2` | erro de uso (pasta/baseline inexistente etc.) |
| `3` | baseline corrompido ou **adulterado** |

## Exemplo real de saída

Gerado por `bash exemplo/demo.sh`:

```text
### 1) Criando o baseline
Baseline criado: /tmp/demo/base.json (3 arquivo(s) em /tmp/demo/site)

### 2) Verificando sem mexer em nada
Verificando /tmp/demo/site
Baseline de 2026-10-23T15:05:42-03:00 com 3 arquivo(s)

Nenhuma alteração: 3 arquivo(s) íntegro(s).
(código de saída: 0)

### 3) Simulando um incidente

### 4) Verificando de novo
Verificando /tmp/demo/site
Baseline de 2026-10-23T15:05:42-03:00 com 3 arquivo(s)

[MODIFICADO] index.html
             sha256 e65b75a13425 -> 67f0765fe51c (19 -> 73 bytes)
[NOVO]       shell.php
[REMOVIDO]   config/app.conf
[PERMISSÃO]  config/usuarios.txt (0600 -> 0666)

Resumo: 1 modificado(s), 1 novo(s), 1 removido(s), 1 com permissão alterada.
(código de saída: 1)

### 5) Atacante tenta esconder a mudança editando o baseline
[ALERTA] o checksum do baseline NÃO confere: o arquivo foi alterado depois de criado.
Não confie neste baseline: recrie-o a partir de um estado conhecido e íntegro.
(código de saída: 3)
```

## Decisões de projeto

- **Leitura em blocos:** arquivos grandes não são carregados inteiros na memória.
- **Links simbólicos não são seguidos:** o próprio link e seu destino são monitorados, evitando sair da pasta alvo ou entrar em loop.
- **Arquivos ilegíveis viram aviso**, não derrubam a verificação.
- **Baseline fora da pasta monitorada** é ignorado automaticamente se estiver dentro dela.
- **Códigos de saída distintos** para facilitar cron, systemd e CI.

## Testes

```bash
python3 -m unittest discover -s tests -v
```

Cobrem: hash conhecido, mudança/novo/removido, permissões, baseline adulterado ou inválido, exclusões, saída JSON e links simbólicos. Rodam em Python 3.11, 3.12 e 3.13 via GitHub Actions.

## Automação e limitações

Veja [`docs/automacao.md`](docs/automacao.md) (cron, systemd timer, Agendador de Tarefas do Windows e o que esta ferramenta **não** faz).

## Uso ético

Use apenas em sistemas seus ou com autorização.

## Autor

**Kacy Jhony Rezende Parreiras**: estudante de Sistemas de Informação (PUC Minas), em formação em Segurança da Informação.
[LinkedIn](https://www.linkedin.com/in/kacy-jhony-5702b5302/) · [GitHub](https://github.com/Kacyjhony57)

## Licença

MIT
