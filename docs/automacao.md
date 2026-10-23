# Rodando o monitor de forma automática

Um FIM só serve se for executado **regularmente** e se alguém **olhar o resultado**.
O código de saída (`0` ok, `1` mudanças, `3` baseline adulterado) existe para isso.

## Linux: cron

Verificação a cada hora, registrando só quando há mudança:

```cron
0 * * * * /usr/bin/python3 /opt/fim/monitor_integridade.py check --baseline /opt/fim/nginx.json >> /var/log/fim.log 2>&1 || logger -t fim "ALTERACAO DETECTADA"
```

## Linux: systemd timer

`/etc/systemd/system/fim.service`:

```ini
[Unit]
Description=Verificacao de integridade de arquivos

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/fim/monitor_integridade.py check --baseline /opt/fim/nginx.json
```

`/etc/systemd/system/fim.timer`:

```ini
[Unit]
Description=Roda o FIM a cada hora

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

Ative com `sudo systemctl enable --now fim.timer`. Quando o script sai com código
diferente de 0, o serviço aparece como *failed* em `systemctl --failed` e no journal.

## Windows: Agendador de Tarefas

```bat
schtasks /Create /SC HOURLY /TN "FIM" /TR "python C:\fim\monitor_integridade.py check --baseline C:\fim\site.json"
```

## Limitações (leia antes de confiar)

- **O checksum do baseline não é uma assinatura.** Ele detecta edição acidental ou
  descuidada, mas quem consegue reescrever o baseline *inteiro* também consegue
  recalcular o checksum. Guarde o baseline fora do alcance de quem você monitora
  (outro servidor, mídia somente leitura, ou assine com GPG/HMAC com chave separada).
- **O baseline deve ser criado num estado conhecido e limpo.** Se a pasta já estava
  comprometida, o baseline vai tratar isso como "normal".
- **Não é tempo real.** Ele compara fotos; uma alteração feita e revertida entre duas
  execuções passa despercebida. Ferramentas como `auditd`, `inotify` ou o OSSEC
  cobrem monitoramento contínuo.
- **Não monitora conteúdo de diretórios vazios, donos (uid/gid) nem atributos
  estendidos.** Só caminho, tipo, hash, tamanho e permissões.
- **Arquivos que mudam por natureza** (logs, caches, bancos) devem entrar em `--excluir`,
  senão geram falso positivo constante.
- Um invasor com acesso de root pode, em teoria, trocar o próprio script ou o Python.
  FIM é uma camada de detecção, não de prevenção.
