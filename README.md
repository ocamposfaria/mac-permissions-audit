# mac-permissions-audit

Audita as permissões de privacidade do macOS (Acesso Total ao Disco, Acessibilidade,
Gravação de Tela, Automação, Microfone etc.), agrupadas por risco, e avisa o que mudou
desde a última vez.

## O app

**Auditar Permissões** (em Aplicativos). A cada abertura:

1. Compara com a última vez e lista numa janela as permissões **novas** e as **religadas**
   (que você tinha removido e voltaram). Marque as que quer remover.
2. Abre no navegador um relatório colorido: o que mudou, o que está ligado agora por risco,
   o que você já removeu e o histórico completo.

"Decidir depois" não remove nada. As novas não marcadas passam a contar como aceitas;
as religadas não marcadas saem da lista de removidas.

Na primeira vez o app pede **Acesso Total ao Disco** (sem isso o macOS não deixa ler os
bancos de permissões) e abre os Ajustes no lugar certo.

Os dados ficam em `~/Library/Application Support/Auditar Permissões/`
(`estado.json`, `historico.jsonl`, `relatorio.html`).

## Montar / atualizar o app

    ./build.sh

Instala em `/Applications/Auditar Permissões.app`. Depois de remontar, o macOS trata como
app novo: ligue de novo o Acesso Total ao Disco para ele.

## Sem o app

    python3 -I audit.py

Só imprime a lista atual. Quem roda (Terminal, VS Code) precisa de Acesso Total ao Disco.

## Leitura

- 🔴 **Alto**: o app pode ver todos os arquivos, ler o que você digita ou controlar o Mac.
- 🟡 **Médio**: acesso a dados pessoais (Fotos, Contatos, Lembretes) ou a outros apps (Automação).
- 🟢 **Baixo**: câmera, microfone, pastas. Só confira se ainda usa o app.
- "app não encontrado": o app provavelmente foi desinstalado e a permissão ficou para trás.

Remover usa o `tccutil` da Apple, que só funciona com apps que ainda existem no Mac.
Serviços internos de sincronização do iCloud (`Liverpool`, `Ubiquity`) são ignorados.
