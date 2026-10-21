#!/usr/bin/env python3
"""Lista as permissões de privacidade concedidas no macOS, agrupadas por risco.

Sem argumentos, só imprime a lista. O app (Auditar Permissões.app) usa os modos:
  --candidatos   o que mudou desde a última vez e pode ser removido (uma por linha)
  --decidir ...  remove as escolhidas; as religadas não escolhidas passam a ser aceitas
  --relatorio    guarda a foto atual, registra o histórico e gera o relatório HTML

Lê os bancos do TCC; só altera permissões via tccutil, quando você escolhe.
Quem roda precisa de Acesso Total ao Disco.
"""
import datetime
import functools
import html
import json
import os
import sqlite3
import subprocess
import sys

BANCOS = [
    os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db"),
    "/Library/Application Support/com.apple.TCC/TCC.db",
]
DADOS = os.path.expanduser("~/Library/Application Support/Auditar Permissões")
ESTADO = os.path.join(DADOS, "estado.json")
HISTORICO = os.path.join(DADOS, "historico.jsonl")
RELATORIO = os.path.join(DADOS, "relatorio.html")

# serviço -> (nome em Ajustes, risco)
SERVICOS = {
    "kTCCServiceSystemPolicyAllFiles": ("Acesso Total ao Disco", "alto"),
    "kTCCServiceAccessibility": ("Acessibilidade", "alto"),
    "kTCCServiceListenEvent": ("Monitoramento de Entrada", "alto"),
    "kTCCServicePostEvent": ("Acessibilidade (controlar teclado/mouse)", "alto"),
    "kTCCServiceScreenCapture": ("Gravação de Tela e Áudio do Sistema", "alto"),
    "kTCCServiceEndpointSecurityClient": ("Segurança do sistema (antivírus)", "alto"),
    "kTCCServiceDeveloperTool": ("Ferramentas de Desenvolvedor", "alto"),
    "kTCCServiceAppleEvents": ("Automação", "medio"),
    "kTCCServicePhotos": ("Fotos", "medio"),
    "kTCCServicePhotosAdd": ("Fotos (só adicionar)", "medio"),
    "kTCCServiceAddressBook": ("Contatos", "medio"),
    "kTCCServiceCalendar": ("Calendários", "medio"),
    "kTCCServiceReminders": ("Lembretes", "medio"),
    "kTCCServiceLocation": ("Localização", "medio"),
    "kTCCServiceSystemPolicyAppBundles": ("Gerenciamento de Apps", "medio"),
    "kTCCServiceSystemPolicyAppData": ("Dados de Outros Apps", "medio"),
    "kTCCServiceMicrophone": ("Microfone", "baixo"),
    "kTCCServiceCamera": ("Câmera", "baixo"),
    "kTCCServiceAudioCapture": ("Áudio do Sistema", "baixo"),
    "kTCCServiceSpeechRecognition": ("Reconhecimento de Fala", "baixo"),
    "kTCCServiceBluetoothAlways": ("Bluetooth", "baixo"),
    "kTCCServiceMediaLibrary": ("Mídia e Apple Music", "baixo"),
    "kTCCServiceFocusStatus": ("Foco", "baixo"),
    "kTCCServiceSystemPolicyDesktopFolder": ("Arquivos: Mesa", "baixo"),
    "kTCCServiceSystemPolicyDocumentsFolder": ("Arquivos: Documentos", "baixo"),
    "kTCCServiceSystemPolicyDownloadsFolder": ("Arquivos: Downloads", "baixo"),
    "kTCCServiceSystemPolicyNetworkVolumes": ("Arquivos: Volumes de Rede", "baixo"),
    "kTCCServiceSystemPolicyRemovableVolumes": ("Arquivos: Volumes Removíveis", "baixo"),
    "kTCCServiceFileProviderDomain": ("Arquivos: iCloud Drive/OneDrive", "baixo"),
}
# Serviços internos de sincronização do iCloud: só barulho.
IGNORAR = {"kTCCServiceLiverpool", "kTCCServiceUbiquity"}

RISCOS = [
    ("alto", "🔴 ALTO RISCO: pode ver tudo, ler o que você digita ou controlar o Mac"),
    ("medio", "🟡 MÉDIO: acesso a dados pessoais ou a outros apps"),
    ("baixo", "🟢 BAIXO: confira se ainda usa o app"),
]
BOLINHA = {"alto": "🔴", "medio": "🟡", "baixo": "🟢"}

SEM_ACESSO = (
    "Sem acesso aos bancos de permissões.\n"
    "Dê Acesso Total ao Disco ao app que está rodando isto:\n"
    "Ajustes do Sistema → Privacidade e Segurança → Acesso Total ao Disco."
)


@functools.cache
def nome_app(client):
    if client.startswith("/"):
        return os.path.basename(client)
    try:
        caminho = subprocess.run(
            ["mdfind", f"kMDItemCFBundleIdentifier == '{client}'"],
            capture_output=True, text=True, timeout=10,
        ).stdout.split("\n")[0]
    except subprocess.TimeoutExpired:
        caminho = ""
    return os.path.basename(caminho).removesuffix(".app") if caminho else f"{client} (app não encontrado)"


def ler(banco):
    con = sqlite3.connect(f"file:{banco}?mode=ro", uri=True)
    try:
        return con.execute(
            "select service, client, indirect_object_identifier, last_modified "
            "from access where auth_value in (2, 3)"
        ).fetchall()
    finally:
        con.close()


def permissoes():
    """Permissões ligadas agora, por chave. Sai com aviso se não houver acesso."""
    itens = {}
    for banco in BANCOS:
        try:
            linhas = ler(banco)
        except sqlite3.DatabaseError:
            sys.exit(SEM_ACESSO)
        for servico, client, alvo, quando in linhas:
            if servico in IGNORAR:
                continue
            nome, risco = SERVICOS.get(servico, (servico.removeprefix("kTCCService"), "medio"))
            # Só na Automação o alvo diferencia uma permissão de outra.
            alvo = alvo if servico == "kTCCServiceAppleEvents" and alvo else ""
            if alvo:
                nome += f" → {nome_app(alvo)}"
            chave = f"{servico}|{client}|{alvo}"
            itens.setdefault(chave, {
                "servico": servico, "client": client, "nome": nome, "app": nome_app(client),
                "risco": risco,
                "desde": datetime.date.fromtimestamp(quando).isoformat() if quando else "?",
            })
    return itens


def carregar_estado():
    try:
        with open(ESTADO) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"ultima": None, "foto": {}, "removidas": {}}


def salvar_estado(estado):
    os.makedirs(DADOS, exist_ok=True)
    with open(ESTADO, "w") as f:
        json.dump(estado, f, ensure_ascii=False, indent=1)


def registrar(tipo, item):
    os.makedirs(DADOS, exist_ok=True)
    with open(HISTORICO, "a") as f:
        f.write(json.dumps({
            "quando": datetime.datetime.now().isoformat(timespec="seconds"), "tipo": tipo,
            "app": item["app"], "nome": item["nome"], "risco": item["risco"],
        }, ensure_ascii=False) + "\n")


def candidatos(atual, estado):
    """{rótulo: (motivo, [chaves])}: religadas e, fora a primeira vez, as novas."""
    saida = {}
    for chave, item in atual.items():
        if chave in estado["removidas"]:
            motivo = "religada"
        elif estado["ultima"] and chave not in estado["foto"]:
            motivo = "nova"
        else:
            continue
        rotulo = f"{BOLINHA[item['risco']]} {'Religada' if motivo == 'religada' else 'Nova'}: {item['app']} — {item['nome']}"
        saida.setdefault(rotulo, (motivo, []))[1].append(chave)
    return dict(sorted(saida.items(), key=lambda kv: (kv[1][0] != "religada", kv[0])))


def remover(item):
    """Desliga via tccutil. Ferramentas sem bundle id (caminho) não dá."""
    if item["client"].startswith("/"):
        return False
    r = subprocess.run(
        ["tccutil", "reset", item["servico"].removeprefix("kTCCService"), item["client"]],
        capture_output=True, text=True,
    )
    return r.returncode == 0


def cmd_candidatos():
    for rotulo in candidatos(permissoes(), carregar_estado()):
        print(rotulo)


def cmd_decidir(escolhidas):
    atual, estado = permissoes(), carregar_estado()
    agora = datetime.datetime.now().isoformat(timespec="seconds")
    for rotulo, (motivo, chaves) in candidatos(atual, estado).items():
        for chave in chaves:
            item = atual[chave]
            if motivo == "religada":
                registrar("religada", item)
            if rotulo not in escolhidas:
                if motivo == "religada":
                    estado["removidas"].pop(chave)
                    registrar("mantida", item)
            elif remover(item):
                estado["removidas"][chave] = {"quando": agora, **item}
                registrar("removida", item)
            else:
                registrar("falhou", item)
    salvar_estado(estado)


def cmd_relatorio():
    atual, estado = permissoes(), carregar_estado()
    anterior = estado["ultima"]
    if anterior is None:
        registrar("inicio", {"app": "", "nome": f"{len(atual)} permissões ligadas", "risco": "baixo"})
    else:
        for chave in atual.keys() - estado["foto"].keys():
            if chave not in estado["removidas"]:
                registrar("nova", atual[chave])
        for chave in estado["foto"].keys() - atual.keys():
            if chave not in estado["removidas"]:  # essas já entraram como "removida"
                registrar("saiu", estado["foto"][chave])
    estado["ultima"] = datetime.datetime.now().isoformat(timespec="seconds")
    estado["foto"] = atual
    salvar_estado(estado)

    with open(HISTORICO) as f:
        historico = [json.loads(l) for l in f if l.strip()]
    with open(RELATORIO, "w") as f:
        f.write(gerar_html(atual, estado, historico, anterior))
    print(RELATORIO)


# tipo do histórico -> (texto, classe de cor)
EVENTOS = {
    "inicio": ("PRIMEIRA VEZ", "info"),
    "removida": ("REMOVIDA", "ok"),
    "religada": ("RELIGADA", "perigo"),
    "mantida": ("ACEITA DE VOLTA", "neutro"),
    "nova": ("NOVA", "aviso"),
    "saiu": ("SAIU", "info"),
    "falhou": ("NÃO REMOVEU", "perigo"),
}


def data_br(iso):
    return datetime.datetime.fromisoformat(iso).strftime("%d/%m/%Y %H:%M")


def linha_log(e):
    texto, cor = EVENTOS.get(e["tipo"], (e["tipo"].upper(), "neutro"))
    app = f"<b>{html.escape(e['app'])}</b> — " if e["app"] else ""
    return (f'<div class="log {cor}"><span class="quando">{data_br(e["quando"])}</span>'
            f'<span class="tag">{texto}</span><span>{app}{html.escape(e["nome"])}</span></div>')


def gerar_html(atual, estado, historico, anterior):
    desta_vez = [e for e in historico if anterior is None or e["quando"] > anterior]
    ainda_religadas = [atual[c] for c in atual if c in estado["removidas"]]

    partes = []
    if ainda_religadas:
        itens = "".join(f"<li><b>{html.escape(i['app'])}</b> — {html.escape(i['nome'])}</li>" for i in ainda_religadas)
        partes.append(f'<div class="alerta">⚠️ Você tinha removido, e estão ligadas de novo:<ul>{itens}</ul>'
                      "Abra o app de novo para decidir.</div>")

    partes.append("<h2>O que mudou desde a última vez</h2>")
    if desta_vez:
        partes.append('<div class="logs">' + "".join(linha_log(e) for e in desta_vez) + "</div>")
    else:
        partes.append(f'<p class="vazio">Nada mudou desde {data_br(anterior)}. ✅</p>')

    partes.append("<h2>Ligadas agora</h2>")
    for risco, titulo in RISCOS:
        itens = sorted(atual.values(), key=lambda i: (i["nome"], i["app"]))
        itens = [i for i in itens if i["risco"] == risco]
        if not itens:
            continue
        linhas = "".join(
            f"<tr><td>{html.escape(i['nome'])}</td><td>{html.escape(i['app'])}</td><td>{i['desde']}</td></tr>"
            for i in itens
        )
        partes.append(f'<h3 class="{risco}">{titulo} ({len(itens)})</h3>'
                      f'<table class="{risco}"><tr><th>Permissão</th><th>App</th><th>Desde</th></tr>{linhas}</table>')

    removidas = sorted(estado["removidas"].values(), key=lambda i: i["quando"], reverse=True)
    if removidas:
        linhas = "".join(
            f"<tr><td>{html.escape(i['nome'])}</td><td>{html.escape(i['app'])}</td><td>{data_br(i['quando'])}</td></tr>"
            for i in removidas
        )
        partes.append(f"<h2>Você removeu ({len(removidas)})</h2>"
                      "<p class=\"vazio\">Se alguma voltar, o app avisa.</p>"
                      f'<table class="removidas"><tr><th>Permissão</th><th>App</th><th>Removida em</th></tr>{linhas}</table>')

    partes.append("<h2>Histórico</h2>")
    partes.append('<div class="logs">' + "".join(linha_log(e) for e in reversed(historico[-300:])) + "</div>")

    return PAGINA.format(hoje=datetime.datetime.now().strftime("%d/%m/%Y %H:%M"), corpo="\n".join(partes))


PAGINA = """<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Auditar Permissões</title>
<style>
:root {{ --fundo:#f6f6f4; --cartao:#fff; --texto:#1d1d1f; --suave:#6e6e73; --linha:#e3e3e0;
  --alto:#c62828; --medio:#a86b00; --baixo:#2e7d32; --info:#1565c0; --perigo-fundo:#fdecea; }}
@media (prefers-color-scheme: dark) {{ :root {{ --fundo:#161618; --cartao:#1f1f22; --texto:#ececec;
  --suave:#9a9aa0; --linha:#333338; --alto:#ff6b6b; --medio:#f5b342; --baixo:#5fd068; --info:#64a8ff;
  --perigo-fundo:#3a1c1c; }} }}
body {{ background:var(--fundo); color:var(--texto); font:15px/1.5 -apple-system, sans-serif;
  max-width:900px; margin:0 auto; padding:24px 16px 64px; }}
h1 {{ margin:0 }} .sub {{ color:var(--suave); margin:4px 0 24px }}
h2 {{ margin-top:36px; border-bottom:1px solid var(--linha); padding-bottom:6px }}
h3.alto {{ color:var(--alto) }} h3.medio {{ color:var(--medio) }} h3.baixo {{ color:var(--baixo) }}
table {{ width:100%; border-collapse:collapse; background:var(--cartao); border-radius:8px; overflow:hidden;
  border-left:4px solid var(--suave) }}
table.alto {{ border-left-color:var(--alto) }} table.medio {{ border-left-color:var(--medio) }}
table.baixo {{ border-left-color:var(--baixo) }} table.removidas {{ border-left-color:var(--baixo) }}
th, td {{ text-align:left; padding:6px 10px; border-bottom:1px solid var(--linha) }}
th {{ color:var(--suave); font-weight:500; font-size:13px }}
td:last-child, th:last-child {{ white-space:nowrap; color:var(--suave) }}
.logs {{ background:#111; color:#ddd; border-radius:8px; padding:12px; font:13px/1.7 ui-monospace, Menlo, monospace;
  overflow-x:auto }}
.log {{ display:flex; gap:12px; white-space:nowrap }}
.quando {{ color:#777 }} .tag {{ font-weight:700; min-width:15ch }}
.log.ok .tag {{ color:#5fd068 }} .log.perigo .tag {{ color:#ff6b6b }} .log.aviso .tag {{ color:#f5b342 }}
.log.info .tag {{ color:#64a8ff }} .log.neutro .tag {{ color:#aaa }}
.alerta {{ background:var(--perigo-fundo); border-left:4px solid var(--alto); padding:12px 16px; border-radius:8px }}
.vazio {{ color:var(--suave) }}
</style></head><body>
<h1>🔐 Auditar Permissões</h1>
<p class="sub">Verificado em {hoje} · Para desligar algo à mão: Ajustes do Sistema → Privacidade e Segurança</p>
{corpo}
</body></html>
"""


def main():
    if sys.argv[1:2] == ["--candidatos"]:
        return cmd_candidatos()
    if sys.argv[1:2] == ["--decidir"]:
        return cmd_decidir(set(sys.argv[2:]))
    if sys.argv[1:2] == ["--relatorio"]:
        return cmd_relatorio()

    grupos = {r: [] for r, _ in RISCOS}
    for item in permissoes().values():
        grupos[item["risco"]].append((item["nome"], item["app"], item["desde"]))

    print(f"Permissões concedidas em {datetime.date.today():%d/%m/%Y}\n")
    for risco, titulo in RISCOS:
        itens = sorted(grupos[risco])
        if not itens:
            continue
        print(titulo)
        largura = max(len(n) for n, _, _ in itens)
        largura_app = max(len(a) for _, a, _ in itens)
        for nome, app, data in itens:
            print(f"  {nome:<{largura}}  {app:<{largura_app}}  desde {data}")
        print()
    print("Para desligar: Ajustes do Sistema → Privacidade e Segurança → [categoria].")


if __name__ == "__main__":
    main()
