"""Ética em Ação — site institucional + Canal de Denúncias (Flask + SQLite, tudo neste arquivo).

Rodar local:   pip install -r requirements.txt && python app.py      (http://localhost:5000)
Produção:      gunicorn app:app   (Dockerfile já pronto)

Variáveis de ambiente (Dokploy > Environment):
    SECRET_KEY    chave longa aleatória (se vazia, é gerada e guardada em /data/.secret_key)
    ADMIN_USER    usuário do painel
    ADMIN_PASS    senha do painel
    DATA_DIR      pasta do volume (padrão /data) -> banco em /data/etica.db, imagens em /data/uploads
    WHATSAPP      ex.: 5511999999999 (opcional; se vazio o botão some)
    COOKIE_SECURE 1 (padrão) / 0 para testar em http puro

O templates/index.html é o SEU arquivo, sem alterações: as páginas internas (blog, canal, painel)
herdam automaticamente o mesmo CSS, topo e rodapé dele.
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
import unicodedata
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (Flask, Response, abort, g, redirect, render_template, request,
                   send_file, session, url_for, jsonify)
from jinja2 import ChoiceLoader, DictLoader
from markupsafe import Markup, escape
from PIL import Image, ImageOps
from werkzeug.middleware.proxy_fix import ProxyFix

# ═══ CONFIG ════════════════════════════════════════════════════════════════
BASE = Path(__file__).resolve().parent


def _data_dir():
    d = Path(os.environ.get("DATA_DIR", "/data"))
    try:
        d.mkdir(parents=True, exist_ok=True)
        if os.access(d, os.W_OK):
            return d
    except OSError:
        pass
    d = BASE / "data"
    d.mkdir(exist_ok=True)
    return d


DATA = _data_dir()
UP = DATA / "uploads"
CACHE = UP / "cache"
CACHE.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DATA / "etica.db")


def _secret():
    k = os.environ.get("SECRET_KEY", "").strip()
    if k:
        return k
    f = DATA / ".secret_key"
    if f.exists():
        return f.read_text().strip()
    k = secrets.token_hex(32)
    f.write_text(k)
    return k


app = Flask(__name__, static_folder=None, template_folder=str(BASE / "templates"))
app.secret_key = _secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") != "0",
    PERMANENT_SESSION_LIFETIME=12 * 3600, MAX_CONTENT_LENGTH=20 * 1024 * 1024)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

ADMIN_USER = os.environ.get("ADMIN_USER", "").strip()
ADMIN_PASS = os.environ.get("ADMIN_PASS", "")
WHATSAPP = re.sub(r"\D", "", os.environ.get("WHATSAPP", ""))

STATUS = ["Recebida", "Em análise", "Em apuração", "Concluída"]
CATEGORIAS = ["Assédio moral ou sexual", "Fraude ou corrupção", "Conflito de interesses",
              "Discriminação", "Violação de dados / LGPD", "Descumprimento de políticas", "Outro"]
SLOTS = {
    "logo": "Logo (topo e rodapé)",
    "hero": "Imagem do topo (hero)",
    "fundo": "Fundo da seção “Por que escolher”",
    "canal": "Foto da seção Canal de Denúncias",
    "fundadora": "Foto da seção Quem somos",
    "og": "Imagem de compartilhamento (opcional)",
}
SLOT_RE = re.compile(r"^[a-z0-9-]{1,40}$")

# ═══ BANCO (SQLite no volume) ══════════════════════════════════════════════
SCHEMA = """
CREATE TABLE IF NOT EXISTS denuncias(
  id INTEGER PRIMARY KEY AUTOINCREMENT, protocolo TEXT UNIQUE NOT NULL, anonima INTEGER NOT NULL DEFAULT 1,
  nome TEXT, contato TEXT, categoria TEXT, relato TEXT NOT NULL, data_fato TEXT, local TEXT, envolvidos TEXT,
  status TEXT NOT NULL DEFAULT 'Recebida', resposta TEXT, criado_em TEXT NOT NULL, atualizado_em TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS leads(
  id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT, email TEXT, interesse TEXT, mensagem TEXT, pagina TEXT,
  referrer TEXT, utm_source TEXT, utm_medium TEXT, utm_campaign TEXT, ip TEXT,
  atendido INTEGER NOT NULL DEFAULT 0, criado_em TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS posts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, titulo TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, resumo TEXT,
  corpo TEXT NOT NULL DEFAULT '', publicado INTEGER NOT NULL DEFAULT 0, publicado_em TEXT, criado_em TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS hits(chave TEXT NOT NULL, ts REAL NOT NULL);
CREATE INDEX IF NOT EXISTS ix_hits ON hits(chave, ts);
"""


def agora():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def conectar():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=10000")
    return c


def db():
    if "db" not in g:
        g.db = conectar()
    return g.db


@app.teardown_appcontext
def _fechar(_):
    c = g.pop("db", None)
    if c:
        c.close()


def init_db():
    c = conectar()
    c.executescript(SCHEMA)
    c.commit()
    c.close()


init_db()

# ═══ UTILS ═════════════════════════════════════════════════════════════════
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


def limpar(v, n=500):
    v = re.sub(r"<[^>]*>", "", str(v or ""))
    v = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", v).strip()
    return v[:n]


def slugify(t):
    t = unicodedata.normalize("NFKD", str(t or "")).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-")[:80].strip("-") or "post"


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


def check_csrf():
    if not hmac.compare_digest(request.form.get("_csrf", ""), session.get("_csrf", "x")):
        abort(400, "Sessão expirada. Volte e tente novamente.")


def excedido(acao, maximo, janela):
    """Rate limit persistente (vale entre workers). Retorna True se passou do limite."""
    ip = request.remote_addr or "0"
    chave = acao + ":" + hashlib.sha256((ip + app.secret_key).encode()).hexdigest()[:16]
    t = time.time()
    d = db()
    d.execute("DELETE FROM hits WHERE ts<?", (t - 86400,))
    n = d.execute("SELECT COUNT(*) FROM hits WHERE chave=? AND ts>?", (chave, t - janela)).fetchone()[0]
    if n >= maximo:
        return True
    d.execute("INSERT INTO hits VALUES(?,?)", (chave, t))
    d.commit()
    return False


def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("adm"):
            return redirect("/admin/login")
        return f(*a, **k)
    return w


def novo_protocolo():
    alfabeto = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    while True:
        p = "EA-" + "".join(secrets.choice(alfabeto) for _ in range(8))
        if not db().execute("SELECT 1 FROM denuncias WHERE protocolo=?", (p,)).fetchone():
            return p


# ═══ IMAGENS (volume /data/uploads, por "slots") ═══════════════════════════
def slot_path(slot):
    return UP / (slot + ".webp")


def salvar_imagem(slot, arq):
    try:
        img = Image.open(arq)
        img = ImageOps.exif_transpose(img)
        img = img.convert("RGBA" if img.mode in ("RGBA", "LA", "P") else "RGB")
        img.thumbnail((2400, 2400))
        img.save(slot_path(slot), "WEBP", quality=85)
    except Exception:
        return False
    for f in CACHE.glob(slot + "-*.webp"):
        f.unlink(missing_ok=True)
    return True


def apagar_imagem(slot):
    slot_path(slot).unlink(missing_ok=True)
    for f in CACHE.glob(slot + "-*.webp"):
        f.unlink(missing_ok=True)


def tem_img(slot):
    return slot_path(slot).exists()


def img_url(slot, w=None):
    p = slot_path(slot)
    v = int(p.stat().st_mtime) if p.exists() else 0
    return "/midia/%s?v=%d%s" % (slot, v, "&w=%d" % w if w else "")


def img_abs(slot, w=None):
    return request.url_root.rstrip("/") + img_url(slot, w)


def capa_url(post, w=None):
    s = "capa-%d" % post["id"]
    return img_url(s, w) if tem_img(s) else ""


PLACEHOLDER = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 9"><rect width="16" height="9" fill="#e8e2d6"/></svg>')


@app.get("/midia/<slot>")
def midia(slot):
    if not SLOT_RE.match(slot):
        abort(404)
    p = slot_path(slot)
    if not p.exists():
        return Response(PLACEHOLDER, mimetype="image/svg+xml", headers={"Cache-Control": "no-cache"})
    w = request.args.get("w", type=int)
    cab = {"Cache-Control": "public, max-age=31536000, immutable" if request.args.get("v") else "public, max-age=3600"}
    if w and 100 <= w <= 2400:
        v = CACHE / ("%s-%d.webp" % (slot, w))
        if not v.exists():
            with Image.open(p) as im:
                if im.width > w:
                    im = im.resize((w, int(im.height * w / im.width)), Image.LANCZOS)
                im.save(v, "WEBP", quality=82)
        p = v
    r = send_file(p, mimetype="image/webp")
    r.headers.update(cab)
    return r


# ═══ HELPERS DE TEMPLATE ═══════════════════════════════════════════════════
@app.context_processor
def _ctx():
    return dict(
        canonical_url=lambda: request.url_root.rstrip("/") + request.path,
        img_url=img_url, img_abs=img_abs, tem_img=tem_img, capa_url=capa_url,
        whatsapp_link=lambda t="": ("https://wa.me/%s?text=%s" % (WHATSAPP, __import__("urllib.parse").parse.quote(t))) if WHATSAPP else "",
        blog_url="/blog",
        csrf_input=lambda: Markup('<input type="hidden" name="_csrf" value="%s">' % csrf_token()),
        STATUS=STATUS, CATEGORIAS=CATEGORIAS, SLOTS=SLOTS)


@app.template_filter("data_br")
def data_br(v):
    try:
        return datetime.strptime(str(v)[:10], "%Y-%m-%d").strftime("%d/%m/%Y")
    except ValueError:
        return ""


@app.template_filter("dh")
def dh(v):
    try:
        return datetime.strptime(str(v)[:16], "%Y-%m-%d %H:%M").strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return ""


@app.template_filter("corpo")
def corpo(txt):
    out = []
    for b in re.split(r"\n\s*\n", (txt or "").strip()):
        b = b.strip()
        if not b:
            continue
        if b.startswith("## "):
            out.append("<h2>%s</h2>" % escape(b[3:]))
        else:
            out.append("<p>%s</p>" % str(escape(b)).replace("\n", "<br>"))
    return Markup("".join(out))


# ═══ LEAD.JS (servido em /static/lead.js) ══════════════════════════════════
LEAD_JS = r"""
document.addEventListener('submit',function(e){
  var f=e.target; if(!f.matches||!f.matches('[data-lead]'))return;
  e.preventDefault();
  var b=f.querySelector('button[type=submit]'),t=b?b.innerHTML:'';
  if(b){b.disabled=true;b.textContent='Enviando...';}
  var m=f.querySelector('.lead-msg');
  if(!m){m=document.createElement('p');m.className='lead-msg';m.style.cssText='margin:10px 0 0;font-size:13px;font-weight:700';f.appendChild(m);}
  fetch(f.action,{method:'POST',body:new FormData(f),headers:{'Accept':'application/json'}})
   .then(function(r){return r.json()})
   .then(function(d){m.style.color=d.ok?'#1d7a46':'#b3261e';m.textContent=d.msg;if(d.ok)f.reset();})
   .catch(function(){m.style.color='#b3261e';m.textContent='Não foi possível enviar. Tente novamente.';})
   .finally(function(){if(b){b.disabled=false;b.innerHTML=t;}});
});
"""


@app.get("/static/<path:filename>")
def static_files(filename):
    if filename == "lead.js":
        return Response(LEAD_JS, mimetype="application/javascript", headers={"Cache-Control": "public, max-age=3600"})
    abort(404)


# ═══ TEMPLATES DAS PÁGINAS INTERNAS (herdam CSS/topo/rodapé do index.html) ═
INT_CSS = """<style>
.x{padding:125px 0 70px;min-height:72vh;background:var(--paper)}
.x h1{font:clamp(30px,4vw,44px)/1.1 Georgia,serif;letter-spacing:-1px;margin:0 0 12px}.x h2{font:26px/1.2 Georgia,serif;margin:0 0 10px}.x h3{margin:0 0 8px}
.x p.lead{font-size:15px;line-height:1.7;color:var(--muted);max-width:720px;margin:0 0 26px}
.x-card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:24px;margin-bottom:20px}
.x-grid{display:grid;gap:20px;grid-template-columns:1fr 1fr;align-items:start}@media(max-width:820px){.x-grid{grid-template-columns:1fr}}
.x label{display:block;font-size:12px;font-weight:700;margin:13px 0 5px}
.x input:not([type=checkbox]):not([type=file]),.x select,.x textarea{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:8px;font:inherit;font-size:14px;background:#fff;color:var(--ink)}
.x textarea{min-height:140px;resize:vertical}.x .btn{cursor:pointer;margin-top:16px}
.x-check{display:flex;gap:9px;align-items:flex-start;font-weight:400!important;font-size:13px!important;line-height:1.5}.x-check input{margin-top:3px}
.x-alert{padding:12px 15px;border-radius:9px;font-size:13px;margin-bottom:18px;background:#fdecea;color:#8c1d18}.x-ok{background:#e7f5ec;color:#17603a}
.x table{width:100%;border-collapse:collapse;font-size:13px;background:#fff}.x th,.x td{padding:10px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.x th{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--muted)}
.x-pill{display:inline-block;padding:3px 10px;border-radius:20px;background:#f3ece0;font-size:11px;font-weight:700}
.x-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 20px}.x-tabs a{padding:9px 16px;border:1px solid var(--line);border-radius:22px;font-size:12px;font-weight:700;background:#fff}.x-tabs a.on{background:var(--orange);border-color:var(--orange);color:#fff}
.x-proto{font:700 34px Georgia,serif;letter-spacing:3px;color:var(--orange);margin:10px 0;word-break:break-all}
.x-art{max-width:760px;font-size:16px;line-height:1.8}.x-art h2{margin-top:30px}.x-scroll{overflow-x:auto}
.x-thumb{width:150px;height:90px;object-fit:contain;background:#eee;border-radius:8px;border:1px solid var(--line)}
</style>"""

T = {}
T["erro.html"] = """{% extends "base_int.html" %}{% block title %}Ops · Ética em Ação{% endblock %}
{% block c %}<div class="wrap"><h1>{{ msg }}</h1><p class="lead">Se precisar, volte para o início e tente de novo.</p><a class="btn" href="/">Voltar ao início</a></div>{% endblock %}"""

T["obrigado.html"] = """{% extends "base_int.html" %}{% block title %}Mensagem enviada · Ética em Ação{% endblock %}
{% block c %}<div class="wrap"><h1>Mensagem enviada!</h1><p class="lead">Recebemos o seu contato e retornaremos em breve.</p><a class="btn" href="/">Voltar ao início</a></div>{% endblock %}"""

T["privacidade.html"] = """{% extends "base_int.html" %}{% block title %}Política de Privacidade · Ética em Ação{% endblock %}
{% block c %}<div class="wrap"><h1>Política de Privacidade</h1><div class="x-art">
<p><strong>TEXTO-MODELO — deve ser revisado e validado por profissional habilitado antes da publicação.</strong></p>
<h2>1. Dados que coletamos</h2><p>Coletamos apenas os dados informados voluntariamente nos formulários do site (nome, e-mail, interesse e mensagem) e, no Canal de Denúncias, o relato e as informações que você decidir fornecer.</p>
<h2>2. Finalidade</h2><p>Os dados do formulário de contato são usados para retornar o seu contato. Os dados do Canal de Denúncias são usados exclusivamente para registrar, apurar e responder a denúncia.</p>
<h2>3. Anonimato no Canal de Denúncias</h2><p>Você pode registrar uma denúncia sem se identificar. Nesse caso, nome e contato não são gravados, nem o endereço de IP. O acompanhamento é feito apenas pelo número de protocolo.</p>
<h2>4. Compartilhamento e armazenamento</h2><p>Não vendemos nem compartilhamos seus dados com terceiros para fins comerciais. Os dados ficam armazenados em ambiente protegido pelo tempo necessário para cumprir as finalidades acima e obrigações legais.</p>
<h2>5. Seus direitos (LGPD)</h2><p>Você pode solicitar acesso, correção, anonimização ou exclusão dos seus dados pelo e-mail comercial@eticaemacao.com.br.</p>
</div></div>{% endblock %}"""

T["blog.html"] = """{% extends "base_int.html" %}{% block title %}Conteúdos · Ética em Ação{% endblock %}
{% block c %}<div class="wrap"><p class="eyebrow">Conteúdos</p><h1>Informação para decidir melhor.</h1>
<p class="lead">Artigos e materiais sobre Compliance, LGPD e governança corporativa.</p>
{% if posts %}<div class="posts">{% for p in posts %}<a class="post" href="/blog/{{ p.slug }}"><div class="post-capa"{% if capa_url(p, 800) %} style="background-image:url('{{ capa_url(p, 800) }}')"{% endif %}></div><div class="post-body"><small>{{ p.publicado_em|data_br }}</small><h3>{{ p.titulo }}</h3>{% if p.resumo %}<p>{{ p.resumo }}</p>{% endif %}</div></a>{% endfor %}</div>
{% else %}<p class="lead">Em breve, novos conteúdos por aqui.</p>{% endif %}</div>{% endblock %}"""

T["post.html"] = """{% extends "base_int.html" %}{% block title %}{{ p.titulo }} · Ética em Ação{% endblock %}
{% block head %}<meta name="description" content="{{ p.resumo or '' }}">{% endblock %}
{% block c %}<div class="wrap"><a href="/blog" style="font-size:12px;color:var(--orange);font-weight:700">← Todos os conteúdos</a>
<p class="eyebrow" style="margin-top:22px">{{ p.publicado_em|data_br }}</p><h1>{{ p.titulo }}</h1>
{% if capa_url(p, 1200) %}<img src="{{ capa_url(p, 1200) }}" alt="" style="width:100%;max-width:760px;border-radius:12px;margin:10px 0 24px">{% endif %}
<div class="x-art">{{ p.corpo|corpo }}</div></div>{% endblock %}"""

T["canal.html"] = """{% extends "base_int.html" %}{% block title %}Canal de Denúncias · Ética em Ação{% endblock %}
{% block head %}<meta name="robots" content="noindex">{% endblock %}
{% block c %}<div class="wrap"><p class="eyebrow">Canal de denúncias</p><h1>Sua voz importa.<br>Sua identidade é protegida.</h1>
<p class="lead">Relate situações que precisam ser apuradas. Você pode se identificar ou permanecer anônimo, e acompanhar o andamento apenas com o número de protocolo.</p>
{% if erro %}<div class="x-alert">{{ erro }}</div>{% endif %}
<div class="x-grid">
<div class="x-card" id="registrar"><h2>Registrar uma denúncia</h2>
<form method="post" action="/canal-de-denuncias/enviar" autocomplete="off">{{ csrf_input() }}
<label for="c-cat">Categoria</label><select id="c-cat" name="categoria">{% for c in CATEGORIAS %}<option>{{ c }}</option>{% endfor %}</select>
<label for="c-rel">Relato *</label><textarea id="c-rel" name="relato" required maxlength="5000" placeholder="Descreva o que aconteceu com o máximo de detalhes possível."></textarea>
<label for="c-dt">Quando aconteceu?</label><input id="c-dt" name="data_fato" maxlength="60" placeholder="Ex.: mês passado, 10/10/2026">
<label for="c-lo">Onde aconteceu?</label><input id="c-lo" name="local" maxlength="200">
<label for="c-en">Pessoas envolvidas</label><input id="c-en" name="envolvidos" maxlength="300">
<label class="x-check"><input type="checkbox" name="anonima" value="1" checked id="c-an" onchange="document.getElementById('c-id').style.display=this.checked?'none':'block'"><span>Quero permanecer anônimo(a). Nome e contato não serão gravados.</span></label>
<div id="c-id" style="display:none"><label for="c-no">Seu nome</label><input id="c-no" name="nome" maxlength="120"><label for="c-co">E-mail ou telefone para retorno</label><input id="c-co" name="contato" maxlength="150"></div>
<div class="hp" aria-hidden="true"><label>Não preencha<input name="website" tabindex="-1" autocomplete="off"></label></div>
<button class="btn" type="submit">Enviar denúncia <span>→</span></button></form></div>
<div class="x-card" id="acompanhar"><h2>Acompanhar uma denúncia</h2><p style="font-size:14px;line-height:1.6;color:var(--muted)">Informe o protocolo que você recebeu ao registrar.</p>
<form method="post" action="/canal-de-denuncias/consultar" autocomplete="off">{{ csrf_input() }}
<label for="c-pr">Protocolo</label><input id="c-pr" name="protocolo" required maxlength="20" placeholder="EA-XXXXXXXX" value="{{ protocolo or '' }}">
<button class="btn" type="submit">Consultar <span>→</span></button></form>
{% if d %}<div style="margin-top:22px;border-top:1px solid var(--line);padding-top:16px"><p style="margin:0 0 6px;font-size:12px;color:var(--muted)">Protocolo {{ d.protocolo }}</p>
<p style="margin:0 0 10px"><span class="x-pill">{{ d.status }}</span></p>
<p style="font-size:13px;margin:0 0 6px">Registrada em {{ d.criado_em|dh }} · Atualizada em {{ d.atualizado_em|dh }}</p>
{% if d.resposta %}<h3 style="margin-top:14px">Resposta</h3><p style="font-size:14px;line-height:1.6">{{ d.resposta }}</p>{% else %}<p style="font-size:14px;color:var(--muted)">Ainda não há resposta final. Consulte novamente mais tarde.</p>{% endif %}</div>{% endif %}
</div></div></div>{% endblock %}"""

T["protocolo.html"] = """{% extends "base_int.html" %}{% block title %}Denúncia registrada · Ética em Ação{% endblock %}
{% block head %}<meta name="robots" content="noindex">{% endblock %}
{% block c %}<div class="wrap"><h1>Denúncia registrada</h1><div class="x-card" style="max-width:640px"><p>Guarde o seu número de protocolo. <strong>Ele é a única forma de acompanhar a denúncia e não poderá ser recuperado.</strong></p>
<div class="x-proto">{{ protocolo }}</div><a class="btn" href="/canal-de-denuncias?p={{ protocolo }}#acompanhar">Acompanhar agora <span>→</span></a></div></div>{% endblock %}"""

T["admin_login.html"] = """{% extends "base_int.html" %}{% block title %}Entrar · Painel{% endblock %}
{% block head %}<meta name="robots" content="noindex">{% endblock %}
{% block c %}<div class="wrap"><div class="x-card" style="max-width:420px;margin:auto"><h2>Painel administrativo</h2>
{% if erro %}<div class="x-alert">{{ erro }}</div>{% endif %}
<form method="post">{{ csrf_input() }}<label>Usuário</label><input name="u" required autocomplete="username"><label>Senha</label><input name="s" type="password" required autocomplete="current-password"><button class="btn" type="submit">Entrar</button></form></div></div>{% endblock %}"""

T["admin.html"] = """{% extends "base_int.html" %}{% block title %}Painel · Ética em Ação{% endblock %}
{% block head %}<meta name="robots" content="noindex">{% endblock %}
{% block c %}<div class="wrap"><div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap"><h1>Painel</h1><a class="btn outline" href="/admin/sair" style="margin:0">Sair</a></div>
{% if msg %}<div class="x-alert x-ok">{{ msg }}</div>{% endif %}
<div class="x-tabs">{% for k,n in abas %}<a href="/admin?aba={{ k }}" class="{{ 'on' if aba==k }}">{{ n }}{% if cont[k] %} ({{ cont[k] }}){% endif %}</a>{% endfor %}</div>
{% if aba=='den' %}
<p style="font-size:13px">Filtrar: <a href="/admin?aba=den">Todas</a>{% for s in STATUS %} · <a href="/admin?aba=den&status={{ s }}">{{ s }}</a>{% endfor %}</p>
<div class="x-scroll"><table><tr><th>Protocolo</th><th>Data</th><th>Categoria</th><th>Identificação</th><th>Status</th><th></th></tr>
{% for d in itens %}<tr><td><strong>{{ d.protocolo }}</strong></td><td>{{ d.criado_em|dh }}</td><td>{{ d.categoria }}</td><td>{{ 'Anônima' if d.anonima else d.nome }}</td><td><span class="x-pill">{{ d.status }}</span></td><td><a href="/admin/denuncia/{{ d.id }}" style="color:var(--orange);font-weight:700">Abrir</a></td></tr>{% else %}<tr><td colspan="6">Nenhuma denúncia.</td></tr>{% endfor %}</table></div>
{% elif aba=='leads' %}
<div class="x-scroll"><table><tr><th>Data</th><th>Nome</th><th>E-mail</th><th>Interesse</th><th>Mensagem</th><th>Origem</th><th></th></tr>
{% for l in itens %}<tr><td>{{ l.criado_em|dh }}</td><td>{{ l.nome }}</td><td><a href="mailto:{{ l.email }}">{{ l.email }}</a></td><td>{{ l.interesse }}</td><td>{{ l.mensagem }}</td><td>{{ l.utm_source or l.referrer or '' }}</td>
<td><form method="post" action="/admin/lead/{{ l.id }}/atendido" style="margin:0">{{ csrf_input() }}<button class="x-pill" style="border:0;cursor:pointer">{{ 'Atendido ✓' if l.atendido else 'Marcar atendido' }}</button></form></td></tr>{% else %}<tr><td colspan="7">Nenhum contato.</td></tr>{% endfor %}</table></div>
{% elif aba=='posts' %}
<a class="btn" href="/admin/post/novo" style="margin:0 0 16px">+ Novo conteúdo</a>
<div class="x-scroll"><table><tr><th>Título</th><th>Status</th><th>Publicado em</th><th></th></tr>
{% for p in itens %}<tr><td>{{ p.titulo }}</td><td>{{ 'Publicado' if p.publicado else 'Rascunho' }}</td><td>{{ p.publicado_em|data_br }}</td><td><a href="/admin/post/{{ p.id }}" style="color:var(--orange);font-weight:700">Editar</a></td></tr>{% else %}<tr><td colspan="4">Nenhum conteúdo.</td></tr>{% endfor %}</table></div>
{% else %}
<p class="lead">Envie JPG, PNG ou WEBP. As imagens ficam no volume (/data/uploads) e são otimizadas automaticamente.</p>
<div class="x-grid">{% for k,n in SLOTS.items() %}<div class="x-card"><h3>{{ n }}</h3><img class="x-thumb" src="{{ img_url(k, 300) }}" alt="">
<form method="post" action="/admin/img/{{ k }}" enctype="multipart/form-data">{{ csrf_input() }}<input type="file" name="arq" accept="image/*" required><button class="btn" type="submit" style="margin-top:10px">Enviar</button></form>
{% if tem_img(k) %}<form method="post" action="/admin/img/{{ k }}/excluir" style="margin-top:8px">{{ csrf_input() }}<button class="x-pill" style="border:0;cursor:pointer">Remover</button></form>{% endif %}</div>{% endfor %}</div>
{% endif %}</div>{% endblock %}"""

T["admin_den.html"] = """{% extends "base_int.html" %}{% block title %}{{ d.protocolo }} · Painel{% endblock %}
{% block head %}<meta name="robots" content="noindex">{% endblock %}
{% block c %}<div class="wrap"><a href="/admin?aba=den" style="font-size:12px;color:var(--orange);font-weight:700">← Denúncias</a><h1 style="margin-top:14px">{{ d.protocolo }}</h1>
{% if msg %}<div class="x-alert x-ok">{{ msg }}</div>{% endif %}
<div class="x-grid"><div class="x-card"><p><span class="x-pill">{{ d.status }}</span> · {{ d.criado_em|dh }}</p><p><strong>Categoria:</strong> {{ d.categoria }}</p>
<p><strong>Identificação:</strong> {% if d.anonima %}Anônima{% else %}{{ d.nome }} — {{ d.contato }}{% endif %}</p>
<p><strong>Quando:</strong> {{ d.data_fato or '—' }}<br><strong>Onde:</strong> {{ d.local or '—' }}<br><strong>Envolvidos:</strong> {{ d.envolvidos or '—' }}</p>
<h3>Relato</h3><p style="white-space:pre-wrap;line-height:1.6">{{ d.relato }}</p></div>
<div class="x-card"><h3>Atualizar andamento</h3><form method="post">{{ csrf_input() }}<label>Status</label><select name="status">{% for s in STATUS %}<option{{ ' selected' if s==d.status }}>{{ s }}</option>{% endfor %}</select>
<label>Resposta ao denunciante (visível na consulta por protocolo)</label><textarea name="resposta" maxlength="3000">{{ d.resposta or '' }}</textarea><button class="btn" type="submit">Salvar</button></form></div></div></div>{% endblock %}"""

T["admin_post.html"] = """{% extends "base_int.html" %}{% block title %}Conteúdo · Painel{% endblock %}
{% block head %}<meta name="robots" content="noindex">{% endblock %}
{% block c %}<div class="wrap"><a href="/admin?aba=posts" style="font-size:12px;color:var(--orange);font-weight:700">← Conteúdos</a><h1 style="margin-top:14px">{{ 'Editar conteúdo' if p else 'Novo conteúdo' }}</h1>
{% if erro %}<div class="x-alert">{{ erro }}</div>{% endif %}
<form method="post" enctype="multipart/form-data" class="x-card" style="max-width:820px">{{ csrf_input() }}
<label>Título *</label><input name="titulo" required maxlength="200" value="{{ p.titulo if p else '' }}">
<label>Resumo (aparece nos cards)</label><input name="resumo" maxlength="300" value="{{ p.resumo if p and p.resumo else '' }}">
<label>Texto (separe parágrafos com linha em branco; use “## ” no início para subtítulo)</label><textarea name="corpo" style="min-height:300px">{{ p.corpo if p else '' }}</textarea>
<label>Imagem de capa</label>{% if p and tem_img('capa-%d'|format(p.id)) %}<img class="x-thumb" src="{{ img_url('capa-%d'|format(p.id), 300) }}" alt=""><br>{% endif %}<input type="file" name="capa" accept="image/*">
<label class="x-check"><input type="checkbox" name="publicado" value="1"{{ ' checked' if p and p.publicado }}><span>Publicado</span></label>
<button class="btn" type="submit">Salvar</button></form>
{% if p %}<form method="post" action="/admin/post/{{ p.id }}/excluir" onsubmit="return confirm('Excluir este conteúdo?')">{{ csrf_input() }}<button class="x-pill" style="border:0;cursor:pointer">Excluir conteúdo</button></form>{% endif %}</div>{% endblock %}"""


def _montar_base():
    """Gera o base_int.html a partir do SEU index.html (CSS, topo e rodapé), sem alterá-lo."""
    t = (BASE / "templates" / "index.html").read_text(encoding="utf-8")
    i, j = t.index("<main>"), t.index("</main>") + len("</main>")
    pre, pos = t[:i], t[j:]
    pre = re.sub(r"<title>.*?</title>", "<title>{% block title %}Ética em Ação{% endblock %}</title>", pre, flags=re.S)
    pre = pre.replace("</head>", INT_CSS + "{% block head %}{% endblock %}</head>", 1)
    return pre + '<main class="x">{% block c %}{% endblock %}</main>' + pos


T["base_int.html"] = _montar_base()
app.jinja_env.loader = ChoiceLoader([app.jinja_env.loader, DictLoader(T)])


# ═══ SEGURANÇA ═════════════════════════════════════════════════════════════
@app.after_request
def _headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "SAMEORIGIN"
    r.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if request.path.startswith(("/canal-de-denuncias", "/admin")):
        r.headers["Cache-Control"] = "no-store"
    return r


def erro(msg, code=400):
    return render_template("erro.html", msg=msg), code


@app.errorhandler(404)
def _404(_):
    return erro("Página não encontrada.", 404)


@app.errorhandler(400)
def _400(e):
    return erro(getattr(e, "description", "Requisição inválida."), 400)


@app.errorhandler(413)
def _413(_):
    return erro("Arquivo muito grande (máximo 20 MB).", 413)


# ═══ SITE PÚBLICO ══════════════════════════════════════════════════════════
def posts_publicados(limite=None):
    q = "SELECT * FROM posts WHERE publicado=1 ORDER BY publicado_em DESC, id DESC"
    return db().execute(q + (" LIMIT %d" % limite if limite else "")).fetchall()


@app.get("/")
def index():
    return render_template("index.html", posts_recentes=posts_publicados(3), blog_url="/blog")


@app.get("/solucoes")
def solucoes():
    return redirect("/#solucoes", 301)


@app.get("/quem-somos")
def quem_somos():
    return redirect("/#quem-somos", 301)


@app.get("/contato")
def contato():
    return redirect("/#contato", 301)


@app.get("/privacidade")
def privacidade():
    return render_template("privacidade.html")


@app.get("/blog")
def blog():
    return render_template("blog.html", posts=posts_publicados())


@app.get("/blog/<slug>")
def blog_post(slug):
    p = db().execute("SELECT * FROM posts WHERE slug=? AND publicado=1", (slug,)).fetchone()
    if not p:
        abort(404)
    return render_template("post.html", p=p)


@app.get("/obrigado")
def obrigado():
    return render_template("obrigado.html")


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /admin\nDisallow: /canal-de-denuncias/\n", mimetype="text/plain")


@app.post("/lead")
def lead():
    quer_json = "application/json" in request.headers.get("Accept", "")

    def resp(ok, msg, code=200):
        if quer_json:
            return jsonify(ok=ok, msg=msg), code
        return redirect("/obrigado") if ok else erro(msg, code)

    if request.form.get("website"):                       # honeypot: finge sucesso
        return resp(True, "Mensagem enviada!")
    if excedido("lead", 5, 600):
        return resp(False, "Muitas tentativas. Aguarde alguns minutos.", 429)
    nome, email = limpar(request.form.get("nome"), 120), limpar(request.form.get("email"), 254)
    if not nome or not EMAIL_RE.match(email):
        return resp(False, "Informe seu nome e um e-mail válido.", 400)
    if request.form.get("consentimento") != "sim":
        return resp(False, "É necessário concordar com a Política de Privacidade.", 400)
    f = request.form
    db().execute(
        "INSERT INTO leads(nome,email,interesse,mensagem,pagina,referrer,utm_source,utm_medium,utm_campaign,ip,criado_em)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (nome, email, limpar(f.get("interesse"), 60), limpar(f.get("mensagem"), 3000), limpar(f.get("pagina"), 300),
         limpar(f.get("referrer"), 300), limpar(f.get("utm_source"), 100), limpar(f.get("utm_medium"), 100),
         limpar(f.get("utm_campaign"), 100), request.remote_addr, agora()))
    db().commit()
    return resp(True, "Mensagem enviada! Retornaremos em breve.")


# ═══ CANAL DE DENÚNCIAS ════════════════════════════════════════════════════
@app.get("/canal-de-denuncias")
def canal():
    p = limpar(request.args.get("p"), 20).upper()
    d = None
    if p:
        d = db().execute("SELECT * FROM denuncias WHERE protocolo=?", (p,)).fetchone()
    return render_template("canal.html", erro=None, d=d, protocolo=p)


@app.post("/canal-de-denuncias/enviar")
def canal_enviar():
    check_csrf()
    if request.form.get("website"):
        return redirect("/canal-de-denuncias")
    if excedido("denuncia", 5, 3600):
        return erro("Muitas tentativas. Aguarde um pouco e tente novamente.", 429)
    relato = limpar(request.form.get("relato"), 5000)
    if len(relato) < 10:
        return render_template("canal.html", erro="Descreva o relato com um pouco mais de detalhes.", d=None, protocolo=""), 400
    anonima = 1 if request.form.get("anonima") else 0
    nome = "" if anonima else limpar(request.form.get("nome"), 120)
    contato_ = "" if anonima else limpar(request.form.get("contato"), 150)
    cat = request.form.get("categoria")
    cat = cat if cat in CATEGORIAS else "Outro"
    proto = novo_protocolo()
    n = agora()
    db().execute(
        "INSERT INTO denuncias(protocolo,anonima,nome,contato,categoria,relato,data_fato,local,envolvidos,status,criado_em,atualizado_em)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (proto, anonima, nome, contato_, cat, relato, limpar(request.form.get("data_fato"), 60),
         limpar(request.form.get("local"), 200), limpar(request.form.get("envolvidos"), 300), STATUS[0], n, n))
    db().commit()
    return render_template("protocolo.html", protocolo=proto)


@app.post("/canal-de-denuncias/consultar")
def canal_consultar():
    check_csrf()
    if excedido("consulta", 20, 600):
        return erro("Muitas consultas. Aguarde alguns minutos.", 429)
    p = limpar(request.form.get("protocolo"), 20).upper()
    d = db().execute("SELECT * FROM denuncias WHERE protocolo=?", (p,)).fetchone()
    return render_template("canal.html", erro=None if d else "Protocolo não encontrado. Confira o código e tente de novo.", d=d, protocolo=p)


# ═══ PAINEL ADMIN ══════════════════════════════════════════════════════════
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    e = None
    if request.method == "POST":
        check_csrf()
        if excedido("login", 6, 600):
            e = "Muitas tentativas. Aguarde alguns minutos."
        elif not ADMIN_USER or not ADMIN_PASS:
            e = "Painel desativado: defina ADMIN_USER e ADMIN_PASS no ambiente."
        elif (hmac.compare_digest(request.form.get("u", ""), ADMIN_USER)
              and hmac.compare_digest(request.form.get("s", ""), ADMIN_PASS)):
            session.clear()
            session["adm"] = True
            session.permanent = True
            return redirect("/admin")
        else:
            e = "Usuário ou senha incorretos."
    return render_template("admin_login.html", erro=e)


@app.get("/admin/sair")
def admin_sair():
    session.clear()
    return redirect("/admin/login")


@app.get("/admin")
@admin_required
def admin():
    aba = request.args.get("aba", "den")
    d = db()
    cont = {"den": d.execute("SELECT COUNT(*) FROM denuncias WHERE status='Recebida'").fetchone()[0],
            "leads": d.execute("SELECT COUNT(*) FROM leads WHERE atendido=0").fetchone()[0], "posts": 0, "img": 0}
    if aba == "leads":
        itens = d.execute("SELECT * FROM leads ORDER BY id DESC LIMIT 500").fetchall()
    elif aba == "posts":
        itens = d.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    elif aba == "img":
        itens = []
    else:
        aba = "den"
        s = request.args.get("status")
        itens = (d.execute("SELECT * FROM denuncias WHERE status=? ORDER BY id DESC", (s,)).fetchall() if s in STATUS
                 else d.execute("SELECT * FROM denuncias ORDER BY id DESC").fetchall())
    abas = [("den", "Denúncias"), ("leads", "Contatos"), ("posts", "Conteúdos"), ("img", "Imagens")]
    return render_template("admin.html", aba=aba, itens=itens, abas=abas, cont=cont, msg=request.args.get("ok"))


@app.route("/admin/denuncia/<int:i>", methods=["GET", "POST"])
@admin_required
def admin_denuncia(i):
    d = db().execute("SELECT * FROM denuncias WHERE id=?", (i,)).fetchone()
    if not d:
        abort(404)
    msg = None
    if request.method == "POST":
        check_csrf()
        st = request.form.get("status")
        if st in STATUS:
            db().execute("UPDATE denuncias SET status=?, resposta=?, atualizado_em=? WHERE id=?",
                         (st, limpar(request.form.get("resposta"), 3000), agora(), i))
            db().commit()
            d = db().execute("SELECT * FROM denuncias WHERE id=?", (i,)).fetchone()
            msg = "Andamento atualizado."
    return render_template("admin_den.html", d=d, msg=msg)


@app.post("/admin/lead/<int:i>/atendido")
@admin_required
def admin_lead(i):
    check_csrf()
    db().execute("UPDATE leads SET atendido=1-atendido WHERE id=?", (i,))
    db().commit()
    return redirect("/admin?aba=leads")


@app.route("/admin/post/<i>", methods=["GET", "POST"])
@admin_required
def admin_post(i):
    p = None
    if i != "novo":
        p = db().execute("SELECT * FROM posts WHERE id=?", (int(i) if i.isdigit() else 0,)).fetchone()
        if not p:
            abort(404)
    if request.method == "POST":
        check_csrf()
        titulo = limpar(request.form.get("titulo"), 200)
        if not titulo:
            return render_template("admin_post.html", p=p, erro="Informe o título."), 400
        resumo, corpo_ = limpar(request.form.get("resumo"), 300), (request.form.get("corpo") or "")[:60000]
        pub = 1 if request.form.get("publicado") else 0
        d = db()
        if p:
            pe = p["publicado_em"] or (agora() if pub else None)
            d.execute("UPDATE posts SET titulo=?,resumo=?,corpo=?,publicado=?,publicado_em=? WHERE id=?",
                      (titulo, resumo, corpo_, pub, pe, p["id"]))
            pid = p["id"]
        else:
            slug = slugify(titulo)
            if d.execute("SELECT 1 FROM posts WHERE slug=?", (slug,)).fetchone():
                slug += "-" + secrets.token_hex(2)
            cur = d.execute("INSERT INTO posts(titulo,slug,resumo,corpo,publicado,publicado_em,criado_em) VALUES(?,?,?,?,?,?,?)",
                            (titulo, slug, resumo, corpo_, pub, agora() if pub else None, agora()))
            pid = cur.lastrowid
        d.commit()
        capa = request.files.get("capa")
        if capa and capa.filename:
            salvar_imagem("capa-%d" % pid, capa)
        return redirect("/admin?aba=posts&ok=Conteúdo salvo.")
    return render_template("admin_post.html", p=p, erro=None)


@app.post("/admin/post/<int:i>/excluir")
@admin_required
def admin_post_excluir(i):
    check_csrf()
    db().execute("DELETE FROM posts WHERE id=?", (i,))
    db().commit()
    apagar_imagem("capa-%d" % i)
    return redirect("/admin?aba=posts&ok=Conteúdo excluído.")


@app.post("/admin/img/<slot>")
@admin_required
def admin_img(slot):
    check_csrf()
    if slot not in SLOTS:
        abort(404)
    arq = request.files.get("arq")
    if not arq or not salvar_imagem(slot, arq):
        return redirect("/admin?aba=img&ok=Arquivo inválido. Envie JPG, PNG ou WEBP.")
    return redirect("/admin?aba=img&ok=Imagem atualizada.")


@app.post("/admin/img/<slot>/excluir")
@admin_required
def admin_img_del(slot):
    check_csrf()
    if slot in SLOTS:
        apagar_imagem(slot)
    return redirect("/admin?aba=img&ok=Imagem removida.")


if __name__ == "__main__":
    app.config["SESSION_COOKIE_SECURE"] = False
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=os.environ.get("DEBUG") == "1")
