# ============================================================
# Day 5: 安全なファイルアップロードを学ぶ Flask アプリ（安全な書き方だけ）
#
# このアプリは「ファイル置き場」です。画像・PDF・テキストをアップロードして、
# あとから表示したりダウンロードしたりできます。
# ファイルの名前も中身もユーザーが自由に決められるので、次の5つの対策で守ります。
#   1. 大きさの制限         … 大きすぎるリクエストは読み込む前に断る
#   2. 拡張子の許可リスト   … 決まった種類のファイルだけを受け付ける
#   3. 中身のシグネチャ確認 … ファイルの先頭のバイトを見て、本当にその種類か確かめる
#   4. サーバーが決める名前 … 保存するファイル名はランダムに作り、公開フォルダの外に置く
#   5. 安全な返し方         … Content-Type などのヘッダーをサーバーが決めて返す
#
# ※ 学習用です。自分のパソコンの中だけで動かしてください。
# ============================================================

# os: ファイルやフォルダのパスを扱う標準ライブラリ
import os
# re: 正規表現（文字列の形をチェックする仕組み）の標準ライブラリ
import re
# secrets: 推測されにくいランダムな値（ファイル名や CSRF トークン）を作る標準ライブラリ
import secrets
# sqlite3: ファイル1つで動くデータベースの標準ライブラリ
import sqlite3

# Flask の部品を読み込む
#   send_file … ファイルをレスポンスとして返す
from flask import Flask, request, render_template_string, session, redirect, abort, send_file

app = Flask(__name__)

# セッションCookieに署名するための鍵（Day 2 と同じく、起動のたびにランダムに作る）
app.secret_key = secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # 今回は http://127.0.0.1 なので False
    # ★対策1★ リクエスト全体の大きさの上限（1MB）。超えたら Flask が 413 を返す
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# ★対策4★ アップロードされたファイルの保存先。
# Flask が自動で公開する static フォルダとは別の場所にするので、
# URL を直接打ってもこのフォルダの中身は見えない（必ず /files/... の処理を通る）
STORAGE_DIR = os.path.join(APP_DIR, "storage")
# ファイルの情報（元の名前・種類・大きさ）を入れるデータベース
DB_PATH = os.path.join(APP_DIR, "uploads.db")

MAX_FILES = 50  # 保存できるファイルの数の上限（ディスクを埋め尽くされないように）

# ★対策2・3★ 受け付けるファイルの種類の一覧（許可リスト）
#   拡張子 → (Content-Type, 先頭のバイト列の候補)
#   SVG や HTML は、中に JavaScript を書けるので、わざと入れていない
ALLOWED_TYPES = {
    "png":  ("image/png",       [b"\x89PNG\r\n\x1a\n"]),
    "jpg":  ("image/jpeg",      [b"\xff\xd8\xff"]),
    "jpeg": ("image/jpeg",      [b"\xff\xd8\xff"]),
    "gif":  ("image/gif",       [b"GIF87a", b"GIF89a"]),
    "pdf":  ("application/pdf", [b"%PDF-"]),
    "txt":  ("text/plain",      None),  # テキストは別の方法で確かめる（返すときは Flask が charset=utf-8 を付ける）
}
# ブラウザの中で表示してよい種類（それ以外はダウンロードさせる）
INLINE_TYPES = {"image/png", "image/jpeg", "image/gif"}

# 保存するファイルの ID の形（32文字の16進数）
FILE_ID = re.compile(r"[0-9a-f]{32}")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """files テーブルと保存先フォルダを作る関数（すでにあれば何もしない）"""
    os.makedirs(STORAGE_DIR, exist_ok=True)
    with get_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS files (
                            id TEXT PRIMARY KEY,
                            original_name TEXT NOT NULL,
                            ext TEXT NOT NULL,
                            mime TEXT NOT NULL,
                            size INTEGER NOT NULL)""")


def get_extension(filename):
    """ファイル名から、最後の「.」より後ろの拡張子を小文字で返す（無ければ空文字）"""
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower()


def content_matches(ext, data):
    """★対策3★ ファイルの中身が、拡張子の種類と本当に合っているかを調べる関数"""
    mime, signatures = ALLOWED_TYPES[ext]
    if signatures is not None:
        # 画像や PDF は、先頭の数バイト（マジックナンバー）が決まっている
        return any(data.startswith(sig) for sig in signatures)
    # テキストは「UTF-8 として読めて、制御用の NUL 文字を含まない」ことを確かめる
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def clean_display_name(filename):
    """画面に出すための元のファイル名を整える関数（保存には使わない）"""
    # フォルダの部分（C:\Users\... や ../ など）を取り除き、名前だけにする
    name = filename.replace("\\", "/").rsplit("/", 1)[-1]
    # 改行などの制御文字を取り除き、長すぎる名前は切る
    name = "".join(ch for ch in name if ch.isprintable())
    return name[:100] or "noname"


def get_csrf_token():
    """Day 2 と同じ CSRF トークン（アップロードのフォームも守る）"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        # ★対策1★ ここで request.form を読むときに、大きすぎるリクエストなら
        # Flask が中身を読まずに 413 エラーにしてくれる
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(403)


@app.after_request
def security_headers(response):
    # ★対策5★ nosniff: ブラウザに「Content-Type を勝手に推測しないで」と伝える
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


PAGE = """
<!doctype html>
<meta charset="utf-8">
<title>{{ title }}</title>
<h1>{{ title }}</h1>
{% if message %}<p><b>{{ message }}</b></p>{% endif %}
{{ body | safe }}
"""

INDEX_BODY = """
<form method="post" action="/upload" enctype="multipart/form-data">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input type="file" name="file" accept="{{ accept }}">
  <button type="submit">アップロード</button>
</form>
<p>使える種類: {{ exts }}（1MB まで）</p>

<h2>アップロードされたファイル</h2>
<ul>
{% for f in files %}
  {# 元のファイル名は二重波かっこで出すので、HTML として解釈されない（自動エスケープ） #}
  <li>{{ f.original_name }}（{{ f.size }} バイト, {{ f.mime }}）
    {% if f.mime in inline_types %}<a href="/files/{{ f.id }}">表示</a>{% endif %}
    <a href="/files/{{ f.id }}?download=1">ダウンロード</a>
    <br><small>保存名: storage/{{ f.id }}.{{ f.ext }}</small>
  </li>
{% else %}
  <li>まだありません</li>
{% endfor %}
</ul>
"""


def render(title, body, message=None, **values):
    # 先に body の中の {{ }} を埋めてから、ページ全体に入れる
    inner = render_template_string(body, **values)
    return render_template_string(PAGE, title=title, body=inner, message=message)


def render_index(message=None, status=200):
    with get_db() as conn:
        files = conn.execute("SELECT * FROM files ORDER BY rowid DESC").fetchall()
    exts = sorted(ALLOWED_TYPES)
    return render("ファイル置き場", INDEX_BODY, message=message, files=files,
                  exts=", ".join(exts), accept=",".join("." + e for e in exts),
                  inline_types=INLINE_TYPES), status


@app.route("/")
def index():
    return render_index()


@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files.get("file")
    if uploaded is None or uploaded.filename == "":
        return render_index("ファイルを選んでください", 400)

    # ★対策2★ 拡張子が許可リストにあるか（大文字・小文字は区別しない）
    ext = get_extension(uploaded.filename)
    if ext not in ALLOWED_TYPES:
        return render_index("その種類のファイルはアップロードできません", 400)

    # 中身を読む（★対策1★ で 1MB 以下なのが分かっているので、全部読んで大丈夫）
    data = uploaded.read()
    if not data:
        return render_index("空のファイルはアップロードできません", 400)

    # ★対策3★ 中身が拡張子どおりの種類か、先頭のバイトで確かめる
    # （ブラウザが送ってくる uploaded.content_type は、ユーザーが自由に変えられるので使わない）
    if not content_matches(ext, data):
        return render_index("ファイルの中身が拡張子と合いません", 400)

    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        if count >= MAX_FILES:
            return render_index("保存できるファイルの数がいっぱいです", 400)

        # ★対策4★ 保存名はサーバーがランダムに作る。ユーザーが送った名前は使わない
        file_id = secrets.token_hex(16)
        path = os.path.join(STORAGE_DIR, f"{file_id}.{ext}")
        # "xb": 同じ名前のファイルがすでにあればエラー（上書きしない）
        with open(path, "xb") as f:
            f.write(data)

        mime = ALLOWED_TYPES[ext][0]
        # 元の名前は、画面に表示するためだけにデータベースへ入れておく（Day 1 と同じく ? を使う）
        conn.execute("INSERT INTO files (id, original_name, ext, mime, size) VALUES (?, ?, ?, ?, ?)",
                     (file_id, clean_display_name(uploaded.filename), ext, mime, len(data)))
    return redirect("/")


@app.route("/files/<file_id>")
def get_file(file_id):
    # ID の形をチェック（Day 3 と同じく、決まった形以外は受け付けない）
    if not FILE_ID.fullmatch(file_id):
        abort(404)
    with get_db() as conn:
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None:
        abort(404)

    # 開くパスは、データベースの ID と拡張子だけから組み立てる
    path = os.path.join(STORAGE_DIR, f"{row['id']}.{row['ext']}")

    # ★対策5★ 返し方をサーバーが決める
    #   mimetype      … 保存時に確かめた種類で Content-Type を付ける
    #   as_attachment … 画像以外は Content-Disposition: attachment でダウンロードさせる
    #   download_name … 保存されるときの名前（日本語の名前も正しくエンコードされる）
    inline = row["mime"] in INLINE_TYPES and request.args.get("download") != "1"
    response = send_file(path, mimetype=row["mime"], as_attachment=not inline,
                         download_name=row["original_name"])
    # CSP sandbox: 万が一ブラウザがこのファイルをページとして開いても、
    # スクリプトを動かさず、このサイトの Cookie などにも触れさせない
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return response


@app.errorhandler(403)
def forbidden(e):
    return render("403 Forbidden", '<p><a href="/">トップへ戻る</a></p>',
                  message="CSRFトークンが無いか、正しくないため拒否しました"), 403


@app.errorhandler(404)
def not_found(e):
    return render("404 Not Found", '<p><a href="/">トップへ戻る</a></p>',
                  message="そのファイルは見つかりませんでした"), 404


@app.errorhandler(413)
def too_large(e):
    return render("413 Payload Too Large", '<p><a href="/">トップへ戻る</a></p>',
                  message="ファイルが大きすぎます（1MB まで）"), 413


init_db()

if __name__ == "__main__":
    # host="127.0.0.1": 自分のパソコンからしかアクセスできないようにする
    app.run(host="127.0.0.1", port=5000, debug=True)
