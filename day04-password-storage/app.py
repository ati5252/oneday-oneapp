# ============================================================
# Day 4: パスワードの安全な保存とログインを学ぶ Flask アプリ（安全な書き方だけ）
#
# このアプリには「ユーザー登録」と「ログイン」があります。
# パスワードは次の4つの対策で守ります。
#   1. ソルト付きの遅いハッシュ … パスワードそのものは保存せず、
#                                 ユーザーごとのソルトと scrypt で変換した値だけを保存する
#   2. 時間差の出ない比較       … ハッシュの比較に hmac.compare_digest を使う
#   3. ユーザーの有無を隠す     … 存在しないユーザーでも同じだけ計算し、同じメッセージを返す
#   4. ログイン回数の制限       … 短い時間に何度も失敗したら、しばらくログインを止める
#
# ※ 学習用です。自分のパソコンの中だけで動かしてください。
# ============================================================

# hashlib: ハッシュ（scrypt など）を計算する標準ライブラリ
import hashlib
# hmac: compare_digest（時間差の出ない比較）を使うための標準ライブラリ
import hmac
# os: ファイルのパスを扱う標準ライブラリ
import os
# secrets: 推測されにくいランダムな値（ソルトやトークン）を作る標準ライブラリ
import secrets
# sqlite3: ファイル1つで動くデータベースの標準ライブラリ
import sqlite3
# time: 今の時刻（秒）を取得して、回数制限に使う
import time

from flask import Flask, request, render_template_string, session, redirect, abort

app = Flask(__name__)

# セッションCookieに署名するための鍵。起動のたびにランダムに作る
# （本物のアプリでは環境変数などから読み込み、固定の値を使います）
app.secret_key = secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # 今回は http://127.0.0.1 なので False
)

# データベースのファイル（app.py の隣に作る）
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

# ★対策1★ scrypt の設定。数字を大きくするほど、1回の計算が重くなる
#   n … 計算とメモリの重さ（2の累乗）。2**15 だと約32MBのメモリを使う
#   r … 1回に扱うブロックの大きさ
#   p … 並列の数
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16       # ソルトの長さ（バイト）
MIN_PASSWORD_LEN = 8  # 登録できるパスワードの最低文字数

# ★対策4★ ログイン回数の制限の設定
MAX_FAILURES = 5      # この回数まで失敗できる
WINDOW_SECONDS = 300  # 何秒間の失敗を数えるか（5分）
# 失敗した時刻を覚えておく辞書 { "user:alice": [時刻, 時刻, ...], "ip:127.0.0.1": [...] }
# （学習用にメモリに置いているので、アプリを再起動すると消えます）
failed_logins = {}


def hash_password(password, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    """パスワードを「ソルト付きの scrypt ハッシュ」に変換して、保存用の文字列を返す関数"""
    # ユーザーごと・登録ごとに新しいランダムなソルトを作る
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                            n=n, r=r, p=p, maxmem=64 * 1024 * 1024, dklen=32)
    # あとで同じ計算をやり直せるように、設定とソルトも一緒に保存する
    # 例: scrypt$32768$8$1$ソルト(16進数)$ハッシュ(16進数)
    return f"scrypt${n}${r}${p}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    """入力されたパスワードが、保存されているハッシュと一致するかを調べる関数"""
    _, n, r, p, salt_hex, digest_hex = stored.split("$")
    # 保存されているソルトと設定で、入力されたパスワードをもう一度ハッシュにする
    digest = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
                            n=int(n), r=int(r), p=int(p),
                            maxmem=64 * 1024 * 1024, dklen=32)
    # ★対策2★ compare_digest: 何文字目で違ったかによって時間が変わらない比較
    return hmac.compare_digest(digest, bytes.fromhex(digest_hex))


def needs_rehash(stored):
    """保存されているハッシュの設定が、今の設定より古い（弱い）かを調べる関数"""
    _, n, r, p, _, _ = stored.split("$")
    return (int(n), int(r), int(p)) != (SCRYPT_N, SCRYPT_R, SCRYPT_P)


# ★対策3★ 存在しないユーザーのときに比べるための「ダミーのハッシュ」
# これと比べることで、ユーザーがいてもいなくても同じだけ時間がかかる
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """users テーブルを作る関数（すでにあれば何もしない）"""
    with get_db() as conn:
        # username は UNIQUE（同じ名前は1人だけ）。パスワードの列は無く、ハッシュだけを持つ
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
                            username TEXT PRIMARY KEY,
                            password_hash TEXT NOT NULL)""")


def recent_failures(key, now):
    """key（ユーザー名やIP）の、最近 WINDOW_SECONDS 秒以内の失敗時刻だけを残して返す"""
    times = [t for t in failed_logins.get(key, []) if now - t < WINDOW_SECONDS]
    failed_logins[key] = times
    return times


def is_locked(keys, now):
    """★対策4★ どれか1つのキーで失敗が多すぎたら、ロック中とみなす"""
    return any(len(recent_failures(k, now)) >= MAX_FAILURES for k in keys)


def get_csrf_token():
    """Day 2 と同じ CSRF トークン（ログインフォームなども守る）"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(403)


PAGE = """
<!doctype html>
<meta charset="utf-8">
<title>{{ title }}</title>
<h1>{{ title }}</h1>
{% if message %}<p><b>{{ message }}</b></p>{% endif %}
{{ body | safe }}
"""

LOGIN_BODY = """
<form method="post" action="/login">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  ユーザー名: <input name="username"><br>
  パスワード: <input name="password" type="password"><br>
  <button type="submit">ログイン</button>
</form>
<p><a href="/register">ユーザー登録はこちら</a></p>
"""

REGISTER_BODY = """
<form method="post" action="/register">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  ユーザー名: <input name="username"><br>
  パスワード（{{ min_len }}文字以上）: <input name="password" type="password"><br>
  <button type="submit">登録</button>
</form>
<p><a href="/">ログイン画面へ</a></p>
"""

HOME_BODY = """
<p>ログイン中: {{ user }} さん</p>
<p>データベースに保存されているのは、パスワードではなく次の文字列です（学習用に表示）:</p>
<pre>{{ stored }}</pre>
<p>左から「方式 $ n $ r $ p $ ソルト $ ハッシュ」です。</p>
<form method="post" action="/logout">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <button type="submit">ログアウト</button>
</form>
"""


def render(title, body, message=None, **values):
    # 先に body の中の {{ }} を埋めてから、ページ全体に入れる
    inner = render_template_string(body, **values)
    return render_template_string(PAGE, title=title, body=inner, message=message)


@app.route("/")
def index():
    if "user" in session:
        return redirect("/home")
    return render("ログイン", LOGIN_BODY)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render("ユーザー登録", REGISTER_BODY, min_len=MIN_PASSWORD_LEN)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username or len(username) > 32:
        return render("ユーザー登録", REGISTER_BODY, message="ユーザー名は1〜32文字にしてください",
                      min_len=MIN_PASSWORD_LEN)
    if len(password) < MIN_PASSWORD_LEN:
        return render("ユーザー登録", REGISTER_BODY,
                      message=f"パスワードは{MIN_PASSWORD_LEN}文字以上にしてください",
                      min_len=MIN_PASSWORD_LEN)

    try:
        with get_db() as conn:
            # ★対策1★ 保存するのはハッシュだけ。パスワードそのものはどこにも書かない
            # （Day 1 と同じく、値は ? のプレースホルダで渡す）
            conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                         (username, hash_password(password)))
    except sqlite3.IntegrityError:
        # UNIQUE 制約に引っかかった＝同じ名前のユーザーがすでにいる
        return render("ユーザー登録", REGISTER_BODY, message="そのユーザー名は使えません",
                      min_len=MIN_PASSWORD_LEN)
    return render("ログイン", LOGIN_BODY, message="登録しました。ログインしてください")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    now = time.time()
    # ユーザー名ごと と 接続元IPごと の両方で数える
    keys = [f"user:{username}", f"ip:{request.remote_addr}"]

    # ★対策4★ 失敗が多すぎるときは、パスワードを調べる前に断る
    if is_locked(keys, now):
        return render("ログイン", LOGIN_BODY,
                      message="ログインの失敗が続いたため、しばらく待ってからやり直してください"), 429

    with get_db() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE username = ?",
                           (username,)).fetchone()

    # ★対策3★ ユーザーがいなくても、ダミーのハッシュで同じだけ計算する
    stored = row["password_hash"] if row else DUMMY_HASH
    ok = verify_password(password, stored) and row is not None

    if not ok:
        for k in keys:
            failed_logins.setdefault(k, []).append(now)
        # 「ユーザーがいない」「パスワードが違う」を区別しないメッセージにする
        return render("ログイン", LOGIN_BODY, message="ユーザー名またはパスワードが違います")

    # 成功したら、そのユーザー名の失敗記録は消す
    failed_logins.pop(f"user:{username}", None)

    # 設定を強くしたあとなら、正しいパスワードが手元にある今のうちに作り直す
    if needs_rehash(stored):
        with get_db() as conn:
            conn.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                         (hash_password(password), username))

    session.clear()  # ログインのたびにセッションを作り直す
    session["user"] = username
    get_csrf_token()
    return redirect("/home")


@app.route("/home")
def home():
    if "user" not in session:
        return redirect("/")
    with get_db() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE username = ?",
                           (session["user"],)).fetchone()
    if row is None:  # データベースを消した場合など、ユーザーがもういないとき
        session.clear()
        return redirect("/")
    return render("ホーム", HOME_BODY, user=session["user"], stored=row["password_hash"])


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


@app.errorhandler(403)
def forbidden(e):
    return render("403 Forbidden", '<p><a href="/">トップへ戻る</a></p>',
                  message="CSRFトークンが無いか、正しくないため拒否しました"), 403


init_db()

if __name__ == "__main__":
    # host="127.0.0.1": 自分のパソコンからしかアクセスできないようにする
    app.run(host="127.0.0.1", port=5000, debug=True)
