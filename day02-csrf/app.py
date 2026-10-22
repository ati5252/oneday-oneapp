# ============================================================
# Day 2: CSRF対策を学ぶ Flask アプリ（安全な書き方だけ）
#
# このアプリには「プロフィール更新フォーム」が1つあります。
# フォームは次の2つの対策で守られています。
#   1. CSRFトークン … フォームに秘密の合言葉を入れ、送信時に照合する
#   2. SameSite=Lax … 他のサイトから送られたPOSTにCookieを付けない
#
# ※ 学習用です。自分のパソコンの中だけで動かしてください。
# ============================================================

# secrets: 推測されにくいランダムな文字列を作るための標準ライブラリ
import secrets

# Flask の部品を読み込む
#   session … ユーザーごとのデータをCookieに（署名付きで）保存する仕組み
#   abort   … エラー（403など）を返して処理を止める
from flask import Flask, request, render_template_string, session, redirect, abort

app = Flask(__name__)

# セッションCookieに署名するための鍵。起動のたびにランダムに作る
# （本物のアプリでは環境変数などから読み込み、固定の値を使います）
app.secret_key = secrets.token_hex(32)

# ★対策2★ セッションCookieの属性を設定する
app.config.update(
    # SameSite=Lax: 他のサイトから送られた POST リクエストには Cookie を付けない
    SESSION_COOKIE_SAMESITE="Lax",
    # HttpOnly: JavaScript から Cookie を読めないようにする
    SESSION_COOKIE_HTTPONLY=True,
    # Secure: HTTPS のときだけ Cookie を送る（今回は http://127.0.0.1 なので False）
    SESSION_COOKIE_SECURE=False,
)

# 学習用のかんたんなユーザーデータ（本物ならデータベースに入れる）
USERS = {"alice": {"password": "alice123", "email": "alice@example.com"}}


def get_csrf_token():
    """セッションに CSRF トークンが無ければ作り、それを返す関数"""
    if "csrf_token" not in session:
        # token_urlsafe(32): 推測できない長いランダム文字列を作る
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


# テンプレートの中で {{ csrf_token() }} と書けるようにする
app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def check_csrf():
    """★対策1★ 状態を変えるリクエスト（POST）が来たら、毎回トークンを確かめる"""
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")       # フォームから送られてきたトークン
        expected = session.get("csrf_token", "")        # サーバーが覚えているトークン
        # compare_digest: 文字列を「時間差で中身がばれない」方法で比べる
        if not expected or not secrets.compare_digest(sent, expected):
            abort(403)  # 一致しなければ「禁止」として処理を止める


PAGE = """
<!doctype html>
<meta charset="utf-8">
<title>{{ title }}</title>
<h1>{{ title }}</h1>
{% if message %}<p><b>{{ message }}</b></p>{% endif %}
{{ body | safe }}
"""

LOGIN_FORM = """
<form method="post" action="/login">
  <!-- ログインフォームにもトークンを入れる -->
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  ユーザー名: <input name="username" value="alice"><br>
  パスワード: <input name="password" type="password" value="alice123"><br>
  <button type="submit">ログイン</button>
</form>
"""

PROFILE_FORM = """
<p>ログイン中: {{ user }} さん</p>
<p>現在のメールアドレス: <b>{{ email }}</b></p>
<form method="post" action="/profile">
  <!-- ★対策1★ 画面ごとに埋め込まれる秘密のトークン。外部サイトはこの値を知らない -->
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  新しいメールアドレス: <input name="email"><br>
  <button type="submit">更新</button>
</form>
<p>今のトークン（学習用に表示）: <code>{{ csrf_token() }}</code></p>
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
        return redirect("/profile")
    return render("ログイン", LOGIN_FORM)


@app.route("/login", methods=["POST"])
def login():
    # ここに来た時点で check_csrf() がトークンを確認済み
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user = USERS.get(username)
    if user and secrets.compare_digest(password, user["password"]):
        session.clear()  # ログインのたびにセッションを作り直す
        session["user"] = username
        get_csrf_token()  # 新しいトークンを発行する
        return redirect("/profile")
    return render("ログイン", LOGIN_FORM, message="ログイン失敗")


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user" not in session:
        return redirect("/")
    user = session["user"]
    message = None
    if request.method == "POST":
        # トークンが正しいリクエストだけがここまで来られる
        USERS[user]["email"] = request.form.get("email", "")
        message = "メールアドレスを更新しました"
    return render("プロフィール", PROFILE_FORM, message=message,
                  user=user, email=USERS[user]["email"])


@app.route("/logout", methods=["POST"])
def logout():
    # ログアウトも「状態を変える操作」なので GET ではなく POST にする
    session.clear()
    return redirect("/")


@app.errorhandler(403)
def forbidden(e):
    return render("403 Forbidden", '<p><a href="/">トップへ戻る</a></p>',
                  message="CSRFトークンが無いか、正しくないため拒否しました"), 403


if __name__ == "__main__":
    # host="127.0.0.1": 自分のパソコンからしかアクセスできないようにする
    app.run(host="127.0.0.1", port=5000, debug=True)
