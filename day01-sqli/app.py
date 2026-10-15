# ============================================================
# Day 1: SQLインジェクションを体験して学ぶ Flask アプリ
#
# このアプリには「ログイン画面」が2つあります。
#   /vulnerable  … わざと危険な書き方をした（脆弱な）ログイン
#   /safe        … 正しい書き方をした（安全な）ログイン
# 同じ攻撃を両方に試して、何が違うのかを確かめましょう。
#
# ※ 学習用です。自分のパソコンの中だけで動かしてください。
# ============================================================

# sqlite3: Python に最初から入っている、ファイル1つで動く小さなデータベース
import sqlite3

# Flask の部品を読み込む
#   Flask           … アプリ本体を作るためのクラス
#   request         … ブラウザから送られてきたデータ（フォームの入力など）を読む
#   render_template_string … HTMLの文字列に値を埋め込んで画面を作る
from flask import Flask, request, render_template_string

# アプリ本体を作る（__name__ は「このファイル自身」を表すおまじない）
app = Flask(__name__)

# データベースのファイル名
DB_PATH = "users.db"


def init_db():
    """データベースを作り、テスト用のユーザーを登録する関数"""
    # データベースに接続する（ファイルが無ければ自動で作られる）
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()  # cursor = SQLを実行するための道具

    # users テーブルを毎回作り直す（何度起動しても同じ状態から始められるように）
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")

    # テスト用ユーザーを2人登録する
    # ※ 本物のアプリではパスワードをそのまま保存してはいけません（今回は学習用に単純化）
    cur.execute("INSERT INTO users (username, password) VALUES ('admin', 'super-secret')")
    cur.execute("INSERT INTO users (username, password) VALUES ('alice', 'alice123')")

    conn.commit()  # 変更を確定する
    conn.close()   # 接続を閉じる


# 画面のHTML（ログインフォーム＋結果表示）
# {{ ... }} や {% ... %} の部分に、Python から渡した値が入る
PAGE = """
<!doctype html>
<meta charset="utf-8">
<title>{{ title }}</title>
<h1>{{ title }}</h1>
<form method="post">
  ユーザー名: <input name="username"><br>
  パスワード: <input name="password"><br>
  <button type="submit">ログイン</button>
</form>
{% if sql %}
  <p>実行されたSQL:</p>
  <pre>{{ sql }}</pre>
{% endif %}
{% if message %}
  <p><b>{{ message }}</b></p>
{% endif %}
<p><a href="/">トップへ戻る</a></p>
"""


@app.route("/")  # 「/」（トップページ）にアクセスされたら、下の関数が動く
def index():
    return """
    <meta charset="utf-8">
    <h1>SQLインジェクション体験</h1>
    <ul>
      <li><a href="/vulnerable">脆弱なログイン（危険な書き方）</a></li>
      <li><a href="/safe">安全なログイン（正しい書き方）</a></li>
    </ul>
    """


# ------------------------------------------------------------
# ❌ 脆弱なログイン
# ------------------------------------------------------------
# methods=["GET", "POST"]: 画面を開く(GET)のと、フォームを送信する(POST)の両方を受け付ける
@app.route("/vulnerable", methods=["GET", "POST"])
def vulnerable_login():
    sql = None
    message = None

    # フォームが送信されたとき（POST）だけログイン処理をする
    if request.method == "POST":
        # フォームに入力された文字を取り出す
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ★ここが脆弱性の原因★
        # 入力された文字を、そのまま SQL の文章に「文字列としてつなげて」いる。
        # もし入力に ' （シングルクォート）などの記号が入っていると、
        # SQL の文の意味そのものが書き換わってしまう。
        sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        conn = sqlite3.connect(DB_PATH)
        try:
            # 組み立てた SQL をそのまま実行する
            user = conn.execute(sql).fetchone()  # fetchone(): 結果の1行目だけ取り出す
        except sqlite3.Error as e:
            # SQL の文法が壊れたときはエラー内容を表示（これも攻撃者のヒントになる）
            user = None
            message = f"SQLエラー: {e}"
        finally:
            conn.close()

        if user:
            # user は (id, username, password) の形。user[1] がユーザー名
            message = f"ログイン成功！ ようこそ {user[1]} さん"
        elif message is None:
            message = "ログイン失敗"

    # 画面を作って返す
    return render_template_string(PAGE, title="❌ 脆弱なログイン", sql=sql, message=message)


# ------------------------------------------------------------
# ✅ 安全なログイン
# ------------------------------------------------------------
@app.route("/safe", methods=["GET", "POST"])
def safe_login():
    sql = None
    message = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ★ここが対策★「プレースホルダ」を使う
        # SQL の中の値を入れたい場所に ? を書いておき、
        # 実際の値は execute の2番目の引数として「別に」渡す。
        # こうすると、入力に ' が入っていても「ただの文字」として扱われ、
        # SQL の文の意味は変わらない。
        sql = "SELECT * FROM users WHERE username = ? AND password = ?"

        conn = sqlite3.connect(DB_PATH)
        try:
            user = conn.execute(sql, (username, password)).fetchone()
        finally:
            conn.close()

        if user:
            message = f"ログイン成功！ ようこそ {user[1]} さん"
        else:
            message = "ログイン失敗"

    return render_template_string(PAGE, title="✅ 安全なログイン", sql=sql, message=message)


# このファイルを直接実行したとき（python app.py）だけ、下が動く
if __name__ == "__main__":
    init_db()  # 起動時にデータベースを準備
    # debug=True: コードを書き換えると自動で再起動してくれる（学習・開発用）
    # host="127.0.0.1": 自分のパソコンからしかアクセスできないようにする
    app.run(host="127.0.0.1", port=5000, debug=True)
