# ============================================================
# Day 3: パストラバーサル対策を学ぶ Flask アプリ（安全な書き方だけ）
#
# このアプリは「メモ閲覧アプリ」です。files フォルダの中にある
# テキストファイルを、URL の ?name=ファイル名 で指定して表示します。
# ファイル名はユーザーが自由に送れる値なので、次の3つの対策で守ります。
#   1. ファイル名の許可リスト … 決まった形の名前以外は受け付けない
#   2. 実際のパスを確かめる   … 最終的な場所が files フォルダの中か確認する
#   3. ふつうのファイルだけ   … フォルダや特殊なデバイス名は開かない
#
# ※ 学習用です。自分のパソコンの中だけで動かしてください。
# ============================================================

# os: ファイルやフォルダのパスを扱う標準ライブラリ
import os
# re: 正規表現（文字列の形をチェックする仕組み）の標準ライブラリ
import re

# Flask の部品を読み込む
#   abort … エラー（400 や 404 など）を返して処理を止める
from flask import Flask, request, render_template_string, abort

app = Flask(__name__)

# このファイル（app.py）が置いてあるフォルダ
APP_DIR = os.path.dirname(os.path.abspath(__file__))

# ★ 公開してよいファイルを置くフォルダ。ここより外は絶対に見せない
# realpath: 「..」やシンボリックリンクをすべて解決した、本当の場所に直す
BASE_DIR = os.path.realpath(os.path.join(APP_DIR, "files"))

# ★対策1★ ファイル名の許可リスト（正規表現）
#   英数字・アンダースコア・ハイフンだけの名前 + 拡張子 .txt または .md
#   「/」「\」「:」「.」の連続などは、この形に当てはまらないので入れない
SAFE_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\.(txt|md)")

# Windows で特別な意味を持つ名前（デバイス名）。ファイルとして開かない
WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}

# 起動時に用意するサンプルのメモ
SAMPLE_FILES = {
    "welcome.txt": "ようこそ！これは files フォルダの中のメモです。\n",
    "todo.md": "# 今日やること\n- Day 3 のアプリを動かす\n- README を読む\n",
    "python_tips.txt": "pathlib や os.path を使うと、パスを安全に組み立てられます。\n",
}


def prepare_sample_files():
    """files フォルダとサンプルのメモを作る関数（すでにあれば何もしない）"""
    os.makedirs(BASE_DIR, exist_ok=True)
    for name, text in SAMPLE_FILES.items():
        path = os.path.join(BASE_DIR, name)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)


def resolve_safe_path(name):
    """ユーザーが送ったファイル名から、安全に開ける本当のパスを返す関数。
    少しでも怪しければ abort() で処理を止める。"""

    # ★対策1★ 名前の形をチェック（fullmatch: 文字列「全体」が形に一致するか）
    if not SAFE_NAME.fullmatch(name):
        abort(400)  # 「リクエストがおかしい」として拒否

    # Windows のデバイス名（CON.txt など）も拒否する
    stem = name.split(".")[0].upper()
    if stem in WINDOWS_RESERVED:
        abort(400)

    # ★対策2★ フォルダとファイル名をつなげてから、本当の場所に直す
    full_path = os.path.realpath(os.path.join(BASE_DIR, name))

    # commonpath: 2つのパスに共通する一番深いフォルダを求める
    # それが BASE_DIR と同じなら、full_path は BASE_DIR の中にある
    # （文字列の startswith で比べると「files_secret」のような
    #   名前の違うフォルダを見逃すので、commonpath を使う）
    if os.path.commonpath([BASE_DIR, full_path]) != BASE_DIR:
        abort(400)

    # ★対策3★ ふつうのファイルだけを開く（フォルダや存在しないものは 404）
    if not os.path.isfile(full_path):
        abort(404)

    return full_path


PAGE = """
<!doctype html>
<meta charset="utf-8">
<title>{{ title }}</title>
<h1>{{ title }}</h1>
{% if message %}<p><b>{{ message }}</b></p>{% endif %}
{{ body | safe }}
"""

INDEX_BODY = """
<p>files フォルダにあるメモ:</p>
<ul>
{% for name in names %}
  <li><a href="/view?name={{ name | urlencode }}">{{ name }}</a></li>
{% endfor %}
</ul>
"""

VIEW_BODY = """
<p>ファイル名: <code>{{ name }}</code></p>
{# ファイルの中身は二重波かっこで表示するので、HTML として解釈されない（自動エスケープ） #}
<pre>{{ text }}</pre>
<p><a href="/">一覧へ戻る</a></p>
"""


def render(title, body, message=None, **values):
    # 先に body の中の {{ }} を埋めてから、ページ全体に入れる
    inner = render_template_string(body, **values)
    return render_template_string(PAGE, title=title, body=inner, message=message)


@app.route("/")
def index():
    # 一覧には、許可リストの形に合うファイルだけを出す
    names = sorted(n for n in os.listdir(BASE_DIR)
                   if SAFE_NAME.fullmatch(n) and os.path.isfile(os.path.join(BASE_DIR, n)))
    return render("メモ一覧", INDEX_BODY, names=names)


@app.route("/view")
def view():
    name = request.args.get("name", "")
    path = resolve_safe_path(name)  # ここを通ったパスだけが開かれる
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return render("メモを表示", VIEW_BODY, name=name, text=text)


@app.errorhandler(400)
def bad_request(e):
    return render("400 Bad Request", '<p><a href="/">一覧へ戻る</a></p>',
                  message="使えないファイル名なので拒否しました"), 400


@app.errorhandler(404)
def not_found(e):
    return render("404 Not Found", '<p><a href="/">一覧へ戻る</a></p>',
                  message="そのファイルは見つかりませんでした"), 404


prepare_sample_files()

if __name__ == "__main__":
    # host="127.0.0.1": 自分のパソコンからしかアクセスできないようにする
    app.run(host="127.0.0.1", port=5000, debug=True)
