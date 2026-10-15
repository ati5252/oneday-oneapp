# Day 1: SQLインジェクション

## 動かし方

```bash
pip install flask
python app.py
```

ブラウザで http://127.0.0.1:5000 を開きます。

## やってみよう

1. 「脆弱なログイン」を開き、次のように入力します。
   - ユーザー名: `admin' --`
   - パスワード: （何でもよい）
2. パスワードを知らないのに admin でログインできてしまいます。
3. 「安全なログイン」で同じ入力をすると、ログイン失敗になります。

## なぜ起きるのか

脆弱なほうでは、入力がそのままSQLにつながり、次の文になります。

```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = '...'
```

`--` から後ろはSQLの「コメント」として無視されるので、パスワードの確認が消えてしまいます。

## 対策

値をSQLの文字列に直接つなげず、`?`（プレースホルダ）を使って別に渡します。

```python
conn.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```

ほかの攻撃例: ユーザー名に `' OR '1'='1' --` と入れると、最初のユーザーでログインできます。
