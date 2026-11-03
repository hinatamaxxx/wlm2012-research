# 5. メールの保存庫（Mail.MSMessageStore）

Windows Live メール 2012 は、メールの本文を 1 通ずつ `.eml` ファイルで保存します。そのため、乗り換えのときに本文を取り込むのは簡単です。ところが、`.eml` には**既読・未読が書かれていません**。取り込むと全部が既読（または全部が未読）になってしまいます。

既読・未読は、保存フォルダーの直下にある `Mail.MSMessageStore` というファイルに入っていました。

## 形式を突き止める

- ファイルの 4 バイト目からの値が `0x89abcdef` でした。これは Windows の **ESE（Extensible Storage Engine、esent.dll）** のデータベースの印です。Exchange や Windows Search と同じ仕組みです。
- 最初に `libesedb`（`esedbexport`）で開こうとしましたが、この版の形式（format revision 0x12C）に対応しておらず、開けませんでした。
- Python の `dissect.esedb` では開けました。テーブルは `Folders`、`Messages` などです。

`Messages` テーブルの主な列:

| 列 | 中身 |
|---|---|
| `MSGCOL_FOLDERID` | どのフォルダーか |
| `MSGCOL_FLAGS` | 状態のビット |
| `MSGCOL_MESSAGEID` | メールの Message-ID |
| `MSGCOL_SUBJECT` | 件名 |
| `MSGCOL_DATE` | 日時（FILETIME） |

`Folders` テーブルには、フォルダーごとの件数（`FLDCOL_MESSAGES`）と未読の数（`FLDCOL_UNREAD`）が入っています。

## 既読のビットを確かめる

`MSGCOL_FLAGS` のどのビットが「既読」なのかは、列名からはわかりません。そこで、次のように確かめました。

1. ビットの候補ごとに、そのビットが立っていないメッセージをフォルダーごとに数える。
2. その数が、`Folders` テーブルに保存されている未読の数と**すべてのフォルダーで**一致するか比べる。

**0x80** のとき、手元の保存庫の 6 つのフォルダーすべてで一致しました。つまり、0x80 が立っていれば既読です。[観察: データでの照合]

`tools/ese/wlm_store.py` は、この照合をするだけの道具です。件名やアドレスは表示しません。

```bash
python3 -m venv venv && venv/bin/pip install dissect.esedb
venv/bin/python -I tools/ese/wlm_store.py /path/to/copy/of/Mail.MSMessageStore
```

## 取り込みでの使い方

作り直したアプリ（C#）では、Microsoft の `ManagedEsent` で読みました。気を付けた点です。

- **写しを読む**: 元のファイルは Windows Live メールが使っている最中かもしれないので、一時フォルダーに写してから、読み取り専用で開きます。
- **ログを再生しない**: きれいに閉じられたデータベースの写しなので、回復処理（Recovery）を切って開きます。
- **ページの大きさ**: ESE はデータベースを開く前にページの大きさを決める必要があります。ヘッダーの 0xEC にある値を読んで設定しました。
- **メールとの結び付け**: Message-ID で結び付けます。Message-ID が無いメールは、件名と日時（分単位）で結び付けます。`.eml` の Date ヘッダーには秒より細かい時刻が無いので、分にそろえています。

これで、取り込んだメールの既読・未読が、前のアプリでの状態のまま引き継がれるようになりました。
