# 道具

Windows Live メール 2012 のファイルを読むための自作の道具です。Python 3 の標準ライブラリだけで動きます（`ese/` だけは `dissect.esedb` が必要）。

解析する対象のファイルは含みません。手元の正規のインストール（`C:\Program Files (x86)\Windows Live`）を、リポジトリの直下の `targets/Windows Live/` に写して使います（`.gitignore` で除外しています）。場所を変えるときは、環境変数 `WLM_TARGETS` か `--targets` で指定します。

| 場所 | 何をするか | 解説 |
|---|---|---|
| `tools-res.py` | REA の `inspect-pe-resources` の JSON をもとに、リソースを位置と SHA-256 で切り出す | 1 章 |
| `uib/uib2xml.py` | 画面の設計図（種類 4010、"UIB"）を XML にする。`--check` で全バイトを読めたか確かめる | 2 章 |
| `uib/peres.py` | `uib2xml.py` が参照先の値を読むための、小さな PE リソース読み取り | 2 章 |
| `rules.py` | XML の中のシートの規則を、クラス名とプロパティで絞って一覧にする | 2 章 |
| `resources/decode_resources.py` | 色（4002）、画像（4000 の PNG と RLE）、余白（4006）、スプライト（4011/4012）を書き出す | 3 章 |
| `resources/rle.py`, `colorize.py`, `pe.py`, `png.py` | RLE の解読、配色の計算、PE と PNG の読み書き | 3 章 |
| `inventory/res.py` | MUI から文字列表、メニュー、ダイアログを取り出す | 4 章 |
| `inventory/bmllib.py`, `bml2.py`, `bml.py` | コンパイル済みのリボン（UIFILE）の読み取り | 4 章 |
| `inventory/ribbons.py`, `gen.py` | リボンの木とコマンド表を書き出し、確認用の表にする | 4 章 |
| `ese/wlm_store.py` | `Mail.MSMessageStore` の既読ビットを、フォルダーの未読数と照合する | 5 章 |

## 手順の例

```bash
rea inspect-pe-resources "targets/Windows Live/Mail/mailres2.dll" --format json > mailres2.resources.json
python3 -I tools/tools-res.py extract mailres2.resources.json 4010 extract/4010
python3 -I tools/uib/uib2xml.py --check extract/4010/7001_1033.bin
python3 -I tools/uib/uib2xml.py extract/4010/7001_1033.bin -o xml/7001.xml
python3 -I tools/rules.py xml/7001.xml 'MLV|Conversation'
python3 -I tools/resources/decode_resources.py out/
```

書き出したもの（XML、画像、文字列表）は Microsoft の著作物を含むので、公開しないでください。
