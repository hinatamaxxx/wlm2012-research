# 1. 解析の環境

解析は Linux（Kubuntu）の上で行いました。Windows の DLL を Linux で調べることになりますが、静的な解析（ファイルを読むだけで、実行はしない）なら OS は関係ありません。

## 使った道具

| 道具 | 版 | 役割 |
|---|---|---|
| [REA](https://github.com/morluto/rea)（`rea-agents`） | 6.8.0 | 解析をまとめる道具。PE のリソース一覧、Ghidra での逆コンパイル、文字列の検索などを、AI エージェントから呼べる形（MCP）でも、コマンドでも使える |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | 12.1.4 | 逆コンパイラー。REA 6.8.0 が検証した 12.1 系に合わせる（12.2 系は REA が受け付けない） |
| Eclipse Temurin JDK | 21.0.13+9 | Ghidra を動かす Java |
| Node.js | 26.13.0 | REA を動かす |
| Python 3 | 3.12 以降 | 自作の道具（[tools/](../tools/README.md)） |
| `dissect.esedb` | — | ESE データベース（5 章）を読む |

Ghidra と JDK は、システム全体には入れません。作業用のフォルダーに置き、REA の起動スクリプトの中だけで `GHIDRA_INSTALL_DIR` と `JAVA_HOME` を設定しました。版を固定し、ダウンロードしたファイルは SHA-256 で照合します。こうしておくと、別の PC でも同じ環境を作り直せます。

## 準備の手順（概略）

1. Node.js を用意して、`rea-agents@6.8.0` を入れる。
2. Ghidra 12.1.4 と JDK 21 を公式の配布元から取り、展開する。
3. `rea doctor --provider ghidra` で、Ghidra が使えることを確かめる。
4. AI エージェント（Claude Code）から使うときは `rea setup --client claude_code` で MCP サーバーとして登録する。REA が登録する起動ファイルは `#!/usr/bin/env node` で始まるので、`node` に PATH が通っている必要がある。PATH に無いときは `~/.local/bin` にリンクを置く。

## 解析の対象

- 手元の PC に入っていた Windows Live Essentials 2012 の `C:\Program Files (x86)\Windows Live` フォルダーを、まるごと写したもの。
- どのファイルにも Microsoft の Authenticode 署名が付いています（2014 年 4 月）。署名の中のハッシュとファイルの中身が一致することを確かめてから使いました。Linux には古い Microsoft のルート証明書が入っていないので、`osslsigncode verify` は「証明書の連鎖が検証できない」と報告します。ハッシュの一致は、それとは別に確かめられます。

主に調べたファイル:

| ファイル | 中身 |
|---|---|
| `Mail/wlmail.exe` | 起動するだけの小さな exe |
| `Mail/msmail.dll` | メールの本体（一覧、作成、送受信、オプション） |
| `Mail/mailcomm.dll` | 共通の部品（本文の組み立て、返信の引用ヘッダーなど） |
| `Mail/mailres2.dll` | 画面の設計図（UIB）、画像、色 |
| `Mail/ja/maillang.dll.mui` | 日本語の文字列、ダイアログ、メニュー、リボン、キー操作 |
| `Shared/uxcore.dll` | 画面の部品（DirectUI）。UIB を読み込んで画面を組み立てる |
| `Mail/*.thm`, `Shared/*.thm` | テーマ（ハイコントラストなど）の上書き用リソース |

## 進め方

1. **リソースの一覧を取る**: `rea inspect-pe-resources <dll> --format json`。種類・名前・言語ごとに、ファイル内の位置、大きさ、SHA-256 が出ます。自作の `tools/tools-res.py` は、この一覧をもとにリソースを切り出します。
2. **読み込み処理を逆コンパイルする**: たとえば UIB は `uxcore.dll` が読みます。`rea decompile-all` で全関数の疑似コードを出しておき、`"UIB"` という 4 バイトを比べている関数から、たどっていきました。
3. **形式を文書にし、デコーダーを書く**: 読み取った規則で、手元のすべてのリソースが最後のバイトまで読めることを確かめます（2・3 章）。
4. **作り直す側で使う**: 読み取った寸法・色・画像の番号を、作り直したアプリに当てはめます（7 章）。

AI エージェント（Claude Code）に REA を使わせて、逆コンパイルの読み取りや、デコーダーを書いて確かめる作業を手伝わせました。画面の設計図、色と画像、リボン、オプション画面など、分野ごとに別のエージェントを並行して動かしています。
