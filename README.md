# certmgr - ＳＳＬ証明書マネージャー
ＳＳＬ証明書（ＣＳＲ、公開鍵、秘密鍵、中間証明書・クロスルート証明書）をまとめて管理するためのプログラムです。
以下の効能を期待して作成しています。

* 証明書リポジトリ（ＤＢ）内にＳＳＬ証明書を収容することでＳＳＬ証明書を散逸を防ぐ。そのためバックアップが容易です。
* 証明書管理手順の正規化ができる。
* ＣＳＲの作成・署名・デプロイといった手順をコマンド一発で行えるようになる。
* 中間証明書・クロスルート証明書の組み合わせを自動的に手繰ってくれる。
* 認証局より（メールで）送られてきた証明書をとりあえず放り込んでおいて、必要なものだけ取り出すことができる。

またプログラム作成にあたり以下の点に気を付けています。

* 外部モジュールへ過度に依存しない。デプロイはシンプルに。
* そのため証明書に関する主要なオペレーションは全て openssl コマンドを呼び出す形で実装。
* なるべくセキュアになるようプログラミングする。
* オブジェクティブな構造に作り替えたい。

## 使い方
* ＳＳＬ証明書一覧
  * `certmgr [-c config_file] list [-r][-o <ORDER[,ORDER]...>][[-o <ORDER>]...]`
* ＳＳＬ証明書の詳細表示
  * `certmgr [-c config_file] info <証明書ＩＤ|コモンネーム|ファイル名>[<証明書ＩＤ|コモンネーム|ファイル名>...]`
* ＣＳＲ作成
  * `certmgr [-c config_file] generate [-m][-u][-t TYPE][-s SIGN][--sans=<ドメイン>[,<ドメイン>...][--ocsp-must-staple] <サブジェクト|コモンネーム>`
* ＳＳＬ証明書のインポート（ＣＳＲ、公開鍵、秘密鍵、中間証明書問わず）
  * `certmgr [-c config_file] import [-m][-u] <証明書ファイル名> [<証明書ファイル名>...]`
* ＳＳＬ証明書のエクスポート（ＣＳＲ、公開鍵、秘密鍵、中間証明書問わず）
  * `certmrt [-c config_file] export [-a][-b <バックアップ先パス名>]`
  * `certmrt [-c config_file] export [-r][-b <ベースファイル名>][--pubout=公開鍵ファイル名][--keyout=秘密鍵ファイル名][--chainout=中間証明書ファイル名] <コモンネーム|証明書ＩＤ>`

## オプション
* `-o`
  * リストの順番の指定
* `-m`
  * 作成されるＣＳＲを「マーキングします」。
* `-u`
  * 作成されるＣＳＲを「マーキングしません」。
* `-t TYPE` or `--type=TYPE`
  * ＣＳＲの鍵種別の指定（`rsa:2048`, `rsa:1024`, `rsa:3072`, `rsa:4096`, `prime256v1`, `secp256r1`, `secp384r1`, `secp521r1`）
* `-s SIGN` or `--sign=SIGN`
  * ＣＳＲの署名種別の指定（`sha256`, `sha`＝`sha1`, `sha384`, `sha512`）
* `--sans=ドメイン`
  * カンマ区切りで複数のＳＡＮｓ（Subject Alternative Names）を指定する。
* `--ocsp-must-staple`
  * ＯＣＳＰ Ｍｕｓｔ－Ｓｔａｐｌｅを有効にする。証明書のオンライン失効確認に失敗すると一時的に失効扱い（hard fail）となります。
* `-a` or `--all`
  * 証明書リポジトリ中のすべての証明書を対象とします。出力先パス名を `-b` オプションで指定します。
* `-r` or `--full-chain` or `--fullchain`
  * 公開鍵をエクスポートする際に再帰的に中間証明書をたどります（フルチェイン証明書）。
* `-b` or `--basename` or `--backup`
  * 各種証明書（公開鍵、秘密鍵、中間証明書）の出力ファイル名のベースを指定する（拡張子はなしで）。下記のオプションにより上書きできる。
* `--pubout`
  * 公開鍵の出力ファイル名を指定する。
* `--keyout`
  * 秘密鍵の出力ファイル名を指定する。
* `--chainout`
  * 中間証明書（クロスルート証明書を含む）の出力ファイル名を指定する。

## 設定ファイル
certmgr は設定ファイルを必要とします。
以下の順序で設定ファイルを探します。

* （カレントディレクトリの）.certmgrrc
* （ホームディレクトリの）.certmgrrc
* /etc/certmgrrc

また、サブコマンドの前に `-c 設定ファイル名` を指定することで設定ファイルの読み込みを上書きできます。

設定ファイルでは最低でも「CertRepo」の指定が必須となります。
今のところ「dbi:SQLite:」以外のデータソースには対応していません。

### certmgrrc
    CertRepo:	dbi:SQLite:dbname=/var/db/certmgr.sqlite
    UserName:
    PassWord:
    DefaultMarked:	yes
    BaseName:	%CN%

## 証明書のパッケージング
* 証明書（ＣＳＲ、公開鍵、秘密鍵）一つの証明書ＩＤでパッケージングされます。
* 中間証明書（クロスルート証明書）は「公開鍵」の一種として１つの証明書ＩＤでそれぞれパッケージングします。
* 証明書ＩＤの発行はＣＳＲまたは公開鍵・中間証明書の、作成（ＣＳＲのみ）またはインポート時に行われます。
* また紐づけは証明書の中の「パブリックキー」（-----BEGIN PUBLIC KEY-----～-----END PUBLIC KEY-----）の同一性に基づいて行います。
* そのため、同一鍵のインポートは行えません（無視されます）。
* あくまでも「公開鍵」ベースなので、同一サブジェクト（ディスティングウィッシュ名）による複数の証明書の作成・インポートは可能です。

## 状態遷移
* ＣＳＲ作成→新規証明書ＩＤ発行・ＣＳＲおよび秘密鍵の作成・収納→公開鍵のインポート→完了
* ＣＳＲインポート→新規証明書ＩＤ発行・ＣＳＲの収納→公開鍵のインポート→完了
* 公開鍵インポート→新規証明書ＩＤ発行・公開鍵の収納→完了
* 中間証明書インポート→新規証明書ＩＤ発行・中間証明書の収納→完了

また、ＣＳＲおよび公開鍵のインポートにおいて、公開鍵およびＣＳＲまたは秘密鍵の追加インポートが行える。

* ＣＳＲインポート→新規証明書ＩＤ発行・ＣＳＲの収納→公開鍵・秘密鍵のインポート→完了
* 公開鍵インポート→新規証明書ＩＤ発行・公開鍵の収納→ＣＳＲ・秘密鍵のインポート→完了

合わせてＣＳＲのみインポートするだけのオペレーションも許可している。

* ＣＳＲインポート→新規証明書ＩＤ発行・ＣＳＲの収納→完了

なお秘密鍵のインポートについては、証明書ＩＤ発行に必要な情報が足りないので、証明書ＩＤに紐づけ不能のためインポートはできません。

## 依存
* [Perl](https://www.perl.org/) （動作確認は 5.26）
* [App::Rad](http://search.cpan.org/~garu/App-Rad-1.05/)
* [DBD::SQLite](http://search.cpan.org/~ishigaki/DBD-SQLite-1.54/)
* [DBI](http://search.cpan.org/~timb/DBI-1.637/)
* [openssl](https://www.openssl.org/) （動作確認は 1.0.2k）

## バグ

### 重大バク
* 現バージョン（０系）は証明書リポジトリの内部フォーマットの互換性を維持しません。
* 証明書一覧（certmgr list）機能はフィルタリング等を想定しておらず、使い勝手を変える可能性があります。

### 優先度低バグ
* 証明書チェインの検証は行っていません。
* 証明書（ＩＤ）の削除は実装していません。
* 証明書マーカーの変更は実装していません。
* ＣＲＬ（ＯＣＳＰ）には対応していません。

## 仕様
* コモンネームが無いＣＳＲおよび公開鍵はインポートできません。
* 中間証明書をインポートしていたらコモンネームが無かった場合、それはルート証明書の可能性があります。ルート証明書は本システムの管理対象外です。
* ＥＶＳＳＬ証明書への対応は予定していません（機会がないため）。おそらくＵｎｉｃｏｄｅ対応が必須と思われ。
* 暗号化された秘密鍵のインポートは行えません。
* 秘密鍵の保存は暗号化されません。

## ＴＯＤＯ
ここまでできてたら予想できると思いますが以下の機能を実装していきたいです。

* 内部にＨＳＭ（Hardware Security Module）を持つようなアプライアンス機器のＣＳＲ生成（外部委託）する機能。
* ＣＳＲをＡＣＭＥ（Automatic Certificate Management Environment）で署名する機能。
* その際、チャレンジタイプ（http-01, tls-sni-01 または dns-01）に対応したデプロイ方法の自由化（外部委託）。
* 証明書のデプロイする機能（外部委託）。
* 証明書有効期限、失効等の監査および報告する機能。
* 公開鍵をインポートする際にルートＣＡからのチェインをたどって問題なければインポートするようにする機能。

## バージョン番号
「0.YYYYMMDD」。将来内部フォーマットの仕様および更新ルールが確定したら、バージョン１に格上げする予定（いわゆる x.y フォーマット）。

### 0.20171113
証明書のユニーク性を確認するためのＳＰＫＩ（Subject Public Key Info）ハッシュ値取得方法をＨＰＫＰ仕様に改めました。
この結果、既存の証明書情報の照合ができなくなっています。
一旦すべての証明書を export して、新しい証明書リポジトリに import してください。

`certmgr req` を `certmgr generate` に改めました。

## 著者
重村法克

## スポンサー
[株式会社エンターモーション](http://entermotion.jp/)

## 参考文献
* [SSLサーバー証明書の作り方](https://wiki.ninth-nine.com/SSL証明書/サーバー証明書の作り方)
* [俺々ＳＳＬサーバー証明書の作り方](https://wiki.ninth-nine.com/SSL証明書/俺々SSLサーバー証明書の作り方)
* [openssl req](https://wiki.ninth-nine.com/OpenSSL/req)
* [openssl x509](https://wiki.ninth-nine.com/OpenSSL/x509)
* [X.509証明書の検証手順とありがちな脆弱性](https://qiita.com/n-i-e/items/35cba71d04b9123e676c)
* [OCSP Must-Staple と OCSP Multi-Stapling、及び OneCRL](https://www.cybertrust.ne.jp/journal/ocsp-must-staple-ocsp-multi-stapling-onecrl.html)
