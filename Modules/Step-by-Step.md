# 環境の確認

## 資格情報

### Azure Portal

* ユーザー名：ex<2桁の数字>@csg.yoo.tokyo
* パスワード：p@ssword1rocks

### Linux マシン

* ユーザー名：azureuser
* マシン DNS 名：sentinel-ubuntu<2桁の数字>.japaneast.cloudapp.azure.com
* パスワード：p@ssword1rocks


# 作業開始

## Azure Portal にログイン

上記の資格情報で https://portal.azure.com にログインしてください。
左のメニューからリソースグループを選択肢、２つのリソースグループが見えていることを確認してください。

## Azure Sentinel へ進む

上の検索窓で、Sentinel と入力し、Sentinelをクリックします。中にあるワークスペースを選択します。

## Linux マシンからログを取る

データコネクタータブから、Syslog のコネクターを見つけて開きます。
Install agent on a non-Azure Linux Machine を選び、リンクをクリックします。

Linux 用エージェントをダウンロードおよびオンボードするのコマンドをコピーします。

Portal右上のCloud Shell を起動します。
ssh azureuser@マシンDNS名 でログインします。

![](https://github.com/YoshiakiOi/AzureSentinel-Experience/blob/main/Images/Ubuntu1.png)

コピーしたコマンドを実行します。

![](https://github.com/YoshiakiOi/AzureSentinel-Experience/blob/main/Images/Ubuntu2.png)


Portal に戻り、上の検索窓で Log Analytics と入力し、Log Analyticsワークスペースを選択します。中のワークスペースに進みます。

エージェント構成から Syslog を選択し、ファシリティの追加で、authとauthprivを選択して適用します。

## 脅威インテリジェンス情報を追加する

Sentinel ワークスペースに戻り、データコネクターから、脅威インテリジェンス - TAXII を見つけて開きます。
構成で下記情報を追加します。

* Friendly name (for server): RansomwareIPs
* API root URL: https://limo.anomali.com/api/v1/taxii2/feeds/
* Collection ID: 135
* Username: guest
* Password: guest
* Import Indicators: At most one month old (review all available options)
* Polling frequency: Once an minute (review all available options)

次の手順タブをクリックするとこれらを活用できるダッシュボードやクエリのテンプレートが多数あることが分かります。

## ログの検索

Sentinel ワークスペースでログを検索します。検索画面で以下のクエリを実行します。

```
OfficeActivity_CL
| take 10
```

このログの10個のレコードがランダムで取得されます。

次に、下記を試しましょう。

```
OfficeActivity_CL
| distinct Operation_s
```

実行結果を眺めてみましょう。Office 365 ログで記録されるオペレーション一覧が取れます。

次に、下記のクエリで、対話的な可視化を試してみましょう。

```
OfficeActivity_CL
| summarize count() by Operation_s
| render barchart 
```

## 脅威検知ルールの追加

### テンプレートの有効化

Sentinelワークスペースで、分析を選択します。規則のテンプレートから Rare RDP Connectionsを検索してみつけます。ルールの作成を押し、デフォルトの設定で作成します。

### 自分自身の検知ルールの作成

作成 > スケジュール済みクエリルールから、自分自身のルールを作ります。

* 名前：Malicious Inbox Rule - custom
* 説明： This rule is detecting on delete all traces of phishing email from user mailboxes.

とし、ロジックに進みます。下記のクエリをコピーペーストしてください。

```
let Keywords = dynamic(["helpdesk", " alert", " suspicious", "fake", "malicious", "phishing", "spam", "do not click", "do not open", "hijacked", "Fatal"]);
OfficeActivity_CL
| where Operation_s =~ "New-InboxRule"
| where Parameters_s has "Deleted Items" or Parameters_s has "Junk Email" 
| extend Events=todynamic(Parameters_s)
| parse Events  with * "SubjectContainsWords" SubjectContainsWords '}'*
| parse Events  with * "BodyContainsWords" BodyContainsWords '}'*
| parse Events  with * "SubjectOrBodyContainsWords" SubjectOrBodyContainsWords '}'*
| where SubjectContainsWords has_any (Keywords)
or BodyContainsWords has_any (Keywords)
or SubjectOrBodyContainsWords has_any (Keywords)
| extend ClientIPAddress = case( ClientIP_s has ".", tostring(split(ClientIP_s,":")[0]), ClientIP_s has "[", tostring(trim_start(@'[[]',tostring(split(ClientIP_s,"]")[0]))), ClientIP_s )
| extend Keyword = iff(isnotempty(SubjectContainsWords), SubjectContainsWords, (iff(isnotempty(BodyContainsWords),BodyContainsWords,SubjectOrBodyContainsWords )))
| extend RuleDetail = case(OfficeObjectId_s contains '/' , tostring(split(OfficeObjectId_s, '/')[-1]) , tostring(split(OfficeObjectId_s, '\\')[-1]))
| summarize count(), StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by  Operation_s, UserId__s, ClientIPAddress, ResultStatus_s, Keyword, OriginatingServer_s, OfficeObjectId_s, RuleDetail
```

エンティティマッピングでは、

* Account - FullName - UserId_s
* Host - FullName - OriginatingServer_s
* IP - Address - ClientIPAddress

を選択します。

5分間隔＆過去12時間を検索するように設定し、抑制を12時間で有効化し進みます。レビューまで進み、作成します。

## インシデント管理

Sentinel ワークスペースに進み、今のカスタムルールから作られたインシデントを選択し、すべての詳細を開きます。状態をアクティブに変えます。
また、右のエンティティタブで情報が入っていることを確認します。
コメントタブでは、「調査開始」と入れてみましょう。

## 調査

調査ボタンを押すと、エンティティ情報のグラフが出てきます。Adeleの上にカーソルを合わせ、Related Alertsをクリックしてこのユーザーに紐づく別のアラートがあるか見てみましょう。

また、Adeleをクリックしてタイムラインを見ると攻撃の流れが分かります。また、情報を選択し、すべての詳細を表示を押すと、Adeleについてまとめたユーザーページを開くことができます。UEBAが有効化されているとその情報も見ることができますが、本セッションでは見れません。

## Automation

ワークスペースでオートメーションを開き、作成から「インシデントトリガーを使用したプレイブック」を選択します。

* プレイブック名：Playbook1

として進みます。

デザイナーでステップを作っていきます。色々なコネクターがあることを確認した後、すべてタブを選び「変数」と検索して出てきた「変数」をクリックします。アクションの中から、「変数を初期化する」を選びましょう。

* 名前：インシデント本文
* 種類：文字列

とします。

次に新しいステップ - 「変数」 - 「変数の設定」と進み、

* 名前：インシデント本文
* 値：右に選べる値群が出てくるので、その中から Sentinel のアイコンが付いた「本文」を選ぶ

を選択し、左上の保存を押します。

次に作成から、オートメーションを選びルールを作っていきます。

* オートメーションルール名：Automation1
* 条件 - 分析ルール名 - 次を含む - Malicious Inbox Rule - custom (複数あるときはすべて)
* アクション - プレイブックの実行 - Playbook1
＊グレーアウトされているときは、アクセス許可を選択して追加します。

分析のアクティブな規則から、さきほど作った Malicious Inbox Rule - custom を選択し編集を押します。アラートの抑制をOFFにして進み、インシデントの自動化に設定が入っていることを確認し、レビューへ進みます。その後保存を押します。

再度オートメーションからプレイブックタブに進み、Playbook1を選択します。少し時間がたっていると履歴に今の実行結果が反映されているはずです。





