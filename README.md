本稿は、2018年7月2日に開催された Anti-Phishing Working Group 主催『[巧妙化・国際化するオンライン詐欺やサイバー犯罪にどう対応していくのか？](https://apwg-201807.peatix.com/)』にて講演された内容の解説記事です。

# 登壇資料
[![thumbnail](https://image.slidesharecdn.com/20180702apwgnoriakihayashi-200323101709/95/live-1-638.jpg)](https://www.slideshare.net/NoriakiHayashi/live-230725152)

- 登壇資料のダウンロードはこちら -> [【LIVE】 すぐ貢献できる！偽サイトの探索から通報まで](https://www.slideshare.net/NoriakiHayashi/live-230725152)

不特定多数を狙った偽サイト・フィッシング詐欺は未然に防ぐのが難しく、犯罪者にとっては期待利益が高い犯行のひとつです。こうした現状を打開しようと、個人のボランティア活動として、技能を活かし「サイバー空間の浄化活動（サイバーパトロール）」に貢献されている方が数多くいらっしゃいます。本セミナーでは、誰かのために貢献してみたいとの志をお持ちの方へ、フリーツールを使った偽サイトの探索から得られた情報の通報先についてLIVE形式でご紹介いたします。

# 犯罪抑止のための打ち手
- 『[刑務所の経済学](https://www.amazon.co.jp/dp/4569801617)』中島隆信 より抜粋

>犯罪を抑止する方法は、**犯罪から得られる便益を減らし**、露見した時の損失を増やすことである。<省略>抑止のためには**成功確率を下げればよい。**

犯罪者にとって一番の痛手とは、誘導を狙っていた詐欺サイトが「**テイクダウン（閉鎖）**」され、自らも法執行機関によって「**検挙**」されるという不利益を被ることです。

# Pro bono publico:プロボノ
職務上の専門的な知識や経験、技能を社会貢献のために無償もしくはわずかな報酬で提供する活動

# 活動における基本的心得
- 警察庁「[サイバー防犯ボランティア 活動のためのマニュアル](https://www.npa.go.jp/cyber/policy/volunteer/manual.pdf)」, 平成29年(2017年)5月 より抜粋

>1. 安全を第一に
>2. インターネットの実態を知る
>3. 秘密の保持
>4. 最新情報の共有
>5. 関連機関・団体等との連携
>6. 活動記録の保存
>7. 実社会での活動

# 代表的な詐欺サイト
## フィッシング詐欺サイト
フィッシング（Phishing）とは、実在する組織を騙って、ユーザネーム、パスワード、アカウントID、ATMの暗証番号、クレジットカード番号といった個人情報を詐取する行為です。

## 偽ショッピングサイト
偽ショッピングサイト（FakeStore）とは、実在する企業のサイトに似せた・そのままコピーした「なりすましECサイト」や、ショッピングサイトにてお金を振り込んだにもかかわらず商品が送られてこない「詐欺サイト」の総称です。

## サポート詐欺サイト
サポート詐欺（Tech Support Scam）とは、サイト上でウイルス感染やシステムの異常などを示す表示するサイトです。利用者の不安をあおり、画面上に表示されているサポート電話に問い合わせをさせ、サポート契約の名目で金銭を詐取する詐欺行為です。

- トレンドマイクロ セキュリティブログ 「[不安をあおって電話でだます「サポート詐欺」の手口を追う](https://blog.trendmicro.co.jp/archives/13970)」, 2016年10月31日

# 犯罪者が被害者を詐欺サイトへ誘導する手口

| 手口 | 代表的な事例 |
|:---|:---|
| 検索エンジン（Googleなど）の検索結果より誘導 | 偽ショッピングサイトやサポート詐欺サイト、マルウェア感染など |
| メール（フィッシングメール）やSMS（スミッシング）、電話による被害者への直接接触により誘導 | IDやパスワード、銀行口座、クレジットカード番号などの詐取 |

# 探索に有効な無償利用可能なウェブサービス

## 傾向を知る
- フィッシング対策協議会 緊急情報, https://www.antiphishing.jp/news/alert/
- JC3 犯罪被害につながるメール INDEX版, https://www.jc3.or.jp/topics/vm_index.html
- 国立大学法人 電気通信大学 情報基盤センター セキュリティ情報アーカイブ, https://www.cc.uec.ac.jp/blogs/news/cat62/
- 消費者庁, 悪質な海外ウェブサイト一覧, https://www.caa.go.jp/policies/policy/consumer_policy/caution/internet/#m03
- 【ご注意ください】「楽天を装ったWEBサイト」一覧, https://ichiba.faq.rakuten.net/detail/000009756

## データの収集
- Yahoo!リアルタイム検索, https://search.yahoo.co.jp/realtime
- TweetDeck, https://tweetdeck.twitter.com/

## リポジトリ
- PhishTank, https://www.phishtank.com
- OpenPhish, https://openphish.com/
- PhishStats, https://phishstats.info/
- Phishing.Databasem, https://github.com/mitchellkrogza/Phishing.Database
- neonprimetime / PhishingKitTracker, https://github.com/neonprimetime/PhishingKitTracker

## ドメイン名の探索
- DN Pedia, https://dnpedia.com/tlds/search.php

## 派生ドメイン名
- dnstwister, https://dnstwister.report/

## スクリーンショット取得
- ScreenshotMachine, http://screenshotmachine.com/

## 状態取得・調査
- aguse.jp, https://www.aguse.jp/
- Urlscan.io, https://urlscan.io/
- Web Insight, https://webint.io/

## サイト評価
- VirusTotal, https://www.virustotal.com/gui/domain/
- Google Safe Browsing API, https://safebrowsing.google.com/
- Trend Micro Site Safety Center, https://global.sitesafety.trendmicro.com/?cc=jp
- CheckPhish.ai, https://checkphish.ai/
- phishcheck.me, https://phishcheck.me/
- gredでチェック, http://check.gred.jp/

## リバース WHOIS
- DomainTools Whois Lookup, https://whois.domaintools.com/
- DomainBigData, https://domainbigdata.com/
- DomainWatch, https://domainwat.ch/

## IPアドレス
- Censys, https://censys.io/
- SHODAN, https://www.shodan.io/
- Hurricane Electric BGP Toolkit, https://bgp.he.net/
- MYIP.MS, https://myip.ms/
- ipinfo.io, https://ipinfo.io/

## ドメイン Historical Data
- RiskIQ Community Edition, PassiveTotal, https://community.riskiq.com/home
- SecurityTrails, https://securitytrails.com/
 
## ホスティングプロバイダの特定
- HostingDetector.com, https://hostingdetector.com/

>最新の情報源については「[普段の調査で利用するOSINTまとめ](https://qiita.com/00001B1A/items/4d8ceb53993d3217307e)」をオススメします。

# 探索に有効な無償利用可能なツール
- [0x4445565A / Sushiphish](https://github.com/0x4445565A/sushiphish)
- [elceef / dnstwist](https://github.com/elceef/dnstwist)
- [ninoseki / miteru](https://github.com/ninoseki/miteru)
- [ninoseki / osakana](https://github.com/ninoseki/osakana)
- [ecstatic-nobel / OSweep](https://github.com/ecstatic-nobel/OSweep)
- [x0rz / phishing_catcher](https://github.com/x0rz/phishing_catcher)
- [t4d / StalkPhish](https://github.com/t4d/StalkPhish)
- [sherlock-project / sherlock](https://github.com/sherlock-project/sherlock)：ユーザー名でソーシャルメディアアカウントを探すツール

# 悪性ドメインのハンティング方法
1. 「[DN Pedia](https://dnpedia.com/tlds/search.php)」を使い、ブランド名や特徴的な単語をクエリに検索する
2. 「[dnstwister](https://dnstwister.report/)」を使い、ホモグラフィック攻撃、タイポスクワッティング攻撃の兆候を確認する
3. 「[HostingDetector.com](https://hostingdetector.com/)」/「[DomainTools Whois Lookup](https://whois.domaintools.com/)」/「[DomainBigData](https://domainbigdata.com/)」を使い、WHOIS情報を深掘りする
4. 「[Google Safe Browsing API](https://safebrowsing.google.com/)」/「[VirusTotal](https://www.virustotal.com/gui/domain/)」を使い評判を確認する

# フィッシングサイトの通報

|被害|通報窓口|
|:--|:--|
|フィッシングと思しきメールを受け取った|[フィッシング対策協議会](https://www.antiphishing.jp/contact.html), info@antiphishing.jp|
|ネット犯罪に遭遇|[警察庁 サイバー犯罪相談窓口](https://www.npa.go.jp/cyber/soudan.htm)|
|迷惑メールを受け取った|[迷惑メール相談センター](http://www.dekyo.or.jp/soudan/index.html)|
|偽装品の販売に遭遇|[一般社団法人 ユニオン・デ・ファブリカン](http://www.udf-jp.org/)|
|商品やサービスなど消費生活全般に関する苦情や問合せ|[独立行政法人国民生活センター 消費生活センター](http://www.kokusen.go.jp/)|
|自社ブランドになりすました偽サイトを確認|[悪質ECサイトホットライン 通報フォーム, 一般社団法人セーファーインターネット協会（SIA）](https://www.saferinternet.or.jp/akushitsu_ec_form/)|
|JPドメイン名の不正登録に関する情報受付窓口|[株式会社日本レジストリサービス(JPRS)](https://jprs.jp/whatsnew/notice/2019/191002.html)|
|サイトに違法情報（銀行口座や飛ばし携帯などの売買）の掲載を確認|[インターネットホットラインセンター](http://www.internethotline.jp/)|

## フィッシング対策協議会
info@antiphishing.jp 宛てに報告。詳細な情報提供方法は [こちら](https://www.antiphishing.jp/registration.html)

フィッシング対策協議会「[フィッシング対策ガイドライン 2020年度版](https://www.antiphishing.jp/report/antiphishing_guideline_2020.pdf)」, 2020年06月02日 より抜粋

>協議会ではフィッシング詐欺報告は電子メールで受付けている。フィッシングメールに関する報告は、フィッシングメールを転送、あるいは本文に貼り付け、または以下のようにタイトル、差出人名、送信日時、概要などを記述して報告していただきたい。

- フィッシングメール報告の例

```
Subject：フィッシングメールに関する情報提供
タイトル：緊急のお知らせ
差出人名：john@xxbank.example.co.jp
送信日時：2008 年3 月XX 日
概要：○○銀行を装ってリンクを含んだメールを送ってきた。
--
○○ ○○（報告者氏名、匿名での報告も可）
```

- フィッシング被害報告の例

```
Subject：フィッシング被害に関する情報提供
概要：○○銀行をかたるフィッシング（e-mail を添付します）があり、そこに ID、パスワードを入力し
てしまいました。 すぐ気が付いたのでパスワードを変更し、当該銀行に連絡・相談し対策を進めて
います。 また、警察．．．
--
○○ ○○（報告者氏名、匿名での報告も可）
```

## Google Safe Browsing
[Report Phishing Page](https://safebrowsing.google.com/safebrowsing/report_phish/) のフォームにフィッシングサイトのURLを報告。
<img width="576" alt="Google_report_phish.png" src="https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/294810/a600f0ee-82d4-6cb7-9190-4ec1eb409fff.png">

## Microsoft Security Intelligence
Microsoft Security Intelligenceが運営する「[Report an unsafe site](https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest)」フォームにフィッシングサイトのURLを報告。
<img width="1324" alt="Microsoft_Report unsafe site.png" src="https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/294810/0a8a889e-b3dd-5135-b3df-35eaa20bbc30.png">

## PhishTank
[PhishTank](https://www.phishtank.com/)は、コミュニティによって運営されているWebサービスです。コミュニティに参加する人たちがフィッシングURLの「検証」および「報告」が可能です。
もし、あなたがフィッシングサイトを発見したとき、すでに知られているURLなのか、まだ多くの人にしられていないURLなのか確認することができます。

### URLの検証
URLの検証は直ちに利用可能です。フォームにURLを入力し、`[Is It a phish?]`ボタンをクリックします。
![01_PhishTank.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/294810/b1a2aa0d-2b00-d123-5993-7e6d975a2a2d.png)

PhishTankにすでに報告されているURLの場合、「だれ, `by`」が「いつ, `Submitted`」報告しているのか「登録番号 `Submission #`」とともに表示されます。
URLの評価について「投票 `Vote`」することが可能です。フィッシングサイトであると思う場合には、`[Is a phish]`ボタンをクリックします。このURLはフィッシングサイトではないと思う場合には`[Is NOT a phish]`ボタンをクリックします。
![PhishTank_phish_detail.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/294810/b08cff89-0f75-5509-7422-5229ddf9caff.png)

これまでにPhishTankへ報告されていないURLの場合、`Nothing known about`の表記とともに入力したURLが表示されます。
初の「報告者 Submitter」としてコミュニティに貢献できるチャンスです。
![PhishTank_Nothing.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/294810/560f34ae-7261-a5d6-c9b5-7cc495844ff0.png)

### PhishTankのアカウント作成
PhishTankにて「報告者 Submitter」として貢献するには、無償のアカウント登録が必要です。「[Register](https://www.phishtank.com/register.php)」ページにて、メールアドレス、ユーザー名、パスワードを入力します。
<img width="1110" alt="PhishTank_register.png" src="https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/294810/ddcbb1a6-df36-7995-eb81-1dcbbb3e2c27.png">

### フィッシングURLの報告
作成したPhishTankのアカウントで「[Sing In](https://www.phishtank.com/login.php)」します。
<img width="1110" alt="PhishTank_Sign In.png" src="https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/294810/f4789d2d-052f-e8dd-5aed-9030a89fb739.png">

疑わしいURLを手元に用意し、「[Add a Phish](https://www.phishtank.com/login_required.php)」 にアクセスします。
`[Phish URL]`にフィッシングサイトのURLを入力し、「`What is the organization referenced in the email?`（フィッシングメールの分類）」を選択し、`[Submit]`ボタンをクリックします。
<img width="1392" alt="PhishTank_add a phish.png" src="https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/294810/21d0e5ed-b7be-ace9-0fc3-291650d2f355.png">

無事、フィッシングURLの登録が完了すると、次の画面が表示されます。
<img width="1392" alt="PhishTank_thanks.png" src="https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/294810/fdfb6c0d-16f6-cea6-97c6-0d5c10b073c5.png">

## プロバイダへのテイクダウン要請文例
フィッシング対策協議会「[フィッシング対策ガイドライン 2020年度版](https://www.antiphishing.jp/report/antiphishing_guideline_2020.pdf)」, 2020年06月02日 より抜粋

```
To whom it may concern,
[簡潔な企業プロファイル].
The website is located at the following address:
＜当該フィッシングサイトのURI＞
For your information, the fraudulent website appears to be a forgery of this legitimate
website:
<正規サイトのURL>
Please take all necessary measures to suspend services of this fraudulent site.
We highly appreciate your cooperation on this matter.
Thank you very much. Sincerely,

[担当者、送信者の名前]
[担当者、送信者の所属部署]
[企業名]
[国際電話番号]
[担当者、送信者のメールアドレス]
```

# コミュニティで注意を促す
## 偽サイトのURLを無害化
コミュニティに対して偽サイトの情報を共有する際、共有先にて意図せぬ事故を防ぐことが重要です。
そこで、URLやIPアドレスなどの値に対して、記号や文字の置換を行うことが一般的です。このように、リンクが機能しないように無害化することを、「**Defang**」と呼びます。
次のような方法によるDefangが一般的です。

```
192.168.100.1 => 192.168.100[.]1
http://www.example.com => hXXp://www[.]example[.]com
info@example.org => info[at]example[.]org
```

大量の情報に対して、Defang処理を行う場合、「[Floyd Hightower](https://hightower.space/)」氏によって開発された「IOC Fanger GUI」オンラインツールによって一括処理を行うことが可能です。

- IOC Fanger GUI：http://ioc-fanger.hightower.space/

テキストボックスにDefang処理すべき、URLやIPアドレスを入力します。`Defang`ラジオボタンを選択し、`[送信]`ボタンをクリックします。
なお、Defangされた情報を元に戻す場合には、`Fang`ラジオボタンを選択します。
![IOC Fanger GUI .png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/294810/8fd5b338-3d96-057a-8017-dc92b1016d5f.png)

## Tweetする
個人が多くの人へ偽サイトの情報について注意を促す場合、[Twitter](https://twitter.com/search/%7BsearchTerms%7D%20lang:ja?source=desktop-search) などのソーシャルメディアを活用するのが有効です。

ここでは、文例について検討します。

<img width="375" alt="Phishing_Alert_Tweet.png.png" src="https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/294810/2bdebc0b-6722-f547-8099-243fdd396dc0.png">

|項目|内容|
|:--|:--|
|ハッシュタグ「#Phishing」|同じくコミュニティで活動している「**Phish Hunter**」や「**セキュリティリサーチャー**」へ広く知らせることを目的としています。|
|「abuse報告です。」の一文|不正行為の通報窓口へ連絡済みであることを示しています。どの窓口へ報告済みなのか文末にチェックボックスをつけて記載しました。|
|偽サイトのURL|必ずDefang処理ずみのURLを記載しましょう。|
|偽サイトのIPアドレスとAS番号|こちらもDefang処理ずみのIPアドレスです。|
|Registar|何処のドメインレジストラにて取得されていたのか記載します。|
|Brand|フィッシングサイトの場合、標的ブランドを記載します。標的ブランドが公式Twitterアカウントを運用している場合、@ツイートするのもよいでしょう。|
|URLScanの結果|偽サイトの稼働期間は極めて短命です。報告時の稼働状況をあとから確認できるように「urlscan.io」のスキャン結果を記載しておくこともよいでしょう。|
|画像|フィッシングメール、フィッシングサイト、digコマンドの結果、[Maltego](https://www.maltego.com/)や[ThreatCrowd](https://www.threatcrowd.org/)など調査ツールにてまとめた情報などを投稿する場合が多いです。|

- Maltego, How to Uncover Phishing Domains Using Maltego to Analyze Domain Infrastructure, 2020/04/22, https://www.maltego.com/blog/how-to-uncover-phishing-domains/
- Maltego, Using Maltego to Hunt for Phishing Subdomains, 2020/07/01, https://www.maltego.com/blog/using-maltego-to-hunt-for-phishing-subdomains/

# 関連団体による活動内容

## フィッシング対策協議会の取り組み

- フィッシング対策協議会 パンフレット「[活動のご案内](https://member.antiphishing.jp/about_ap/pdf/pamphlet_200221.pdf)」 より抜粋

> 日々発生する違法なフィッシングサイトの報告を受け、JPCERT/CCとの連携によって違法なサイトをいち早く閉鎖するオペレーションを行っています。海外の犯罪グループによる犯行の場合もあるため、国際的な情報交換なども不可欠です。緊急情報の発信だけでなく、収集された情報をまとめ、報告書の発行などもおこなっています。

![capj_activity.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/294810/807d367a-ea22-2061-9ff2-cb4d88da1d71.png)

- フィッシング対策協議会「[フィッシングサイト URL 提供](https://www.antiphishing.jp/enterprise/url.html)」 より抜粋

> フィッシング対策協議会では、JPCERT/CCと連携し、2010 年 2 月から、フィッシング対策機能への実装を前提としたフィッシングサイトの URL 情報の提供を開始いたしました。
>
> <b>対象</b>
>フィッシングサイトへのアクセスを遮断するソフトウエアやサービス (ブラウザ、ウイルス対策ソフト、ツールバーなど) を提供している法人、 且つ、提供の条件に合致しているとJPCERT/CCが認めた法人
>
> 提供先組織 43 組織 (2020 年 6月時点)

## 警察庁の取り組み

- 警察庁 広報資料「[APWGに対する海外偽サイト等の情報提供の開始について](https://www.npa.go.jp/cyber/pdf/APWG.pdf)」, 平成28年（2016年）7月14日 より参照

> ウェブブラウザ事業者等が加盟する、国際的な団体であるAPWG（Anti-Phishing Working Group)へ海外偽サイト等の情報提供を行う。これにより、警察が把握した海外偽サイト等について、ウイルス対策ソフト等を導入していない利用者に対しても警告が可能となり、海外の偽サイトによる被害のより一層の抑止が可能となる。

- 警察庁 広報資料「[日本サイバー犯罪対策センターによるインターネットショッピングに係る詐欺サイト対策について](http://www.npa.go.jp/cyber/policy/pdf/20171221.pdf)」, 平成29年（2017年）12月21日
- 一般財団法人 日本サイバー犯罪対策センター（JC3）「[APWG・JC3共同レポート（要約） 顕在化した偽ショッピングサイトの脅威]()」, 2018年6月6日
- Anti-Phishing Working Group「[Revealed Threat of Fake Store, Proposed New Definition of Fake Store](https://docs.apwg.org//reports/Revealed_Threat_of_Fake_Store_JC3_20180318.pdf)」, 2018年6月5日

## PhishTankの取り組み
PhishTankではコミュニティに登録されたフィッシングURLのデータを `RSS` や `API` の形式にて無償提供しています。こうしたデータは研究機関や組織が活用しています。
開発者としてデータを入手する方法は、「[Developer Information](https://www.phishtank.com/developer_info.php)」ページに詳細が記載されています。

- 「[Friends of PhishTank](https://www.phishtank.com/friends.php)」ページより抜粋
<img width="1392" alt="PhishTank_Friends.png" src="https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/294810/bb24fd9a-68c0-3420-9d62-d3d0d1a432f2.png">


# むすび
<dl>
  <dt>・現代のサイバー犯罪は経済活動が主目的</dt>
      <dd>だからこそ打ち手がある</dd>
  <dt>・犯罪者の期待利益を下げる取り組み</dt>
      <dd>犯罪の「コスト」を上げ「成功確率」を下げる</dd>
  <dt>・サイバー犯罪に対して一緒に戦いましょう</dt>
      <dd>身の安全を確保し、まずはできることから</dd>
</dl>

# 参考情報
## フィッシング対策協議会
- フィッシング対策協議会 「活動のご案内」, https://member.antiphishing.jp/about_ap/pdf/pamphlet_200221.pdf
- フィッシング対策協議会 「フィッシングサイト URL 提供」, https://www.antiphishing.jp/enterprise/url.html 
- フィッシング対策協議会 「フィッシング対策ガイドライン 2020年度版」, 2020年06月02日, https://www.antiphishing.jp/report/antiphishing_guideline_2020.pdf
- フィッシング対策協議会 「フィッシングレポート 2020 の掲載について」, 2020年06月02日, https://www.antiphishing.jp/report/phishing_report_2020.pdf
- 一般社団法人 セキュリティ対策推進協議会（SPREAD）, いまなお深刻なフィッシング詐欺被害, 2015年04月22日, https://www.spread.or.jp/column/2015/04/22/2947/

## JPCERT/CC
- 偽JPCERTドメイン名を取り戻すための60日間~ドメイン名紛争処理をしてみた～, 2017年05月19日, https://blogs.jpcert.or.jp/ja/2017/05/udrp.html
- JPCERT/CCに報告されたフィッシングサイトの傾向, 2020年03月19日, https://blogs.jpcert.or.jp/ja/2020/03/phishing2019.html

## 講演スライド
- 大角祐介, フィッシング詐欺と如何に戦い、そして如何にして勝つか, 2019年10月16日, https://www.slideshare.net/techblogyahoo/mixleap
- 今井健, 国内を標的とした 銀行フィッシング詐欺の分析, 2020年02月13日, https://speakerdeck.com/studentkyushu/guo-nei-wobiao-de-tosita-yin-xing-huitusinguzha-qi-falsefen-xi
- 林憲明, APWG Counter-eCrime Operations Summit 2013 (CeCOS VII), Finding the Banking Trojan in Eastern Asia (極東地域におけるオンライン銀行詐欺ツール関する所見), 2013年04月23日, https://www.antiphishing.jp/report/wg/2013cecosvii.html
- 林憲明, APWGセミナー, 【LIVE】 すぐ貢献できる！偽サイトの探索から通報まで, 2018年07月02日, https://www.slideshare.net/NoriakiHayashi/live-230725152

## Phish Hunter記事
- Manabu Niseki, ゼロからはじめるフィッシング対策, https://ninoseki.github.io/2019/01/24/how-to-protect-you-from-phishing.html
- 午前７時のしなもんぶろぐ, 【やってみた】意外と簡単？　フィッシングサイトの発見から通報まで, 2020年9月22日, https://am7cinnamon.hatenablog.com/entry/how-to-phishhunt

## 英語記事
- Execute Malware Blog, Finding Phishing Websites, 2016年09月7日, http://executemalware.com/?p=258
- Imperva, Our Analysis of 1,019 Phishing Kits, 2018年01月04日, https://www.imperva.com/blog/our-analysis-of-1019-phishing-kits/

## Qiita投稿記事
- @moneymog, あやしいサイトの3分調査方法(初心者向け), https://qiita.com/moneymog/items/2205388ff18b3f89f021
- @sanyamarseille, 使えるサイト, https://qiita.com/sanyamarseille/items/da922f62e4b41ccf4cab
- @00001B1A, 普段の調査で利用するOSINTまとめ, https://qiita.com/00001B1A/items/4d8ceb53993d3217307e
