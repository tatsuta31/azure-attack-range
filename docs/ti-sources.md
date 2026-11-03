# 外部 TI ソースの選定（Foundry 連携用）

Foundry のエージェントがアラートを解析するときに参照する、外部の脅威インテリジェンス（TI）の候補一覧。**無料のまま商用で使えるか** を、各提供元の規約ページで確認した（確認日 2026-11-04）。

Excel でフィルタするなら CSV を使う：[`ti/ti_sources.csv`](ti/ti_sources.csv)（UTF-8 BOM 付き）

## 「商用利用」列の意味

| 値 | 意味 |
|---|---|
| 可能 | 提供元が、無料のまま商用で使えると明記している（帰属表示などの条件はあり得る） |
| 条件付き | 自社の防御には使えるが、製品・MSSP・再配布は有料、など範囲に条件がある |
| 要確認 | 規約に商用利用の明記が見つからなかった |
| 不可 | 無料版は非商用のみ（商用は有料プラン） |

## 「取得方法」列の意味

| 値 | 意味 |
|---|---|
| API | 1 件ずつ問い合わせる（IP を渡すと評価が返る） |
| ファイル（提供元サイト） | 提供元の Web サイトから一覧（txt / csv など）をまとめてダウンロードする |
| ファイル（GitHub） | GitHub のリポジトリにある一覧をダウンロードする |

「有料プランの料金」は、無料版では商用に使えないものなどについて、提供元の料金ページに出ていた金額（米ドル、税抜き、確認日時点）。「見積もり」は価格が公開されていないもの。

## 注意

- **法的な判断ではない。** 規約は変わるので、業務で使う前に最新の規約を確認し、必要なら法務に相談すること
- **「商用」の範囲に注意。** 「自社の社内業務」まではよくても、**顧客向けのサービス（MSSP / MDR）や再配布は別扱い** の規約がある（Maltrail、MaxMind、SANS ISC など）。SOC としてお客様の監視に使う場合は、後者に当たるかを確認する
- **AI での利用。** abuse.ch（URLhaus / MalwareBazaar / ThreatFox）は「AI モデルの学習・改善への利用」を禁止している。Foundry で照会結果を解析に使うだけなら学習ではないが、念のため規約の該当箇所を確認すること
- 集約系（FireHOL、Phishing Army など）は、元になっている各リストの条件が優先される

## 一覧（商用利用の可否順）

<!-- BEGIN TABLE -->
| 名称 | 商用利用 | 有料プランの料金 | IP | ドメイン | URL | ハッシュ | その他 | 取得方法 | 登録 | 条件・制限 | 根拠 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Feodo Tracker | 可能 | — | ○ | — | — | — | ボットネットの C2 | ファイル（提供元サイト） | 不要 | CC0。商用・非商用とも無料。ベストエフォート | [リンク](https://abuse.ch/terms-of-use/) |
| SSL Blacklist（SSLBL） | 可能 | — | ○ | — | — | ○ | 悪性の SSL 証明書・JA3 | ファイル（提供元サイト） | 不要 | CC0。商用・非商用とも無料 | [リンク](https://abuse.ch/terms-of-use/) |
| YARAify | 可能 | — | — | — | — | ○ | YARA ルール | API / ファイル（提供元サイト） | 要（Auth-Key） | CC0。商用・非商用とも無料 | [リンク](https://abuse.ch/terms-of-use/) |
| PhishTank | 可能 | — | — | — | ○ | — | — | API / ファイル（提供元サイト） | 要（API キー） | FAQ で商用・非商用とも OK と明記 | [リンク](https://phishtank.org/faq.php) |
| Spamhaus DROP | 可能 | — | ○ | — | — | — | 乗っ取られたネットワーク帯 | ファイル（提供元サイト） | 不要 | 規模・業種を問わず無料。Spamhaus の帰属表示と著作権表記を残す。取得は 1 日 1 回まで | [リンク](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) |
| IPsum | 可能 | — | ○ | — | — | — | — | ファイル（GitHub） | 不要 | Unlicense（パブリックドメイン相当） | [リンク](https://github.com/stamparm/ipsum) |
| Phishing.Database | 可能 | — | — | ○ | ○ | — | — | ファイル（GitHub） | 不要 | MIT ライセンス。著作権表示を残す | [リンク](https://github.com/mitchellkrogza/Phishing.Database) |
| Tor の出口ノード一覧（Tor Metrics / CollecTor） | 可能 | — | ○ | — | — | — | Tor | ファイル（提供元サイト） | 不要 | Tor Metrics のデータは CC0 | [リンク](https://metrics.torproject.org/collector) |
| CIRCL hashlookup | 可能 | — | — | — | — | ○ | 既知の正規ファイル | API / ファイル（提供元サイト） | 不要 | CC-BY。商用・非商用とも利用可。ページへの参照が必要 | [リンク](https://www.circl.lu/services/hashlookup/) |
| IPinfo Lite | 可能 | （Lite で商用可）上位は Core $26/月、Max $163/月 | ○ | — | — | — | 国・ASN | ファイル（提供元サイト） / API | 要 | CC BY-SA 4.0。商用 OK。IPinfo の帰属表示が必要 | [リンク](https://ipinfo.io/lite) |
| CISA KEV | 可能 | — | — | — | — | — | 悪用が確認された脆弱性 | ファイル（提供元サイト、CSV / JSON） | 不要 | CC0。CISA のロゴは使えない | [リンク](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| MITRE ATT&CK | 可能 | — | — | — | — | — | 攻撃手法の体系 | ファイル（GitHub、STIX） | 不要 | 研究・開発・商用目的で無料。MITRE の著作権表示とライセンスを残す | [リンク](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) |
| URLhaus | 条件付き | 見積もり（Spamhaus 経由、価格非公開） | — | ○ | ○ | ○ | — | API / ファイル（提供元サイト） | 要（Auth-Key） | 営利目的の商用利用は Spamhaus の有料契約が必要な場合がある。AI モデルの学習への利用は禁止 | [リンク](https://abuse.ch/terms-of-use/) |
| MalwareBazaar | 条件付き | 見積もり（Spamhaus 経由、価格非公開） | — | — | — | ○ | マルウェア検体 | API / ファイル（提供元サイト） | 要（Auth-Key） | URLhaus と同じ規約 | [リンク](https://abuse.ch/terms-of-use/) |
| ThreatFox | 条件付き | 見積もり（Spamhaus 経由、価格非公開） | ○ | ○ | ○ | ○ | C2・IOC 全般 | API / ファイル（提供元サイト） | 要（Auth-Key） | URLhaus と同じ規約 | [リンク](https://abuse.ch/terms-of-use/) |
| SANS ISC / DShield | 条件付き | — | ○ | ○ | — | — | 攻撃の多いポート | API / ファイル（提供元サイト） | 不要 | 自社ネットワークの防御なら商用 OK。データの再販は禁止（ライセンス名は CC BY-NC-SA 4.0 と併記されている） | [リンク](https://isc.sans.edu/api/) |
| Maltrail（trails） | 条件付き | 見積もり（ライセンス、価格非公開） | ○ | ○ | ○ | — | — | ファイル（GitHub） | 不要 | 社内の防御・研究・教育は無料。商用製品・MSSP / MDR・再配布はライセンスが必要（エンジンは MIT） | [リンク](https://github.com/stamparm/maltrail) |
| MaxMind GeoLite2 | 条件付き | GeoIP2 Country 年 $418、ISP（ASN 含む）年 $539、City 年 $1,628 | ○ | — | — | — | 国・ASN | ファイル（提供元サイト） / API | 要 | 自社の社内業務の範囲で利用可。MaxMind の帰属表示が必要 | [リンク](https://www.maxmind.com/en/geolite2/eula) |
| EPSS | 条件付き | — | — | — | — | — | 脆弱性の悪用確率 | API / ファイル（提供元サイト） | 不要 | 無料・登録不要。製品で使うときは帰属表示を求めている（商用の明記はない） | [リンク](https://www.first.org/epss/faq) |
| CINS Army | 要確認 | — | ○ | — | — | — | — | ファイル（提供元サイト） | 不要 | 「好きなように使ってよい」とあるが、ライセンスの明記はない | [リンク](https://cinsscore.com/) |
| blocklist.de | 要確認 | — | ○ | — | — | — | — | ファイル（提供元サイト） | 不要 | ダウンロード先にライセンスの記載なし | [リンク](https://lists.blocklist.de/lists/) |
| FireHOL IP Lists | 要確認 | — | ○ | — | — | — | — | ファイル（GitHub） | 不要 | 集約サイト。各リストは元の管理者のもので、条件はリストごとに確認が必要 | [リンク](https://iplists.firehol.org/) |
| Emerging Threats Open（IP リスト） | 要確認 | — | ○ | — | — | — | — | ファイル（提供元サイト） | 不要 | ダウンロード案内にライセンスの記載なし | [リンク](https://rules.emergingthreats.net/) |
| Phishing Army | 要確認 | — | — | ○ | — | — | — | ファイル（提供元サイト） | 不要 | 自身は制限を設けていない。ただし元データの条件は提供元ごとに確認が必要 | [リンク](https://phishing.army/license/) |
| threatview.io（Community） | 要確認 | — | ○ | ○ | ○ | ○ | — | ファイル（提供元サイト） | 不要 | 無料と明記。商用の条件は記載なし | [リンク](https://threatview.io/) |
| Hybrid Analysis | 要確認 | — | — | ○ | ○ | ○ | サンドボックス | API | 要 | 規約を取得できず未確認。無料版の提出物はコミュニティに共有される | [リンク](https://www.hybrid-analysis.com/terms) |
| Pulsedive（Free） | 要確認 | Pro $29/月（商用可否は未確認） | ○ | ○ | ○ | — | — | API | 要 | 規約に無料版の商用利用の明記なし | [リンク](https://pulsedive.com/terms) |
| IBM X-Force Exchange（Free） | 要確認 | — | ○ | ○ | ○ | ○ | — | API | 要 | 規約を取得できず未確認 | [リンク](https://exchange.xforce.ibmcloud.com/) |
| CIRCL OSINT Feed（MISP） | 要確認 | — | ○ | ○ | ○ | ○ | — | ファイル（提供元サイト、MISP 形式） | 不要 | フィードにライセンスの記載が見つからない | [リンク](https://www.circl.lu/doc/misp/feed-osint/) |
| NIST NSRL | 要確認 | — | — | — | — | ○ | 既知の正規ファイル | ファイル（提供元サイト） | 不要 | 再配布ポリシーが別ページにあり未確認 | [リンク](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl) |
| VirusTotal（Public API） | 不可 | 見積もり（Premium / Enterprise、価格非公開） | ○ | ○ | ○ | ○ | — | API | 要 | Public API は非商用・学術用途のみ。商用は Private API（有料） | [リンク](https://docs.virustotal.com/docs/difference-public-private) |
| AlienVault OTX | 不可 | 見積もり（LevelBlue、価格非公開） | ○ | ○ | ○ | ○ | — | API / ファイル（提供元サイト） | 要 | 非商用の利用者向けに無料。商用での利用・第三者への提供を禁止 | [リンク](https://www.levelblue.com/terms/otx-eula) |
| AbuseIPDB（Free プラン） | 不可 | Basic $25/月（年 $228）、Premium $99/月（年 $1,068） | ○ | — | — | — | — | API | 要 | Free プランは商用利用不可。商用は Basic 以上の有料プラン | [リンク](https://www.abuseipdb.com/legal) |
| GreyNoise（Community / Free） | 不可 | 見積もり（Standard / Advanced / Elite、価格非公開） | ○ | — | — | — | — | API | 要 | 無料の利用者は非商用目的に限る | [リンク](https://www.greynoise.io/terms) |
| urlscan.io（無料） | 不可 | Automate（API のみ）年 $5,000、Professional $1,250/月（年 $12,500）〜 | ○ | ○ | ○ | — | スクリーンショット | API | 要 | 個人・非商用のみ。商用は書面の許可または商用契約 | [リンク](https://urlscan.io/terms/) |
| Shodan InternetDB | 不可 | 商用は Corporate $1,099/月（API プランは Freelancer $69/月〜） | ○ | — | — | — | 開いているポート・脆弱性 | API | 不要 | 非商用は無料。収益を得る用途はエンタープライズライセンスが必要 | [リンク](https://internetdb.shodan.io/) |
| Censys（Free） | 不可 | 見積もり（Core ほか、価格非公開） | ○ | ○ | — | — | 証明書 | Web（API は有料のみ） | 要 | 無料の利用者は、社内業務を含む商用目的での利用を禁止 | [リンク](https://censys.com/terms-of-service/) |
| Google Safe Browsing API | 不可 | Web Risk（Google Cloud の従量課金。料金ページ参照） | — | ○ | ○ | — | — | API | 要 | 非商用のみ。商用は Web Risk（有料） | [リンク](https://developers.google.com/safe-browsing/v4/usage-limits) |
| OpenPhish（Community Feed） | 不可 | 見積もり（価格非公開） | — | — | ○ | — | — | ファイル（提供元サイト） | 不要 | 個人利用のみ。商用は書面の同意が必要 | [リンク](https://openphish.com/terms.html) |
| C2IntelFeeds | 不可 | — | ○ | ○ | ○ | — | C2 サーバー | ファイル（GitHub） | 不要 | CC BY-NC-SA 4.0（非商用のみ） | [リンク](https://github.com/drb-ra/C2IntelFeeds) |
<!-- END TABLE -->

## 更新のしかた

`tools/ti_sources_build.py` の一覧を編集してから実行すると、この表と CSV が作り直される。

```powershell
python -I tools\ti_sources_build.py
```
