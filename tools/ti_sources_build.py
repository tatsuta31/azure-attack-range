"""Build docs/ti/ti_sources.csv and the table in docs/ti-sources.md from the list below.

Usage: python -I tools/ti_sources_build.py
"商用利用" is what the provider's own page said on the check date:
  可能     = free commercial use is stated
  条件付き = allowed with conditions, or some commercial uses need a paid plan
  要確認   = no clear statement was found
  不可     = the free tier is for non-commercial use only
"""
import csv
import os
from collections import Counter

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CHECKED = "2026-11-04"
COLS = ["名称", "提供元", "IP", "ドメイン", "URL", "ハッシュ", "その他", "取得方法", "登録", "無料",
        "商用利用", "有料プランの料金", "条件・制限", "根拠"]
Y = "○"
# name, provider, ip, domain, url, hash, other, access, signup, free, commercial, conditions, source
S = [
    ("VirusTotal（Public API）", "Google", Y, Y, Y, Y, "", "API", "要", "可能", "不可",
     "Public API は非商用・学術用途のみ。商用は Private API（有料）",
     "https://docs.virustotal.com/docs/difference-public-private"),
    ("AlienVault OTX", "LevelBlue", Y, Y, Y, Y, "", "API / ファイル（提供元サイト）", "要", "可能", "不可",
     "非商用の利用者向けに無料。商用での利用・第三者への提供を禁止",
     "https://www.levelblue.com/terms/otx-eula"),
    ("AbuseIPDB（Free プラン）", "AbuseIPDB", Y, "", "", "", "", "API", "要", "可能", "不可",
     "Free プランは商用利用不可。商用は Basic 以上の有料プラン", "https://www.abuseipdb.com/legal"),
    ("GreyNoise（Community / Free）", "GreyNoise", Y, "", "", "", "", "API", "要", "可能", "不可",
     "無料の利用者は非商用目的に限る", "https://www.greynoise.io/terms"),
    ("urlscan.io（無料）", "urlscan", Y, Y, Y, "", "スクリーンショット", "API", "要", "可能", "不可",
     "個人・非商用のみ。商用は書面の許可または商用契約", "https://urlscan.io/terms/"),
    ("Shodan InternetDB", "Shodan", Y, "", "", "", "開いているポート・脆弱性", "API", "不要", "可能", "不可",
     "非商用は無料。収益を得る用途はエンタープライズライセンスが必要", "https://internetdb.shodan.io/"),
    ("Censys（Free）", "Censys", Y, Y, "", "", "証明書", "Web（API は有料のみ）", "要", "可能", "不可",
     "無料の利用者は、社内業務を含む商用目的での利用を禁止", "https://censys.com/terms-of-service/"),
    ("Google Safe Browsing API", "Google", "", Y, Y, "", "", "API", "要", "可能", "不可",
     "非商用のみ。商用は Web Risk（有料）",
     "https://developers.google.com/safe-browsing/v4/usage-limits"),
    ("OpenPhish（Community Feed）", "OpenPhish", "", "", Y, "", "", "ファイル（提供元サイト）", "不要", "可能", "不可",
     "個人利用のみ。商用は書面の同意が必要", "https://openphish.com/terms.html"),
    ("C2IntelFeeds", "drb-ra（GitHub）", Y, Y, Y, "", "C2 サーバー", "ファイル（GitHub）", "不要", "可能", "不可",
     "CC BY-NC-SA 4.0（非商用のみ）", "https://github.com/drb-ra/C2IntelFeeds"),
    ("URLhaus", "abuse.ch / Spamhaus", "", Y, Y, Y, "", "API / ファイル（提供元サイト）", "要（Auth-Key）", "可能", "条件付き",
     "営利目的の商用利用は Spamhaus の有料契約が必要な場合がある。AI モデルの学習への利用は禁止",
     "https://abuse.ch/terms-of-use/"),
    ("MalwareBazaar", "abuse.ch / Spamhaus", "", "", "", Y, "マルウェア検体", "API / ファイル（提供元サイト）", "要（Auth-Key）",
     "可能", "条件付き", "URLhaus と同じ規約", "https://abuse.ch/terms-of-use/"),
    ("ThreatFox", "abuse.ch / Spamhaus", Y, Y, Y, Y, "C2・IOC 全般", "API / ファイル（提供元サイト）", "要（Auth-Key）",
     "可能", "条件付き", "URLhaus と同じ規約", "https://abuse.ch/terms-of-use/"),
    ("Feodo Tracker", "abuse.ch", Y, "", "", "", "ボットネットの C2", "ファイル（提供元サイト）", "不要", "可能", "可能",
     "CC0。商用・非商用とも無料。ベストエフォート", "https://abuse.ch/terms-of-use/"),
    ("SSL Blacklist（SSLBL）", "abuse.ch", Y, "", "", Y, "悪性の SSL 証明書・JA3", "ファイル（提供元サイト）", "不要", "可能",
     "可能", "CC0。商用・非商用とも無料", "https://abuse.ch/terms-of-use/"),
    ("YARAify", "abuse.ch", "", "", "", Y, "YARA ルール", "API / ファイル（提供元サイト）", "要（Auth-Key）", "可能", "可能",
     "CC0。商用・非商用とも無料", "https://abuse.ch/terms-of-use/"),
    ("PhishTank", "Cisco Talos", "", "", Y, "", "", "API / ファイル（提供元サイト）", "要（API キー）", "可能", "可能",
     "FAQ で商用・非商用とも OK と明記", "https://phishtank.org/faq.php"),
    ("Spamhaus DROP", "Spamhaus", Y, "", "", "", "乗っ取られたネットワーク帯", "ファイル（提供元サイト）", "不要", "可能", "可能",
     "規模・業種を問わず無料。Spamhaus の帰属表示と著作権表記を残す。取得は 1 日 1 回まで",
     "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"),
    ("SANS ISC / DShield", "SANS", Y, Y, "", "", "攻撃の多いポート", "API / ファイル（提供元サイト）", "不要", "可能", "条件付き",
     "自社ネットワークの防御なら商用 OK。データの再販は禁止（ライセンス名は CC BY-NC-SA 4.0 と併記されている）",
     "https://isc.sans.edu/api/"),
    ("Maltrail（trails）", "stamparm（GitHub）", Y, Y, Y, "", "", "ファイル（GitHub）", "不要", "可能", "条件付き",
     "社内の防御・研究・教育は無料。商用製品・MSSP / MDR・再配布はライセンスが必要（エンジンは MIT）",
     "https://github.com/stamparm/maltrail"),
    ("MaxMind GeoLite2", "MaxMind", Y, "", "", "", "国・ASN", "ファイル（提供元サイト） / API", "要", "可能", "条件付き",
     "自社の社内業務の範囲で利用可。MaxMind の帰属表示が必要", "https://www.maxmind.com/en/geolite2/eula"),
    ("EPSS", "FIRST", "", "", "", "", "脆弱性の悪用確率", "API / ファイル（提供元サイト）", "不要", "可能", "条件付き",
     "無料・登録不要。製品で使うときは帰属表示を求めている（商用の明記はない）", "https://www.first.org/epss/faq"),
    ("IPsum", "stamparm（GitHub）", Y, "", "", "", "", "ファイル（GitHub）", "不要", "可能", "可能",
     "Unlicense（パブリックドメイン相当）", "https://github.com/stamparm/ipsum"),
    ("Phishing.Database", "mitchellkrogza（GitHub）", "", Y, Y, "", "", "ファイル（GitHub）", "不要", "可能", "可能",
     "MIT ライセンス。著作権表示を残す", "https://github.com/mitchellkrogza/Phishing.Database"),
    ("Tor の出口ノード一覧（Tor Metrics / CollecTor）", "Tor Project", Y, "", "", "", "Tor", "ファイル（提供元サイト）", "不要",
     "可能", "可能", "Tor Metrics のデータは CC0", "https://metrics.torproject.org/collector"),
    ("CIRCL hashlookup", "CIRCL", "", "", "", Y, "既知の正規ファイル", "API / ファイル（提供元サイト）", "不要", "可能", "可能",
     "CC-BY。商用・非商用とも利用可。ページへの参照が必要", "https://www.circl.lu/services/hashlookup/"),
    ("IPinfo Lite", "IPinfo", Y, "", "", "", "国・ASN", "ファイル（提供元サイト） / API", "要", "可能", "可能",
     "CC BY-SA 4.0。商用 OK。IPinfo の帰属表示が必要", "https://ipinfo.io/lite"),
    ("CISA KEV", "CISA", "", "", "", "", "悪用が確認された脆弱性", "ファイル（提供元サイト、CSV / JSON）", "不要", "可能", "可能",
     "CC0。CISA のロゴは使えない", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    ("MITRE ATT&CK", "MITRE", "", "", "", "", "攻撃手法の体系", "ファイル（GitHub、STIX）", "不要", "可能", "可能",
     "研究・開発・商用目的で無料。MITRE の著作権表示とライセンスを残す",
     "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"),
    ("CINS Army", "Sentinel IPS", Y, "", "", "", "", "ファイル（提供元サイト）", "不要", "可能", "要確認",
     "「好きなように使ってよい」とあるが、ライセンスの明記はない", "https://cinsscore.com/"),
    ("blocklist.de", "blocklist.de", Y, "", "", "", "", "ファイル（提供元サイト）", "不要", "可能", "要確認",
     "ダウンロード先にライセンスの記載なし", "https://lists.blocklist.de/lists/"),
    ("FireHOL IP Lists", "FireHOL", Y, "", "", "", "", "ファイル（GitHub）", "不要", "可能", "要確認",
     "集約サイト。各リストは元の管理者のもので、条件はリストごとに確認が必要", "https://iplists.firehol.org/"),
    ("Emerging Threats Open（IP リスト）", "Proofpoint", Y, "", "", "", "", "ファイル（提供元サイト）", "不要", "可能", "要確認",
     "ダウンロード案内にライセンスの記載なし", "https://rules.emergingthreats.net/"),
    ("Phishing Army", "Phishing Army", "", Y, "", "", "", "ファイル（提供元サイト）", "不要", "可能", "要確認",
     "自身は制限を設けていない。ただし元データの条件は提供元ごとに確認が必要", "https://phishing.army/license/"),
    ("threatview.io（Community）", "Threatview", Y, Y, Y, Y, "", "ファイル（提供元サイト）", "不要", "可能", "要確認",
     "無料と明記。商用の条件は記載なし", "https://threatview.io/"),
    ("Hybrid Analysis", "CrowdStrike", "", Y, Y, Y, "サンドボックス", "API", "要", "可能", "要確認",
     "規約を取得できず未確認。無料版の提出物はコミュニティに共有される", "https://www.hybrid-analysis.com/terms"),
    ("Pulsedive（Free）", "Pulsedive", Y, Y, Y, "", "", "API", "要", "可能", "要確認",
     "規約に無料版の商用利用の明記なし", "https://pulsedive.com/terms"),
    ("IBM X-Force Exchange（Free）", "IBM", Y, Y, Y, Y, "", "API", "要", "可能", "要確認",
     "規約を取得できず未確認", "https://exchange.xforce.ibmcloud.com/"),
    ("CIRCL OSINT Feed（MISP）", "CIRCL", Y, Y, Y, Y, "", "ファイル（提供元サイト、MISP 形式）", "不要", "可能", "要確認",
     "フィードにライセンスの記載が見つからない", "https://www.circl.lu/doc/misp/feed-osint/"),
    ("NIST NSRL", "NIST", "", "", "", Y, "既知の正規ファイル", "ファイル（提供元サイト）", "不要", "可能", "要確認",
     "再配布ポリシーが別ページにあり未確認",
     "https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl"),
]

# Paid plans (USD, excl. tax), from the providers' pricing pages on the check date.
# "見積もり" = no public price. Only filled where the free tier is not enough for commercial use.
PRICES = {
    "VirusTotal（Public API）": "見積もり（Premium / Enterprise、価格非公開）",
    "AlienVault OTX": "見積もり（LevelBlue、価格非公開）",
    "AbuseIPDB（Free プラン）": "Basic $25/月（年 $228）、Premium $99/月（年 $1,068）",
    "GreyNoise（Community / Free）": "見積もり（Standard / Advanced / Elite、価格非公開）",
    "urlscan.io（無料）": "Automate（API のみ）年 $5,000、Professional $1,250/月（年 $12,500）〜",
    "Shodan InternetDB": "商用は Corporate $1,099/月（API プランは Freelancer $69/月〜）",
    "Censys（Free）": "見積もり（Core ほか、価格非公開）",
    "Google Safe Browsing API": "Web Risk（Google Cloud の従量課金。料金ページ参照）",
    "OpenPhish（Community Feed）": "見積もり（価格非公開）",
    "URLhaus": "見積もり（Spamhaus 経由、価格非公開）",
    "MalwareBazaar": "見積もり（Spamhaus 経由、価格非公開）",
    "ThreatFox": "見積もり（Spamhaus 経由、価格非公開）",
    "Maltrail（trails）": "見積もり（ライセンス、価格非公開）",
    "MaxMind GeoLite2": "GeoIP2 Country 年 $418、ISP（ASN 含む）年 $539、City 年 $1,628",
    "IPinfo Lite": "（Lite で商用可）上位は Core $26/月、Max $163/月",
    "Pulsedive（Free）": "Pro $29/月（商用可否は未確認）",
}


def main():
    rows = []
    for s in S:
        r = dict(zip([c for c in COLS if c != "有料プランの料金"], s), 確認日=CHECKED)
        r["有料プランの料金"] = PRICES.get(r["名称"], "")
        rows.append(r)
    with open(os.path.join(ROOT, "docs", "ti", "ti_sources.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS + ["確認日"])
        w.writeheader()
        w.writerows(rows)
    order = {"可能": 0, "条件付き": 1, "要確認": 2, "不可": 3}
    rows.sort(key=lambda r: order[r["商用利用"]])
    path = os.path.join(ROOT, "docs", "ti-sources.md")
    md = open(path, encoding="utf-8").read()
    head, rest = md.split("<!-- BEGIN TABLE -->", 1)
    _, tail = rest.split("<!-- END TABLE -->", 1)
    show = ["名称", "商用利用", "有料プランの料金", "IP", "ドメイン", "URL", "ハッシュ", "その他", "取得方法", "登録", "条件・制限"]
    t = ["| " + " | ".join(show) + " | 根拠 |", "|" + "---|" * (len(show) + 1)]
    for r in rows:
        t.append("| " + " | ".join((r[c] or "—").replace("|", "\\|") for c in show)
                 + f" | [リンク]({r['根拠']}) |")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(head + "<!-- BEGIN TABLE -->\n" + "\n".join(t) + "\n<!-- END TABLE -->" + tail)
    print(len(rows), dict(Counter(r["商用利用"] for r in rows)))


if __name__ == "__main__":
    main()
