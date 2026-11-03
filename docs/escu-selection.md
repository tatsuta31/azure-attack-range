# ESCU 検知ルールの選定（v0）

対象：ESCU **5.18.0**（ラボの core Splunk に入っている版）。会社の環境（884 件）の版は未確認。ルール名は版をまたいでほぼ変わらないので、版が分かったら名前で突き合わせる。

同じ内容の CSV：[`escu/escu_selection.csv`](escu/escu_selection.csv)（Excel でそのまま開ける UTF-8 BOM 付き。`saved_search` 列は Splunk 上の名前）

## この 98 本の位置づけ

**「ラボにログがあり、攻撃を再現できる」ことを基準に選んだルールで、まだ全部の発火は確かめていない。** 有効化したあと、1 本ずつ攻撃して発火を確かめる。発火しないものは「SPL・マクロの修正」列と「前提と共通の修正」を見直す。

## 選定の範囲（2026-11-02 決定）

- **対象にするログ**：ラボで実際に取れるログ ＋ **Palo Alto のログ（ある前提）**
- **除外**：上記以外の製品のログが前提のルール（AWS、Azure AD、O365、CrowdStrike、Cisco、Okta など）。626 本
- Palo はラボには**置かない**。ネットワークのルールは「Palo のログがあれば動くルール」として選ぶが、ラボでは再現・検証しない

## 再現方法

| 再現方法 | 中身 | 使うログ |
|---|---|---|
| ART / Caldera | `attack_range.py simulate` または Caldera から実行 | Sysmon、Windows のセキュリティログ、PowerShell 4104、Linux（Sysmon for Linux / auditd） |
| 手動（RDP / SSH で入って実行） | 端末に入って手でコマンドを打つ。親プロセスが `explorer.exe` や `sshd` になり、実戦に近い | 同上 |
| DC で実行 | ドメインコントローラー（ar-dc）で実行しないとログが出ないもの | 同上 |
| ラボでは再現しない | Palo のログが前提のもの | Palo のトラフィック／脅威ログ（CIM の `Network_Traffic` / `Intrusion_Detection`） |

前提：Windows は全台 `advanced_logging: "1"`（Kerberos 4768/4769、ディレクトリサービスアクセス 4662、ユーザー／グループ管理 4720/4728/4732/4738、詳細なファイル共有 5145、その他のオブジェクトアクセス 4698 など）と `win_sysmon_config: "AttackRangeSysmon.xml"`。Linux は Sysmon for Linux（`sysmon:linux`）と auditd（`linux:audit`）。

## 前提と共通の修正

「SPL・マクロの修正」列に出てくるキーワードの中身。

| キーワード | 対象 | やること |
|---|---|---|
| CIM | データモデル（`tstats`）を使うルール全部 | CIM のデータモデル（Endpoint / Network_Traffic / Authentication）の対象 index を設定する。CIM アプリの設定で `cim_Endpoint_indexes` などに `index=win OR index=unix` を入れる。未設定だと、ロールの既定の検索 index しか見ないので、win / unix のイベントが拾われないことがある |
| AUDITD | Linux の auditd 系 3 本 | マクロ `linux_auditd` を `sourcetype="auditd"` から `sourcetype="linux:audit"` に変える（ラボの auditd は `linux:audit` で送っている）。`proctitle` が 16 進のまま取り込まれる場合は、フィールド抽出も確認する |
| PALO | ネットワークの 15 本 | Palo Alto のログ（CIM 対応の TA）が前提。ラボでは発火しない |

ほかに、しきい値がラボの規模に合わないルールがある（30 ユーザー、30 台など）。メモ列に書いた。

## ART のテスト番号について

ART のテスト番号は、**2026-11-04 時点の ART 本家（master）の索引** に合わせた。ATT&CK v18 で防御回避系が付け替えられ、ART でも Defender の無効化、ログの消去、Sysmon のアンロードなどが `T1562.001` / `T1070.001` から **`T1685` 系** に移っている。ラボの ART は build のたびに master を入れるので、新しい番号で実行する。実行前に `Invoke-AtomicTest <番号> -ShowDetailsBrief` で中身を確かめること。

## 絞り込みの経過

| 段階 | 本数 | 内容 |
|---|---|---|
| ESCU 5.18.0 の検知ルール | 1,941 | 廃止済みを除くと 1,934 |
| ラボのログで動く | 1,235 | 製品なし（CrowdStrike、AWS、O365 など）626、追加設定が必要（5136 など）60、Palo 13 を除く |
| 攻撃計画のテクニックに該当（TTP / Anomaly） | 437 | `escu/escu_5180_shortlist.csv` |
| うち TTP | 293 | |
| **本命（このファイルの下の表）** | **98** | 手で選定（エンドポイント 83 ＋ ネットワーク 15）。全ルール名が 5.18.0 に実在することを機械照合済み |

全件の仕分け結果は `escu/escu_5180_classified.csv`。再生成は `tools/escu/` のスクリプトで行う（手順は末尾）。

## 本命リスト

<!-- BEGIN RULE TABLES (generated) -->
### 認証情報の窃取

| ルール | ATT&CK | 種別 | ESCU ストーリー | 概要 | 再現方法 | ART のテスト | SPL・マクロの修正 | メモ |
|---|---|---|---|---|---|---|---|---|
| Windows Possible Credential Dumping | T1003.001 | TTP | CISA AA22-257A / CISA AA22-264A / CISA AA23-347A / Credential Dumping / DarkSide Ransomware / Detect Zerologon Attack / Scattered Lapsus$ Hunters | lsass.exe へのメモリ読み取りアクセス（特定の GrantedAccess と dbghelp/dbgcore を含む CallTrace）を検知する（Sysmon 10） | ART / Caldera | T1003.001 #1（Dump LSASS.exe Memory using ProcDump）; T1003.001 #4（Dump LSASS.exe Memory using NanoDump）; T1003.001 #13（Dump LSASS.exe using lolbin rdrleakdiag.exe） | — | 2026-11-01 の ART で、対象の Sysmon 10 のログが出ることは確認済み（ルールの発火は未確認） |
| Access LSASS Memory for Dump Creation | T1003.001 | TTP | CISA AA23-347A / Cactus Ransomware / Credential Dumping / Lokibot / Scattered Lapsus$ Hunters | dbghelp.dll / dbgcore.dll 経由で lsass.exe にアクセスした、ダンプ作成の痕跡を検知する（Sysmon 10） | ART / Caldera | T1003.001 #1（Dump LSASS.exe Memory using ProcDump）; T1003.001 #2（Dump LSASS.exe Memory using comsvcs.dll） | — |  |
| Dump LSASS via comsvcs DLL | T1003.001 | TTP | CISA AA22-257A / CISA AA22-264A / Compromised Windows Host / Credential Dumping / Data Destruction / Flax Typhoon / HAFNIUM Group / Hellcat Ransomware / Industroyer2 / Living Off The Land / Prestige Ransomware / Scattered Lapsus$ Hunters / Suspicious Rundll32 Activity / Volt Typhoon | rundll32 から comsvcs.dll の MiniDump を呼んで lsass をダンプしたコマンドラインを検知する | ART / Caldera | T1003.001 #2（Dump LSASS.exe Memory using comsvcs.dll） | CIM | LOLBin の定番 |
| Dump LSASS via procdump | T1003.001 | TTP | CISA AA22-257A / Compromised Windows Host / Credential Dumping / HAFNIUM Group / Seashell Blizzard / Storm-2460 CLFS Zero Day Exploitation | procdump に -ma / -mm などを付けて lsass をダンプしたコマンドラインを検知する | ART / Caldera | T1003.001 #1（Dump LSASS.exe Memory using ProcDump）; T1003.001 #9（Create Mini Dump of LSASS.exe using ProcDump） | CIM |  |
| Windows Non-System Account Targeting Lsass | T1003.001 | TTP | CISA AA23-347A / Credential Dumping / Lokibot / Scattered Lapsus$ Hunters | SYSTEM 以外のアカウントが lsass.exe にアクセスしたことを検知する（Sysmon 10） | ART / Caldera | T1003.001 #1（Dump LSASS.exe Memory using ProcDump）; T1003.001 #2（Dump LSASS.exe Memory using comsvcs.dll） | — | Caldera エージェントは SYSTEM で動くので、Caldera 経由では発火しない |
| Windows Sensitive Registry Hive Dump Via CommandLine | T1003.002 | TTP | CISA AA22-257A / CISA AA23-347A / Compromised Windows Host / Credential Dumping / DarkSide Ransomware / Data Destruction / Industroyer2 / Seashell Blizzard / Volt Typhoon / Windows Registry Abuse | reg.exe で SAM / SYSTEM / SECURITY ハイブを保存・エクスポートしたことを検知する | ART / Caldera | T1003.002 #1（Registry dump of SAM, creds, and secrets） | CIM |  |
| Creation of Shadow Copy | T1003.003 | TTP | Compromised Windows Host / Credential Dumping / Volt Typhoon | vssadmin / wmic でボリュームシャドウコピーを作成したことを検知する | ART / Caldera ＋ DC で実行 | T1003.003 #1（Create Volume Shadow Copy with vssadmin）; T1003.003 #4（Create Volume Shadow Copy with WMI） | CIM | DC で実行すると NTDS.dit 窃取の下準備になる |
| Ntdsutil Export NTDS | T1003.003 | TTP | Credential Dumping / HAFNIUM Group / Living Off The Land / Prestige Ransomware / Rhysida Ransomware / Volt Typhoon | ntdsutil で AD データベース（NTDS.dit）をエクスポートしたことを検知する | ART / Caldera ＋ DC で実行 | T1003.003 #3（Dump Active Directory Database with NTDSUtil） | CIM | DC で実行 |
| Windows AD Replication Request Initiated by User Account | T1003.006 | TTP | Compromised Windows Host / Credential Dumping / Sneaky Active Directory Persistence Tricks | ユーザーアカウントからのディレクトリ複製要求（DCSync）を検知する（4662） | ART / Caldera ＋ DC で実行 | T1003.006 #1（DCSync (Active Directory)）; T1003.006 #2（Run DSInternals Get-ADReplAccount） | — | DC で 4662 が出るには、ドメインのルートに監査（SACL）が必要。出なければ SACL を確認する |
| Windows AD Replication Request Initiated from Unsanctioned Location | T1003.006 | TTP | Compromised Windows Host / Credential Dumping / Sneaky Active Directory Persistence Tricks | DC 以外のコンピューターアカウントからの複製要求（DCSync）を検知する（4662） | ART / Caldera ＋ DC で実行 | T1003.006 #1（DCSync (Active Directory)）; T1003.006 #2（Run DSInternals Get-ADReplAccount） | — | 上と同じく 4662 の SACL が前提 |
| Kerberoasting spn request with RC4 encryption | T1558.003 | TTP | Active Directory Kerberos Attacks / Compromised Windows Host / Data Destruction / Hermetic Wiper / Windows Privilege Escalation | RC4 暗号を指定したサービスチケット要求（Kerberoasting）を検知する（4769） | ART / Caldera ＋ DC で実行 | T1558.003 #1（Request for service tickets）; T1558.003 #2（Rubeus kerberoast） | — | SPN を持つサービスアカウントがドメインに必要（既定のラボには無いので作る） |
| ServicePrincipalNames Discovery with SetSPN | T1558.003 | TTP | Active Directory Discovery / Active Directory Kerberos Attacks / Active Directory Privilege Escalation / Compromised Windows Host | setspn.exe でドメインの SPN を列挙したことを検知する | ART / Caldera | T1558.003 #3（Extract all accounts in use as SPN using setspn） | CIM |  |
| Rubeus Command Line Parameters | T1558.003 | TTP | Active Directory Kerberos Attacks / Active Directory Privilege Escalation / BlackSuit Ransomware / CISA AA23-347A / Scattered Lapsus$ Hunters | Rubeus 特有のコマンドライン引数（kerberoast / asreproast / ptt など）を検知する | ART / Caldera | T1558.003 #2（Rubeus kerberoast）; T1558.004 #1（Rubeus asreproast） | CIM |  |
| Kerberos Pre-Authentication Flag Disabled in UserAccountControl | T1558.004 | TTP | Active Directory Kerberos Attacks / BlackSuit Ransomware | ユーザーの「Kerberos 事前認証を要求しない」が有効にされたことを検知する（4738） | 手動（RDP / SSH で入って実行） ＋ DC で実行 | — | — | AS-REP Roasting の下準備。DC の「Active Directory ユーザーとコンピューター」でフラグを付けて再現する |
| Detect Password Spray Attempts | T1110.003 | TTP | Active Directory Password Spraying / Compromised User Account | 1 つの送信元からの認証失敗が統計的に多いこと（パスワードスプレー）を検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1110.003 #1（Password Spray all Domain Users）; T1110.003 #2（Password Spray (DomainPasswordSpray)） | CIM | 3 シグマ判定なので、平常時の認証ログがある程度たまってから試す |
| Windows Multiple Users Failed To Authenticate Using Kerberos | T1110.003 | TTP | Active Directory Kerberos Attacks / Active Directory Password Spraying / Volt Typhoon | 1 つの送信元から 30 以上のユーザーで Kerberos 事前認証に失敗したことを検知する（4771） | ART / Caldera ＋ 手動（RDP / SSH で入って実行） ＋ DC で実行 | T1110.003 #2（Password Spray (DomainPasswordSpray)） | — | しきい値が 30 ユーザーなので、ドメインにユーザーを 30 以上作っておく必要がある |
| Enable WDigest UseLogonCredential Registry | T1003 | TTP | CISA AA22-320A / Credential Dumping / Windows Registry Abuse | WDigest の UseLogonCredential を 1 にして平文の資格情報をメモリに残す設定変更を検知する | 手動（RDP / SSH で入って実行） | — | CIM | レジストリ変更は Sysmon 13。手動でレジストリを変更して再現する |

### 偵察

| ルール | ATT&CK | 種別 | ESCU ストーリー | 概要 | 再現方法 | ART のテスト | SPL・マクロの修正 | メモ |
|---|---|---|---|---|---|---|---|---|
| Domain Controller Discovery with Nltest | T1018 | TTP | Active Directory Discovery / BlackSuit Ransomware / CISA AA23-347A / Medusa Ransomware / Rhysida Ransomware | nltest の /dclist: / /dsgetdc: で DC を探したことを検知する | ART / Caldera | T1018 #3（Remote System Discovery - nltest） | CIM | Caldera の Discovery でも実行される（2026-11-01 確認） |
| NLTest Domain Trust Discovery | T1482 | TTP | Active Directory Discovery / Cleo File Transfer Software / Domain Trust Discovery / IcedID / Medusa Ransomware / Qakbot / Rhysida Ransomware / Ryuk Ransomware | nltest の /domain_trusts / /all_trusts でドメインの信頼関係を調べたことを検知する | ART / Caldera | T1482 #2（Windows - Discover domain trusts with nltest） | CIM |  |
| DSQuery Domain Discovery | T1482 | TTP | Active Directory Discovery / Compromised Windows Host / Domain Trust Discovery | dsquery で trustedDomain を問い合わせたことを検知する | ART / Caldera | T1482 #1（Windows - Discover domain trusts with dsquery） | CIM |  |
| Windows AdFind Exe | T1018 | TTP | BlackSuit Ransomware / Domain Trust Discovery / Graceful Wipe Out Attack / IcedID / NOBELIUM Group | AdFind.exe の実行（AD の列挙ツール）を検知する | ART / Caldera | T1018 #10（Adfind - Enumerate Active Directory Computer Objects）; T1018 #11（Adfind - Enumerate Active Directory Domain Controller Objects） | CIM |  |
| Domain Account Discovery with Wmic | T1087.002 | TTP | Active Directory Discovery / Interlock Ransomware | wmic で LDAP 名前空間からドメインユーザーを列挙したことを検知する | 手動（RDP / SSH で入って実行） | — | CIM | 対応する ART テストが無いので手動で再現する |
| Get DomainUser with PowerShell Script Block | T1087.002 | TTP | Active Directory Discovery / CISA AA23-347A | PowerView の Get-DomainUser の実行を検知する（4104） | ART / Caldera | T1087.002 #11（Get-DomainUser with PowerView） | — |  |
| GetDomainGroup with PowerShell Script Block | T1069.002 | TTP | Active Directory Discovery | PowerView の Get-DomainGroup の実行を検知する（4104） | ART / Caldera | T1069.002 #13（Get-DomainGroup with PowerView） | — |  |
| Elevated Group Discovery With Wmic | T1069.002 | TTP | Active Directory Discovery | wmic で Domain Admins などの特権グループを列挙したことを検知する | 手動（RDP / SSH で入って実行） | — | CIM | 対応する ART テストが無いので手動で再現する |
| PowerShell Domain Enumeration | T1059.001 | TTP | CISA AA23-347A / Data Destruction / Hermetic Wiper / Interlock Ransomware / Malicious PowerShell / Microsoft WSUS CVE-2025-59287 | Get-ADDomain / Get-ADGroupMember などドメイン列挙のコマンドレットを検知する（4104） | ART / Caldera | T1087.002 #11（Get-DomainUser with PowerView）; T1482 #6（Get-DomainTrust with PowerView） | — |  |
| Detect SharpHound Usage | T1069.001 | TTP | Ransomware / Windows Discovery Techniques | SharpHound.exe（BloodHound の収集ツール）の実行を検知する | ART / Caldera | T1059.001 #2（Run BloodHound from local disk）; T1069.001 #4（SharpHound3 - LocalAdmin） | CIM |  |
| Detect SharpHound Command-Line Arguments | T1069.001 | TTP | BlackSuit Ransomware / Ransomware / Windows Discovery Techniques | SharpHound の -collectionMethod / Invoke-BloodHound を検知する | ART / Caldera | T1059.001 #2（Run BloodHound from local disk）; T1059.001 #3（Run Bloodhound from Memory using Download Cradle） | CIM |  |
| Check Elevated CMD using whoami | T1033 | TTP | FIN7 | whoami /groups の結果を find で絞り、管理者権限（12288）か確かめる動きを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | — | CIM | FIN7 の手口。手動で再現する |
| Windows File Share Discovery With Powerview | T1135 | TTP | Active Directory Discovery / Active Directory Privilege Escalation | PowerView の Invoke-ShareFinder の実行を検知する（4104） | ART / Caldera | T1135 #8（PowerView ShareFinder） | — |  |

### 実行・防御回避

| ルール | ATT&CK | 種別 | ESCU ストーリー | 概要 | 再現方法 | ART のテスト | SPL・マクロの修正 | メモ |
|---|---|---|---|---|---|---|---|---|
| Malicious PowerShell Process With Obfuscation Techniques | T1059.001 | TTP | Data Destruction / GhostRedirector IIS Module and Rungan Backdoor / Hellcat Ransomware / Hermetic Wiper / Malicious PowerShell | 難読化の特徴（記号の多用など）を持つ PowerShell のコマンドラインを検知する | ART / Caldera | T1027 #7（Obfuscated Command in PowerShell）; T1027 #11（Obfuscated PowerShell Command via Character Array） | CIM | Caldera の base64 難読化でも狙える |
| Powershell Fileless Script Contains Base64 Encoded Content | T1027 | TTP | 0bj3ctivity Stealer / APT37 Rustonotto and FadeStealer / AsyncRAT / Data Destruction / GhostRedirector IIS Module and Rungan Backdoor / Hellcat Ransomware / Hermetic Wiper / IcedID / Malicious PowerShell / Medusa Ransomware / Microsoft WSUS CVE-2025-59287 / NjRAT / Winter Vivern / XWorm | スクリプト内の FromBase64String（base64 のデコード）を検知する（4104） | ART / Caldera | T1027 #2（Execute base64-encoded PowerShell） | — | 正規のスクリプトでも使われるので誤検知が出やすい |
| Detect Mimikatz With PowerShell Script Block Logging | T1059.001 | TTP | CISA AA22-264A / CISA AA22-320A / CISA AA23-347A / Data Destruction / Hellcat Ransomware / Hermetic Wiper / Malicious PowerShell / Sandworm Tools / Scattered Spider | スクリプト内の mimikatz / sekurlsa / kerberos::golden などの文字列を検知する（4104） | ART / Caldera | T1059.001 #1（Mimikatz） | — |  |
| Windows PowerShell Script Block With Malicious String | T1059.001 | TTP | Malicious PowerShell | 攻撃ツールでよく使う文字列を含むスクリプトを検知する（4104） | ART / Caldera | T1059.001 #1（Mimikatz）; T1059.001 #3（Run Bloodhound from Memory using Download Cradle） | — |  |
| Unloading AMSI via Reflection | T1059.001 | TTP | Data Destruction / Hermetic Wiper / Malicious PowerShell | リフレクションで AMSI（マルウェア対策のスキャン機能）を無効化するスクリプトを検知する（4104） | ART / Caldera | T1685 #16（AMSI Bypass - AMSI InitFailed） | — |  |
| Windows Suspicious Process File Path | T1036.005 | TTP | AgentTesla / Amadey / AsyncRAT / Azorult / BlackByte Ransomware / Brute Ratel C4 / CISA AA23-347A / Castle RAT / Chaos Ransomware / China-Nexus Threat Activity / DarkCrystal RAT / DarkGate Malware / Data Destruction / Double Zero Destructor / Earth Alux / GhostRedirector IIS Module and Rungan Backdoor / Graceful Wipe Out Attack / Handala Wiper / Hermetic Wiper / IcedID / Industroyer2 / Interlock Ransomware / Interlock Rat / LockBit Ransomware / Lokibot / Malicious Inno Setup Loader / Meduza Stealer / MoonPeak / NailaoLocker Ransomware / Phemedrone Stealer / PlugX / Prestige Ransomware / PromptLock / Qakbot / Quasar RAT / RedLine Stealer / Remcos / Rhysida Ransomware / Salt Typhoon / SnappyBee / Swift Slicer / SystemBC / Trickbot / ValleyRAT / Volt Typhoon / Warzone RAT / Water Gamayun / WhisperGate / XMRig / XWorm | C:\Users\Public や C:\PerfLogs など、通常プログラムを置かない場所からの実行を検知する | ART / Caldera | T1036.005 #4（WMIC masquerade as ncv.exe in temp directory） | CIM | Caldera の C:\Temp\splunkd.exe は、ルールが \temp\ を除外しているので当たらない |
| Windows LOLBAS Executed Outside Expected Path | T1036.005 | TTP | Living Off The Land / Masquerading - Rename System Utilities / Windows Defense Evasion Tactics | LOLBAS（OS 標準の悪用されやすいツール）を本来と違う場所にコピーして実行したことを検知する | ART / Caldera | T1036.005 #2（Masquerade as a built-in system executable）; T1036.005 #3（Masquerading cmd.exe as VEDetector.exe） | CIM |  |
| Attacker Tools On Endpoint | T1036.005 | TTP | CISA AA22-264A / Cisco Network Visibility Module Analytics / Compromised Windows Host / PHP-CGI RCE Attack on Japanese Organizations / SamSam Ransomware / Scattered Spider / Unusual Processes / XMRig | 攻撃ツールの一覧（ルックアップ）にあるプロセス名の実行を検知する | ART / Caldera | T1003.001 #1（Dump LSASS.exe Memory using ProcDump）; T1059.001 #2（Run BloodHound from local disk） | CIM | procdump や SharpHound なども一覧に含まれる |
| Suspicious Rundll32 no Command Line Arguments | T1218.011 | TTP | BlackByte Ransomware / Cobalt Strike / Graceful Wipe Out Attack / Hellcat Ransomware / PrintNightmare CVE-2021-34527 / Suspicious Rundll32 Activity | 引数なしの rundll32.exe の実行（プロセスインジェクションの踏み台によくある）を検知する | 手動（RDP / SSH で入って実行） | — | CIM | Cobalt Strike の典型。ART に直接のテストは無いので手動で再現する |
| Detect Rundll32 Inline HTA Execution | T1218.005 | TTP | APT37 Rustonotto and FadeStealer / Living Off The Land / NOBELIUM Group / Suspicious MSHTA Activity | rundll32 に javascript: / vbscript: を渡したインライン実行を検知する | ART / Caldera | T1218.011 #1（Rundll32 execute JavaScript Remote Payload With GetObject）; T1218.011 #2（Rundll32 execute VBscript command） | CIM |  |
| Suspicious mshta child process | T1218.005 | TTP | Living Off The Land / Lumma Stealer / Suspicious MSHTA Activity | mshta.exe から powershell や cmd などが起動したことを検知する | ART / Caldera | T1218.005 #2（Mshta executes VBScript to execute malicious command）; T1218.005 #10（Mshta used to Execute PowerShell） | CIM |  |
| Windows Event Log Cleared | T1070.001 | TTP | CISA AA22-264A / Clop Ransomware / Compromised Windows Host / Ransomware / ShrinkLocker / Windows Log Manipulation | セキュリティログ（1102）やシステムログ（104）が消去されたことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1685.005 #1（Clear Logs）; T1685.005 #2（Delete System Logs Using Clear-EventLog） | — | ART の旧番号は T1070.001 |
| Disable Logs Using WevtUtil | T1070.001 | TTP | CISA AA23-347A / Ransomware / Rhysida Ransomware | wevtutil でイベントログを無効化・消去したことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1685.001 #6（Disable Event Logging with wevtutil） | CIM | ART の旧番号は T1562.002 / T1070.001 |
| Unload Sysmon Filter Driver | T1562.001 | TTP | CISA AA23-347A / Disabling Security Tools | fltMC で Sysmon のドライバーをアンロードして、Sysmon の記録を止めたことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1685 #14（Unload Sysmon Filter Driver） | CIM | SOC 的に最重要。成功すると以降の Sysmon ログが止まるので、テストのあとに Sysmon を戻す |
| Windows Attempt To Stop Security Service | T1562.001 | TTP | Azorult / Data Destruction / Disabling Security Tools / Graceful Wipe Out Attack / Trickbot / WhisperGate | net / sc でセキュリティ製品のサービスを停止しようとしたことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1685 #18（Disable Arbitrary Security Windows Service）; T1685 #24（Stop and Remove Arbitrary Security Windows Service） | CIM |  |
| Add or Set Windows Defender Exclusion | T1562.001 | TTP | AgentTesla / CISA AA22-320A / Compromised Windows Host / Crypto Stealer / Data Destruction / Remcos / ValleyRAT / WhisperGate / Windows Defense Evasion Tactics / XWorm | Add-MpPreference / Set-MpPreference で Defender の除外を追加したことを検知する | ART / Caldera | T1685 #26（Tamper with Windows Defender Evade Scanning -Folder）; T1685 #27（Tamper with Windows Defender Evade Scanning -Extension）; T1685 #28（Tamper with Windows Defender Evade Scanning -Process） | CIM | Server に Defender が無くても、コマンドの実行は記録される |
| Disable AMSI Through Registry | T1562.001 | TTP | CISA AA23-347A / Ransomware / Windows Registry Abuse | レジストリの AmsiEnable を 0 にして AMSI を無効化したことを検知する | ART / Caldera | T1685 #56（AMSI Bypass - Create AMSIEnable Reg Key） | CIM |  |

### 永続化・権限

| ルール | ATT&CK | 種別 | ESCU ストーリー | 概要 | 再現方法 | ART のテスト | SPL・マクロの修正 | メモ |
|---|---|---|---|---|---|---|---|---|
| Windows Scheduled Task with Highest Privileges | T1053.005 | TTP | AsyncRAT / CISA AA23-347A / Castle RAT / Compromised Windows Host / Quasar RAT / RedLine Stealer / Scheduled Tasks / XWorm | schtasks で /rl highest（最上位の特権）付きのタスクを作成したことを検知する | 手動（RDP / SSH で入って実行） | — | CIM | schtasks.exe のコマンドラインだけを見ている。Caldera エージェントのタスクは Ansible が API で登録するので当たらない見込み |
| WinEvent Scheduled Task Created Within Public Path | T1053.005 | TTP | 0bj3ctivity Stealer / APT37 Rustonotto and FadeStealer / Active Directory Lateral Movement / AsyncRAT / CISA AA22-257A / CISA AA23-347A / Castle RAT / China-Nexus Threat Activity / Compromised Windows Host / Data Destruction / IcedID / Industroyer2 / Malicious Inno Setup Loader / Medusa Ransomware / Prestige Ransomware / Quasar RAT / Ransomware / Ryuk Ransomware / Salt Typhoon / Scheduled Tasks / SystemBC / Windows Persistence Techniques / Winter Vivern / XWorm | Public / ProgramData / Temp などのパスを実行するスケジュールタスクの登録を検知する（4698） | ART / Caldera | T1053.005 #2（Scheduled task Local）; T1053.005 #4（Powershell Cmdlet Scheduled Task） | — | Caldera エージェントのタスク（C:\Temp\splunkd.exe）が build のたびに当たる（ラボ固有の誤検知） |
| Scheduled Task Deleted Or Created via CMD | T1053.005 | TTP | 0bj3ctivity Stealer / APT37 Rustonotto and FadeStealer / AgentTesla / Amadey / AsyncRAT / Azorult / CISA AA22-257A / CISA AA23-347A / CISA AA24-241A / China-Nexus Threat Activity / DHS Report TA18-074A / DarkCrystal RAT / Living Off The Land / Lokibot / Medusa Ransomware / MoonPeak / NOBELIUM Group / NjRAT / Phemedrone Stealer / Prestige Ransomware / Qakbot / Quasar RAT / RedLine Stealer / Rhysida Ransomware / Salt Typhoon / Sandworm Tools / Scattered Spider / Scheduled Tasks / ShrinkLocker / Trickbot / Windows Persistence Techniques / Winter Vivern / XWorm | schtasks の /create / /delete を検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1053.005 #1（Scheduled Task Startup Script）; T1053.005 #2（Scheduled task Local） | CIM |  |
| Windows Schtasks Create Run As System | T1053.005 | TTP | Castle RAT / Medusa Ransomware / Qakbot / Scheduled Tasks / Windows Persistence Techniques | schtasks で /ru system（SYSTEM 権限で実行）のタスクを作成したことを検知する | ART / Caldera | T1053.005 #1（Scheduled Task Startup Script） | CIM | テストのコマンドに /ru system が入っているかは実行前に -ShowDetails で確認する |
| Sc exe Manipulating Windows Services | T1543.003 | TTP | Azorult / Crypto Stealer / DHS Report TA18-074A / Disabling Security Tools / NOBELIUM Group / Orangeworm Attack Group / Scattered Spider / Windows Drivers / Windows Persistence Techniques / Windows Service Abuse | sc.exe でサービスを作成・変更したことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1543.003 #2（Service Installation CMD） | CIM |  |
| Windows Service Creation on Remote Endpoint | T1543.003 | TTP | Active Directory Lateral Movement / CISA AA23-347A / China-Nexus Threat Activity / Salt Typhoon / SnappyBee | sc.exe \\<リモート> create でリモートの端末にサービスを作成したことを検知する | ART / Caldera | T1543.003 #5（Remote Service Installation CMD） | CIM |  |
| Registry Keys Used For Persistence | T1547.001 | TTP | 0bj3ctivity Stealer / APT37 Rustonotto and FadeStealer / Amadey / AsyncRAT / Azorult / BlackByte Ransomware / BlackSuit Ransomware / Braodo Stealer / CISA AA23-347A / Cactus Ransomware / Chaos Ransomware / China-Nexus Threat Activity / DHS Report TA18-074A / DarkGate Malware / Derusbi / Emotet Malware DHS Report TA18-201A / IcedID / Interlock Ransomware / MoonPeak / NjRAT / Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns / Qakbot / Quasar RAT / Ransomware / RedLine Stealer / Remcos / Salt Typhoon / Snake Keylogger / SnappyBee / Sneaky Active Directory Persistence Tricks / Suspicious MSHTA Activity / Suspicious Windows Registry Activities / SystemBC / Warzone RAT / WinDealer RAT / Windows Persistence Techniques / Windows Registry Abuse / XWorm | Run / RunOnce など自動起動用のレジストリキーの変更を検知する | ART / Caldera | T1547.001 #1（Reg Key Run）; T1547.001 #2（Reg Key RunOnce）; T1547.001 #3（PowerShell Registry RunOnce） | CIM |  |
| Detect New Local Admin account | T1136.001 | TTP | CISA AA22-257A / CISA AA24-241A / DHS Report TA18-074A / HAFNIUM Group / Scattered Lapsus$ Hunters | 新しいユーザーの作成（4720）と Administrators への追加（4732）が続いたことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1136.001 #8（Create a new Windows admin user） | — |  |
| Windows AD Privileged Group Modification | T1098 | TTP | Active Directory Privilege Escalation / Sneaky Active Directory Persistence Tricks | Domain Admins など特権の AD グループへのメンバー追加を検知する（4728） | ART / Caldera ＋ 手動（RDP / SSH で入って実行） ＋ DC で実行 | T1098 #2（Domain Account and Group Manipulate） | — | DC で実行 |
| Windows AD add Self to Group | T1098 | TTP | Active Directory Privilege Escalation / Medusa Ransomware / Sneaky Active Directory Persistence Tricks | ユーザーが自分自身を AD グループに追加したことを検知する（4728） | 手動（RDP / SSH で入って実行） ＋ DC で実行 | — | — | DC で、追加する人と追加される人を同じアカウントにして手動で再現する |

### 横展開

| ルール | ATT&CK | 種別 | ESCU ストーリー | 概要 | 再現方法 | ART のテスト | SPL・マクロの修正 | メモ |
|---|---|---|---|---|---|---|---|---|
| Detect PsExec With accepteula Flag | T1021.002 | TTP | Active Directory Lateral Movement / BlackByte Ransomware / CISA AA22-320A / Cactus Ransomware / DHS Report TA18-074A / DarkGate Malware / DarkSide Ransomware / HAFNIUM Group / IcedID / Medusa Ransomware / Rhysida Ransomware / SamSam Ransomware / Sandworm Tools / Seashell Blizzard / VanHelsing Ransomware / Volt Typhoon | PsExec に -accepteula を付けて実行したことを検知する | ART / Caldera | T1021.002 #3（Copy and Execute File with PsExec） | CIM |  |
| Impacket Lateral Movement Commandline Parameters | T1021.002 | TTP | Active Directory Lateral Movement / CISA AA22-277A / Compromised Windows Host / Data Destruction / Gozi Malware / Graceful Wipe Out Attack / Industroyer2 / Prestige Ransomware / Volt Typhoon / WhisperGate | Impacket（smbexec / atexec など）が作る特徴的な cmd.exe のコマンドラインを検知する | ART / Caldera | T1047 #11（Impacket wmiexec.py） | CIM | Impacket は Python のツール。Linux 側から実行する |
| Impacket Lateral Movement WMIExec Commandline Parameters | T1021.002 | TTP | Active Directory Lateral Movement / CISA AA22-277A / Compromised Windows Host / Data Destruction / Gozi Malware / Graceful Wipe Out Attack / Industroyer2 / Prestige Ransomware / Volt Typhoon / WhisperGate | wmiprvse.exe から起動した、wmiexec 特有の cmd.exe のコマンドラインを検知する | ART / Caldera | T1047 #11（Impacket wmiexec.py） | CIM |  |
| Executable File Written in Administrative SMB Share | T1021.002 | TTP | Active Directory Lateral Movement / BlackSuit Ransomware / Compromised Windows Host / Data Destruction / Graceful Wipe Out Attack / Hermetic Wiper / IcedID / Industroyer2 / Prestige Ransomware / Trickbot / VanHelsing Ransomware | 管理共有（C$ / ADMIN$）に .exe / .dll を書き込んだことを検知する（5145） | ART / Caldera | T1021.002 #3（Copy and Execute File with PsExec） | — | 5145 は advanced_logging の「詳細なファイル共有」監査で出る |
| Remote Process Instantiation via WMI | T1047 | TTP | Active Directory Lateral Movement / CISA AA23-347A / China-Nexus Threat Activity / Ransomware / Salt Typhoon / Suspicious WMI Use | wmic /node: でリモートの端末にプロセスを作成したことを検知する | ART / Caldera | T1047 #6（WMI Execute Remote Process） | CIM |  |
| Remote Process Instantiation via WinRM and PowerShell | T1021.006 | TTP | Active Directory Lateral Movement | Invoke-Command -ComputerName でリモートの端末にコマンドを実行したことを検知する | ART / Caldera | T1021.006 #2（Remote Code Execution with PS Credentials Using Invoke-Command） | CIM |  |
| Wsmprovhost LOLBAS Execution Process Spawn | T1021.006 | TTP | Active Directory Lateral Movement / CISA AA24-241A / Hellcat Ransomware | WinRM のホストプロセス（wsmprovhost.exe）から LOLBAS（rundll32 / mshta など）が直接起動したことを検知する | ART / Caldera | T1021.006 #2（Remote Code Execution with PS Credentials Using Invoke-Command） | CIM | ART の simulate は WinRM 経由だが、wsmprovhost の直下は powershell.exe（一覧に無い）なので、常に発火するわけではない。テストのバイナリが直下に来たときだけ当たる |
| Windows Remote Services Rdp Enable | T1021.001 | TTP | Azorult / BlackSuit Ransomware / Medusa Ransomware / Windows RDP Artifacts and Defense Evasion | レジストリの fDenyTSConnections を 0 にして RDP を有効化したことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | — | CIM | 手動でレジストリを変更して再現する |
| Windows RDP Login Session Was Established | T1021.001 | Anomaly | Scattered Lapsus$ Hunters / Windows RDP Artifacts and Defense Evasion | RDP でのログオン（4624、ログオンの種類 10）を検知する | 手動（RDP / SSH で入って実行） | — | — | RDP で入るだけで発火する |
| Windows Remote Desktop Network Bruteforce Attempt | T1110.001 | Anomaly | Compromised User Account / Ryuk Ransomware / SamSam Ransomware / Windows RDP Artifacts and Defense Evasion | 1 時間以内に 3389 番への接続が 10 回を超えたこと（RDP の総当たり）を検知する（Sysmon 3） | 手動（RDP / SSH で入って実行） | — | CIM | SPL の values(Al_Traffic.src_port) は All_Traffic のタイプミス（src_port が空になるだけで、発火には影響しない）。RDP のログイン失敗を手で繰り返して再現する |
| Windows Special Privileged Logon On Multiple Hosts | T1021.002 | TTP | Active Directory Lateral Movement / Active Directory Privilege Escalation / Compromised Windows Host | 同じユーザーが 5 分以内に 30 台以上へ特権ログオン（4672）したことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | — | — | しきい値 30 台に対してラボは Windows 4 台なので、そのままでは発火しない。試すならしきい値を 3 に下げたコピーを作る |

### ツールの持ち込み

| ルール | ATT&CK | 種別 | ESCU ストーリー | 概要 | 再現方法 | ART のテスト | SPL・マクロの修正 | メモ |
|---|---|---|---|---|---|---|---|---|
| Windows File Download Via CertUtil | T1105 | TTP | CISA AA22-277A / Cisco Network Visibility Module Analytics / Compromised Windows Host / DarkSide Ransomware / Flax Typhoon / Forest Blizzard / Ingress Tool Transfer / Living Off The Land / ProxyNotShell | certutil の -urlcache / -verifyctl でファイルをダウンロードしたことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1105 #7（certutil download (urlcache)）; T1105 #8（certutil download (verifyctl)） | CIM |  |
| BITSAdmin Download File | T1105 | TTP | APT37 Rustonotto and FadeStealer / BITS Jobs / DarkSide Ransomware / Flax Typhoon / GhostRedirector IIS Module and Rungan Backdoor / Gozi Malware / Hellcat Ransomware / Ingress Tool Transfer / Living Off The Land / Scattered Spider | bitsadmin の /transfer でファイルをダウンロードしたことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1105 #9（Windows - BITSAdmin BITS Download） | CIM |  |
| Windows Curl Download to Suspicious Path | T1105 | TTP | APT37 Rustonotto and FadeStealer / Black Basta Ransomware / China-Nexus Threat Activity / Cisco Network Visibility Module Analytics / Compromised Windows Host / Forest Blizzard / GhostRedirector IIS Module and Rungan Backdoor / IcedID / Ingress Tool Transfer / Salt Typhoon | curl.exe で AppData / ProgramData / Public などにファイルを保存したことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1105 #18（Curl Download File） | CIM | 保存先が対象のパスになるかは、テストの引数で確認する |

### Linux

| ルール | ATT&CK | 種別 | ESCU ストーリー | 概要 | 再現方法 | ART のテスト | SPL・マクロの修正 | メモ |
|---|---|---|---|---|---|---|---|---|
| Linux Decode Base64 to Shell | T1027 | TTP | Linux Living Off The Land | base64 でデコードした内容をシェルにパイプで渡したことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1027 #1（Decode base64 Data into Script） | CIM | Linux は Sysmon for Linux（sysmon:linux）のプロセスログを使う |
| Linux Curl Upload File | T1105 | TTP | Data Exfiltration / Ingress Tool Transfer / Linux Living Off The Land | curl の -F / --upload-file / -d などでファイルを外部に送ったことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | — | CIM | ルールは AWS の認証情報ファイルの送信を想定。手動で再現する |
| Linux Ingress Tool Transfer with Curl | T1105 | Anomaly | Ingress Tool Transfer / Linux Living Off The Land / XorDDos | curl の -O / --output などでスクリプトやバイナリをダウンロードしたことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1105 #27（Linux Download File and Run） | CIM |  |
| Linux NOPASSWD Entry In Sudoers File | T1548.003 | Anomaly | China-Nexus Threat Activity / Linux Persistence Techniques / Linux Privilege Escalation / Salt Typhoon | sudoers に NOPASSWD のエントリを書き込むコマンドを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | — | CIM | 手動で再現する |
| Linux Auditd Sudo Or Su Execution | T1548.003 | Anomaly | Compromised Linux Host / Linux Persistence Techniques / Linux Privilege Escalation | sudo / su の実行を検知する（auditd） | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1548.003 #1（Sudo usage） | AUDITD |  |
| Linux Find Privilege Escalation | T1548.003 | Anomaly | Linux Living Off The Land / Linux Privilege Escalation | sudo 付きの find -exec（GTFOBins の代表的な権限昇格）を検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | — | CIM | 手動で再現する |
| Linux Add Files In Known Crontab Directories | T1053.003 | Anomaly | Linux Living Off The Land / Linux Persistence Techniques / Linux Privilege Escalation / Scheduled Tasks / XorDDos | /etc/cron* や /var/spool/cron にファイルが作られたことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1053.003 #1（Cron - Replace crontab with referenced file）; T1053.003 #3（Cron - Add script to /etc/cron.d folder） | CIM | ファイル作成のログ（Sysmon for Linux の 11）が前提 |
| Linux Auditd Add User Account | T1136.001 | Anomaly | Compromised Linux Host / Linux Persistence Techniques / Linux Privilege Escalation | useradd / adduser でユーザーを作成したことを検知する（auditd） | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1136.001 #1（Create a user account on a Linux system） | AUDITD |  |
| Linux SSH Authorized Keys Modification | T1098.004 | Anomaly | Hellcat Ransomware / Linux Living Off The Land | authorized_keys を書き換えるコマンドを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1098.004 #1（Modify SSH Authorized Keys） | CIM |  |
| Linux Possible Access Or Modification Of sshd Config File | T1098.004 | Anomaly | Linux Living Off The Land / Linux Persistence Techniques / Linux Privilege Escalation | cat / vi などで sshd_config を開いたことを検知する | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | — | CIM | 手動で再現する |
| Linux SSH Remote Services Script Execute | T1021.004 | TTP | Hellcat Ransomware / Linux Living Off The Land | ssh の -o StrictHostKeyChecking などを付けて、リモートでスクリプトを実行したことを検知する | 手動（RDP / SSH で入って実行） | — | CIM | SSH で入って手動で再現する |
| Linux Auditd Whoami User Discovery | T1033 | Anomaly | Compromised Linux Host / Linux Living Off The Land / Linux Persistence Techniques / Linux Privilege Escalation | whoami の実行を検知する（auditd） | ART / Caldera ＋ 手動（RDP / SSH で入って実行） | T1033 #2（System Owner/User Discovery） | AUDITD |  |

### ネットワーク（Palo 前提）

| ルール | ATT&CK | 種別 | ESCU ストーリー | 概要 | 再現方法 | ART のテスト | SPL・マクロの修正 | メモ |
|---|---|---|---|---|---|---|---|---|
| Internal Horizontal Port Scan | T1046 | TTP | China-Nexus Threat Activity / Cisco Secure Firewall Threat Defense Analytics / Network Discovery / Scattered Lapsus$ Hunters | 内部の 1 台が、同じポートで 250 以上の宛先に通信したこと（横方向のスキャン）を検知する | ラボでは再現しない。Palo があれば：複数ホストへの同一ポートのスキャン（OpenCanary を含むサブネットへ nmap） | — | PALO |  |
| Internal Vertical Port Scan | T1046 | TTP | China-Nexus Threat Activity / Cisco Secure Firewall Threat Defense Analytics / Network Discovery / Scattered Lapsus$ Hunters | 内部の 1 台が、1 つの宛先の 500 以上のポートに通信したこと（縦方向のスキャン）を検知する | ラボでは再現しない。Palo があれば：OpenCanary 1 台へのポートスキャン | — | PALO |  |
| Internal Horizontal Port Scan NMAP Top 20 | T1046 | TTP | China-Nexus Threat Activity / Cisco Secure Firewall Threat Defense Analytics / Network Discovery / Scattered Lapsus$ Hunters | nmap の上位 20 ポートで、250 以上の宛先に通信したことを検知する | ラボでは再現しない。Palo があれば：`nmap --top-ports 20` | — | PALO |  |
| Internal Vulnerability Scan | T1595.002, T1046 | TTP | Network Discovery / Scattered Lapsus$ Hunters | 内部からの脆弱性スキャン（IDS の検知が多数の宛先に出る）を検知する | ラボでは再現しない。Palo があれば：脆弱性スキャナ（nmap の NSE など） | — | PALO | ESCU 側で EXPERIMENTAL 扱い |
| Protocols passing authentication in cleartext | — | Anomaly | Cisco Secure Firewall Threat Defense Analytics / Scattered Lapsus$ Hunters / Use of Cleartext Protocols | Telnet / FTP / POP3 など平文で認証するプロトコルの通信を検知する | ラボでは再現しない。Palo があれば：OpenCanary の FTP / Telnet にログイン試行 | — | PALO |  |
| Remote Desktop Network Traffic | T1021.001 | Anomaly | Active Directory Lateral Movement / Hidden Cobra Malware / Ryuk Ransomware / SamSam Ransomware / Windows RDP Artifacts and Defense Evasion | 普段 RDP を使わない端末どうしの 3389 番の通信を検知する | ラボでは再現しない。Palo があれば：OpenCanary の RDP（3389）へ接続 | — | PALO |  |
| SMB Traffic Spike | T1021.002 | Anomaly | DHS Report TA18-074A / Emotet Malware DHS Report TA18-201A / Hidden Cobra Malware / Ransomware | SMB（139 / 445）の通信量が普段より急に増えたことを検知する | ラボでは再現しない。Palo があれば：OpenCanary の SMB 共有へ大量アクセス | — | PALO | ESCU 側で EXPERIMENTAL 扱い |
| Protocol or Port Mismatch | T1048.003 | Anomaly | Cisco Secure Firewall Threat Defense Analytics / Command And Control / Prohibited Traffic Allowed or Protocol Mismatch | ポートとアプリが合わない通信（80 番で HTTP 以外など）を検知する | ラボでは再現しない。Palo があれば：非標準ポートで HTTP など | — | PALO |  |
| Prohibited Network Traffic Allowed | T1048 | TTP | Cisco Secure Firewall Threat Defense Analytics / Command And Control / Prohibited Traffic Allowed or Protocol Mismatch / Ransomware | 禁止しているポート（ルックアップで定義）の通信が許可されていたことを検知する | ラボでは再現しない。Palo があれば：禁止ポート（要ルックアップ定義） | — | PALO | ルックアップ lookup_interesting_ports の定義が必要 |
| Windows AD Replication Service Traffic | T1003.006, T1207 | TTP | Sneaky Active Directory Persistence Tricks | DC 以外からの AD 複製（DRSUAPI）の通信を検知する | ラボでは再現しない。Palo があれば：DCSync の通信。DC と端末の間を Palo が見ている必要あり | — | PALO | ESCU 側で EXPERIMENTAL 扱い |
| Detect Remote Access Software Usage Traffic | T1219 | Anomaly | Command And Control / Insider Threat / Interlock Ransomware / Ransomware / Remote Monitoring and Management Software / Scattered Lapsus$ Hunters / Scattered Spider | AnyDesk / TeamViewer などリモートアクセスソフトの通信を検知する（Palo の App-ID） | ラボでは再現しない。Palo があれば：Palo の App-ID（AnyDesk など） | — | PALO |  |
| Detect Large ICMP Traffic | T1095 | TTP | Backdoor Pingpong / China-Nexus Threat Activity / Command And Control | 外部宛ての 1,000 バイトを超える ICMP 通信（ICMP トンネルなど）を検知する | ラボでは再現しない。Palo があれば：大きな ICMP | — | PALO |  |
| TOR Traffic | T1090.003 | TTP | Cisco Secure Firewall Threat Defense Analytics / Command And Control / Interlock Ransomware / NOBELIUM Group / Prohibited Traffic Allowed or Protocol Mismatch / Ransomware | TOR の通信が許可されていたことを検知する（Palo の App-ID） | ラボでは再現しない。Palo があれば：Palo の App-ID `tor` | — | PALO |  |
| Detect Remote Access Software Usage URL | T1219 | Anomaly | CISA AA24-241A / Command And Control / Insider Threat / Interlock Ransomware / Ransomware / Remote Monitoring and Management Software / Scattered Lapsus$ Hunters | リモートアクセスソフトの URL へのアクセスを検知する（Palo の URL フィルタリングのログ） | ラボでは再現しない。Palo があれば：Palo の URL フィルタリングのログ | — | PALO |  |
| Detect Outbound LDAP Traffic | T1190, T1059 | Hunting | Cisco Secure Firewall Threat Defense Analytics / Log4Shell CVE-2021-44228 | 外部の IP への LDAP（389 / 636）通信を検知する（Log4Shell の JNDI など） | ラボでは再現しない。Palo があれば：外向きの LDAP（Log4Shell の JNDI など）。Hunting | — | PALO | Hunting（定期実行ではなく調査用） |

<!-- END RULE TABLES (generated) -->

ネットワークのルールは、データソース欄が Cisco や AWS でも、中身が CIM の `Network_Traffic` を見ていれば Palo の TA（CIM 対応）でそのまま動く。Palo のデータソースを名指ししている 13 本のうち、特定製品の脆弱性悪用（F5 BIG-IP、Confluence、FortiNAC、Fortinet、Citrix ADC、VMware Aria / Workspace ONE）の 8 本は、守る対象にその製品が無いので除外した。

OpenCanary 自身のログ（index `honeypot`）には ESCU のルールが無い。OpenCanary 側の検知は自作ルールで補う（別途）。

## ラボ固有の誤検知（除外条件を書く練習台）

- `WinEvent Scheduled Task Created Within Public Path`：Attack Range が build 時に Caldera エージェントを `C:\Temp\splunkd.exe` を実行するタスクとして登録するので、4698 で当たる
- `Wsmprovhost LOLBAS Execution Process Spawn`：ART の simulate は WinRM 経由なので `wsmprovhost.exe` 配下で動く。直下は `powershell.exe`（ルールの一覧に無い）なので常には当たらないが、テストのバイナリが直下に来ると当たる
- `svchost.exe` → `lsass.exe` の `GrantedAccess 0x1000`：正常なアクセス。LSASS 系のルールで拾わないか確認する

（2026-11-04 訂正：`Windows Scheduled Task with Highest Privileges` は `schtasks.exe` のコマンドラインだけを見ているので、Ansible が API で登録する Caldera のタスクには当たらない見込み）

## ルールの有効化

ESCU のルールは、最初は全部無効になっている。98 本を 1 本ずつ画面で有効にする必要はなく、まとめて有効にできる（手順は別途用意する）。

## 次の手順

1. 「前提と共通の修正」を済ませる
2. 本命リストのルールを Splunk で有効化する
3. テクニックごとに ART / Caldera / 手動で再現し、発火を確認する。発火しなければ「ログが無い」「マクロのずれ」「データモデル」「しきい値」のどれかを切り分ける
4. 会社の ESCU の版が分かったら、そのパッケージで `tools/escu/` を回し、名前で突き合わせる

## 一覧の再生成

```powershell
# ESCU パッケージ（例：5.18.0）を空のフォルダに展開してから
python -I tools\escu\escu_extract.py <DA-ESS-ContentUpdate\default\savedsearches.conf> escu.csv
# ART の索引：https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/Indexes/Indexes-CSV
python -I tools\escu\escu_classify.py escu.csv windows-index.csv linux-index.csv escu_classified.csv
python -I tools\escu\escu_shortlist.py escu_classified.csv escu_shortlist.csv

# 本命リスト（このファイルの表と escu/escu_selection.csv）
#   ルールの増減は docs\escu\escu_selection.csv、概要や ART の対応は tools\escu\selection_notes.py を編集してから
python -I tools\escu\escu_selection_build.py <DA-ESS-ContentUpdate\default\savedsearches.conf> <ART の索引 CSV のフォルダ>
```
