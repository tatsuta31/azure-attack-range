# ESCU 検知ルールの選定（v0）

対象：ESCU **5.18.0**（ラボの core Splunk に入っている版）。会社の環境（884 件）の版は未確認。ルール名は版をまたいでほぼ変わらないので、版が分かったら名前で突き合わせる。

## 選定の範囲（2026-11-02 決定）

- **対象にするログ**：ラボで実際に取れるログ ＋ **Palo Alto のログ（ある前提）**
- **除外**：上記以外の製品のログが前提のルール（AWS、Azure AD、O365、CrowdStrike、Cisco、Okta など）。626 本
- Palo はラボには**置かない**。区分 B は「Palo のログがあれば動くルール」として選ぶが、ラボでは再現・検証しない

## 選定の軸

| 区分 | 再現手段 | 使うログ |
|---|---|---|
| A | ART / Caldera | Sysmon、Windows Security、PowerShell 4104、Linux（Sysmon for Linux / auditd） |
| B | **ラボでは再現しない**（Palo 前提の選定のみ） | Palo のトラフィック／脅威ログ（CIM の `Network_Traffic` / `Intrusion_Detection`） |
| C | RDP / SSH で入って手でコマンド実行 | A と同じ。親プロセスが `explorer.exe` や `sshd` になり、実戦に近い |

前提：Windows は全台 `advanced_logging: "1"`（Kerberos 4768/4769、ディレクトリサービスアクセス 4662、ログオン 4624/4625、プロセス作成 4688 など）と `win_sysmon_config: "AttackRangeSysmon.xml"`。

## 絞り込みの経過

| 段階 | 本数 | 内容 |
|---|---|---|
| ESCU 5.18.0 の検知ルール | 1,941 | 廃止済みを除くと 1,934 |
| ラボのログで動く | 1,235 | 製品なし（CrowdStrike、AWS、O365 など）626、追加設定が必要（5136 など）60、Palo 13 を除く |
| 攻撃計画のテクニックに該当（TTP / Anomaly） | 437 | `escu/escu_5180_shortlist.csv` |
| うち TTP | 293 | |
| **本命（このファイルの下の表）** | **98** | 手で選定（エンドポイント 83 ＋ ネットワーク 15）。全ルール名が 5.18.0 に実在することを機械照合済み |

全件の仕分け結果は `escu/escu_5180_classified.csv`（列 `bucket` が A/B/C/-、`availability` が ok/config/palo/no）。再生成は `tools/escu/` のスクリプトで行う（手順は末尾）。

## 本命リスト（A / C：エンドポイント）

「再現」は、A＝ART／Caldera、C＝手動、DC＝ドメインコントローラーが必要なもの。

### 認証情報の窃取

| ルール | ATT&CK | 再現 | メモ |
|---|---|---|---|
| Windows Possible Credential Dumping | T1003.001 | A | Sysmon 10。2026-11-01 の ART で該当ログを確認済み |
| Access LSASS Memory for Dump Creation | T1003.001 | A | |
| Dump LSASS via comsvcs DLL | T1003.001 | A | LOLBin の定番 |
| Dump LSASS via procdump | T1003.001 | A | |
| Windows Non-System Account Targeting Lsass | T1003.001 | A | |
| Windows Sensitive Registry Hive Dump Via CommandLine | T1003.002 | A | `reg save HKLM\SAM` |
| Creation of Shadow Copy | T1003.003 | A / DC | |
| Ntdsutil Export NTDS | T1003.003 | A / DC | |
| Windows AD Replication Request Initiated by User Account | T1003.006 | A / DC | DCSync。4662 が必要 |
| Windows AD Replication Request Initiated from Unsanctioned Location | T1003.006 | A / DC | DCSync |
| Kerberoasting spn request with RC4 encryption | T1558.003 | A / DC | 4769 |
| ServicePrincipalNames Discovery with SetSPN | T1558.003 | A | |
| Rubeus Command Line Parameters | T1558.003 | A | |
| Kerberos Pre-Authentication Flag Disabled in UserAccountControl | T1558.004 | A / DC | AS-REP Roasting の下準備 |
| Detect Password Spray Attempts | T1110.003 | A / C | |
| Windows Multiple Users Failed To Authenticate Using Kerberos | T1110.003 | A / C / DC | |
| Enable WDigest UseLogonCredential Registry | T1003 | A | |

### 偵察

| ルール | ATT&CK | 再現 | メモ |
|---|---|---|---|
| Domain Controller Discovery with Nltest | T1018 | A | Caldera の Discovery で実行済み（`nltest /dsgetdc`） |
| NLTest Domain Trust Discovery | T1482 | A | |
| DSQuery Domain Discovery | T1482 | A | |
| Windows AdFind Exe | T1018 | A | |
| Domain Account Discovery with Wmic | T1087.002 | A | |
| Get DomainUser with PowerShell Script Block | T1087.002 | A | 4104 |
| GetDomainGroup with PowerShell Script Block | T1069.002 | A | 4104 |
| Elevated Group Discovery With Wmic | T1069.002 | A | |
| PowerShell Domain Enumeration | T1059.001 | A | |
| Detect SharpHound Usage | T1069.001 | A | BloodHound の収集 |
| Detect SharpHound Command-Line Arguments | T1069.001 | A | |
| Check Elevated CMD using whoami | T1033 | A / C | |
| Windows File Share Discovery With Powerview | T1135 | A | |

### 実行・防御回避

| ルール | ATT&CK | 再現 | メモ |
|---|---|---|---|
| Malicious PowerShell Process With Obfuscation Techniques | T1059.001 | A | Caldera の base64 難読化で狙う |
| Powershell Fileless Script Contains Base64 Encoded Content | T1027 | A | 4104。同上 |
| Detect Mimikatz With PowerShell Script Block Logging | T1059.001 | A | |
| Windows PowerShell Script Block With Malicious String | T1059.001 | A | |
| Unloading AMSI via Reflection | T1059.001 | A | |
| Windows Suspicious Process File Path | T1036.005 | A | Caldera の偽 `C:\Temp\splunkd.exe` に当たるか要確認 |
| Windows LOLBAS Executed Outside Expected Path | T1036.005 | A | |
| Attacker Tools On Endpoint | T1036.005 | A | |
| Suspicious Rundll32 no Command Line Arguments | T1218.011 | A | |
| Detect Rundll32 Inline HTA Execution | T1218.005 | A | |
| Suspicious mshta child process | T1218.005 | A | |
| Windows Event Log Cleared | T1070.001 | A / C | 1102 |
| Disable Logs Using WevtUtil | T1070.001 | A / C | |
| Unload Sysmon Filter Driver | T1562.001 | A / C | `fltmc unload SysmonDrv`。SOC 的に最重要 |
| Windows Attempt To Stop Security Service | T1562.001 | A / C | |
| Add or Set Windows Defender Exclusion | T1562.001 | A | Server は Defender 未導入でもコマンドは記録される |
| Disable AMSI Through Registry | T1562.001 | A | |

### 永続化・権限

| ルール | ATT&CK | 再現 | メモ |
|---|---|---|---|
| Windows Scheduled Task with Highest Privileges | T1053.005 | A | **build 時の Caldera エージェント登録でも発火する**（ラボ固有の誤検知） |
| WinEvent Scheduled Task Created Within Public Path | T1053.005 | A | 4698 |
| Scheduled Task Deleted Or Created via CMD | T1053.005 | A / C | |
| Windows Schtasks Create Run As System | T1053.005 | A | |
| Sc exe Manipulating Windows Services | T1543.003 | A / C | |
| Windows Service Creation on Remote Endpoint | T1543.003 | A | |
| Registry Keys Used For Persistence | T1547.001 | A | Run キー |
| Detect New Local Admin account | T1136.001 | A / C | |
| Windows AD Privileged Group Modification | T1098 | A / C / DC | Domain Admins への追加 |
| Windows AD add Self to Group | T1098 | A / DC | |

### 横展開

| ルール | ATT&CK | 再現 | メモ |
|---|---|---|---|
| Detect PsExec With accepteula Flag | T1021.002 | A | |
| Impacket Lateral Movement Commandline Parameters | T1021.002 | A | |
| Impacket Lateral Movement WMIExec Commandline Parameters | T1021.002 | A | |
| Executable File Written in Administrative SMB Share | T1021.002 | A | |
| Remote Process Instantiation via WMI | T1047 | A | |
| Remote Process Instantiation via WinRM and PowerShell | T1021.006 | A | |
| Wsmprovhost LOLBAS Execution Process Spawn | T1021.006 | A | **ART の simulate 自体が WinRM 経由なので常に発火する**（ラボ固有の誤検知。除外条件の練習台） |
| Windows Remote Services Rdp Enable | T1021.001 | A / C | |
| Windows RDP Login Session Was Established | T1021.001 | C | RDP で入るだけで発火 |
| Windows Remote Desktop Network Bruteforce Attempt | T1110.001 | C | Sysmon 3。RDP の連続失敗 |
| Windows Special Privileged Logon On Multiple Hosts | T1021.002 | A / C | |

### ツールの持ち込み

| ルール | ATT&CK | 再現 | メモ |
|---|---|---|---|
| Windows File Download Via CertUtil | T1105 | A / C | |
| BITSAdmin Download File | T1105 | A / C | |
| Windows Curl Download to Suspicious Path | T1105 | A / C | |

### Linux

| ルール | ATT&CK | 再現 | メモ |
|---|---|---|---|
| Linux Decode Base64 to Shell | T1027 | A / C | TTP |
| Linux Curl Upload File | T1105 | A / C | TTP |
| Linux Ingress Tool Transfer with Curl | T1105 | A / C | |
| Linux NOPASSWD Entry In Sudoers File | T1548.003 | A / C | |
| Linux Auditd Sudo Or Su Execution | T1548.003 | A / C | |
| Linux Find Privilege Escalation | T1548.003 | A / C | GTFOBins 系の代表 |
| Linux Add Files In Known Crontab Directories | T1053.003 | A / C | |
| Linux Auditd Add User Account | T1136.001 | A / C | |
| Linux SSH Authorized Keys Modification | T1098.004 | A / C | |
| Linux Possible Access Or Modification Of sshd Config File | T1098.004 | A / C | |
| Linux SSH Remote Services Script Execute | T1021.004 | C | SSH で入って実行 |
| Linux Auditd Whoami User Discovery | T1033 | A / C | |

## 本命リスト（B：ネットワーク / Palo Alto のログ前提）

データソース欄が Cisco や AWS でも、中身が CIM の `Network_Traffic` を見ているルールは Palo の TA（CIM 対応）でそのまま動く。ラボに Palo は置かないので、右の列は「Palo があればこう再現できる」という参考。

Palo のデータソースを名指ししている 13 本のうち、特定製品の脆弱性悪用（F5 BIG-IP、Confluence、FortiNAC、Fortinet、Citrix ADC、VMware Aria / Workspace ONE）の 8 本は、守る対象にその製品が無いので除外した。

| ルール | ATT&CK | 再現の参考（Palo がある場合） |
|---|---|---|
| Internal Horizontal Port Scan | T1046 | 複数ホストへの同一ポートのスキャン（OpenCanary を含むサブネットへ nmap） |
| Internal Vertical Port Scan | T1046 | OpenCanary 1 台へのポートスキャン |
| Internal Horizontal Port Scan NMAP Top 20 | T1046 | `nmap --top-ports 20` |
| Internal Vulnerability Scan | T1595.002, T1046 | 脆弱性スキャナ（nmap の NSE など） |
| Protocols passing authentication in cleartext | — | OpenCanary の FTP / Telnet にログイン試行 |
| Remote Desktop Network Traffic | T1021.001 | OpenCanary の RDP（3389）へ接続 |
| SMB Traffic Spike | T1021.002 | OpenCanary の SMB 共有へ大量アクセス |
| Protocol or Port Mismatch | T1048.003 | 非標準ポートで HTTP など |
| Prohibited Network Traffic Allowed | T1048 | 禁止ポート（要ルックアップ定義） |
| Windows AD Replication Service Traffic | T1003.006, T1207 | DCSync の通信。DC と端末の間を Palo が見ている必要あり |
| Detect Remote Access Software Usage Traffic | T1219 | Palo の App-ID（AnyDesk など） |
| Detect Large ICMP Traffic | T1095 | 大きな ICMP |
| TOR Traffic | T1090.003 | Palo の App-ID `tor` |
| Detect Remote Access Software Usage URL | T1219 | Palo の URL フィルタリングのログ |
| Detect Outbound LDAP Traffic | T1190, T1059 | 外向きの LDAP（Log4Shell の JNDI など）。Hunting |

OpenCanary 自身のログ（アラート JSON）には ESCU のルールが無い。OpenCanary 側の検知は自作ルールで補う（別途）。

## ラボ固有の誤検知（除外条件を書く練習台）

- `Wsmprovhost LOLBAS Execution Process Spawn`：ART の simulate は Ansible の WinRM 経由で実行されるので、毎回 `wsmprovhost.exe` が親になる
- `Windows Scheduled Task with Highest Privileges`：Attack Range が build 時に Caldera エージェントを `CalderaAgent` という隠しタスクで登録する
- `svchost.exe` → `lsass.exe` の `GrantedAccess 0x1000`：正常なアクセス。LSASS 系のルールで拾わないか確認する

## 次の手順

1. 本命リストのルールを Splunk で有効化する（ESCU の saved search は既定で無効）
2. テクニックごとに ART / Caldera / 手動で再現し、発火を確認する。発火しなければ「ログが無い」「マクロのずれ」「データモデル」のどれかを切り分ける
3. 会社の ESCU の版が分かったら、そのパッケージで `tools/escu/` を回し、名前で突き合わせる

## 一覧の再生成

```powershell
# ESCU パッケージ（例：5.18.0）を空のフォルダに展開してから
python -I tools\escu\escu_extract.py <DA-ESS-ContentUpdate\default\savedsearches.conf> escu.csv
# ART の索引：https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/Indexes/Indexes-CSV
python -I tools\escu\escu_classify.py escu.csv windows-index.csv linux-index.csv escu_classified.csv
python -I tools\escu\escu_shortlist.py escu_classified.csv escu_shortlist.csv
```
