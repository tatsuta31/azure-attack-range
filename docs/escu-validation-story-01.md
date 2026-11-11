# 検知検証ストーリー #01：ランサムウェア侵入を模した正検知検証（草案）

対象ラボ：このリポジトリの Azure Attack Range（ar-dc / ar-win1 / ar-win2 / ar-srv / ar-linux / ar-canary）＋ core Splunk 10.6.1。
目的：下の 6 ルールを **有効化し、1 件の架空の侵入ストーリーに沿って攻撃を再現して、正検知（True Positive）として発火することを確認する。**

> **草案メモ（2026-11-11）**：これは下書き。コマンドは裏取り済み（各ルールの検知 SPL を本家 security_content `develop` で確認）だが、ラボでの実発火はまだ未確認。実施しながら「発火した／しない」を記録表に埋めていく。

## 安全上の前提（必ず読む）

- 実行はすべて**この隔離ラボ内のみ**。range の Windows/Linux は侵害される前提の使い捨て端末。
- ランサムの再現は**ノート（脅迫文）を模した空テキストの大量作成だけ**。暗号化・破壊・実マルウェアは一切使わない。
- 監査ポリシー変更・ACL 変更は**すべて可逆**。各テストに「元に戻す手順」を付けた。戻してから次へ進む。
- 外部への実データ送信はしない（収集の再現は端末内のアーカイブ作成まで）。

---

## 対象ルールと実現可能性（サマリ）

| # | ルール | ATT&CK | データソース | 実行ホスト | 可否 | 前提 |
|---|---|---|---|---|---|---|
| 1 | Windows AD Domain Controller Audit Policy Disabled | T1685（旧 T1562.001） | Security 4719 | ar-dc | 条件付き可 | SPL の `dest_category="domain_controller"` を外す／`Computer=ar-dc` に差し替え |
| 2 | Palo : code injection internal→internal→external | T1055 系＋C2 | Palo トラフィック／脅威ログ | Palo（境界） | **可** | Palo ログが CIM の DataModel（Network_Traffic / Intrusion_Detection）に乗る設定は作業済み（ユーザー確認） |
| 3 | Windows Archive Collected Data via Powershell | T1560 | PowerShell 4104 | ar-win1 | 可 | 4104 は全 Windows で有効済み |
| 4 | Windows Scheduled Task with Suspicious Command | T1053.005 | Security 4698/4700/4702 | ar-win1 | 可 | `advanced_logging` の "Other Object Access Events" で 4698 出力済み |
| 5 | Ransomware Notes bulk creation | T1486 | Sysmon 11 | ar-win1 | 可（安全） | 同名ファイルを 15 個以上の別フォルダに作る |
| 6 | Windows AD Admin SDHolder ACL Modified | T1546 | Security 5136 | ar-dc | 条件付き可 | AdminSDHolder に SACL ＋ "Directory Service Changes" 有効化が必要 |

---

## 攻撃者ストーリー（全体像）

架空のランサムウェアオペレーター **「CRIMSON-LAB」** が、フィッシングで ar-win1 に初期侵入した後、ドメインを掌握してデータを収集し、最後にランサムノートを撒くまで。各段で上の 6 ルールが順に発火する想定。

```
[初期侵入] ar-win1 に foothold（前提。RDP で手動 or Caldera）
   │
   ├─(T1053.005) 永続化：怪しいコマンドのスケジュールタスクを登録 ……………………… ルール #4
   │
   ├─(T1055/C2) Palo が内部→内部→外部へのコードインジェクション通信を検知 ………… ルール #2
   │
   │   ── ここで DC へ水平移動（前提）──
   │
   ├─(T1546) AD 永続化：AdminSDHolder の ACL を改ざんし隠れ特権を仕込む（ar-dc） … ルール #6
   │
   ├─(T1685) 防御回避：DC の監査ポリシーを無効化して追跡を潰す（ar-dc） …………… ルール #1
   │
   ├─(T1560) 収集：窃取データを PowerShell で Temp にアーカイブ（ar-win1） ………… ルール #3
   │
   └─(T1486) 影響：全フォルダにランサムノートを撒く（ar-win1） …………………………… ルール #5
```

> **検証実務での注意**：ストーリー上は「#1 監査無効化 → #6 AdminSDHolder」の順だが、**先に監査を切ると #6 の 5136 が消える**。検証では **1 本ずつ独立に実行し、各テストの前後で監査をリセット**する（下の各手順に「戻す」を付けた）。ストーリーは読み物、実施順は別物として扱う。

---

## 事前準備（全テスト共通）

### A. ルールを有効化する

Splunk Web →「設定 → サーチ、レポート、およびアラート」で各ルール名（`ESCU - … - Rule`）を検索し、有効化する。ES が無いので通知は飛ばないが、スケジュール実行の履歴で発火は確認できる。

### B. CIM の index マクロ（tstats 系の保険）

今回の 6 本は主に生サーチ（`wineventlog_security` / `powershell` / `sysmon`）だが、`troubleshooting-escu-tstats.md` のとおり CIM マクロに index を入れておく：

```
cim_Endpoint_indexes = (index=win OR index=unix)
```

### C. 発火確認のやり方（2 段階）

1. **生ログ確認**：攻撃直後、該当 EventCode が core Splunk に届いたか（下の各手順の「生ログ確認 SPL」）。
2. **発火確認**：ルールのスケジュール履歴を見る。すぐ見たいときは本家 SPL をコピーし時間範囲を広げて手実行。

```
index=_internal sourcetype=scheduler savedsearch_name="ESCU - *"
| table _time savedsearch_name status result_count
```

---

## ルール #4：Windows Scheduled Task with Suspicious Command（永続化・T1053.005）

**検知の急所**：4698/4700/4702 を拾い、`windows_suspicious_tasks` ルックアップで Command が「シェル（powershell/cmd/wscript/cscript）」か「怪しいパス（Users/Temp/ProgramData）」にマッチした行だけ残す。→ **タスクのコマンドを powershell.exe にすれば確実**。

### 手順（ar-win1 に RDP、管理者 PowerShell）

```powershell
# 怪しいスケジュールタスクを登録（コマンドが powershell なのでルールのルックアップに当たる）
schtasks /create /tn "CrimsonUpdater" /tr "powershell.exe -NoProfile -WindowStyle Hidden -Command whoami" /sc minute /mo 5 /ru SYSTEM /f
```

- `/tr` に powershell を置くのが肝。実被害が無いよう中身は `whoami` だけ。
- ART 版：`Invoke-AtomicTest T1053.005 -ShowDetailsBrief` で該当番号を確認して実行してもよい。

### 生ログ確認 SPL

```
index=win EventCode IN (4698,4700,4702) TaskName="*CrimsonUpdater*"
| table _time Computer Caller_User_Name TaskName
```

### 元に戻す

```powershell
schtasks /delete /tn "CrimsonUpdater" /f
```

---

## ルール #3：Windows Archive Collected Data via Powershell（収集・T1560）

**検知の急所**：4104（スクリプトブロック）に `Compress-Archive` **かつ** パスに `\Temp\` が含まれること。両方そろわないと当たらない。

### 手順（ar-win1、管理者 PowerShell）

```powershell
# 窃取データに見立てたダミーを作り、Temp に圧縮（Compress-Archive + \Temp\ の両方を満たす）
$stage = "C:\Users\AzureAdmin\Documents\loot"
New-Item -ItemType Directory -Force -Path $stage | Out-Null
1..5 | ForEach-Object { "dummy data $_" | Out-File "$stage\doc$_.txt" }
Compress-Archive -Path "$stage\*" -DestinationPath "C:\Windows\Temp\exfil.zip" -Force
```

- `DestinationPath` を必ず `...\Temp\...` にする（SPL の `ScriptBlockText = "*\\Temp\\*"` 条件）。

### 生ログ確認 SPL

```
index=win source="*PowerShell/Operational*" EventCode=4104 ScriptBlockText="*Compress-Archive*" ScriptBlockText="*Temp*"
| table _time dest ScriptBlockText
```

### 元に戻す

```powershell
Remove-Item "C:\Windows\Temp\exfil.zip","C:\Users\AzureAdmin\Documents\loot" -Recurse -Force -ErrorAction SilentlyContinue
```

---

## ルール #5：Ransomware Notes bulk creation（影響・T1486）

**検知の急所**：Sysmon 11（FileCreate）で、拡張子が `.txt`/`.html`/`.hta`。SPL は `dc(TargetFilename) >= 15` を **BY dest, file_name** で数える。つまり**同じ名前のノートを 15 個以上の別フォルダに作る**と発火（ランサムが各ディレクトリに同じ脅迫文を撒く挙動そのもの）。暗号化は不要。

### 手順（ar-win1、管理者 PowerShell）

```powershell
# 20 個の別フォルダに「同名」のランサムノート（空テキスト）を作る。暗号化・破壊は一切なし
$note = "RESTORE_FILES.txt"
$body = "Your files were encrypted. (LAB TEST - no real impact)"
1..20 | ForEach-Object {
    $dir = "C:\Users\AzureAdmin\Desktop\victim\dir$_"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $body | Out-File -FilePath (Join-Path $dir $note) -Encoding ascii
}
```

- ファイル名（`file_name`＝basename）が全部同じ `RESTORE_FILES.txt`、パス（`TargetFilename`）が 20 通り → `dc(TargetFilename)=20 >= 15` で当たる。
- Sysmon 11 が届いているかは前提（既存の疎通確認で OK のはず）。

### 生ログ確認 SPL

```
index=win source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 TargetFilename="*RESTORE_FILES.txt"
| stats dc(TargetFilename) as paths values(TargetFilename) by Computer
```

### 元に戻す

```powershell
Remove-Item "C:\Users\AzureAdmin\Desktop\victim" -Recurse -Force -ErrorAction SilentlyContinue
```

---

## ルール #6：Windows AD Admin SDHolder ACL Modified（AD 永続化・T1546）

**検知の急所**：5136（ディレクトリサービスの変更）で `ObjectDN="CN=AdminSDHolder,CN=System*"` の `nTSecurityDescriptor` に **新しい ACE が追加**されたこと。ラボは既定で 5136 を出していないので、**事前設定が要る（これが「条件付き可」の中身）**。

### 事前設定（ar-dc で 1 回だけ、管理者 PowerShell）

```powershell
# 1. 監査サブカテゴリ "Directory Service Changes" を有効化（既定は off。これが無いと 5136 が出ない）
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# 2. AdminSDHolder オブジェクトに「書き込み系の監査(SACL)」を付ける
#    （SACL が無いと、変更しても 5136 は記録されない。ACE 追加＝DACL 書き換えなので WriteDacl が必須）
#    ※ dsacls /S は「権限を既定値に戻す」オプションで SACL 付与ではない。使わないこと（2026-11-12 実機で失敗して判明）
Import-Module ActiveDirectory
$dn = "AD:CN=AdminSDHolder,CN=System," + (Get-ADDomain).DistinguishedName
$acl  = Get-Acl -Path $dn -Audit
$everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
$rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($everyone, "WriteDacl, WriteProperty", "Success")
$acl.AddAuditRule($rule)
Set-Acl -Path $dn -AclObject $acl
(Get-Acl -Path $dn -Audit).Audit | Format-Table IdentityReference, ActiveDirectoryRights, AuditFlags   # 確認

# 3. 攻撃に使う低権限ユーザーが無ければ作る
New-ADUser -Name labuser1 -AccountPassword (Read-Host -AsSecureString 'labuser1 password') -Enabled $true
```

> この SACL 付与は実環境では attack ではなく**防御側の監査設定**。手順が固まったら `advanced_logging.yml` に取り込む案も検討（恒久化）。

### 攻撃手順（ar-dc、管理者 PowerShell）

```powershell
# 低権限ユーザー（例：ラボの一般ユーザー）に AdminSDHolder へ GenericAll を付与 = 隠れ特権の仕込み
$dn = "CN=AdminSDHolder,CN=System," + ([ADSI]"LDAP://RootDSE").defaultNamingContext
dsacls "$dn" /G "ATTACKRANGE\<低権限ユーザー>:GA"
```

- `<低権限ユーザー>` はラボに作った一般ユーザー名に置き換え。これで `nTSecurityDescriptor` に新 ACE が入り 5136 が出る。

### 生ログ確認 SPL

```
index=win source="*Security*" EventCode=5136 ObjectDN="CN=AdminSDHolder,CN=System*"
| table _time ObjectDN OperationType AttributeLDAPDisplayName SubjectUserName
```

### 元に戻す

```powershell
# 付与した ACE を削除
$dn = "CN=AdminSDHolder,CN=System," + ([ADSI]"LDAP://RootDSE").defaultNamingContext
dsacls "$dn" /R "ATTACKRANGE\<低権限ユーザー>"
# 検証が済んだら SACL とサブカテゴリも戻してよい（他テストに影響させたくない場合）
# auditpol /set /subcategory:"Directory Service Changes" /success:disable /failure:disable
```

---

## ルール #1：Windows AD Domain Controller Audit Policy Disabled（防御回避・T1685）

**検知の急所**：DC で 4719（監査ポリシー変更）が出て、`AuditPolicyChanges` が「Success removed / Failure removed（`%%8448`/`%%8450`）」であること。**本家 SPL は `dest_category="domain_controller"` で絞る**が、これは ES の Assets & Identities 由来。**ラボには ES が無いので、このままでは 0 件。**

### 事前対応（どちらか）

- **（推奨）ルールをクローンして `dest_category="domain_controller"` を削除**し、代わりに `host=ar-dc`（または `Computer=ar-dc`）で絞る。ラボ用の改変版として保存。
- または A&I の資産ルックアップに ar-dc を `category=domain_controller` で登録する（ES 相当の仕組みが要るので v0 では非推奨）。

あわせて、ar-dc で「Audit Policy Change」サブカテゴリが Success になっているか確認（既定の DC ポリシーで on のはずだが念のため）：

```powershell
auditpol /get /subcategory:"Audit Policy Change"
```

### 攻撃手順（ar-dc、管理者 PowerShell）

```powershell
# いずれかのサブカテゴリの監査を無効化 → 4719 が「Success removed」で出る
# ※ #6 を先にやる場合は、5136 を潰さないよう "Directory Service Changes" 以外を選ぶ
auditpol /set /subcategory:"Credential Validation" /success:disable /failure:disable
```

- ART 版：「Windows Audit Policy Tampering」ストーリー。`Invoke-AtomicTest T1562.001 -ShowDetailsBrief` で auditpol 系の番号を確認（ATT&CK v18 で一部 T1685 系に移動。実行前に中身確認）。

### 生ログ確認 SPL

```
index=win source="*Security*" EventCode=4719 host=ar-dc
| table _time host SubcategoryGuid AuditPolicyChanges Changes
```

### 元に戻す

```powershell
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
```

---

## ルール #2：Palo : code injection internal→internal→external（C2・T1055 系）

**前提（ユーザー確認済み）**：Palo の **Traffic / Threat / Web** ログを取り込み済みで、CIM の DataModel（`Network_Traffic` / `Intrusion_Detection` / `Web`）がそれを対象にするよう設定済み。よってこのルールも**ラボで発火を検証できる**。これは ESCU ではなく独自の `Palo : …` ルール（Palo の脅威シグネチャ／相関）。

**検知の急所**：横展開（内部→内部）から C2（内部→外部）へ抜ける通信で、Palo の脅威ログに「code injection」系シグネチャが付くこと。方向（zone の内→内→外、inbound/outbound）＋脅威カテゴリ／シグネチャの組み合わせで当たる。生ログは `pan:traffic` / `pan:threat` / `pan:web` の sourcetype（Palo Add-on の CIM マッピング経由で DataModel に入る）。

> **実行時に合わせること**：このルールの検知 SPL が見ている**シグネチャ名・脅威カテゴリ**と、**internal / external を判定している zone 名**。テストトラフィックや投入ログの値を、この 2 つに合わせる。ルールの SPL をコピーして確認するのが早い。

### 手順（code injection を Palo に検知させる）

内部ホスト → 内部ホスト → 外部、の経路で、Palo の脅威プロファイルが「code injection」系シグネチャを引く通信を流す。段取り：

1. **内部→内部**：ar-win1（内部 zone）から ar-win2 / ar-dc（内部 zone）へ、脆弱性を突く体のリクエストを送る（横展開の体）。
2. **内部→外部**：続けて ar-win1 から外部（インターネット）へ、同じ code-injection 系のペイロードを含むリクエストを送る（C2 への抜けの体）。
3. いずれも Palo が inline でシグネチャを引ける経路であること。実機で狙ったシグネチャを確実に引くのは難しいので、**該当シグネチャを持つ検証用トラフィック**（攻撃シミュレータ、または既知の PoC リクエスト）を使う。どうしても実トラフィックで引けない場合は、ルールのマッチ値に合わせた `pan:threat` / `pan:traffic` のサンプルイベントを投入して SPL・DataModel 経路だけ確認する。

### 生ログ／DataModel 確認 SPL

```
# 1) 生ログ：Palo の脅威ログに code injection シグネチャが来ているか
index=* sourcetype=pan:threat
| search signature="*code*injection*" OR category="*code-execution*" OR threat_name="*injection*"
| table _time src_ip dest_ip app action rule signature

# 2) Intrusion_Detection DataModel に乗っているか
| tstats summariesonly=false count from datamodel=Intrusion_Detection
  where nodename=IDS_Attacks IDS_Attacks.signature="*injection*"
  by IDS_Attacks.src IDS_Attacks.dest IDS_Attacks.signature

# 3) 方向（内→内→外）が Network_Traffic に乗っているか
| tstats summariesonly=false count from datamodel=Network_Traffic
  by All_Traffic.src_zone All_Traffic.dest_zone All_Traffic.action
```

（フィールド名・シグネチャ名はルールの実 SPL に合わせて直す。）

### 元に戻す

- 実トラフィックで引いた場合は後片付け不要。サンプルイベントを投入した場合は、検証用 index を分けておいてそのイベントだけ掃除する。

---

## 検証記録テンプレ

| # | ルール | 実施日時 | 生ログ(EventCode)有無 | 発火 | 発火までの遅延 | メモ |
|---|---|---|---|---|---|---|
| 1 | AD DC Audit Policy Disabled | 2026-11-12 00:35 JST | 4719: あり（ar-dc、`%%8448, %%8450`＝Success/Failure removed） | 発火（アラート設定済み・待ち） | — | `dest_category` を `host=ar-dc` に改変済み。戻しの 00:40/01:28 は `%%8449,%%8451`（added）でルール非該当＝正しい挙動 |
| 3 | Archive via Powershell | 2026-11-12 00:55 JST | 4104: あり（ar-win1、`Compress-Archive ... C:\Windows\Temp\exfil.zip`） | 生ログ確認済み | — | Compress-Archive ＋ `\Temp\` の両条件を満たす |
| 4 | Scheduled Task Suspicious Command | 2026-11-11 23:22 JST | 4698: あり（ar-win1、Caller=AzureAdmin） | 発火（手動実行） | —（ルールは無効のまま、ESCU アプリ上で SPL を手動実行） | 同時に誤検知 5 件：OneDrive Startup Task（`C:\Users\...`）、Defender の MpCmdRun 系（`C:\ProgramData\...`）、いずれも 4702。「suspicious paths」に当たる正規タスク。本番なら `windows_scheduled_task_with_suspicious_command_filter` で除外 |
| 5 | Ransomware Notes bulk creation | 2026-11-12 00:45 JST | Sysmon11: あり（ar-win1、`paths=20`、全て `RESTORE_FILES.txt`） | 生ログ確認済み | — | 同名×20フォルダ。しきい値 `dc>=15` を満たす |
| 6 | AD AdminSDHolder ACL Modified | 2026-11-12 01:29 JST | 5136: あり（ar-dc、`ObjectDN=CN=AdminSDHolder`、`nTSecurityDescriptor`、`%%14674`/`%%14675`） | 生ログ確認済み | — | 事前設定は `Set-Acl`＋`ActiveDirectoryAuditRule`（WriteDacl,WriteProperty/Success）でやり直し。`dsacls /S` は誤り。SubjectUserName=AzureAdmin（＝攻撃者）が正しい |
| 2 | Palo code injection | | threat/traffic: | | | DataModel 経由（Network_Traffic / Intrusion_Detection） |

---

## 未確定・実施時に詰めること

- ルール #1：`dest_category` を外したクローンの保存名と、`host` vs `Computer` のどちらで届いているか（Windows TA のフィールド名）。
- ルール #6：AdminSDHolder への SACL 付与を `dsacls` だけで完結できるか、GUI（監査タブ）か。恒久化するなら `advanced_logging.yml` へ。`<低権限ユーザー>` はラボに実在するユーザー名に。
- ルール #5：Sysmon 11 の `file_name`（basename）抽出が core 側の TA で効いているか（効いていないと BY file_name が割れる）。
- ルール #2（Palo）：ログの取り込みと DataModel マッピング（Traffic/Threat/Web）は設定済み。残りは**実際の検知 SPL が見ているシグネチャ名・zone 名**をルールからコピーして、テストトラフィック／投入イベントの値をそれに合わせること。
- 全体：ルールのスケジュール（cron / earliest-latest）を控え、「攻撃してから何分で履歴に出るか」を記録表に。
