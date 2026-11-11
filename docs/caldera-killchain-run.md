# Caldera 通し実行で5検知を正検知として出す手順書

story-02（`docs/attack-killchain-story-02.md`）の設計を、**Caldera のオペレーション1発**で実行するための実務手順。
狙いは「**ログ生成は1本のキルチェーン**（＝相関が1インシデントに束なる）」「**解析・レポートは5検知を個別**」という実務の型。

- 対象検知：#1 監査無効化 / #3 アーカイブ収集 / #4 不審タスク / #5 ランサムノート / #6 AdminSDHolder（本命5本）
- 生成プロセスの親は全て sandcat 実体（`C:\Temp\splunkd.exe`）＝「対話セッションでない＝攻撃」と言い切れる
- **非破壊・可逆**。暗号化・シャドウ削除・LSASS ダンプは含めない（story-02 の「グルー検知」はこのコアから除外。必要なら末尾「巻き添え検知」参照）

> この手順は**認可済みの自ラボ**（個人サブスク・隔離 VNet・使い捨て VM）での検知検証専用。各アビリティに cleanup を付け、実施後は元に戻す。

---

## 使うファイル（本リポジトリ）

| ファイル | 中身 |
|---|---|
| `caldera/abilities/aar-killchain/01-defense-evasion-audit-disable.yml` | #1 auditpol 無効化（DC 限定） |
| `caldera/abilities/aar-killchain/03-collection-archive-powershell.yml` | #3 Compress-Archive → Temp（クライアント限定） |
| `caldera/abilities/aar-killchain/04-persistence-scheduled-task.yml` | #4 不審コマンドのタスク登録（クライアント限定） |
| `caldera/abilities/aar-killchain/05-impact-ransom-notes.yml` | #5 同名ノート20フォルダ（クライアント限定） |
| `caldera/abilities/aar-killchain/06-persistence-adminsdholder-acl.yml` | #6 AdminSDHolder へ GenericAll（DC 限定） |
| `caldera/adversaries/killchain-01.yml` | 5本を通しで流すアドバーサリ |

各アビリティは先頭で**ホスト役割を判定**（`Win32_ComputerSystem.DomainRole`）し、自分向けでなければ `exit 0` で無害スキップ。
だから ar-win1 と ar-dc を**同じグループ**に入れて1オペレーションを回すと、各ホストが自分の担当だけ実行する。

---

## 事前設定（1回だけ。攻撃ではなく環境側の仕込み）

build 直後のラボに対して、以下がそろっていること。詳細は `docs/escu-validation-story-01.md`。

1. **エージェント check-in**：ar-win1 と ar-dc の sandcat（`C:\Temp\splunkd.exe`）が Caldera に見えていること。落ちていれば対象ホストで `SCHTASKS /RUN /TN CalderaAgent`。
2. **#6 の前提**（DC で 1 回）：
   - `auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable`
   - AdminSDHolder に SACL 付与（`Set-Acl` ＋ `ActiveDirectoryAuditRule`、WriteDacl/WriteProperty/Success）。**`dsacls /S` は使わない**（story-01 で誤りと判明）。
   - `labuser1` が存在すること（無ければ `New-ADUser`）。
3. **#1 のルール**：本家 SPL は `dest_category="domain_controller"`（ES 由来）で 0 件になる → クローンして `host=ar-dc` に差し替えた改変版を有効化。
4. **#5 の前提**：Sysmon 11 が core Splunk に届き、`file_name`（basename）抽出が core 側 TA で効いていること。
5. **Defender**：有効だと一部 LOLBin がブロックされ得る。本命5本は Defender に素直に通る構成（LSASS ダンプを外したため）。ブロックされたら、それ自体を1検知として記録しつつ実機判断。

---

## ステップ1：アビリティとアドバーサリを Caldera に配置

ツールボックスコンテナ（`.\ar.ps1`）か、鍵を持つ環境から Caldera サーバ（10.0.1.70、ユーザー `caldera`）へ scp する。
Caldera は stockpile プラグイン配下の YAML を起動時に読む。

```powershell
# ローカル（リポジトリ直下）から Caldera サーバへ転送
# 鍵は Docker ボリューム aar-ssh の /root/.ssh/aar.key（コンテナ内から叩く場合）
$caldera = "caldera@10.0.1.70"
scp -r caldera/abilities/aar-killchain    "${caldera}:/home/caldera/caldera/plugins/stockpile/data/abilities/"
scp    caldera/adversaries/killchain-01.yml "${caldera}:/home/caldera/caldera/plugins/stockpile/data/adversaries/"
```

配置先の確認（Caldera サーバ上）：
- アビリティ：`/home/caldera/caldera/plugins/stockpile/data/abilities/aar-killchain/*.yml`
- アドバーサリ：`/home/caldera/caldera/plugins/stockpile/data/adversaries/killchain-01.yml`

反映（サービス再起動で再読込）：

```bash
sudo systemctl restart caldera
```

> フォルダ名 `aar-killchain` は整理用で、Caldera は tactic をファイル内容から読む（フォルダ名からではない）。あとで消すときはこのフォルダごと削除して再起動。

---

## ステップ2：オペレーションを1本実行

Caldera Web（`https://20.48.49.42:8888`、パスワードは `AarLab-tatsuta`）で：

1. **agents** で ar-win1 と ar-dc の sandcat を同じ group（例 `red`）に入れる。
2. **operations → +** で新規作成：
   - Adversary：`AAR KillChain-01 (5-detection TP validation)`
   - Group：`red`
   - Planner：`atomic`（定義順どおりに流す）
   - Obfuscation：`plain-text`（＝難読化なし。生ログを素直に読ませる。難読化版の比較は余力があれば別オペで）
3. **Start**。atomic_ordering の順（#4 → #1 → #6 → #3 → #5）で、各ホストが自分向けアビリティだけ実行する。
   - ar-win1：#4 #3 #5 を実行、#1 #6 はスキップ（`skip: ...` を返して成功扱い）
   - ar-dc：#1 #6 を実行、#4 #3 #5 はスキップ
4. 各リンクの出力（stdout）で、スキップ行か実行結果かを確認。**start 時刻を控える**（＝このインシデントの T0）。

> オペレーションを閉じるときに Caldera の cleanup が自動で走る（各アビリティの cleanup）。
> ただし #1 の auditpol・#6 の dsacls は「元に戻す」ことで 4719/5136 が **"元に戻した" 側**でも出る。検証記録では「無効化（%%8448/%%8450）＝攻撃」「有効化（%%8449/%%8451）＝cleanup」を区別する（story-01 で確認済みの挙動）。

---

## ステップ3：生成ログを5検知にマッピング（正検知の確認）

T0 を含む時間範囲で、core Splunk で以下を実行。全部「親＝splunkd.exe」であることが本命の肝。

| 検知 | EventCode | 生ログ確認 SPL（親プロセスの確認込み） |
|---|---|---|
| #4 不審タスク | 4698 / Sysmon 1 | `index=win EventCode=1 Image="*\\schtasks.exe" ParentImage="*\\splunkd.exe" \| table _time Computer User ParentImage CommandLine` |
| #1 監査無効化 | 4719 | `index=win source="*Security*" EventCode=4719 host=ar-dc AuditPolicyChanges IN ("%%8448","%%8450") \| table _time host SubjectUserName SubcategoryGuid AuditPolicyChanges` |
| #6 AdminSDHolder | 5136 | `index=win source="*Security*" EventCode=5136 ObjectDN="CN=AdminSDHolder,CN=System*" \| table _time ObjectDN OperationType AttributeLDAPDisplayName SubjectUserName` |
| #3 アーカイブ収集 | 4104 | `index=win EventCode=4104 ScriptBlockText="*Compress-Archive*" ScriptBlockText="*Temp*" \| table _time Computer ScriptBlockText` |
| #5 ランサムノート | Sysmon 11 | `index=win source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 TargetFilename="*RESTORE_FILES.txt" \| stats dc(TargetFilename) as paths by Computer` |

**ルール発火（スケジュール履歴）の確認**：

```
index=_internal sourcetype=scheduler savedsearch_name="ESCU - *"
| table _time savedsearch_name status result_count
```

---

## ステップ4：1インシデントに束ねる（レポート用タイムライン）

5検知が「ひとつの侵入」であることの裏付け。sandcat 配下のプロセスを時系列で並べる。

```
index=win source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ParentImage="*\\splunkd.exe"
| where NOT like(ParentImage,"%\\Program Files\\Splunk\\%")
| table _time Computer User ParentImage Image CommandLine
| sort 0 _time
```

これに Security（4698/4719/5136）と PowerShell(4104)、Sysmon 11 を時刻で重ねると、
「`splunkd.exe` 配下で、ar-win1 と ar-dc にまたがって、永続化→監査無効化→AD永続化→収集→破壊が一連で起きた」図ができる。

**レポートの決め所**（story-02 Part1 の筋）：
> 攻撃者は DC の監査を一部止めた（#1）が "Directory Service Changes" を潰し忘れたため、AdminSDHolder 改ざん（#6, 5136）は捕捉できた。
> ＝「不完全な防御回避」が検知機会になった、という Detection opportunity。

---

## ステップ5：個別トリアージ（レポート本文）

アナリスト視点で5検知を1本ずつ。各カードの「攻撃と断じる根拠」は共通して**親プロセス＝splunkd.exe（非対話）**。
詳細テンプレは `docs/attack-killchain-story-02.md` の Part 3 を使う。各カードに今回の実測（時刻・Computer・親・ユーザー）を追記する。

| 検知 | 攻撃と断じる主根拠 | 主なピボット先 |
|---|---|---|
| #4 | schtasks の親が splunkd.exe（正規なら explorer/mmc） | splunkd の出自 → 同端末 C2 → 同時間帯の探索 |
| #1 | auditpol の親が splunkd.exe、DC に対話ログオン無し | 直後の 5136（#6）／直前の横展開痕 |
| #6 | AdminSDHolder は平時ほぼ不変、直前に監査停止の連鎖 | 付与先 SID（labuser1）→ その後の挙動 |
| #3 | 親 splunkd.exe、出力先が Temp | 圧縮対象 → 直後の外向き通信 |
| #5 | 短時間に同名ノート20フォルダ、書いた親 splunkd.exe | 撒かれた範囲 → バックアップの生死 |

---

## ステップ6：後片付け

1. Caldera のオペレーションを閉じて cleanup を自動実行（タスク削除・zip削除・ノート削除・auditpol復元・dsacls復元）。
2. 手動確認（残りがないか）：
   ```powershell
   # ar-win1
   schtasks /query /tn "MicrosoftEdgeUpdateTaskMachineCore" 2>$null
   Test-Path "C:\Windows\Temp\exfil.zip"; Test-Path "C:\Users\Public\victim"; Test-Path "C:\Users\Public\stage"
   # ar-dc
   auditpol /get /subcategory:"Credential Validation"
   $dn = "CN=AdminSDHolder,CN=System," + ([ADSI]"LDAP://RootDSE").defaultNamingContext; dsacls "$dn" | Select-String "labuser1"
   ```
3. アビリティを恒久的に消すなら、Caldera サーバで `aar-killchain` フォルダと `killchain-01.yml` を削除して再起動。

---

## 補足：検索インベントリ（splunkd 依存の棚卸し）

この手順書で使う検索の一覧。エージェント名（既定 `C:\Temp\splunkd.exe`）を別名に変えるときは、
**「splunkd 依存＝あり」の検索だけ**を新名に直せばよい。ESCU ルール本体は EventCode・コマンド内容で
検知するので名前に依存せず、エージェント名を変えても発火には影響しない。

| 場所 | 何を探す検索か | splunkd 依存 |
|---|---|---|
| ステップ3 #4 | schtasks.exe の親が splunkd か（不審タスク） | **あり** |
| ステップ3 #1 | ar-dc の監査無効化 4719（Success/Failure removed） | なし |
| ステップ3 #6 | AdminSDHolder の 5136 | なし |
| ステップ3 #3 | Compress-Archive ＋ Temp の 4104 | なし |
| ステップ3 #5 | 同名ランサムノート >=15 フォルダ（Sysmon 11） | なし |
| ステップ3 発火確認 | ESCU ルールのスケジュール実行履歴 | なし |
| ステップ4 タイムライン | splunkd 配下プロセスの時系列（相関の核） | **あり** |

> 直すのは「ステップ3 #4」と「ステップ4 タイムライン」の2本だけ。確認用検索（＝ログ到達の目視用、splunkd を使う箇所あり）と
> ESCU ルール本体（＝自動発火する保存済み検索、splunkd 非依存）は別物。

---

## 巻き添え検知（任意・コア外）

本命5本だけでは触れない検知面。レポートで「この侵入は N 本の検知に触れた」と厚みを出したいとき**だけ**、手動で足す。
**セーフガード・安全上の注意**：LSASS ダンプ・vssadmin delete shadows は「武器っぽさ」と実リスク（Defender ブロック、VM のシャドウ実削除）が高い。足すなら実機判断で、story-02 Part2 のフェーズ5/11・Part4 の表を参照。

| 足す挙動 | 追加で光る実在 ESCU（例） | 注意 |
|---|---|---|
| vssadmin delete shadows /all | Deleting Shadow Copies（T1490 直撃） | VM のシャドウを実削除。使い捨て VM 前提で |
| comsvcs で LSASS ダンプ | Dump LSASS via comsvcs DLL ほか | Defender がブロックしたら 1116/1117 も証跡 |
| WMI で ar-win1→ar-dc 実行 | Possible Lateral Movement PowerShell Spawn ほか | 今回は DC にエージェント常駐で代替済み |

---

## このやり方が story-01 と違う点（レポートの売り）

- story-01：各コマンドを `explorer → powershell`（人が叩いた形）で実行 → 生ログは出るが「管理者の正常作業」と見分けづらい。
- 本手順：全コマンドが **sandcat 配下（親＝splunkd.exe）**、ar-win1 と ar-dc にまたがる **1オペレーション**で発生 → プロセスの出自・連鎖・時間帯がそろい、**正検知（True Positive）として説得力がある**。
