# ESCU の tstats ルールが反応しない：切り分けの記録（2026-11-05）

ラボ（このリポジトリ）と、別の検証環境（以下「別環境」）を見比べながら切り分けた記録。

## 結論

- **別環境**：Sysmon を **従来の形式（UF の `renderXml = 0`）** で取り込んでいた。Splunk Add-on for Sysmon の CIM 変換とタグ付けは XML 形式専用なので、Sysmon のログが Endpoint データモデルに入っていなかった
- **対処**：UF の `inputs.conf`（別環境では独自の Ansible のタスクが書き込んでいた）に、次の 3 行を足す

```ini
renderXml = 1
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
sourcetype = XmlWinEventLog
```

- **ラボ**：XML 形式で取り込めていて正常。残りは CIM のマクロに index を入れること

## 検知までの流れ（全体像）

```
[端末] 攻撃 → Sysmon が記録（EventCode 1 など）
   ↓ 1. UF が取り込む（inputs.conf：renderXml / index / source / sourcetype）
   ↓ 2. TA がフィールドを抽出する（CommandLine など）
   ↓ 3. TA が CIM の名前に変換する（計算フィールド：process など）
   ↓ 4. TA がイベントタイプとタグを付ける（tag=process, tag=report）
   ↓ 5. Endpoint データモデルが「index ＋ タグ」でログを集める
   ↓ 6. ESCU のルールが 1 時間ごとにデータモデルを tstats で検索する
[結果] 該当すれば発火
```

どこかで途切れるとルールは反応しない。上から 1 段ずつ確かめる。

## 段階ごとの確認

### 1. UF の取り込み設定

確認（端末の管理者 PowerShell。読むだけのコマンド）：

```powershell
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" btool inputs list "WinEventLog://Microsoft-Windows-Sysmon/Operational" --debug
```

各行の先頭に、その設定を書いているファイルのパスが出る。

- **ラボ**：`sysmon_inputs_app\local\inputs.conf` で `renderXml = 1`、`source = XmlWinEventLog:...`、`index = win` → 正常
- **別環境**：`disabled`、`index`、`current_only` だけで、`renderXml` がなかった → **ここが原因**（既定は従来の形式になり、source は `WinEventLog:Microsoft-Windows-Sysmon/Operational`）
- **設定の元（ラボ）**：Attack Range の `roles/windows_universal_forwarder/files/sysmon_inputs.conf`。build のとき、各端末の `...\etc\apps\sysmon_inputs_app\local\inputs.conf` にコピーされる。端末側を直接直しても、次の build で上書きされる
- **注意**：Sysmon の設定ファイル（`<Sysmon schemaversion=...>` で始まる XML）は「何を記録するか」の設定で、取り込みの設定とは別物

### 2. ログが Splunk に届いているか

```
index=win source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
```

- `index=` を書かないと 0 件になることがある。index を書かないと、ロールの既定の検索対象 index しか見ないため
- 「高速モード」では、SPL に書いていないフィールドが一覧に出ない。`| table ...` で指定するか、「詳細モード」にする

### 3. TA の計算フィールド（CIM の名前への変換）

- 画面：「設定 → フィールド → 計算フィールド」。絞り込み欄には `source::` を付けずに `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational : EVAL-process` と入れると見つかる
- 仕組み：source が `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` のログ 1 件ずつに Eval 式を計算し、`case` の条件に合った結果をフィールド名（`process`）に入れる。EventCode 1 なら `process` に `CommandLine` の値が入る
  - 対象を決めるのは **source（スタンザ名）だけ** で、index は関係ない
  - `case` の条件にどれも当たらなければ、フィールドは作られない
- `source::WinEventLog:Security : EVAL-process` は、Windows 用 TA のセキュリティログ（4688 など）用の別の定義

```
index=win source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time host CommandLine process process_name parent_process_name
```

- **別環境**：`CommandLine` はあるのに `process` がなかった。TA の変換は `source::XmlWinEventLog:...` にしか書かれていないため
- `CommandLine` や `ParentImage` がないログがあるのは、その種類のログ（EventCode 1 以外）にもともと無いから。正常

### 4. イベントタイプとタグ

- 画面：「設定 → イベントタイプ」で `ms-sysmon` を検索。「設定 → タグ → タグごとのリスト」で `process` を見る
- 仕組み：イベントタイプのサーチ文字列に合うログに `eventtype=ms-sysmon-process` が付き、そのイベントタイプに `tag=process` と `tag=report` が付く。実質的な条件はイベントタイプのサーチ文字列

```
index=win source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time eventtype tag
```

- **「サーチ文字列から Xml を抜けばいいのでは？」** → タグは付いてデータモデルには入るが、計算フィールド（TA の XML 用の設定は計算フィールド 62・エイリアス 24・ルックアップ 2）も XML 専用なので、`Processes.process` などが空になり、ルールは当たらない。TA の `default` を書き換えると更新で元に戻る。UF で XML にするのが素直

### 5. Endpoint データモデル

- 画面：「設定 → データモデル → Endpoint → Processes」で、条件（`` `cim_Endpoint_indexes` tag=process tag=report ``）とフィールドの定義が見える
- フィールドの種類
  - `parent_process_name`：データモデルの Eval 式。`parent_process_name` があればそれ、なければ `parent_process` から実行ファイル名を切り出し、それもなければ `unknown`
  - `Processes.process`：ログの `process` フィールドを **そのまま持ってくる**（自動抽出）。名前をそろえる主な仕事は TA、データモデルは足りないところを補う
- CIM のマクロに、ログを入れている index 名を書く（ラボ：`(index=win OR index=unix)`、別環境：`index=windows`）
  - `cim_Endpoint_indexes`、`cim_Authentication_indexes`、`cim_Network_Traffic_indexes`、`cim_Change_indexes`、`cim_Network_Resolution_indexes`
- **ESCU のマクロとの違い**：ESCU の `sysmon` などのマクロに index を書いても、tstats 系のルールには効かない。tstats 系は CIM のマクロを見る。両方に設定する

確認（`where index=` を付けずに実行するのがポイント）：

```
| tstats summariesonly=false count from datamodel=Endpoint.Processes by host sourcetype Processes.process_name
```

### 6. ESCU のルール

- 例：`ESCU - Dump LSASS via comsvcs DLL - Rule`
  - SPL：`tstats ... from datamodel=Endpoint.Processes where` `` `process_rundll32` `` `Processes.process=*comsvcs.dll*` ...
  - ルールはデータモデル（タグで集めたログ）を検索するので、イベントタイプ名を直接は指定していない
- 毎時 0 分に実行し、**70 分前から 10 分前まで** を検索する（`-70m@m` 〜 `-10m@m`）。攻撃してから最大 1 時間 10 分ほど結果に出ない
- すぐ確かめたいときは、ルールの SPL をコピーし、時間範囲を広げて手で実行する
- ES がない環境では、ノータブルやリスクの通知は動かない。発火したかは実行履歴で見る

```
index=_internal sourcetype=scheduler savedsearch_name="ESCU - *"
| table _time savedsearch_name status result_count
```

## 切り分けの早見表

| 症状 | 止まっている段階 | 見るところ |
|---|---|---|
| 生ログが 0 件 | 1・2 | UF の `inputs.conf`、index 名、検索に `index=` を書いたか |
| `CommandLine` はあるが `process` がない | 3 | TA が入っているか、source 名（XML かどうか） |
| `process` はあるが `tag` がない | 4 | イベントタイプの条件（source 名、EventCode） |
| `where index=...` 付きの tstats だけ件数が出る | 5 | `cim_Endpoint_indexes` |
| tstats は出るがルールが 0 件 | 6 | 攻撃のコマンドがルールの条件に合うか、時間範囲、ルールが有効か |

## Sysmon が従来の形式のままだと何が止まるか

全部ではなく、「Sysmon のログがデータモデルに入る分」が止まる。

| データモデル | 状態 |
|---|---|
| Endpoint.Processes | 4688（セキュリティログ。Windows 用 TA は従来の形式にも対応）の分だけで動く。4688 にコマンドラインを入れる監査設定がなければ `process` は空。Sysmon にしかない情報（ハッシュ、元のファイル名、process_guid など）を使うルールは当たらない |
| Endpoint.Registry / Filesystem | ほぼ全滅（ほぼ Sysmon だけが入り口） |
| Network_Traffic | Sysmon 3 の分がなくなる |
| Authentication | ほぼ影響なし |

今どうなっているかの確認：

```
| tstats count from datamodel=Endpoint.Processes where index=windows by sourcetype source
```

## 用語と根拠

- **TA（Technology Add-on）**：製品ごとのログを Splunk の共通ルール（CIM）の形に変換するアプリ。フィールドの抽出、CIM の名前への変換、タグ付けをする
- **ESCU が XML 形式を前提にしている根拠**：ESCU のデータソース定義 [`data_sources/sysmon_eventid_1.yml`](https://github.com/splunk/security_content/blob/develop/data_sources/sysmon_eventid_1.yml) が `source: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`、`sourcetype: XmlWinEventLog`、対応 TA は Splunk Add-on for Sysmon 5.0.1。TA の付属 `inputs.conf` も `renderXml = 1`、`props.conf` と `eventtypes.conf` は `XmlWinEventLog:...` の source だけを対象にしている（TA 5.0.0 の実物で確認）
- 文章で「ESCU は XML 必須」と明記した公式の記述は見つからなかった。ESCU の `sysmon` マクロは従来の形式の source も含んでいるので、生ログを直接検索するルールは従来の形式でも動く可能性がある

## 関連して見つけた本家のバグ

- 4688 にコマンドラインを入れるレジストリの値名が、Attack Range v4.0.2 では `ProcessCreationinclude_tasksCmdLine_Enabled` になっていた（`ignore_errors: yes` で失敗も出ない）。このリポジトリでは修正済み（`roles/windows_common/tasks/windows-enable-4688-cmd-line-audit.yml`）

## 次にやること

1. 別環境：UF の `inputs.conf` に 3 行を足して反映する
2. 別環境：CIM のマクロに `index=windows` を入れる
3. ラボ：CIM のマクロに `(index=win OR index=unix)` を入れる
4. 両方：tstats で、Sysmon がデータモデルに入っているか確かめる
