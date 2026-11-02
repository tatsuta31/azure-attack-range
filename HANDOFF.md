# 引き継ぎメモ（2026-10-31 時点）

前セッション（workbench で起動）からの引き継ぎ。**設計の決定事項と罠は `CLAUDE.md` が正**。ここは「どこまで進んだか」と「次に何をやるか」だけ。完了したら該当行を消すか更新すること。

## 役割分担（2026-10-31 決定）

- **ユーザー**：Azure の実操作すべて（az login、terraform apply、Attack Range の build / destroy、ポータル操作）
- **Claude**：コード・設定ファイルの作成、解説、レビュー。ユーザーが打つコマンドは PowerShell 形式で渡す。Azure に変更を加えるコマンドは Claude から実行しない

## 完了済み

- [x] プロジェクト作成、splunk/attack_range **v4.0.2 を pristine でベンダリング**（commit `735c91b`）
- [x] 自前ツールボックス `docker/Dockerfile` ＋ `ar.ps1`（Terraform 1.9.8 / az 2.91.0 / ansible-core 2.17.7、windows コレクション同梱を確認済み）
- [x] SSH 鍵 `aar.key` / `aar.pub` を Docker ボリューム `aar-ssh`（`/root/.ssh`）に生成済み（600）
- [x] `.gitattributes` で LF 固定（`.ps1` のみ CRLF）
- [x] Docker Desktop 導入・エンジン起動確認（28 CPU / 16GB）

## 今ここ：ユーザーの `az login` 待ち

**2026-10-31：デバイスコードでのログインが `AADSTS530035: Access has been blocked by security defaults` で拒否された**（テナント `<tenant-id>` 既定のディレクトリ）。サインイン自体は成功していて、テナントのポリシーで止められている。対処はユーザーが選ぶ。候補は次の3つ。
- Cloud Shell で Terraform 用のサービスプリンシパルを作り、コンテナではその SP でログインする（推奨）
- ホストに az CLI を入れてブラウザでログインする
- Security Defaults を無効化する（非推奨）

ユーザーが `!` プレフィックスで叩く場合、Git Bash 経由になり `\` が消える。TROUBLESHOOTING.md 2026-10-31 を参照。

**決定（2026-11-01）：サービスプリンシパルで行く（権限は Contributor + User Access Administrator ＝ 実質 Owner）。** 受け入れの仕組みはコミット済み（`e995176`）：`.env`（ARM_*）→ `ar.ps1` が `--env-file` で渡す → `docker/sp-login.sh` でコンテナの az をログイン。Foundry のロールは `foundry_user_object_ids` に入れた人に付く。ユーザーが Cloud Shell で SP を作るのを待っている。

このPCは PowerShell の実行ポリシーが既定（Restricted）で `.\ar.ps1` が弾かれる。**実行ポリシーの変更はユーザー本人の判断・操作**（Claude はセキュリティ設定を変えない）。当面はプロセス限定のバイパスで回避：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\ar.ps1 az login --use-device-code
```

- Claude Code の PowerShell ツールは Process スコープが Bypass なので Claude 側からは `ar.ps1` が動いてしまう点に注意（＝ユーザー側の不具合に気づきにくい）
- `ar.ps1` は `-it` 付きなので、Claude のツールからは非対話で使えない。Claude が叩くときは `docker run --rm -v aar-azure:/root/.azure -v aar-ssh:/root/.ssh -v <root>:/work azure-attack-range:local <cmd>` を直接使う
- Claude Code セッションの PATH が古いと `docker` が見えない → `$env:Path` を Machine+User から再読込（TROUBLESHOOTING.md 2026-10-30）

## 次の一手（順番どおり）

1. **ログイン確認**：`az account show`、従量課金サブスクの ID を控える
2. **クォータ確認**：`az vm list-usage -l japaneast -o table`。目安 合計 10〜16 vCPU（Splunk 4〜8 / Windows 2〜4 / Caldera 2）。足りなければユーザーにクォータ申請を依頼
3. **`core/` の Terraform**：**apply 済み（2026-11-01、15 リソース）**。Splunk 10.10.1.10 / パブリック IP <core-splunk-public-ip>、Foundry `aar-core-foundry-<suffix>`、モデル gpt-4.1-mini（gpt-5.4-mini は GlobalStandard の枠が 0。使うなら引き上げ申請）、ロールは Cognitive Services User（テナントに `Azure AI User` は無い）。初回 apply では Project とデプロイの並列作成が 409 になったので depends_on で直列化済み。以下は当初のメモ：`terraform validate` 通過、cloud-init スクリプトのレンダリングと `bash -n` も確認済み、既定の TA 8 本が S3 に存在することも確認済み。**未コミット**。実行はユーザー（手順は `core/README.md`）
   - ユーザーが tfvars に埋める値：サブスク ID、自宅 IP、Splunk 10.6.1 の .tgz の URL と SHA512（公式ページから）、admin パスワード、モデル名とバージョン（Japan East で使えるもの）
   - 未検証（apply して初めて分かる）：ロール名 `Azure AI User` の割り当て、Splunk 10.6.1 が Ubuntu 24.04 で cloud-init から正常に起動するか、モデル名とバージョン
4. **Attack Range v4.0.2 へのパッチ**：**完了（2026-11-01、4 コミット＋設定見本）**。`terraform validate` 通過、設定見本は本家の ConfigHandler で読めることを確認済み
   - `23b27e5` Azure の Windows/Linux の Ansible 変数に `caldera_server` が無かった本家バグを修正（＋パスワードの JSON エスケープ）
   - `0901e8f` `azure.core_vnet_id` を設定すると双方向ピアリング。両方向とも range の state が持つので、range destroy で消える
   - `ccc0cf2` Caldera ロールの `/home/admin` 固定を `caldera_user` / `caldera_home` に。Windows エージェントの schtasks を `ansible_user`（Azure は AzureAdmin）で実行
   - `1568d1d` Azure 用の Caldera モジュール（Debian 12、ユーザー `caldera`、10.0.1.70）。Windows/Linux は Caldera の完了を待つ
   - 設定見本：`attack_range/attack_range.azure.example.yml` → `attack_range.yml` にコピーして使う。`attack_range.py configure` は使わなくてよい
   - 未検証（build して初めて分かる）：Debian 12 の Azure イメージ（`Debian/debian-12/12`）上で caldera_server ロールが通るか、UF 9.3.0 → Splunk 10.6.1 への転送
   - **build 成功（2026-11-01 06:31 JST）**：ar-caldera-aar-ar / ar-win-aar-ar-0。1 回目は Basic SKU パブリック IP の廃止で失敗 → `d112d9d` で Standard 化
   - 既知の本家バグ（未修正）：`art_simulation_controller.py` の Azure 分岐で、Linux ターゲットのとき `private_key_path` を代入前に使っている。Linux を足すときに直す
   - **疎通確認 完了（2026-11-01）**：ART T1003.001 → Sysmon EventCode 10（nanodump / rdrleakdiag / xordump / powershell → lsass）→ UF → ピアリング → core Splunk で検索できた
     - Sysmon は `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`、`sourcetype=XmlWinEventLog`（sourcetype に sysmon は入らない）
     - 既定の SwiftOnSecurity.xml は EventCode 10 を記録しない → `win_sysmon_config: "AttackRangeSysmon.xml"`。今の VM には手動で `sysmon64 -c` 済み
   - **Caldera も確認済み（2026-11-01）**：Discovery adversary（plain-text）→ `C:\Temp\splunkd.exe`（Attack Range の偽装エージェント）配下の powershell 8 本が Sysmon EventCode 1 で見えた。検索：`ParentImage="*splunkd.exe" ParentImage!="*SplunkUniversalForwarder*"`
   - 次：6. MCP（Caldera の base64 難読化 → 4104 との比較は余力があれば）
5. **疎通確認**（当初のメモ）：ar-win で ART（例 `T1003.001`）→ core Splunk で検索できること。Caldera エージェントのチェックイン
6. **Splunk MCP Server app**（Splunkbase 7931。DL はユーザーが Splunk.com ログインで実施）→ まず Claude Code から MCP 接続
7. **Foundry 側エージェント**：モデル＝Foundry、MCP クライアント＝core VNet 内の自作エージェント（Foundry SDK）。AI-901 の SDK 範囲も兼ねる

## ロードマップ（2026-11-02 ユーザー決定。この順で進める）

1. **環境構築**：DC ＋ Windows 2 台 ＋ Windows Server ＋ Linux ＋ OpenCanary（Palo は置かない）
2. **ルール有効化**：`docs/escu-selection.md` の本命を有効化し、ART / Caldera / 手動で発火を確認
3. **Splunk MCP 構築**：Splunk MCP Server app を core Splunk に入れる
4. **Foundry 構築**：Foundry のリソース・Project・モデル（gpt-4.1-mini）・ロールは core の Terraform で作成済み。ここでやるのはエージェントの作成と MCP との接続（ユーザーはポータルで手で作る練習もしたい可能性あり）
5. **ログ連携確認**：エージェント → MCP → Splunk の検索が通ること
6. **Foundry による分析**：発火したアラートを AI に解析させる

並行：AI-901 を 1 週間程度で受験予定（Foundry 分野が 55〜60%）。

## 次回やりたいこと（2026-11-01 ユーザー談）

1. **destroy の確認**：**2026-11-02 成功（ユーザー報告）**。`python attack_range.py destroy` → range の RG と、core 側のピアリング（`ar-peer-from-aar-ar`）が消え、core 本体（VNet・Splunk・Foundry）は無傷であることを確認。その後に再 build（ART インストールのパッチと `win_sysmon_config: AttackRangeSysmon.xml` が効くかもここで見る）
2. **構成の拡張**：DC ＋ Windows クライアント ＋ Linux、ドメイン参加、ユーザー作成、ハニーポット
   - DC は `windows_servers` の 1 台目に `create_domain: "1"`、2 台目以降に `join_domain: "1"`
   - Windows 10/11 は本家が `win10-21h2-pro` / `win11-21h2-pro` 固定 → Marketplace から消えている可能性大。要パッチ（`azure_controller.py` のイメージ対応表）
   - Linux は `art_simulation_controller.py` の Azure 分岐で `private_key_path` を代入前に使う本家バグあり → simulate 前に直す
   - Linux の VM は Standard_A4_v2（Av2 ファミリー）。クォータ未確認
   - vCPU：DC 4 ＋ クライアント 4 ＋ Linux 4 ＋ Splunk 4 ＋ Caldera 2 ＝ 18 でリージョン上限 18 ちょうど。引き上げ申請を推奨
   - ユーザー作成：本家に `bad_blood`（DC に大量の AD オブジェクトを作る）がある。手動で作るか BadBlood を使うか要相談
   - ハニーポット：設計から相談（range 内に置くか、別セグメントか、何を検知させたいか）
   - 2026-11-02 方針：**2 で行く**（いきなり拡張構成）。ユーザー希望の構成は DC ＋ Windows 2 台 ＋ Windows Server ＋ Linux ＋ Palo VM-Series ＋ OpenCanary。Windows 11 は `win11-26h2-pro` が使える（`azure_image_sku` で上書き可能にした `780c15d`）。Av2 枠は 10。**リージョン合計 18 では足りない**（約 32 vCPU 必要）→ クォータ引き上げか VM サイズ縮小を決める
   - ESCU 選定 v0 を作成：`docs/escu-selection.md`（本命 96 本）、全件仕分け `docs/escu/`、再生成スクリプト `tools/escu/`
3. その後 6. MCP

## ユーザー側の宿題（状況確認すること）

- Splunk **Developer License** の申請状況（未着なら 60 日トライアルで進める）
- Azure 予算アラート、Japan East の vCPU クォータ
- 自宅のグローバル IP（NSG の許可元。`curl ifconfig.me` 等で確認してもらう）

## 未検証の論点（CLAUDE.md にも記載）

- MCP Server app 2.0.0 の Splunk 10.6 対応（Splunkbase の表は 10.2 まで）→ 駄目なら 10.2 系
- Foundry Agent Service のホスト型ツール呼び出しからプライベート MCP に届くか（第2段階で検討）
