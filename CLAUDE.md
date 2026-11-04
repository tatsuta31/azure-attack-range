# azure-attack-range

Azure 上に検知検証ラボを作る。Atomic Red Team / Caldera で攻撃 → Splunk で検知 → Splunk MCP 経由で AI（Foundry）に解析させる。AI-901 対策も兼ねる。

**作業を再開するときは、まず `HANDOFF.md`（進捗と次の一手）を読むこと。**

## 構成の決定事項（2026-10-30）

- **2層構成**
  - `core/`：消さない基盤（自前 Terraform）。Splunk 10.6.1 + Splunk MCP Server app、Microsoft Foundry。削除ロックは **RG ではなく Splunk VM と Foundry に個別に付ける**（2026-10-31 変更）。RG や VNet に付けると、range destroy で core VNet 側のピアリング（VNet の子リソース）が消せず、destroy が毎回失敗するため
- core の azurerm は **4.x（~> 4.81）に固定**。5.x は 2026 年に出たばかりで破壊的変更があり、必要な Foundry リソースは 4.x でそろっている。range 側（本家）は `~> 3.6.0` のまま。state も provider も別なので衝突しない
- core Splunk は Ansible ではなく **cloud-init** で構成する。indexes.conf は本家ロールのファイルを `filebase64` で直接読み、range の UF が送ってくる index 名と必ず一致させる
- NSG：Azure 既定の AllowVnetInBound はピアリング先も信頼するので、range VNet からは 9997 だけ許可し、それ以外は明示的に Deny（range の VM は侵害させる前提の端末）
  - `attack_range/`：splunk/attack_range **v4.0.2 をベンダリングしてパッチ**。build/destroy を繰り返す使い捨て
- 連携は Attack Range 標準の **BYO Splunk**（`splunk_server.byo_splunk: "1"` / `byo_splunk_ip`）。これで range 側の Splunk VM は count=0 になる
- 環境：従量課金サブスク（個人）、リージョン Japan East
- Caldera サーバーは range 側で使い捨て（10.0.1.70）
- **OpenCanary は range VNet 内の DMZ サブネット（10.0.2.0/24）に隔離**（2026-11-02）。インターネットにも公開する（`internet_exposed: "1"`）。DMZ の NSG は「受信＝おとりのポート＋管理用 SSH（22222、ip_whitelist のみ）」「送信＝core Splunk 9997 とインターネット 80/443/123 だけ。VNet 宛ては全部拒否」。乗っ取られても内部に横展開させないため。ログは index `honeypot`（core Splunk に手で作る）
- **Palo Alto はラボに置かない**。ESCU の選定は Palo のログがある前提で行う（`docs/escu-selection.md`）
- Windows クライアントは Windows 11（`win11-26h2-pro`）。Azure では適格なライセンスが前提（ユーザー判断）
- VM ファミリーごとのクォータ（Dv4 は 10 から上げられなかった）に合わせて、サーバーごとに `azure_vm_size` で DDv4 などに振り分ける

## v4.0.2 の罠（コードで確認済み）

- Caldera サーバーの Terraform モジュールは **AWS 版しかない**。Azure で `caldera_server: "1"` にしても何も作られない → Azure 用を移植する
- Caldera の Ansible ロールは `/home/admin/caldera` 固定。**Azure は管理者ユーザー名 `admin` を禁止**しているのでパス修正が必要
- Azure では Kali モジュールがコメントアウト（Marketplace から消えた）
- 既定の Splunk は 9.3.0。BYO にするので range 側では使わない
- Windows の ART インストールで `invoke-atomicredteam` だけ入らず（atomics は入る）、build は成功扱い、初回 simulate で `Invoke-AtomicTest is not recognized`。本家はエンジン側の `IWR` にだけ `-UseBasicParsing` が無い（PS 5.1 は付けないと IE エンジンで解析しようとして失敗し得る）。手動で `-UseBasicParsing` 付きで入れ直したら成功したので、これが原因とみている（元のエラーは未確認）。`31ddd6b` で `-UseBasicParsing`・`$ErrorActionPreference = "Stop"`・存在確認・リトライを追加
- `attack_range.py stop` が `begin_power_off`（電源オフのみ、割り当てたまま）で、**止めても VM 料金が発生し続ける**。`fc56230` で `begin_deallocate` に変更し、resume も `VM deallocated` から起動できるようにした。ポータルの「停止」は割り当て解除なので OK
- OpenCanary（0.9.10）の `opencanaryd --dev` は root でないと中で `sudo` を呼ぶ → systemd では `twistd -noy .../opencanary.tac` を直接起動。`--copyconfig` は PATH の `python3` を使うので venv を PATH の先頭に入れないと `No module named 'opencanary'`（使い捨てコンテナで確認済み）
- Azure の Windows 11 はネットワークが **Public** で起動し、クライアント版 Windows は Public のあいだ WinRM サービスの設定変更を拒否する（`WinRM firewall exception will not work since one of the network connection types on this machine is set to Public`）。`AllowUnencrypted=false` のまま残り、Terraform の remote-exec が `401 - invalid content type` で落ちる → `winrm.ps1` の先頭で `Set-NetConnectionProfile -NetworkCategory Private`（実機で確認、2026-11-03）。ポータルの「接続 → Bastion」を押すと range VNet に Bastion が自動で作られ、destroy が `InUseVirtualNetworkCannotBeDeleted` で失敗する。RDP は直接つなぐ
- 4688 にコマンドラインを入れるレジストリの値名が、本家では `ProcessCreationinclude_tasksCmdLine_Enabled`（`Include` → `include_tasks` の一括置換の巻き添え）。`ignore_errors: yes` なので失敗も出ず、4688 にコマンドラインが入らない → 正しい名前に修正（実機で確認、2026-11-04）。Sysmon の EventCode 1 はこの設定と無関係に CommandLine を記録する
- DC では昇格後に `AzureAdmin` を SID に変換できず、Caldera エージェントのタスク登録が失敗する → タスクは SYSTEM で動かす（2026-11-03）
- Japan East で Av2（A2_v2 / A4_v2）が在庫切れ（`SkuNotAvailable`、2026-11-03）→ Linux は D2_v4、OpenCanary は D2s_v5
- パブリック IP が SKU 未指定（azurerm 3.6 の既定 = Basic）。Basic は 2025-09 に廃止され、新規作成は `IPv4BasicSkuPublicIpCountLimitReached` で失敗する → 全モジュールに `sku = "Standard"` を足した（Standard は NSG で許可したポートしか通らない「既定で安全」型。range の NSG はサブネットに付いているので動作は変わらない）
- **本家 Dockerfile は `git clone` で既定ブランチ（v5）を取る**ので v4.0.2 のパッチが乗らない → 自前の `docker/Dockerfile`（ツールのみ、ソースは bind mount）
- `configure` は SSH 鍵を CWD に作る。Windows の bind mount 上は 0777 に見えて ssh が拒否する → 鍵は名前付きボリューム `aar-ssh`（`/root/.ssh/aar.key`）に置き、configure では既存鍵を再利用
- azure-cli は専用 venv（`/opt/azcli`）。本家は requirements.txt と同居させており azure-* のピン留めと衝突し得る

## ローカル実行環境

- `.\ar.ps1` でツールボックスコンテナに入る（`-Build` で再ビルド）。ボリューム：`aar-azure`（az login）、`aar-ssh`（鍵）
- PowerShell 5.1 からコンテナの stdin にパイプすると先頭に BOM が付いて1行目が壊れる。コマンドは引数で渡す

## パッチ方針

初回コミットは本家そのまま（pristine）。以降のパッチは diff で追えるよう、パッチ単位でコミットする。

## 未解決・要検証

- Splunk MCP Server app（2.0.0）が Splunk 10.6 に対応しているか（Splunkbase の表は 10.2 まで）。駄目なら 10.2 系へ
- Foundry Agent Service（ホスト型ツール呼び出し）からプライベートな MCP に届くか。v0 は「モデル=Foundry / MCP クライアント=VNet 内の自作エージェント」で回避。**8089 は外に出さない**
- Splunk ライセンス：常設なので Developer License が必要（Free に落ちると認証が消え MCP のトークン認証が死ぬ）
