# azure-attack-range

Azure 上に検知検証ラボを作る。Atomic Red Team / Caldera で攻撃 → Splunk で検知 → Splunk MCP 経由で AI（Foundry）に解析させる。AI-901 対策も兼ねる。

## 構成の決定事項（2026-10-30）

- **2層構成**
  - `core/`：消さない基盤（自前 Terraform）。Splunk 10.6.1 + Splunk MCP Server app、Microsoft Foundry。RG に削除ロック
  - `attack_range/`：splunk/attack_range **v4.0.2 をベンダリングしてパッチ**。build/destroy を繰り返す使い捨て
- 連携は Attack Range 標準の **BYO Splunk**（`splunk_server.byo_splunk: "1"` / `byo_splunk_ip`）。これで range 側の Splunk VM は count=0 になる
- 環境：従量課金サブスク（個人）、リージョン Japan East
- Caldera サーバーは range 側で使い捨て（10.0.1.70）

## v4.0.2 の罠（コードで確認済み）

- Caldera サーバーの Terraform モジュールは **AWS 版しかない**。Azure で `caldera_server: "1"` にしても何も作られない → Azure 用を移植する
- Caldera の Ansible ロールは `/home/admin/caldera` 固定。**Azure は管理者ユーザー名 `admin` を禁止**しているのでパス修正が必要
- Azure では Kali モジュールがコメントアウト（Marketplace から消えた）
- 既定の Splunk は 9.3.0。BYO にするので range 側では使わない
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
