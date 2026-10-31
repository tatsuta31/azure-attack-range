# 引き継ぎメモ（2026-10-31 時点）

前セッション（workbench で起動）からの引き継ぎ。**設計の決定事項と罠は `CLAUDE.md` が正**。ここは「どこまで進んだか」と「次に何をやるか」だけ。完了したら該当行を消すか更新すること。

## 完了済み

- [x] プロジェクト作成、splunk/attack_range **v4.0.2 を pristine でベンダリング**（commit `735c91b`）
- [x] 自前ツールボックス `docker/Dockerfile` ＋ `ar.ps1`（Terraform 1.9.8 / az 2.91.0 / ansible-core 2.17.7、windows コレクション同梱を確認済み）
- [x] SSH 鍵 `aar.key` / `aar.pub` を Docker ボリューム `aar-ssh`（`/root/.ssh`）に生成済み（600）
- [x] `.gitattributes` で LF 固定（`.ps1` のみ CRLF）
- [x] Docker Desktop 導入・エンジン起動確認（28 CPU / 16GB）

## 今ここ：ユーザーの `az login` 待ち

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
3. **`core/` の Terraform を書く**（消さない基盤。state は range と別）
   - RG `aar-core`（Japan East）＋ **CanNotDelete ロック**
   - VNet `10.10.0.0/16`（range 側 `10.0.0.0/16` と重ならないこと）
   - Splunk VM：Ubuntu 22.04/24.04、Splunk Enterprise **10.6.1**（DL URL とハッシュは公式で要確認）、静的プライベート IP、**自動シャットダウン**
   - NSG：自宅グローバル IP のみ 22 / 8000。**8089（MCP 含む管理ポート）は外部公開しない**。9997 は range VNet からのみ
   - インデックス・TA：range 側 UF が送ってくる index 名を v4.0.2 の Ansible ロールから拾って作成。TA は Attack Range の公開 S3（`attack-range-appbinaries`）から流用
   - Microsoft Foundry：AI Services アカウント（project management 有効）＋ Project ＋ モデルデプロイ（Japan East で使えるモデルを確認）
   - 実装は自己完結なので `/haiku-delegate` で Haiku に振り、Opus がレビュー可
4. **Attack Range v4.0.2 へのパッチ**（パッチ単位でコミット）
   - BYO Splunk：`splunk_server.byo_splunk: "1"`, `byo_splunk_ip: <core の Splunk IP>`
   - `terraform/azure/modules/network` に **双方向 VNet ピアリング**を追加（core の VNet ID を設定から受け取る。range destroy で両側消える）
   - **Caldera サーバーの Azure モジュール新設**（AWS 版 `terraform/aws/modules/caldera-server` を移植、IP `10.0.1.70`）。Ansible ロールの `/home/admin` 固定パスを修正（Azure は `admin` ユーザー名禁止）
   - `configure` は「既存鍵を再利用」で `/root/.ssh/aar.key` を指定
5. **疎通確認**：ar-win で ART（例 `T1003.001`）→ core Splunk で検索できること。Caldera エージェントのチェックイン
6. **Splunk MCP Server app**（Splunkbase 7931。DL はユーザーが Splunk.com ログインで実施）→ まず Claude Code から MCP 接続
7. **Foundry 側エージェント**：モデル＝Foundry、MCP クライアント＝core VNet 内の自作エージェント（Foundry SDK）。AI-901 の SDK 範囲も兼ねる

## ユーザー側の宿題（状況確認すること）

- Splunk **Developer License** の申請状況（未着なら 60 日トライアルで進める）
- Azure 予算アラート、Japan East の vCPU クォータ
- 自宅のグローバル IP（NSG の許可元。`curl ifconfig.me` 等で確認してもらう）

## 未検証の論点（CLAUDE.md にも記載）

- MCP Server app 2.0.0 の Splunk 10.6 対応（Splunkbase の表は 10.2 まで）→ 駄目なら 10.2 系
- Foundry Agent Service のホスト型ツール呼び出しからプライベート MCP に届くか（第2段階で検討）
