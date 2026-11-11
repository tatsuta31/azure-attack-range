# 引き継ぎメモ（2026-11-12 時点）

**設計の決定事項と罠は `CLAUDE.md` が正**。ここは「どこまで進んだか」と「次に何をやるか」だけ。完了したら該当行を消すか更新すること。

> 履歴は書き換え済み（2026-11-12 確認）。古いメモに出てくるコミット番号は存在しない。コミットはタイトルで探す（`git log --oneline`）。

## 役割分担（2026-10-31 決定）

- **ユーザー**：Azure の実操作すべて（az login、terraform apply、Attack Range の build / destroy、ポータル操作）
- **Claude**：コード・設定ファイルの作成、解説、レビュー。ユーザーが打つコマンドは PowerShell 形式で渡す。Azure に変更を加えるコマンドは Claude から実行しない

## ロードマップ（2026-11-02 ユーザー決定。この順で進める）

1. **環境構築**：**完了（2026-11-04）**
2. **ルール有効化と発火確認**：**進行中**（下の「今ここ」）
3. **Splunk MCP 構築**：Splunk MCP Server app（Splunkbase 7931。DL はユーザーが Splunk.com ログインで実施）を core Splunk に入れる → まず Claude Code から MCP 接続
4. **Foundry 構築**：リソース・Project・モデル（gpt-4.1-mini）・ロールは core の Terraform で作成済み。ここでやるのはエージェントの作成と MCP との接続（モデル＝Foundry、MCP クライアント＝core VNet 内の自作エージェント。ユーザーはポータルで手で作る練習もしたい可能性あり）
5. **ログ連携確認**：エージェント → MCP → Splunk の検索が通ること
6. **Foundry による分析**：発火したアラートを AI に解析させる

並行：AI-901 を受験予定（Foundry 分野が 55〜60%）。

## 今ここ：2. ルール有効化（2026-11-12）

本命5検知（#1 監査無効化 / #3 アーカイブ収集 / #4 不審タスク / #5 ランサムノート / #6 AdminSDHolder）＋ Palo の #2。どの資料を使うかは `docs/detection-validation-guide.md`。

- **パスA（手動 PowerShell、`docs/escu-validation-story-01.md`）**：5本とも生ログは確認済み。記録表は同ファイル末尾
  - #4：ルールは無効のまま SPL を手動実行して発火。正規タスク（OneDrive / Defender）による誤検知 5 件 → 本番なら filter マクロで除外
  - #1：アラートを設定済み、スケジュール発火待ち（Discord 通知のアラートアクションは `core/files/apps/aar_discord_alert`）
  - #3 / #5 / #6：生ログのみ確認。ルール有効化とスケジュール発火は未確認
  - #2（Palo）：Palo はラボに置かないので未実施
- **パスB（Caldera 通し実行、`docs/caldera-killchain-run.md`）**：アビリティ（`caldera/abilities/aar-killchain/`）とアドバーサリー（`caldera/adversaries/killchain-01.yml`）は作成済み。**ラボでの実行は未実施**。設計の背景は `docs/attack-killchain-story-02.md`
- ESCU の tstats ルールが当たらない件の調査記録：`docs/troubleshooting-escu-tstats.md`（ラボでは CIM マクロに `(index=win OR index=unix)` を入れる）
- splunkd エージェント名に依存する SPL の一覧：`docs/caldera-killchain-run.md` 末尾

### 次の一手

1. パスA の残り：#3 / #5 / #6（と #1）をルールとして有効化し、スケジュール実行で発火することを記録表に埋める
2. パスB：Caldera で `killchain-01` を 1 回流し、5 検知が出ることと、親プロセスが `C:\Temp\splunkd.exe` であることを確認する
3. 終わったらロードマップ 3（MCP）へ

## 構成（2026-11-04 build 済み）

- range：ar-dc / ar-win1 / ar-win2（Windows 11）/ ar-srv / ar-linux / ar-canary（DMZ）＋ Caldera（10.0.1.70）
- core Splunk に全ホストのログが届く（ar-dc / ar-win1 / ar-win2 / ar-srv → `win`、ar-linux → `unix`・`osquery`、ar-canary → `honeypot`）
- Sysmon は `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`、`sourcetype=XmlWinEventLog`。設定は `AttackRangeSysmon.xml`（既定の SwiftOnSecurity は EventCode 10 を記録しない）
- Caldera エージェントは SYSTEM で動くので、Caldera 経由の攻撃のユーザーは `NT AUTHORITY\SYSTEM` になる
- Caldera 経由のプロセスの検索：`ParentImage="*splunkd.exe" ParentImage!="*SplunkUniversalForwarder*"`
- destroy で range の RG と core 側のピアリングが消え、core 本体は残ることを確認済み（2026-11-02）
- 設定見本：`attack_range/attack_range.azure.example.yml` → `attack_range.yml` にコピーして使う（`configure` は使わなくてよい）
- 実行環境：Claude から叩くときは `ar.ps1`（`-it` 付き）ではなく `docker run --rm -v aar-azure:/root/.azure -v aar-ssh:/root/.ssh -v <root>:/work azure-attack-range:local <cmd>`。ユーザーの PC は実行ポリシーが Restricted なので `powershell -NoProfile -ExecutionPolicy Bypass -File .\ar.ps1 ...`（実行ポリシーの変更はユーザー本人の判断）

## ユーザー側の宿題（状況確認すること）

- **`attack_range_password` の変更**：2026-11-12 まで文書に直書きされていた（文書側は置き換え済み、ただし過去のコミットには残っている）。次の build から別の値にする。履歴から消すかどうかはユーザー判断
- Splunk **Developer License** の申請状況（未着なら 60 日トライアルで進める）
- Azure 予算アラート

## 未検証の論点（CLAUDE.md にも記載）

- MCP Server app 2.0.0 の Splunk 10.6 対応（Splunkbase の表は 10.2 まで）→ 駄目なら 10.2 系
- Foundry Agent Service のホスト型ツール呼び出しからプライベート MCP に届くか（第2段階で検討）
- Caldera の base64 難読化と 4104 の比較（余力があれば）
