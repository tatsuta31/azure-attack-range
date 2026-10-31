# core/ — 消さない基盤

常設の Splunk（BYO Splunk として Attack Range に使わせる）と Microsoft Foundry。
state はこのディレクトリのローカル（`terraform.tfstate`、git 管理外）。**消すと管理できなくなるのでバックアップ推奨。**

## 作られるもの

| リソース | 名前 | メモ |
|---|---|---|
| RG | `aar-core` | Japan East |
| VNet | `aar-core-vnet` 10.10.0.0/16 | サブネット `splunk` 10.10.1.0/24 / `agent` 10.10.2.0/24（自作エージェント用、今は空） |
| Splunk VM | `aar-core-splunk` 10.10.1.10 | Ubuntu 24.04、D4s_v5、毎日 01:00 自動停止 |
| NSG | `aar-core-splunk-nsg` | 自宅 IP → 22/8000、range VNet → 9997 のみ（他は拒否）。8089 は外に出さない |
| Foundry | `aar-core-foundry-xxxxxx` | AI Services ＋ Project ＋ モデル 1 つ。API キー無効（Entra ID のみ） |
| 削除ロック | Splunk VM と Foundry | `enable_delete_locks` で ON/OFF |

## 手順（PowerShell）

1. 設定ファイルを作る
   ```powershell
   Copy-Item core\terraform.tfvars.example core\terraform.tfvars
   notepad core\terraform.tfvars
   ```
2. ツールボックスに入る（以降はコンテナ内の bash）
   ```powershell
   .\ar.ps1
   ```
3. 初期化 → 差分確認 → 適用
   ```bash
   cd /work/core
   terraform init
   terraform plan -out=core.tfplan
   terraform apply core.tfplan
   ```
4. Splunk のセットアップ完了を待つ（apply 後 5〜10 分）
   ```bash
   $(terraform output -raw ssh_command)
   sudo tail -f /var/log/aar-install-splunk.log   # "[aar] done" が出れば完了
   ```
5. ブラウザで `terraform output -raw splunk_web_url` を開く（自己署名証明書の警告は想定どおり）。admin / tfvars のパスワード

## 運用メモ

- **ロックの付け外し**：構築中は `enable_delete_locks = false`。安定したら `true` にして `terraform apply`
- **Splunk を作り直す**：`custom_data` の変更は無視する設定なので、明示的に `terraform apply -replace=azurerm_linux_virtual_machine.splunk`（ロック OFF が前提。インデックス済みデータは消える）
- **自動停止後の起動**：ポータルで VM を開始するか、`az vm start -g aar-core -n aar-core-splunk`
- **ライセンス**：Developer License が届いたら Splunk Web の「設定 → ライセンス」から追加。Free に落ちると認証が消え、MCP のトークン認証も使えなくなる
- **admin パスワードの扱い**：cloud-init（custom_data）に平文で入るため、state と VM 内の IMDS から読める。個人ラボとして許容している
