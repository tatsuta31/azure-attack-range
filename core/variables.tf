# ---------------------------------------------------------------------------
# 必須（terraform.tfvars で必ず埋める）
# ---------------------------------------------------------------------------

variable "subscription_id" {
  description = "従量課金サブスクの ID（az account show の id）"
  type        = string
}

variable "allowed_source_cidrs" {
  description = "Splunk の SSH(22) / Web(8000) に入ってよい送信元。自宅のグローバル IP を /32 で"
  type        = list(string)

  validation {
    condition     = length(var.allowed_source_cidrs) > 0 && !contains(var.allowed_source_cidrs, "0.0.0.0/0")
    error_message = "0.0.0.0/0 は禁止。自宅 IP を x.x.x.x/32 で指定すること。"
  }
}

variable "splunk_url" {
  description = "Splunk Enterprise の Linux x86_64 .tgz の URL（公式ダウンロードページの wget リンク）"
  type        = string
}

variable "splunk_admin_password" {
  description = "Splunk の admin パスワード（8 文字以上）"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.splunk_admin_password) >= 8
    error_message = "Splunk の admin パスワードは 8 文字以上。"
  }
}

variable "foundry_model_name" {
  description = "Foundry にデプロイするモデル名（Japan East で使えるものを確認して指定）"
  type        = string
}

variable "foundry_model_version" {
  description = "モデルのバージョン"
  type        = string
}

# ---------------------------------------------------------------------------
# 任意（既定値のままでよい）
# ---------------------------------------------------------------------------

variable "location" {
  type    = string
  default = "japaneast"
}

variable "prefix" {
  description = "リソース名の接頭辞"
  type        = string
  default     = "aar-core"
}

variable "enable_delete_locks" {
  description = "Splunk VM と Foundry に削除ロックを付けるか。構築・作り直し中は false、安定したら true"
  type        = bool
  default     = true
}

# --- ネットワーク ---

variable "core_vnet_cidr" {
  description = "core 側 VNet。range 側（10.0.0.0/16）と重ねないこと"
  type        = string
  default     = "10.10.0.0/16"
}

variable "splunk_subnet_cidr" {
  type    = string
  default = "10.10.1.0/24"
}

variable "agent_subnet_cidr" {
  description = "後で置く自作エージェント（MCP クライアント）用。今は空のサブネットだけ作る"
  type        = string
  default     = "10.10.2.0/24"
}

variable "splunk_private_ip" {
  description = "Splunk の固定プライベート IP。attack_range.yml の byo_splunk_ip にこれを書く"
  type        = string
  default     = "10.10.1.10"
}

variable "range_vnet_cidr" {
  description = "Attack Range 側 VNet。ここからは 9997（ログ受信）だけ許可し、他は全部遮断する"
  type        = string
  default     = "10.0.0.0/16"
}

# --- Splunk VM ---

variable "splunk_vm_size" {
  description = "4 vCPU / 16 GB。クォータが厳しければ Standard_D2s_v5 でも動くが検索は重い"
  type        = string
  default     = "Standard_D4s_v5"
}

variable "splunk_os_disk_gb" {
  type    = number
  default = 128
}

variable "admin_username" {
  description = "VM の管理ユーザー名（Azure は admin / root などを禁止している）"
  type        = string
  default     = "azureuser"
}

variable "ssh_public_key_path" {
  description = "ツールボックスコンテナ内の公開鍵パス（ボリューム aar-ssh）"
  type        = string
  default     = "/root/.ssh/aar.pub"
}

variable "splunk_sha512" {
  description = "splunk_url の .tgz の SHA512（公式ページの値）。空ならハッシュ検証をスキップする"
  type        = string
  default     = ""
}

variable "splunk_apps_base_url" {
  description = "Attack Range が使っている TA 置き場（公開 S3）"
  type        = string
  default     = "https://attack-range-appbinaries.s3-us-west-2.amazonaws.com"
}

variable "splunk_apps" {
  description = "初回起動時に入れる TA。ファイル名は attack_range/configs/attack_range_default.yml の splunk_apps から選ぶ"
  type        = list(string)
  default = [
    "splunk-common-information-model-(cim)_630.tgz",
    "splunk-add-on-for-microsoft-windows_911.tgz",
    "splunk-add-on-for-sysmon_500.tgz",
    "splunk-add-on-for-unix-and-linux_1020.tgz",
    "splunk-add-on-for-sysmon-for-linux_100.tgz",
    "splunk-es-content-update_5180.tgz",
    "splunk-security-essentials_382.tgz",
    "splunk_attack_range_reporting-1.0.9.tar.gz",
  ]
}

variable "auto_shutdown_time" {
  description = "毎日の自動シャットダウン時刻（HHmm、日本時間）"
  type        = string
  default     = "0100"
}

# --- Foundry ---

variable "foundry_model_sku" {
  description = "デプロイの種類。GlobalStandard が一番選べるモデルが多い"
  type        = string
  default     = "GlobalStandard"
}

variable "foundry_model_capacity" {
  description = "TPM の上限（1 = 1,000 トークン/分）。従量課金なので上げても待機中のコストは増えない"
  type        = number
  default     = 10
}

variable "foundry_user_object_ids" {
  description = "Foundry のモデルを Entra ID で呼べるようにする人（ユーザーのオブジェクト ID）。Cloud Shell で az ad signed-in-user show --query id -o tsv"
  type        = list(string)
  default     = []
}

variable "foundry_user_role" {
  description = "foundry_user_object_ids に付けるロール名。テナントで使える名前を az role definition list で確認する"
  type        = string
  default     = "Cognitive Services User"
}

variable "foundry_local_auth_enabled" {
  description = "API キー認証を許すか。false なら Entra ID（az login / マネージド ID）のみ"
  type        = bool
  default     = false
}
