# core/ は「消さない基盤」。state は attack_range 側と完全に別（このディレクトリのローカル state）。
#
# azurerm は 4.x の最終系に固定する。5.x は 2026 年に出たばかりで破壊的変更があり、
# Foundry 周り（cognitive_account_project）は 4.x で十分そろっているため。

terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.81"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  # azurerm 4.x からはサブスク ID の明示が必須
  subscription_id = var.subscription_id

  features {
    resource_group {
      # 中身が残っている RG を terraform destroy で巻き込み削除しない
      prevent_deletion_if_contains_resources = true
    }
  }
}
