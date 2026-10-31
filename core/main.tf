data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "core" {
  name     = var.prefix
  location = var.location

  tags = local.tags
}

locals {
  tags = {
    project = "azure-attack-range"
    layer   = "core"
  }
}

# ---------------------------------------------------------------------------
# 削除ロック
#
# RG 全体ではなく「消えると困るもの」だけに付ける。
# RG や VNet に付けると、range 側の destroy で core VNet 側の VNet ピアリング
# （core VNet の子リソース）が消せなくなり、range の destroy が毎回失敗するため。
# ---------------------------------------------------------------------------

resource "azurerm_management_lock" "splunk" {
  count      = var.enable_delete_locks ? 1 : 0
  name       = "do-not-delete"
  scope      = azurerm_linux_virtual_machine.splunk.id
  lock_level = "CanNotDelete"
  notes      = "常設 Splunk。消すときは enable_delete_locks = false で apply してから"
}

resource "azurerm_management_lock" "foundry" {
  count      = var.enable_delete_locks ? 1 : 0
  name       = "do-not-delete"
  scope      = azurerm_cognitive_account.foundry.id
  lock_level = "CanNotDelete"
  notes      = "子リソース（モデルのデプロイ）の削除もブロックされる。モデルを替えるときは一度外す"
}
