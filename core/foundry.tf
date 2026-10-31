# ---------------------------------------------------------------------------
# Microsoft Foundry
#
# 構成：AI Services アカウント（= Foundry リソース）→ Project → モデルのデプロイ
# Project を作るには、アカウント側に project_management_enabled / マネージド ID /
# custom_subdomain_name の 3 点がそろっている必要がある。
# ---------------------------------------------------------------------------

# サブドメイン名は Azure 全体で一意でなければならないので、末尾に乱数を付ける
resource "random_string" "foundry_suffix" {
  length  = 6
  upper   = false
  special = false
}

locals {
  foundry_name = "${var.prefix}-foundry-${random_string.foundry_suffix.result}"
}

resource "azurerm_cognitive_account" "foundry" {
  name                       = local.foundry_name
  location                   = azurerm_resource_group.core.location
  resource_group_name        = azurerm_resource_group.core.name
  kind                       = "AIServices"
  sku_name                   = "S0"
  custom_subdomain_name      = local.foundry_name
  project_management_enabled = true
  local_auth_enabled         = var.foundry_local_auth_enabled

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags
}

resource "azurerm_cognitive_account_project" "lab" {
  name                 = "${var.prefix}-project"
  cognitive_account_id = azurerm_cognitive_account.foundry.id
  location             = azurerm_resource_group.core.location
  display_name         = "Azure Attack Range Lab"
  description          = "Splunk MCP 経由の検知解析エージェント用"

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags
}

resource "azurerm_cognitive_deployment" "model" {
  name                 = var.foundry_model_name
  cognitive_account_id = azurerm_cognitive_account.foundry.id

  model {
    format  = "OpenAI"
    name    = var.foundry_model_name
    version = var.foundry_model_version
  }

  sku {
    name     = var.foundry_model_sku
    capacity = var.foundry_model_capacity
  }
}

# API キーを無効にしているので、apply した本人（az login のユーザー）に
# Entra ID でモデルを呼べる権限を付ける。
resource "azurerm_role_assignment" "me_foundry_user" {
  scope                = azurerm_cognitive_account.foundry.id
  role_definition_name = "Azure AI User"
  principal_id         = data.azurerm_client_config.current.object_id
}
