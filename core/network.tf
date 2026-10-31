resource "azurerm_virtual_network" "core" {
  name                = "${var.prefix}-vnet"
  location            = azurerm_resource_group.core.location
  resource_group_name = azurerm_resource_group.core.name
  address_space       = [var.core_vnet_cidr]

  tags = local.tags
}

resource "azurerm_subnet" "splunk" {
  name                 = "splunk"
  resource_group_name  = azurerm_resource_group.core.name
  virtual_network_name = azurerm_virtual_network.core.name
  address_prefixes     = [var.splunk_subnet_cidr]
}

resource "azurerm_subnet" "agent" {
  name                 = "agent"
  resource_group_name  = azurerm_resource_group.core.name
  virtual_network_name = azurerm_virtual_network.core.name
  address_prefixes     = [var.agent_subnet_cidr]
}

# ---------------------------------------------------------------------------
# Splunk の NSG
#
# 方針（SOC 目線）：Attack Range の VM は「わざと侵害させる端末」。
# Azure の既定ルール AllowVnetInBound はピアリング先の VNet も丸ごと信頼してしまうので、
# range VNet からは 9997（UF → インデクサ）だけ通し、残りは明示的に拒否する。
# 8089（管理 API / MCP）は core VNet 内（agent サブネット）からだけ届く。
# ---------------------------------------------------------------------------

resource "azurerm_network_security_group" "splunk" {
  name                = "${var.prefix}-splunk-nsg"
  location            = azurerm_resource_group.core.location
  resource_group_name = azurerm_resource_group.core.name

  security_rule {
    name                       = "allow-ssh-from-home"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefixes    = var.allowed_source_cidrs
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-splunkweb-from-home"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8000"
    source_address_prefixes    = var.allowed_source_cidrs
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-s2s-from-range"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "9997"
    source_address_prefix      = var.range_vnet_cidr
    destination_address_prefix = var.splunk_private_ip
  }

  security_rule {
    name                       = "deny-everything-else-from-range"
    priority                   = 210
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = var.range_vnet_cidr
    destination_address_prefix = "*"
  }

  tags = local.tags
}

resource "azurerm_subnet_network_security_group_association" "splunk" {
  subnet_id                 = azurerm_subnet.splunk.id
  network_security_group_id = azurerm_network_security_group.splunk.id
}
