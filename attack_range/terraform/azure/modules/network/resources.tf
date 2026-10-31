
resource "azurerm_resource_group" "attackrange" {
  name = "ar-rg-${var.general.key_name}-${var.general.attack_range_name}"
  location = var.azure.location
}

resource "azurerm_virtual_network" "attackrange-network" {
  name = "ar-vnet-${var.general.key_name}-${var.general.attack_range_name}"
  address_space = ["10.0.0.0/16"]
  location = var.azure.location
  resource_group_name = azurerm_resource_group.attackrange.name
}

resource "azurerm_subnet" "attackrange-subnet" {
  name                 = "ar-subnet-${var.general.key_name}-${var.general.attack_range_name}"
  resource_group_name  = azurerm_resource_group.attackrange.name
  virtual_network_name = azurerm_virtual_network.attackrange-network.name
  address_prefixes       = ["10.0.1.0/24"]
}

resource "azurerm_network_security_group" "attackrange-nsg" {
  name                = "ar-nsg-${var.general.key_name}-${var.general.attack_range_name}"
  location = var.azure.location
  resource_group_name  = azurerm_resource_group.attackrange.name

  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefixes    = [var.general.ip_whitelist]
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Splunk_8000"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8000"
    source_address_prefixes    = [var.general.ip_whitelist]
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Splunk_8089"
    priority                   = 1003
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8089"
    source_address_prefixes    = [var.general.ip_whitelist]
    destination_address_prefix = "*"
  }

  # RDP
  security_rule {
    name                       = "RDP"
    priority                   = 1004
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefixes    = [var.general.ip_whitelist]
    destination_address_prefix = "*"
  }

  # WinRM
  security_rule {
    name                       = "WinRM"
    priority                   = 1005
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5985-5986"
    source_address_prefixes    = [var.general.ip_whitelist]
    destination_address_prefix = "*"
  }


  # Allow all traffic from the private subnet
  security_rule {
    name                       = "PrivateSubnet"
    priority                   = 1007
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "10.0.1.0/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "HTTP"
    priority                   = 1008
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefixes    = [var.general.ip_whitelist]
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "HTTPS"
    priority                   = 1009
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefixes    = [var.general.ip_whitelist]
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Caldera"
    priority                   = 1010
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8888"
    source_address_prefixes    = [var.general.ip_whitelist]
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Guacamole"
    priority                   = 1014
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8080"
    source_address_prefixes    = [var.general.ip_whitelist]
    destination_address_prefix = "*"
  }

}

resource "azurerm_subnet_network_security_group_association" "attackrange-nsga" {
  subnet_id                 = azurerm_subnet.attackrange-subnet.id
  network_security_group_id = azurerm_network_security_group.attackrange-nsg.id
}

# --- azure-attack-range patch: VNet peering to the persistent core VNet (BYO Splunk) ---
# Enabled when azure.core_vnet_id is set (output core_vnet_id of core/ Terraform).
# Both directions are owned by this state, so range destroy removes both sides
# and the core VNet is left untouched.

locals {
  core_vnet_id    = lookup(var.azure, "core_vnet_id", "")
  core_peering    = local.core_vnet_id != ""
  core_vnet_parts = split("/", local.core_vnet_id)
}

resource "azurerm_virtual_network_peering" "range-to-core" {
  count                     = local.core_peering ? 1 : 0
  name                      = "ar-peer-to-core-${var.general.key_name}-${var.general.attack_range_name}"
  resource_group_name       = azurerm_resource_group.attackrange.name
  virtual_network_name      = azurerm_virtual_network.attackrange-network.name
  remote_virtual_network_id = local.core_vnet_id
  allow_virtual_network_access = true
}

resource "azurerm_virtual_network_peering" "core-to-range" {
  count                     = local.core_peering ? 1 : 0
  name                      = "ar-peer-from-${var.general.key_name}-${var.general.attack_range_name}"
  resource_group_name       = local.core_vnet_parts[4]
  virtual_network_name      = local.core_vnet_parts[8]
  remote_virtual_network_id = azurerm_virtual_network.attackrange-network.id
  allow_virtual_network_access = true
}