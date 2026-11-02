# azure-attack-range patch: isolated DMZ subnet for the OpenCanary honeypot.
#
# The honeypot is meant to be touched by attackers, so it is boxed in:
#   inbound : decoy ports from the internal subnet (and the Internet if internet_exposed = 1),
#             the real sshd (mgmt_ssh_port) from general.ip_whitelist only, everything else denied
#   outbound: core Splunk 9997 (logs) and Internet 80/443/123 (packages, time) only;
#             the internal subnet, the core VNet and everything else are denied, so a
#             compromised honeypot cannot be used to pivot.

locals {
  canary_enabled  = lookup(var.opencanary_server, "opencanary_server", "0") == "1"
  canary_exposed  = lookup(var.opencanary_server, "internet_exposed", "0") == "1"
  canary_ip       = lookup(var.opencanary_server, "private_ip", "10.0.2.10")
  canary_mgmt     = lookup(var.opencanary_server, "mgmt_ssh_port", "22222")
  canary_subnet   = lookup(var.opencanary_server, "dmz_subnet", "10.0.2.0/24")
  canary_ports    = [for s in split(",", lookup(var.opencanary_server, "decoy_services", "ssh:22")) : split(":", trimspace(s))[1]]
  splunk_ip       = lookup(var.splunk_server, "byo_splunk", "0") == "1" ? lookup(var.splunk_server, "byo_splunk_ip", "") : "10.0.1.12"
  internal_subnet = "10.0.1.0/24"
}

resource "azurerm_subnet" "dmz" {
  count                = local.canary_enabled ? 1 : 0
  name                 = "ar-dmz-${var.general.key_name}-${var.general.attack_range_name}"
  resource_group_name  = azurerm_resource_group.attackrange.name
  virtual_network_name = azurerm_virtual_network.attackrange-network.name
  address_prefixes     = [local.canary_subnet]
}

resource "azurerm_network_security_group" "dmz" {
  count               = local.canary_enabled ? 1 : 0
  name                = "ar-dmz-nsg-${var.general.key_name}-${var.general.attack_range_name}"
  location            = var.azure.location
  resource_group_name = azurerm_resource_group.attackrange.name

  # ---------------- inbound ----------------
  security_rule {
    name                       = "mgmt-ssh-from-whitelist"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = local.canary_mgmt
    source_address_prefixes    = split(",", var.general.ip_whitelist)
    destination_address_prefix = local.canary_ip
  }

  security_rule {
    name                       = "decoys-from-internal"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = local.canary_ports
    source_address_prefix      = local.internal_subnet
    destination_address_prefix = local.canary_ip
  }

  security_rule {
    name                       = "decoys-from-internet"
    priority                   = 120
    direction                  = "Inbound"
    access                     = local.canary_exposed ? "Allow" : "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = local.canary_ports
    source_address_prefix      = "Internet"
    destination_address_prefix = local.canary_ip
  }

  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # ---------------- outbound ----------------
  security_rule {
    name                       = "logs-to-splunk"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "9997"
    source_address_prefix      = "*"
    destination_address_prefix = local.splunk_ip
  }

  security_rule {
    name                       = "deny-to-vnets"
    priority                   = 200
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "VirtualNetwork"
  }

  security_rule {
    name                       = "web-to-internet"
    priority                   = 300
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["80", "443"]
    source_address_prefix      = "*"
    destination_address_prefix = "Internet"
  }

  security_rule {
    name                       = "ntp-to-internet"
    priority                   = 310
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "123"
    source_address_prefix      = "*"
    destination_address_prefix = "Internet"
  }

  security_rule {
    name                       = "deny-all-outbound"
    priority                   = 4000
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "dmz" {
  count                     = local.canary_enabled ? 1 : 0
  subnet_id                 = azurerm_subnet.dmz[0].id
  network_security_group_id = azurerm_network_security_group.dmz[0].id
}
