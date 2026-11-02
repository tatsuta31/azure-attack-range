# Ressource group
output "rg_name" {
  value = azurerm_resource_group.attackrange.name
}

# azure-attack-range patch: DMZ subnet for OpenCanary ("" when disabled).
# Waits for the NSG association so the honeypot never boots unfiltered.
output "dmz_subnet_id" {
  value = local.canary_enabled ? azurerm_subnet.dmz[0].id : ""
  depends_on = [
    azurerm_subnet_network_security_group_association.dmz,
    azurerm_virtual_network_peering.range-to-core,
    azurerm_virtual_network_peering.core-to-range,
  ]
}

# Subnet id
output "subnet_id" {
  value = azurerm_subnet.attackrange-subnet.id
  # azure-attack-range patch: every VM module consumes subnet_id, so this makes
  # Ansible provisioning (UF -> core Splunk:9997) wait until the peering is up.
  depends_on = [
    azurerm_virtual_network_peering.range-to-core,
    azurerm_virtual_network_peering.core-to-range,
  ]
}