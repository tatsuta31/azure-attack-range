# Ressource group
output "rg_name" {
  value = azurerm_resource_group.attackrange.name
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