output "splunk_public_ip" {
  value = azurerm_public_ip.splunk.ip_address
}

output "splunk_web_url" {
  value = "https://${azurerm_public_ip.splunk.ip_address}:8000"
}

output "splunk_private_ip" {
  description = "attack_range.yml の splunk_server.byo_splunk_ip に書く値"
  value       = azurerm_network_interface.splunk.private_ip_address
}

output "ssh_command" {
  description = "ツールボックスコンテナ内から打つ"
  value       = "ssh -i /root/.ssh/aar.key ${var.admin_username}@${azurerm_public_ip.splunk.ip_address}"
}

output "core_resource_group" {
  value = azurerm_resource_group.core.name
}

output "core_vnet_id" {
  description = "range 側の VNet ピアリングに渡す値"
  value       = azurerm_virtual_network.core.id
}

output "core_vnet_name" {
  value = azurerm_virtual_network.core.name
}

output "foundry_endpoint" {
  value = azurerm_cognitive_account.foundry.endpoint
}

output "foundry_project_name" {
  value = azurerm_cognitive_account_project.lab.name
}

output "foundry_deployment_name" {
  value = azurerm_cognitive_deployment.model.name
}
