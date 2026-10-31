resource "azurerm_public_ip" "splunk" {
  name                = "${var.prefix}-splunk-pip"
  location            = azurerm_resource_group.core.location
  resource_group_name = azurerm_resource_group.core.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = local.tags
}

resource "azurerm_network_interface" "splunk" {
  name                = "${var.prefix}-splunk-nic"
  location            = azurerm_resource_group.core.location
  resource_group_name = azurerm_resource_group.core.name

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.splunk.id
    private_ip_address_allocation = "Static"
    private_ip_address            = var.splunk_private_ip
    public_ip_address_id          = azurerm_public_ip.splunk.id
  }

  tags = local.tags
}

# ---------------------------------------------------------------------------
# 初回起動時の構成（cloud-init）
#
# Splunk のインストールは VM 自身にやらせる（Ansible を使わない）。
# indexes.conf は Attack Range 本体のものをそのまま使い、range 側 UF が送ってくる
# index（win / attack / unix / network ...）と必ず一致させる。
#
# 注意：admin パスワードは custom_data に平文で入る（＝ state と VM の IMDS から読める）。
# 個人ラボなので許容。Splunk は初回起動で user-seed.conf を消す。
# ---------------------------------------------------------------------------

locals {
  splunk_install_script = templatefile("${path.module}/templates/install-splunk.sh.tftpl", {
    splunk_url    = var.splunk_url
    splunk_sha512 = var.splunk_sha512
    apps_base_url = var.splunk_apps_base_url
    splunk_apps   = var.splunk_apps
  })

  splunk_user_seed = <<-EOT
    [user_info]
    USERNAME = admin
    PASSWORD = ${var.splunk_admin_password}
  EOT

  splunk_cloud_init = templatefile("${path.module}/templates/cloud-init.yaml.tftpl", {
    install_script_b64 = base64encode(local.splunk_install_script)
    indexes_conf_b64   = filebase64("${path.module}/../attack_range/terraform/ansible/roles/splunk_server/files/indexes.conf")
    inputs_conf_b64    = filebase64("${path.module}/files/inputs.conf")
    web_conf_b64       = filebase64("${path.module}/files/web.conf")
    user_seed_b64      = base64encode(local.splunk_user_seed)
  })
}

resource "azurerm_linux_virtual_machine" "splunk" {
  name                  = "${var.prefix}-splunk"
  computer_name         = "core-splunk"
  location              = azurerm_resource_group.core.location
  resource_group_name   = azurerm_resource_group.core.name
  size                  = var.splunk_vm_size
  admin_username        = var.admin_username
  network_interface_ids = [azurerm_network_interface.splunk.id]

  disable_password_authentication = true

  admin_ssh_key {
    username   = var.admin_username
    public_key = file(var.ssh_public_key_path)
  }

  os_disk {
    name                 = "${var.prefix}-splunk-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = var.splunk_os_disk_gb
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  custom_data = base64encode(local.splunk_cloud_init)

  tags = local.tags

  lifecycle {
    # custom_data は変えると VM 作り直しになる。初回構成用なので、後からの変更は無視する。
    # 作り直したいときは terraform apply -replace=azurerm_linux_virtual_machine.splunk
    ignore_changes = [custom_data]
  }
}

# 毎日の自動シャットダウン（停止＝割り当て解除なので VM 料金が止まる。ディスク代は残る）
resource "azurerm_dev_test_global_vm_shutdown_schedule" "splunk" {
  virtual_machine_id    = azurerm_linux_virtual_machine.splunk.id
  location              = azurerm_resource_group.core.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = "Tokyo Standard Time"

  notification_settings {
    enabled = false
  }

  tags = local.tags
}
