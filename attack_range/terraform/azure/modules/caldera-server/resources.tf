
# azure-attack-range patch: Azure port of terraform/aws/modules/caldera-server.
# v4.0.2 only ships the AWS module, so caldera_server: "1" did nothing on Azure.
#
# - Same OS as the AWS module (Debian 12) so the caldera_server role runs unchanged.
# - Admin user is "caldera" because Azure rejects "admin"; the role reads it via caldera_user.
# - Private IP comes from caldera_server.private_ip (10.0.1.70); agents use it.

locals {
  caldera_enabled = var.caldera_server.caldera_server == "1"
  caldera_user    = "caldera"
  caldera_vm_size = lookup(var.caldera_server, "azure_vm_size", "Standard_D2s_v5")
}

resource "azurerm_public_ip" "caldera-publicip" {
  count               = local.caldera_enabled ? 1 : 0
  name                = "ar-caldera-ip-${var.general.key_name}-${var.general.attack_range_name}"
  location            = var.azure.location
  resource_group_name = var.rg_name
  allocation_method   = "Static"
  sku                 = "Standard" # azure-attack-range patch: Basic SKU public IPs are retired
}

resource "azurerm_network_interface" "caldera-nic" {
  count               = local.caldera_enabled ? 1 : 0
  name                = "ar-caldera-nic-${var.general.key_name}-${var.general.attack_range_name}"
  location            = var.azure.location
  resource_group_name = var.rg_name

  ip_configuration {
    name                          = "ar-caldera-nic-conf-${var.general.key_name}-${var.general.attack_range_name}"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Static"
    private_ip_address            = var.caldera_server.private_ip
    public_ip_address_id          = azurerm_public_ip.caldera-publicip[0].id
  }
}

resource "azurerm_virtual_machine" "caldera" {
  count                         = local.caldera_enabled ? 1 : 0
  name                          = "ar-caldera-${var.general.key_name}-${var.general.attack_range_name}"
  location                      = var.azure.location
  resource_group_name           = var.rg_name
  network_interface_ids         = [azurerm_network_interface.caldera-nic[0].id]
  vm_size                       = local.caldera_vm_size
  delete_os_disk_on_termination = true

  storage_os_disk {
    name              = "disk-caldera-${var.general.key_name}-${var.general.attack_range_name}"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "StandardSSD_LRS"
    disk_size_gb      = 60
  }

  storage_image_reference {
    publisher = "Debian"
    offer     = "debian-12"
    sku       = "12"
    version   = "latest"
  }

  os_profile {
    computer_name  = var.caldera_server.hostname
    admin_username = local.caldera_user
    admin_password = var.general.attack_range_password
  }

  os_profile_linux_config {
    disable_password_authentication = true
    ssh_keys {
      path     = "/home/${local.caldera_user}/.ssh/authorized_keys"
      key_data = file(var.azure.public_key_path)
    }
  }

  provisioner "remote-exec" {
    inline = ["echo booted"]

    connection {
      type        = "ssh"
      user        = local.caldera_user
      host        = azurerm_public_ip.caldera-publicip[0].ip_address
      private_key = file(var.azure.private_key_path)
    }
  }

  provisioner "local-exec" {
    working_dir = "../ansible"
    command     = <<-EOT
      cat <<EOF > vars/caldera_vars.json
      {
        "ansible_python_interpreter": "/usr/bin/python3",
        "general": ${jsonencode(var.general)},
        "caldera_server": ${jsonencode(var.caldera_server)},
        "caldera_user": ${jsonencode(local.caldera_user)},
        "public_ip": ${jsonencode(azurerm_public_ip.caldera-publicip[0].ip_address)}
      }
      EOF
    EOT
  }

  provisioner "local-exec" {
    working_dir = "../ansible"
    command     = <<-EOT
      ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -u ${local.caldera_user} --private-key '${var.azure.private_key_path}' -i '${azurerm_public_ip.caldera-publicip[0].ip_address},' caldera_server.yml -e "@vars/caldera_vars.json"
    EOT
  }
}
