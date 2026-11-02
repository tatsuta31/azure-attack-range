
# azure-attack-range patch: OpenCanary honeypot in the DMZ subnet (see modules/network/dmz.tf).
#
# - Ubuntu 22.04, admin user "canaryadmin" (no real credentials live here)
# - cloud-init moves the real sshd to mgmt_ssh_port on first boot, so Terraform and Ansible
#   connect there and port 22 is free for the decoy SSH
# - Ansible (opencanary_server.yml) installs OpenCanary as an unprivileged service and a UF
#   that forwards its JSON log to the BYO Splunk

locals {
  canary_enabled = lookup(var.opencanary_server, "opencanary_server", "0") == "1"
  canary_user    = "canaryadmin"
  canary_mgmt    = lookup(var.opencanary_server, "mgmt_ssh_port", "22222")
  canary_size    = lookup(var.opencanary_server, "azure_vm_size", "Standard_A2_v2")
  canary_ip      = lookup(var.opencanary_server, "private_ip", "10.0.2.10")
  canary_host    = lookup(var.opencanary_server, "hostname", "ar-canary")

  cloud_init = <<-EOT
    #cloud-config
    write_files:
      - path: /etc/ssh/sshd_config.d/10-aar-mgmt-port.conf
        permissions: "0644"
        content: |
          Port ${local.canary_mgmt}
          PasswordAuthentication no
          PermitRootLogin no
    runcmd:
      - [systemctl, restart, ssh]
  EOT
}

resource "azurerm_public_ip" "opencanary-publicip" {
  count               = local.canary_enabled ? 1 : 0
  name                = "ar-opencanary-ip-${var.general.key_name}-${var.general.attack_range_name}"
  location            = var.azure.location
  resource_group_name = var.rg_name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_interface" "opencanary-nic" {
  count               = local.canary_enabled ? 1 : 0
  name                = "ar-opencanary-nic-${var.general.key_name}-${var.general.attack_range_name}"
  location            = var.azure.location
  resource_group_name = var.rg_name

  ip_configuration {
    name                          = "ar-opencanary-nic-conf-${var.general.key_name}-${var.general.attack_range_name}"
    subnet_id                     = var.dmz_subnet_id
    private_ip_address_allocation = "Static"
    private_ip_address            = local.canary_ip
    public_ip_address_id          = azurerm_public_ip.opencanary-publicip[0].id
  }
}

resource "azurerm_virtual_machine" "opencanary" {
  count                         = local.canary_enabled ? 1 : 0
  name                          = "ar-opencanary-${var.general.key_name}-${var.general.attack_range_name}"
  location                      = var.azure.location
  resource_group_name           = var.rg_name
  network_interface_ids         = [azurerm_network_interface.opencanary-nic[0].id]
  vm_size                       = local.canary_size
  delete_os_disk_on_termination = true

  storage_os_disk {
    name              = "disk-opencanary-${var.general.key_name}-${var.general.attack_range_name}"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "StandardSSD_LRS"
  }

  storage_image_reference {
    publisher = "canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  os_profile {
    computer_name  = local.canary_host
    admin_username = local.canary_user
    admin_password = var.general.attack_range_password
    custom_data    = local.cloud_init
  }

  os_profile_linux_config {
    disable_password_authentication = true
    ssh_keys {
      path     = "/home/${local.canary_user}/.ssh/authorized_keys"
      key_data = file(var.azure.public_key_path)
    }
  }

  provisioner "remote-exec" {
    inline = ["echo booted"]

    connection {
      type        = "ssh"
      user        = local.canary_user
      host        = azurerm_public_ip.opencanary-publicip[0].ip_address
      port        = tonumber(local.canary_mgmt)
      private_key = file(var.azure.private_key_path)
      timeout     = "10m"
    }
  }

  provisioner "local-exec" {
    working_dir = "../ansible"
    command     = <<-EOT
      cat <<EOF > vars/opencanary_vars.json
      {
        "ansible_python_interpreter": "/usr/bin/python3",
        "general": ${jsonencode(var.general)},
        "splunk_server": ${jsonencode(var.splunk_server)},
        "opencanary_server": ${jsonencode(var.opencanary_server)}
      }
      EOF
    EOT
  }

  provisioner "local-exec" {
    working_dir = "../ansible"
    command     = <<-EOT
      ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -u ${local.canary_user} -e ansible_port=${local.canary_mgmt} --private-key '${var.azure.private_key_path}' -i '${azurerm_public_ip.opencanary-publicip[0].ip_address},' opencanary_server.yml -e "@vars/opencanary_vars.json"
    EOT
  }
}
