
module "networkModule" {
  source = "./modules/network"
  general = var.general
  azure = var.azure
  # azure-attack-range patch: DMZ subnet/NSG for OpenCanary
  opencanary_server = var.opencanary_server
  splunk_server = var.splunk_server
}

module "splunk-server" {
  source = "./modules/splunk-server"
  rg_name = module.networkModule.rg_name
  subnet_id = module.networkModule.subnet_id
  azure = var.azure
  splunk_server = var.splunk_server
  phantom_server = var.phantom_server
  general = var.general
  simulation = var.simulation
  windows_servers = var.windows_servers
  linux_servers = var.linux_servers
  zeek_server = var.zeek_server
  kali_server = var.kali_server
  snort_server = var.snort_server
}

module "phantom-server" {
  source = "./modules/phantom-server"
  rg_name = module.networkModule.rg_name
  subnet_id = module.networkModule.subnet_id
  azure = var.azure
  phantom_server = var.phantom_server
  general = var.general
  splunk_server = var.splunk_server
}

module "windows-server" {
  source = "./modules/windows"
  rg_name = module.networkModule.rg_name
	subnet_id = module.networkModule.subnet_id
  general = var.general
  azure = var.azure
  windows_servers = var.windows_servers
  simulation = var.simulation
  splunk_server = var.splunk_server
  caldera_server = var.caldera_server
  # azure-attack-range patch: the caldera_agent role downloads the agent from the server
  depends_on = [module.caldera-server]
}

module "linux-server" {
  source = "./modules/linux-server"
  rg_name = module.networkModule.rg_name
  subnet_id = module.networkModule.subnet_id
  azure = var.azure
  general = var.general
  linux_servers = var.linux_servers
  simulation = var.simulation
  splunk_server = var.splunk_server
  caldera_server = var.caldera_server
  depends_on = [module.caldera-server]
}

# azure-attack-range patch: Caldera server (v4.0.2 had no Azure module)
module "caldera-server" {
  source = "./modules/caldera-server"
  rg_name = module.networkModule.rg_name
  subnet_id = module.networkModule.subnet_id
  azure = var.azure
  general = var.general
  caldera_server = var.caldera_server
}

# azure-attack-range patch: OpenCanary honeypot in the DMZ subnet
module "opencanary-server" {
  source = "./modules/opencanary-server"
  rg_name = module.networkModule.rg_name
  dmz_subnet_id = module.networkModule.dmz_subnet_id
  azure = var.azure
  general = var.general
  splunk_server = var.splunk_server
  opencanary_server = var.opencanary_server
}

# kali linux image was removed from Azure marketplace
# module "kali-server" {
#   source = "./modules/kali-server"
#   rg_name = module.networkModule.rg_name
#   subnet_id = module.networkModule.subnet_id
#   azure = var.azure
#   general = var.general
#   kali_server = var.kali_server
# }