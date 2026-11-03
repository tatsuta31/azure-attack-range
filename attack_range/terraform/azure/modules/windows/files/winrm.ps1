Enable-PSRemoting -Force -SkipNetworkProfileCheck
winrm quickconfig -q
winrm quickconfig -transport:http

# Configure WinRM with optimized settings
powershell.exe -c "winrm set winrm/config '@{MaxTimeoutms=\`"3600000\`"}'"
powershell.exe -c "winrm set winrm/config/winrs '@{MaxMemoryPerShellMB=\`"2048\`"; MaxShellsPerUser=\`"50\`"; MaxProcessesPerShell=\`"25\`"; IdleTimeout=\`"3600000\`"}'"
powershell.exe -c "winrm set winrm/config/service '@{AllowUnencrypted=\`"true\`"; MaxConcurrentOperations=\`"4294967295\`"; MaxConcurrentOperationsPerUser=\`"4294967295\`"; MaxConnections=\`"4294967295\`"}'"
powershell.exe -c "winrm set winrm/config/service/auth '@{Basic=\`"true\`"}'"
powershell.exe -c "winrm set winrm/config/client/auth '@{Basic=\`"true\`"}'"
powershell.exe -c "winrm set winrm/config/listener?Address=*+Transport=HTTP '@{Port=\`"5985\`"}'"
powershell.exe -c "winrm set winrm/config/client '@{TrustedHosts=\`"*\`"}'"

# azure-attack-range patch: set the settings Terraform/Ansible need one by one.
# On Windows 11 the combined "winrm set winrm/config/service" above fails as a whole
# (a limit value is rejected on client SKUs), leaving AllowUnencrypted=false and
# making the remote-exec provisioner fail with "401 - invalid content type" (2026-11-03).
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true -Force

# Configure firewall rules
netsh advfirewall firewall set rule group="Windows Remote Administration" new enable=yes
netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" new enable=yes action=allow remoteip=any
netsh advfirewall firewall add rule name="Port 5985" dir=in action=allow protocol=TCP localport=5985

# Configure WinRM service for auto-start and recovery
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /v StartWinRM /t REG_SZ /f /d "cmd.exe /c 'sc config winrm start= auto & sc start winrm'"
sc.exe config winrm start= auto
sc.exe failure winrm reset= 0 actions= restart/5000/restart/5000/restart/5000

# Restart WinRM service
Restart-Service winrm

# Set LocalAccountTokenFilterPolicy to 1 for better authentication
$token_path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$token_prop_name = "LocalAccountTokenFilterPolicy"
$token_key = Get-Item -Path $token_path
$token_value = $token_key.GetValue($token_prop_name, $null)
if ($token_value -ne 1) {
    if ($null -ne $token_value) {
        Remove-ItemProperty -Path $token_path -Name $token_prop_name
    }
    New-ItemProperty -Path $token_path -Name $token_prop_name -Value 1 -PropertyType DWORD > $null
}