#SR-EDRAGENT
param([string]$ACTION="",
      [string]$IP="demo.seceon.com",
      [string]$TENANT_ID="SECEON",
      [string]$PORT="443")

If (-NOT ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host -ForegroundColor Red "Error: Script must be run using Administrator priviliges."    
    $UserInput = $Host.UI.ReadLine()
    exit 1    
}

#SR-EDRAGENT

function EDRInstall {
#SR-EDRAGENT

    Write-Host "Checking whether the application package is installed"

    $EDR = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -Match "osquery"}

    if([string]::IsNullorEmpty($EDR))
    {
        Write-Host "------------------"
        Write-Host "Starting EDR Installation"
        
        $webclient = New-Object System.Net.WebClient
        $url = "https://${IP}:${PORT}/downloads"

        $osqueryBinaryFile = "osquery.msi"
        $keyFile = "secret.txt"
        $certFile = "certificate.crt"
        $flagFile = "osquery.flags"
        $extensionload = "extensions.load"
        $extension_seceon = "seceon_win.ext.exe"
        $monitorOsqueryIORate = "monitorOsqueryIORate.ps1"
        $agent_upgrade = "agent_upgrade.ps1"

        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

        Write-Host "Please wait while files are being downloaded..." 
        try
        {   
            Write-Progress -Activity "Downloading files" -PercentComplete 20 
            $webclient.DownloadFile("$url/$osqueryBinaryFile", "$pwd\$osqueryBinaryFile")
        }
        catch [System.Net.WebException]
        {
            Write-Host -ForegroundColor Red "Error: Unable to connect to remote server."
            Write-Host -ForegroundColor Red "Please verify IP - ${IP} and Port - ${Port} are correct and accessible."
            Read-Host -Prompt "Press any key to exit."
            exit 1
        }


        Start-Process msiexec.exe -Wait -ArgumentList "/I `"$pwd\$osqueryBinaryFile`" /quiet /Log `"$pwd\install.log`""
        Start-Sleep 15
        Stop-Service osqueryd -Force -ErrorAction SilentlyContinue

        $service = get-wmiobject -query 'select * from win32_service where name="osqueryd"'; 
        $path = ($service.pathname.Split('-')[0]).Replace('"','') | Split-Path | Split-Path

        Move-Item -Force -Path install.log -Destination $path\install.log

        try
        {
            Write-Progress -Activity "Installing files" -PercentComplete 40
            $webclient.DownloadFile("$url/$keyFile", "$path\$keyFile") 
            Write-Progress -Activity "Installing files" -PercentComplete 50
            $webclient.DownloadFile("$url/$certFile", "$path\$certFile") 
            Write-Progress -Activity "Installing files" -PercentComplete 60
            $webclient.DownloadFile("$url/$flagFile", "$path\$flagFile") 
            Write-Progress -Activity "Installing files" -PercentComplete 70
            $webclient.DownloadFile("$url/$monitorOsqueryIORate", "$path\$monitorOsqueryIORate") 
            $webclient.DownloadFile("$url/$agent_upgrade", "$path\$agent_upgrade")
            Write-Progress -Activity "Installing files" -PercentComplete 80
            $webclient.DownloadFile("$url/$extensionload", "$path\$extensionload")
            Write-Progress -Activity "Installing files" -PercentComplete 90
            $webclient.DownloadFile("$url/$extension_seceon", "$path\$extension_seceon")
            Write-Progress -Activity "Finalising install" -PercentComplete 100
        }
        catch [System.Net.WebException]
        {
            Write-Host -ForegroundColor Red "Error: Unable to connect to remote server."
            Write-Host -ForegroundColor Red "Please verify IP - ${IP} and Port - ${Port} are correct and accessible."
            Read-Host -Prompt "Press any key to exit."
            exit 1
        }

        $UUID = (get-wmiobject Win32_ComputerSystemProduct).UUID

        (Get-Content "$path\$flagFile") -replace "--specified_identifier=.*", "--specified_identifier=$TENANT_ID-$UUID" | Set-Content "$path\$flagFile"
        (Get-Content "$path\$flagFile") -replace "--tls_hostname=.*", "--tls_hostname=${IP}:${Port}" | Set-Content "$path\$flagFile"

        #Scheduling Task for monitorOsqueryIORate to run every one hour 
        try
        {  
        New-Item -Path "C:\" -Name "OsqueryIORateLog" -ItemType "directory" | Out-Null 
        schtasks /Create /TN "MonitorOsquerydIORate" /TR "powershell -noprofile -executionpolicy bypass -file 'C:\Program Files\osquery\monitorOsqueryIORate.ps1'" /SC HOURLY /MO 1 /ST 00:00 /RU system /RL HIGHEST /F
        #$Trigger= (New-ScheduledTaskTrigger -Once -At 12am -RepetitionInterval (new-timespan -hour 1) ) # Specify the trigger settings
        #$Action= (New-ScheduledTaskAction -Execute 'powershell' -Argument '-noprofile -executionpolicy bypass -file "C:\Program Files\osquery\monitorOsqueryIORate.ps1"')  # Specify what program to run and with its parameters
        #Register-ScheduledTask -TaskName "MonitorOsquerydIORate" -Trigger $Trigger -Action $Action -RunLevel Highest -user SYSTEM -Force | Out-Null 
        $TaskStatus = (Get-ScheduledTask -TaskName "MonitorOsquerydIORate").State 
        Write-Host "Task scheduled successfully, its current state is $TaskStatus"
        }
        catch
        {
            $_.Exception.GetType().FullName
        }
        
        #Scheduling Task for agent_upgrade to run every one hour 
        try
        {  
        New-Item -Path "C:\" -Name "EDRAgentUpgradeLog" -ItemType "directory" | Out-Null 
        schtasks /Create /TN "EDRAgentUpgrade" /TR "powershell -noprofile -executionpolicy bypass -file 'C:\Program Files\osquery\agent_upgrade.ps1'" /SC HOURLY /MO 1 /ST 00:00 /RU system /RL HIGHEST /F
        #$Trigger= (New-ScheduledTaskTrigger -Once -At 12am -RepetitionInterval (new-timespan -hour 1) ) # Specify the trigger settings
        #$Action= (New-ScheduledTaskAction -Execute 'powershell' -Argument '-noprofile -executionpolicy bypass -file "C:\Program Files\osquery\monitorOsqueryIORate.ps1"')  # Specify what program to run and with its parameters
        #Register-ScheduledTask -TaskName "MonitorOsquerydIORate" -Trigger $Trigger -Action $Action -RunLevel Highest -user SYSTEM -Force | Out-Null 
        $TaskStatus = (Get-ScheduledTask -TaskName "EDRAgentUpgrade").State 
        Write-Host "Task scheduled successfully, its current state is $TaskStatus"
        }
        catch
        {
            $_.Exception.GetType().FullName
        }

        # Service Recovery and Powershell Script Block Logging
        try 
        {
            sc.exe failure osqueryd actions= restart/900000/restart/900000/restart/900000 reset= 86400 | Out-Null
            sc.exe failureflag osqueryd 1 | Out-Null
            sc.exe config osqueryd start= delayed-auto | Out-Null
        }
        catch
        {
            $_.Exception.GetType().FullName
        }

        Auditpol /set /category:"{6997984C-797A-11D9-BED3-505054503030}" /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable
        Auditpol /set /category:"{6997984A-797A-11D9-BED3-505054503030}" /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}","{0CCE9224-69AE-11D9-BED3-505054503030}" /success:enable
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Force | Out-Null
        
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force | Out-Null

        Start-Service osqueryd

        Write-Host "EDR client side installation complete."

    }
    Else
    {
        Write-Host "Osquery is installed, please uninstall by running the script with the parameter:"
        Write-Host ".\getSeceonEDRWindowAgent.ps1 -ACTION uninstall "
        return
    }

    
}


function EDRUninstall {
#SR-EDRAGENT
    Write-Host "Script will attempt to uninstall SeceonEDR from this system."
    Write-Host "Checking whether the application package is installed"

    $EDR = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -Match "osquery"}

    if([string]::IsNullorEmpty($EDR))
    {
        Write-Host -ForegroundColor Red "SeceonEDR installation not found. Skipping uninstall."
        return
    }
    Else
    {
        Write-Host "SeceonEDR package found. Please wait while it is being uninstalled..."
        
        $service = get-wmiobject -query 'select * from win32_service where name="osqueryd"';
        $path = ($service.pathname.Split('-')[0]).Replace('"','') | Split-Path | Split-Path
        
        Stop-Service osqueryd -Force -ErrorAction SilentlyContinue
        $EDR.Uninstall() | Out-Null
        
        #Removing scheduled Task "MonitorOsquerydIORate" 
        schtasks /DELETE /TN "MonitorOsquerydIORate" /F
        #Unregister-ScheduledTask -TaskName "MonitorOsquerydIORate" -Confirm:$false 
        Remove-Item 'C:\OsqueryIORateLog' -Recurse | Out-Null
        
        #Removing scheduled Task "EDRAgentUpgrade" 
        schtasks /DELETE /TN "EDRAgentUpgrade" /F
        #Unregister-ScheduledTask -TaskName "EDRAgentUpgrade" -Confirm:$false 
        Remove-Item 'C:\EDRAgentUpgradeLog' -Recurse | Out-Null
        
        Auditpol /set /category:"{6997984C-797A-11D9-BED3-505054503030}" /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:disable
        Auditpol /set /category:"{6997984A-797A-11D9-BED3-505054503030}" /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}","{0CCE9224-69AE-11D9-BED3-505054503030}" /success:disable

        Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Force
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Force
        Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
        Remove-Item -path "${path}" -recurse
        Write-Host "SeceonEDR package uninstallation complete."
    }
}
   
#SR-EDRAGENT
switch($action.ToLower()) {
    "install" {        
        EDRInstall
        break
    }
    "uninstall" {
        EDRUninstall
        break
    }
    "remove" {
        EDRUninstall
        break
    }
    "help" {
        $scriptName = [io.path]::GetFileName($PSCommandPath)
        Write-Host "Usage: ./$scriptName -action [install|uninstall|help] -IP [valid IP address] -Port [valid port number]"
        break
    }
    default {
        $scriptName = [io.path]::GetFileName($PSCommandPath)
        Write-Host "Usage: .\$scriptName -ACTION [install|uninstall|help]  -TENANT_ID [...] -IP [...] -Port [...]"
        break
    }
}
#SR-EDRAGENT

