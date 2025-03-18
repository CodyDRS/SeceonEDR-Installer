#SR-EDRAGENT
param([string]$ACTION="",
      [string]$TOKEN="")

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
    try
	{
        $decodes=[Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($TOKEN))
        $val = $decodes -split ':'
		$IP=$val[3]
		$PORT=$val[4]
        $webclient = New-Object System.Net.WebClient
        $url = "https://${IP}:${PORT}/downloads"
		
	    $seceon_edr = "seceon-edr.exe"

        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        
        Write-Host "Please wait while files are being downloaded..." 
        try
        {   
            Write-Progress -Activity "Downloading files" -PercentComplete 10 
            $webclient.DownloadFile("$url/$seceon_edr", "$pwd\$seceon_edr")
        }
        catch [System.Net.WebException]
        {
            Write-Host -ForegroundColor Red "Error: Unable to connect to remote server."
            Write-Host -ForegroundColor Red "Please verify IP - ${IP} and Port - ${Port} are correct and accessible."
            Read-Host -Prompt "Press any key to exit."
            exit 1
        }
    }
	catch {
            Write-Host -ForegroundColor Red "Error: Unable to connect to remote server."
            Write-Host -ForegroundColor Red "Please verify IP - ${IP} and Port - ${Port} are correct and accessible."
            Read-Host -Prompt "Press any key to exit."
            exit 1
	}

        try
        {
	    $cmd="$pwd\$seceon_edr /verysilent /secret=$TOKEN"
            cmd.exe /c "$cmd"		

        }
        catch [System.Net.WebException]
        {
            Write-Host -ForegroundColor Red "Error: Unable to connect to remote server."
            Write-Host -ForegroundColor Red "Please verify IP - ${IP} and Port - ${Port} are correct and accessible."
            Read-Host -Prompt "Press any key to exit."
            exit 1
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
		Start-Process -FilePath "C:\Program Files\SeceonEDR\unins000.exe" -ArgumentList /silent
		Start-Process -FilePath "C:\Program Files\SeceonEPP\unins000.exe" -ArgumentList /silent
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

# SIG # Begin signature block
# MIIlXwYJKoZIhvcNAQcCoIIlUDCCJUwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA2UuEMKSw+x9iL
# 2g4LuOxOmXBACs6MVIbrvqKblrRy1aCCDyYwggd+MIIFZqADAgECAhBAAY4uZ/LB
# 4HzbqohLNRTyMA0GCSqGSIb3DQEBCwUAMEgxCzAJBgNVBAYTAlVTMRIwEAYDVQQK
# EwlJZGVuVHJ1c3QxJTAjBgNVBAMTHFRydXN0SUQgRVYgQ29kZSBTaWduaW5nIENB
# IDQwHhcNMjQwMzExMTY0NTQ4WhcNMjUwMzExMTY0NDQ4WjCB4DELMAkGA1UEBhMC
# VVMxFjAUBgNVBAgTDU1hc3NhY2h1c2V0dHMxETAPBgNVBAcTCFdlc3Rmb3JkMRAw
# DgYDVQQFEwc1Njc3OTI1MRMwEQYLKwYBBAGCNzwCAQMTAlVTMR4wHAYLKwYBBAGC
# NzwCAQITDU1hc3NhY2h1c2V0dHMxHTAbBgNVBA8TFFByaXZhdGUgT3JnYW5pemF0
# aW9uMRQwEgYDVQQKEwtTRUNFT04gSU5DLjEUMBIGA1UECxMLU2VjZW9uIEluYy4x
# FDASBgNVBAMTC1NFQ0VPTiBJTkMuMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAxvhZ7niFJAZ0lO1ywO8YcpaJdQS0c6DOsQwsCh5YohdbNdh9VFarZ5Jw
# pT681SO/po2p4tpUAm1ITZOVqUyPBTnHxNMH/FBmwJoDSjaezHkzp3yKhF3z+svF
# Wvh1lZrvxpo8gvxl87fkIuTYv5MrQkU8MiN9ly8y85PZFYBKcLZdeTB9Z4SQr4OU
# l/r5XfDxVWy7vu32inVRQSdrJ2UNFgN8erpZ/Lzl4QcTqgYaWxpkwzdFOIcbfdRw
# Irf87Tz88GHmuRd/nBXkciiywroQml2ULfAEg87cIDHd3yA10OunXfQeSP8uMvfh
# I3dg6H29vveAVCeTe5s2jbidCl97SIPlzZRzTHd+LWjGck8h3ZxGR6Ey57dyQHDy
# s3eJurOktrJukfJnIUqPHTOnG9sYpvR4huQTFOu/NmTb44v0RlbdSKgLIuYEaGjK
# VDRSkpPA1aTp0itl1rrwB1x+kkExTrv4p/C9v6NL22ojrLfMwJtPk7k8sknEGO0E
# IJIFyu49S61/vrzYPdbt4FaN7lXoL2cZJ3YJ21lpUVOE8h8k9b3Vv82Y1OlajTCe
# XilfSdwL4b9LRKiIoK4Pb4oyTUSojc6mAvE1oGkooj4ihPQ+U6zUCrIuhn7tjxYF
# hqn5l1EgmgDnWChhpS+x0ukh9E/6yrqXsM19QpfBAP1K0PWkuI0CAwEAAaOCAckw
# ggHFMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMIGOBggrBgEFBQcBAQSB
# gTB/MDAGCCsGAQUFBzABhiRodHRwOi8vY29tbWVyY2lhbC5vY3NwLmlkZW50cnVz
# dC5jb20wSwYIKwYBBQUHMAKGP2h0dHA6Ly92YWxpZGF0aW9uLmlkZW50cnVzdC5j
# b20vY2VydHMvdHJ1c3RpZGV2Y29kZXNpZ25pbmc0LnA3YzAfBgNVHSMEGDAWgBT+
# BaSGWZo/NAFajQheG9t1ebnhxjBvBgNVHSAEaDBmMAcGBWeBDAEDMFsGC2CGSAGG
# +S8ABg4BMEwwSgYIKwYBBQUHAgEWPmh0dHBzOi8vc2VjdXJlLmlkZW50cnVzdC5j
# b20vY2VydGlmaWNhdGVzL3BvbGljeS90cy9pbmRleC5odG1sME4GA1UdHwRHMEUw
# Q6BBoD+GPWh0dHA6Ly92YWxpZGF0aW9uLmlkZW50cnVzdC5jb20vY3JsL3RydXN0
# aWRldmNvZGVzaWduaW5nNC5jcmwwHQYDVR0OBBYEFNSXOQFXo/6GkaBZD2GLwQzw
# eDBYMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEBCwUAA4ICAQC5DIm9
# rOwfb5aUukQju0soKFDAlLLv7x/M1Cq/oN9RyMMUZSs6mOJC1SJi9qxOVpINsGLg
# s5b98QzIBaLkNNulvrt30qKgbMNsXex5cvxFYYNOyb+xcMJG9m1QVtu/TuHtRNv9
# LOxZuNs6t8KO+xEPBWV3ubp5Q1m6AsKr1Maoi+9VBRrGkJH4mGfvCS3ed9cLchOe
# RAtLZw8bqhorpPezUwc6TfSyY1bbPBXnQXU5KKCjgLnqhar/v0CedqPhnhr3Xmlt
# CbytRqi3cFcRutTW6EAtINlo68WEKXW3KwTHErrGAavFrU6GzEHLsTLaTThdiaQ2
# ChKi7HYfWWIpst1Mqg4UwX1oWhKuzwGsD/nQWu7WPlb5H8HY8U+iam1wUbhbwqsM
# 8tkR/yw4LYhclLrhDFoS+48RdUvwI6wkg+jnFG7FAYGGFQT3wmWGIs+mt+gbt/x4
# HBp399khvZyONADALd3dWyG2mEzuZnkFRwYzoMgGKJs2+alVNx9wj1fxl++aF4Ca
# uO94u+B656WViEK3Ingqqu3b2BUVWdO0G8ZX4POhUyvW6UUFGKLIKjAgWDhoQJrg
# xqKl3XGBFoetxJHlheZ0RjWz0weRGiHA8Sl+qcDk0CGvpHtDphgay/2oo2rTGfdl
# 8vY2kgR2GQYrzpb85OC78em9XAEaMo9VrVzpoTCCB6AwggWIoAMCAQICEEABf54B
# BNDw2piNQ9iXQwMwDQYJKoZIhvcNAQELBQAwSjELMAkGA1UEBhMCVVMxEjAQBgNV
# BAoTCUlkZW5UcnVzdDEnMCUGA1UEAxMeSWRlblRydXN0IENvbW1lcmNpYWwgUm9v
# dCBDQSAxMB4XDTIyMDMxODE3MDkwMVoXDTMwMDMxODE3MDkwMVowSDELMAkGA1UE
# BhMCVVMxEjAQBgNVBAoTCUlkZW5UcnVzdDElMCMGA1UEAxMcVHJ1c3RJRCBFViBD
# b2RlIFNpZ25pbmcgQ0EgNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AL5TZM7EmpxxXXCN1gU0ro9qMiRw0J8BGloZp7C4/T8lexk9XTwBY2KHxJO1q5H2
# xUV+P+DyAyglyfJ3mDtmBOxHfjbZd9cRjORXJUA+q/jIjGlzSLENRKIRSeplKLsd
# IGNptjojnraAjghazM5aE9JtN6guiuvgxidLNuWIivzYcDPFD/r3ARzOOahgk0RA
# pxjRudBEc2AZv4PEJcDJ94vFBSkPhyeMiICX41DHXSYoX383d15IURzdy6LPGSBo
# Tf4Ps8vfAq/qaYgJaIB6zL6ZE/eBfBFzKs0XVEh95QMZAckJpc3yp3Vr9x6LaNEe
# ICyQSfbQdxPwmHrkVr3qBV2C69QOyTI4OXwAolA2PG3dlwcJHpyraY0OgCcDSqGp
# T+l7dbBat3nr+1Sa+zBrsvZyv6WInVZ3ekba+THJ9M4Fk7BfS0XEhzFdg9MvFbDB
# +eOxM2GjMVHTYLy3XhcICbkYi6GpqS+DdNcLlow8y/M/PBjA45NM7iuPwqN/6Qq/
# xMpewN0K9bYNLQWB8lhT4Wb6qduR+QcgGmKMR63rHso0taB4UO17IrzNP0pD8IVa
# Vgml0s/jUh/a9900CKNGJsR/XcsQD7W87D836ulo3aPx8CU20v9Gtw+1eKOO3SpX
# eJWGmvmP9CtVzmwrdBw3SR+Tux4rp7cGaPD0qm1Xva5pAgMBAAGjggKCMIICfjAP
# BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjCBiQYIKwYBBQUHAQEEfTB7
# MDAGCCsGAQUFBzABhiRodHRwOi8vY29tbWVyY2lhbC5vY3NwLmlkZW50cnVzdC5j
# b20wRwYIKwYBBQUHMAKGO2h0dHA6Ly92YWxpZGF0aW9uLmlkZW50cnVzdC5jb20v
# cm9vdHMvY29tbWVyY2lhbHJvb3RjYTEucDdjMB8GA1UdIwQYMBaAFO1EGcDT8AaL
# 7qR7vkLnJlTIjjZ2MIIBLAYDVR0gBIIBIzCCAR8wBwYFZ4EMAQMwggESBgtghkgB
# hvkvAAYOATCCAQEwSgYIKwYBBQUHAgEWPmh0dHBzOi8vc2VjdXJlLmlkZW50cnVz
# dC5jb20vY2VydGlmaWNhdGVzL3BvbGljeS90cy9pbmRleC5odG1sMIGyBggrBgEF
# BQcCAjCBpQyBolRoaXMgY2VydGlmaWNhdGUgaGFzIGJlZW4gaXNzdWVkIGluIGFj
# Y29yZGFuY2Ugd2l0aCBJZGVuVHJ1c3QncyBUcnVzdElEIENlcnRpZmljYXRlIFBv
# bGljeSBmb3VuZCBhdCBodHRwczovL3NlY3VyZS5pZGVudHJ1c3QuY29tL2NlcnRp
# ZmljYXRlcy9wb2xpY3kvdHMvaW5kZXguaHRtbDBKBgNVHR8EQzBBMD+gPaA7hjlo
# dHRwOi8vdmFsaWRhdGlvbi5pZGVudHJ1c3QuY29tL2NybC9jb21tZXJjaWFscm9v
# dGNhMS5jcmwwHQYDVR0OBBYEFP4FpIZZmj80AVqNCF4b23V5ueHGMBMGA1UdJQQM
# MAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEBCwUAA4ICAQB5T7JenukbJcICN8z6nbRK
# DqumlQS83JQo7med/hRKfQWA0RDa26jeD4DvtAqWk0Pmg6DAGZC2C6TDQnxC5Xf9
# cNkRMDXCHrSDv3OYeVUwnQO5a+W2GLBbx+mZ0IzQoU247qIB8Y8BDhMUEi55fO2+
# puu5VhhsSBO6mgu2Vnqzw1wcu3Rnj1+/WQnEJjr8lZZ8YyUa/2JorAYPL86Eq9AN
# NDVJq8oHBcFmYkoYi4nWMVc+vRHz3ulL8fcZayhuLAPgAwyF6TLU93mBW/sg0Jhh
# f1DtICZuJ+hSJhe770SY1UGDWBeAZUKfmJELzbyM7D4R5JjGz8Akgs7l1eFWxOlg
# M5uZ3atRjRWg2r70FE1MS4NVuNEVDHulgmE7LAusUI4aM4BxWjH5qhPPRRN0obAv
# JRg6dw9uRHnDsGYhfnhc1t4AJGqxBLrdWg/c/tzOn1cbprHBDRl3RvI05ueaAT1F
# xtQVYaoKOweL0HdKABRn+GU9kTx/WT8z3KFsKRvumN5SF3gzSW6lGmMiBPWIo3VF
# qqKTs7yO6Zl06qSsQW7G/RnjugeQ1aUdhm0v2Q64yxHJPZg6VpaDQI5dWoajfNkj
# 9g+byefk56XVpjm6VKCmc5aK4m5Ew7xnMjGBZ2+GYd24KrDtIOCeDtUaIWY3ZgWs
# 7X3LEBx6eqTI4FihYjQcijGCFY8wghWLAgEBMFwwSDELMAkGA1UEBhMCVVMxEjAQ
# BgNVBAoTCUlkZW5UcnVzdDElMCMGA1UEAxMcVHJ1c3RJRCBFViBDb2RlIFNpZ25p
# bmcgQ0EgNAIQQAGOLmfyweB826qISzUU8jANBglghkgBZQMEAgEFAKB8MBAGCisG
# AQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQB
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCMDYMapyEG4O/K
# BCJf48o29VLTGqSeJmq7GeDX+DCJDjANBgkqhkiG9w0BAQEFAASCAgCGrDSV9z3q
# xz9BR4csRQXQpMVRahR9U54qyCx3s4wsNVAl9Lj7GwLMmaY7l9GnZ2uAUDGKxFEj
# AfUr8/x3I7OI95zKHFdrPvnEG1MsGLj3K1I7kyqLBbll62L4F+ZuhwvvCEJKJ1Cs
# MdeNTH32iTR3E534u8aDbnfZtE3hPY0AXuu8tyTKwr/TmXjC2itxjdLttMUIPu0Q
# Nf0rweXgViidHw+KjucsjwWqMH5JvjqvH3DO2p3f1OxkZo226f5waJHeaAH+SqNo
# nyM7rwB+L8k7tY+DSP6bNfgZxzgasC/lNY6aASn3UkDxfeLP6JbTbkvmuzNuM6Py
# q1KYGSGCy6mf9zsTPTV3/s4ecCQ2s+RWxq5Q6qUCrBhGkk79C1+bseSH982QlONH
# /nnoVinnTrNxIoU7QM16QiE9BO9eymr4C6R3u4gMAjsa4rhZE0cW5zOyfBlwjus7
# m6tNksRKjMezZ6KebMKlK6Uu97AJNyfAvv8hTEReFX4bani9/OT1yH1e7gH9LmF/
# ZbOporky52QK0Vp/vDFEoRd/dRRrneVc75uOVsJPsybxjmki2J/5DnqQEvJrNYw7
# VFYQKQa+KYxvMy3SIwjE9i/2jr7K/6Dp5UCFeNlR3VOH9yWcwfUGnTZ7HcpEdLs9
# 3zq8jbQy4UA+WfnJZk4qSytuKxsd/ehl/qGCEoYwghKCBgorBgEEAYI3AwMBMYIS
# cjCCEm4GCSqGSIb3DQEHAqCCEl8wghJbAgEDMQ8wDQYJYIZIAWUDBAIBBQAweQYL
# KoZIhvcNAQkQAQSgagRoMGYCAQEGC2CGSAGG+S8ABg0DMDEwDQYJYIZIAWUDBAIB
# BQAEICfzmtjnYQ4mXfPw99A960rj0Wy/VTI3mxMezjh3OR45AhBAAZIpqVTGtIsO
# tOP8YuqPGA8yMDI0MDkyNTE0NTAxNlqggg6lMIIG5TCCBM2gAwIBAgIQQAGJk4QN
# WD269WUVUjYNEjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzESMBAGA1UE
# ChMJSWRlblRydXN0MSIwIAYDVQQDExlUcnVzdElEIFRpbWVzdGFtcGluZyBDQSAz
# MB4XDTIzMDcyNjE4NDQxMloXDTI0MTAyNDE4NDQxMVowSTELMAkGA1UEBhMCVVMx
# EjAQBgNVBAoTCUlkZW5UcnVzdDEmMCQGA1UEAxMdVHJ1c3RJRCBUaW1lc3RhbXAg
# QXV0aG9yaXR5IDMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC6e3mK
# Cfr53vaANY88NV6AU0zlqr4H9sf4Fe7Dl4QLAjnvFstkbpdkdz0/qRs8g70f/A1q
# IpFZAGAZtP25yC+mPyKTiH+H8FYHRxzSaiL2L21dfjxEsC80OQObKBS18PRP6LXA
# gsDGkIUzopgAXqOz95aWi61V/RQy6sWByf2GCmAFNiUSRtM+UgdmGMES+TIUQRU2
# hjPZvQnVNhCv+dGB3mJqE5IpHXA5QTSif6pTNQpDVt1Lp9vpgTwbTZKmxnMKF+NZ
# Jm/laOk0YqvM6O4aLBZcd3e/9IH2JsqzRiI3R/9haxzylCm7iGEfFmT+gvpMqUjb
# BC2T3xRqwcI56+45gSMIIgF3edkpU1wab+vrqUUUYIHi8jT/hkJYXEp7U5tQckUh
# iIRoljRIozTP4GGsNSWMSHyoDEXrkwHVffWroEgWN2/dbklSIWae4U5dmRwESvv9
# CLLDtWGfIr2R9xfLOdsAMH2lQOTadt5vmamqAvtSKzwrmF+mRnsJbb06uIXLNtSD
# CDHH/OF9ZXyql7CvteripHtidWAkJX6fgQjjaQ2LX3c31MkgBSSn7Okin5W/KYCY
# iD6x81T6bkhDtv1yYjKzHHyJ6efW484bxGsk7vj001ezw9xbxBJ0Tp2qYqd26x5h
# UU5cAVaPJoZe3RF16GCN1QLA0YQ0CXQeMYfbGwIDAQABo4IByzCCAccwDAYDVR0T
# AQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgw
# gYUGCCsGAQUFBwEBBHkwdzAwBggrBgEFBQcwAYYkaHR0cDovL2NvbW1lcmNpYWwu
# b2NzcC5pZGVudHJ1c3QuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vdmFsaWRhdGlv
# bi5pZGVudHJ1c3QuY29tL2NlcnRzL3RpbWVzdGFtcGluZzMucDdjMB8GA1UdIwQY
# MBaAFMoy8DZ8xyrakbV8h4oRvbgibL8JMH8GA1UdIAR4MHYwCAYGZ4EMAQQCMA0G
# C2CGSAGG+S8ABg0BMFsGC2CGSAGG+S8ABg0DMEwwSgYIKwYBBQUHAgEWPmh0dHBz
# Oi8vc2VjdXJlLmlkZW50cnVzdC5jb20vY2VydGlmaWNhdGVzL3BvbGljeS90cy9p
# bmRleC5odG1sMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly92YWxpZGF0aW9uLmlk
# ZW50cnVzdC5jb20vY3JsL3RpbWVzdGFtcGluZzMuY3JsMB0GA1UdDgQWBBSvFSEM
# 39oKb3VHnBLQHeh7uDppMzANBgkqhkiG9w0BAQsFAAOCAgEALdqNl3OU7WQAtU79
# WLccd6qjvqjXZ/Lp/1TcSw0+mMbq7NanhwwCZxxwOvSIcr+9izQ2XjuhAObABFiQ
# rqTlncXb3xjd5YfZ3GM6MDqsM4NPuTpOgn0VMY2fGgMNvKH9e9zsWFhpA2U//ohg
# 6l3bs/lArCts+DQtbyBbKRH1rlRRcDJF/4VJn8ibJtt8kF9TcZ7KmR/X+ssJiF+f
# Pu4ywZvppgxq2iLWx8M8sOifvgFoakt8/J+xNterenP11JXyZNyH5h1nIFxd3ysZ
# QX6mMKtpIybK6JLsPMy2r7Xe02qJEdAvOn3Ld01MwGaUgNd21BYz7iu3iHMbHxxp
# k/9rWga/vdxXV/SDxKoge83aLgXCyIg5Cv5sMR/FAjTWbURbX1l8l7tD56ATesAQ
# R9V+31pikcDojxlnX74Ndw8Tn8L+nImacmA7WQrQREkKtCWQv1zsoIVkovLr9bBj
# mUMLE4IMIepJq+fbyUbevCJ1umzpJ7eA/w4/WXM7Q0djwy5QDRUUayTx4+wZUrqA
# LsafQf7KxboF3YQJdo8W4+of6Ds32amx/fUydoPhQX475fB1FeV73ODUhcGsLDXV
# W/iKnOKcVMVKxrEeGIPBDKoPrxZbzCmRsX3bTZp9qzNgZ8PXaq+xhUBFbjOQpSkp
# e6YCopYX//PVk9H9bOfk4ANm+Xowgge4MIIFoKADAgECAhBAAX+UkBW7qRK4V5Y9
# ROzuMA0GCSqGSIb3DQEBCwUAMEoxCzAJBgNVBAYTAlVTMRIwEAYDVQQKEwlJZGVu
# VHJ1c3QxJzAlBgNVBAMTHklkZW5UcnVzdCBDb21tZXJjaWFsIFJvb3QgQ0EgMTAe
# Fw0yMjAzMTYyMTA5MDVaFw0zMzA2MTIyMTA5MDVaMEUxCzAJBgNVBAYTAlVTMRIw
# EAYDVQQKEwlJZGVuVHJ1c3QxIjAgBgNVBAMTGVRydXN0SUQgVGltZXN0YW1waW5n
# IENBIDMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCoYvRFgUbuYvRG
# BJcvKcs1aERWuGwqGtUvitIb40Cni/xNsA/ZheypYHzJmCP0NDnkAQKeZDZSj8Gp
# BKwj8A6v1y2pnKQi2Zxr+caMp7OXWRlLZig1zhmOP7tA72I26dyUDTp8GEj6JAcB
# qbuKxAsrcLBdEMvMqQyztOKwygZA5J3Qzw/phj9A4Zi//60LGZ+9TPYaNbNBB6aC
# K4uO8aE/Cj6Gtw3NrKz2PQbtC0AuQnQp+8lL6C68K9K4R8PO3cFo8ikParoZgr4x
# SI2Kze7DCeBq7IvivTjzB29RKx/3YrKvpPWkB+OM/JUM1rN//D8GPMDp7A168VUs
# 18TQOFCRcyaw1UYHNjk+GGWnl9tPCysPX0rQU+BsY7+X9mnZ2F56IJt7T1vFuF15
# qFIG1NU9xrhW7cuPP49FmMWh2rv6XOKqqmqoI/+KQSeYr9CTGMIbsCRffzh3GDvJ
# vmOO1c6c/li/hJe5XhI01VVQEl9stfJgB/dDQNqXzlnE1B3RA09Aixha/221MxVz
# qxUSt19ME/DfnlK3psfP3UtSgMPRL8aNSJ/wtiFWVkZeXCNiZVk5vZnv4MBqbOPB
# WtKyvEYInroKjLWspqkm4dWx8YBbjinaKggRlPezqdAmQK3u17hpvWJbNrJ1kYBj
# IFqjQruR8re9KngBewTm3nLp2kdijQIDAQABo4ICnTCCApkwEgYDVR0TAQH/BAgw
# BgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwgYkGCCsGAQUFBwEBBH0wezAwBggrBgEF
# BQcwAYYkaHR0cDovL2NvbW1lcmNpYWwub2NzcC5pZGVudHJ1c3QuY29tMEcGCCsG
# AQUFBzAChjtodHRwOi8vdmFsaWRhdGlvbi5pZGVudHJ1c3QuY29tL3Jvb3RzL2Nv
# bW1lcmNpYWxyb290Y2ExLnA3YzAfBgNVHSMEGDAWgBTtRBnA0/AGi+6ke75C5yZU
# yI42djCCAUQGA1UdIASCATswggE3MAgGBmeBDAEEAjANBgtghkgBhvkvAAYNAzCC
# ARoGC2CGSAGG+S8ABg0BMIIBCTBKBggrBgEFBQcCARY+aHR0cHM6Ly9zZWN1cmUu
# aWRlbnRydXN0LmNvbS9jZXJ0aWZpY2F0ZXMvcG9saWN5L3RzL2luZGV4Lmh0bWww
# gboGCCsGAQUFBwICMIGtDIGqVGhpcyBUcnVzdElEIENlcnRpZmljYXRlIGhhcyBi
# ZWVuIGlzc3VlZCBpbiBhY2NvcmRhbmNlIHdpdGggSWRlblRydXN0J3MgVHJ1c3RJ
# RCBDZXJ0aWZpY2F0ZSBQb2xpY3kgZm91bmQgYXQgaHR0cHM6Ly9zZWN1cmUuaWRl
# bnRydXN0LmNvbS9jZXJ0aWZpY2F0ZXMvcG9saWN5L3RzL2luZGV4Lmh0bWwwSgYD
# VR0fBEMwQTA/oD2gO4Y5aHR0cDovL3ZhbGlkYXRpb24uaWRlbnRydXN0LmNvbS9j
# cmwvY29tbWVyY2lhbHJvb3RjYTEuY3JsMB0GA1UdDgQWBBTKMvA2fMcq2pG1fIeK
# Eb24Imy/CTATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAgEA
# K2c7h/pAHq/bIMV6V3c9rUfsGZvLa1LDND/l0HlZeZNkeVXjfezsEOSnAbMrh8YG
# 5NzHzXi49RZZLBwv5/xul+jMG/qnznmP8CUq6XUSI8wqQyUu3B2IrqxZPbHyppOb
# h8wZtymBRtCfE6jgGfNVSaCzd6mb3+pd/0ZpZdHPiZpJaXjPdqkPdf/mgyuuIZYi
# JbqK8KrxuY4FR2bQj2q6Fb1KeTYkBqqRUKOzTquoTetFuXI12tLKkbOjl4FPj3xo
# J9y8M8lfb+rY8yQu+Qqhe1UnWDiwTANDGbayDxAwR3YYqj5ftOo54XwCfso48Or2
# /TG1KwXj658WuXje+Xq/i4x7LrzA4e/pWZoakK1aTV7qVKr2MtCpEEGDwIzCnDqe
# JXK+St2HhO+77kcutqt5kGn3w8nZxDOseTVKI9zIPFKWFtdGSz9OApdOJxSbelmw
# plxO8Jcdyq6U3V6hDfP1rMwi5HtG10QLPZElQjpeD//pl0wyBoOeS0wAuADKj0aA
# YZWKbHgTb9ozmvRyb5EKuT3noFOpqER2IYtaOCOrx0Al7hd8u2noSYa+zDrnS4Fs
# MDQyD2eVIIV0ZMwUEqXDrmjaglp6czKwC8T9ULf1kgQ4F+TYg6PYZNiU6AeLSIgE
# hl/tKp2OFMC2hbtT1NNmPxIdF6f8QR7VYRx9NrBw6EkxggMfMIIDGwIBATBZMEUx
# CzAJBgNVBAYTAlVTMRIwEAYDVQQKEwlJZGVuVHJ1c3QxIjAgBgNVBAMTGVRydXN0
# SUQgVGltZXN0YW1waW5nIENBIDMCEEABiZOEDVg9uvVlFVI2DRIwDQYJYIZIAWUD
# BAIBBQCggZgwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJ
# BTEPFw0yNDA5MjUxNDUwMTZaMCsGCyqGSIb3DQEJEAIMMRwwGjAYMBYEFD2YyQfI
# P90D24fWH55/nZLIM+u1MC8GCSqGSIb3DQEJBDEiBCBgQQTVHECYSZX3LoVw6VS+
# ee/7kSGjReh7oky/d1pdGjANBgkqhkiG9w0BAQEFAASCAgABBS+xbUvQE7ZgWIXL
# d+Hm6FL9VMv8SHBv+gIPG6KD1gDQ6iLFazNXWml/BT2cX5G7ppHLtOlbsjpZbVBa
# Lt7gCh3X6DT/EUZHHtyxks1d7IsNmXzg3SwAGlzvKl8UUekJp1DeplLeYliy83hg
# 9TG6AMPUdLxIeFSXPN/T3Dt6saiPyGa/JmRCNn0W69EclcsEvLvQiq81NuIZbm47
# uq+uMYe44w3yZXkElFssdO1SKw6QKrco9fo9/t2W8nIR2U2AzKfsQLdu2DZocz53
# blnZv/JOJxJfI6WrqRZG0qcuJnPGQaLlRqS9v2Tci5l82rYiMRPM0W6nB2QGfxmt
# xJ1ru0GNaW1L36QHZ8UYHfl/b5ZU+ghc0M3/KzdI3ol9wqcjZ+ptPOyhmelHpomY
# Lg7oofLaj29vulNmMPe98B58qkMDTUaK9DuN90rZnXv9UgQXQ8oPFkNUdQdKRBo6
# nLDsUECvzQ7vwEAkbKCUgwdbdwAGDZgf/YO5wiBLMG8vYGEM/qfjbvrbkbpJJCvv
# UpC5cu86Pc1eBaRKJAnUG7w7dmJo0PJRfvHD+KBtEnlhwQSQuurj8kQfkvQSE9zQ
# 0CK/KnoPA97MUVdKR7HQzyhIPCBMuE0mzvO/ojya81bgRsIOpiyuSoDYeYXtxjn1
# Gnu0/UpztduurlPEomRN/TwnwA==
# SIG # End signature block
