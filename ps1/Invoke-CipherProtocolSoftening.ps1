<#
.SYNOPSIS
  This script softens Windows systems by enabling older/insecure cipher suites and protocols.
.DESCRIPTION
  This script creates/updates registry keys to enable the following cipher suites:
    - TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    - TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    - TLS_RSA_WITH_AES_256_GCM_SHA384
    - TLS_RSA_WITH_AES_128_GCM_SHA256
    - TLS_RSA_WITH_AES_256_CBC_SHA256
    - TLS_RSA_WITH_AES_128_CBC_SHA256
    - TLS_RSA_WITH_AES_256_CBC_SHA
    - TLS_RSA_WITH_AES_128_CBC_SHA
    - TLS_RSA_WITH_3DES_EDE_CBC_SHA
    - TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
    - TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
    - TLS_DHE_DSS_WITH_AES_256_CBC_SHA
    - TLS_DHE_DSS_WITH_AES_128_CBC_SHA
    - TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
    - TLS_RSA_WITH_RC4_128_SHA
    - TLS_RSA_WITH_RC4_128_MD5
    - TLS_RSA_WITH_NULL_SHA256
    - TLS_RSA_WITH_NULL_SHA
    - TLS_PSK_WITH_AES_256_GCM_SHA384
    - TLS_PSK_WITH_AES_128_GCM_SHA256
    - TLS_PSK_WITH_AES_256_CBC_SHA384
    - TLS_PSK_WITH_AES_128_CBC_SHA256
    - TLS_PSK_WITH_NULL_SHA384
    - TLS_PSK_WITH_NULL_SHA256
  This script creates/updates registry keys to enable the following protocols:
    - TLS 1.2 (enable)
    - TLS 1.1 (enable)
    - TLS 1.0 (enable)
    - SSL 3.0 (enable)
    - SSL 2.0 (enable)
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Updated by      : Griff Barker (github@griff.systems)
  Change Date     : 2025-01-09
  Purpose/Change  : Initial development
.EXAMPLE
  & .\Invoke-CipherProtocolSoftening.ps1
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [switch]$FullReset
)

begin {
  function Enable-Tls12 {
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value "1" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -PropertyType "DWord" -Force | Out-Null
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value "1" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Value 0 -PropertyType "DWord" -Force | Out-Null
  }

  function Enable-Tls11 {
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -name "Enabled" -value "1" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -name "DisabledByDefault" -value 0 -PropertyType "DWord" -Force | Out-Null
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -name "Enabled" -value "1" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -name "DisabledByDefault" -value 0 -PropertyType "DWord" -Force | Out-Null
  }

  function Enable-Tls10 {
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -name "Enabled" -value "1" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -name "DisabledByDefault" -value 0 -PropertyType "DWord" -Force | Out-Null
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -name "Enabled" -value "1" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -name "DisabledByDefault" -value 0 -PropertyType "DWord" -Force | Out-Null
  }

  function Enable-Ssl30 {
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -name "Enabled" -value "1" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -name "DisabledByDefault" -value 0 -PropertyType "DWord" -Force | Out-Null
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -name "Enabled" -value "1" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -name "DisabledByDefault" -value 0 -PropertyType "DWord" -Force | Out-Null
  }

  function Enable-Ssl20 {
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -name "Enabled" -value "1" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -name "DisabledByDefault" -value 0 -PropertyType "DWord" -Force | Out-Null
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -name "Enabled" -value "1" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -name "DisabledByDefault" -value 0 -PropertyType "DWord" -Force | Out-Null
  }


  $logDir = "$PSScriptRoot\logs"
  $logFile = "$($MyInvocation.MyCommand.Name.Replace(".ps1","_"))" + "$(Get-Date -Format "yyyyMMddmmss").log"
  if (-not (Test-Path "$logDir")) {
    New-Item -Path "$logDir" -ItemType Directory -Confirm:$false | Out-Null
  }

  Start-Transcript -Path "$logDir\$logFile" -Force

  $weakCiphers = @(
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_NULL_SHA256",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_PSK_WITH_AES_256_GCM_SHA384",
    "TLS_PSK_WITH_AES_128_GCM_SHA256",
    "TLS_PSK_WITH_AES_256_CBC_SHA384",
    "TLS_PSK_WITH_AES_128_CBC_SHA256",
    "TLS_PSK_WITH_NULL_SHA384",
    "TLS_PSK_WITH_NULL_SHA256"
  )
}

process {
  if ($FullReset) {
    $schannelRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    Remove-Item -Path "$schannelRegPath\TLS 1.0"
    Remove-Item -Path "$schannelRegPath\TLS 1.1"
    Remove-Item -Path "$schannelRegPath\TLS 1.2"
  } else {
    try {
      Enable-Tls12
      Write-Output "Enable TLS 1.2: Success."
    }
    catch {
      Write-Output "Enable TLS 1.2: Error."
      throw $_.Exception.Message
    }

    try {
      Enable-Tls11
      Write-Output "Enable TLS 1.1: Success."
    }
    catch {
      Write-Output "Enable TLS 1.1: Error."
      throw $_.Exception.Message
    }

    try {
      Enable-Tls10
      Write-Output "Enable TLS 1.0: Success."
    }
    catch {
      Write-Output "Enable TLS 1.0: Error."
      throw $_.Exception.Message
    }

    try {
      Enable-Ssl30
      Write-Output "Enable SSL 3.0: Success."
    }
    catch {
      Write-Output "Enable SSL 3.0: Error."
      throw $_.Exception.Message
    }

    try {
      Enable-Ssl20
      Write-Output "Enable SSL 2.0: Success."
    }
    catch {
      Write-Output "Enable SSL 2.0: Error."
      throw $_.Exception.Message
    }

    try {
      foreach ($cipher in $weakCiphers) {
        Enable-TlsCipherSuite -Name $cipher
        Write-Output "Enable $($cipher): Success."
      }
    }
    catch {
      Write-Output "Enable $($cipher): Error."
      Write-Output $_.Exception.Message
    }
  }
}

end {
  Stop-Transcript
}
