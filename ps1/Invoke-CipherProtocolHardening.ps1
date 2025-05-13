<#
.SYNOPSIS
  This script hardens Windows systems by disabling older/insecure cipher suites and protocols.
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
  - TLS 1.1 (disable)
  - TLS 1.0 (disable)
  - SSL 3.0 (disable)
  - SSL 2.0 (disable)
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Updated by      : Griff Barker (github@griff.systems)
  Change Date     : 2025-01-09
  Purpose/Change  : Initial development
.EXAMPLE
  & .\Invoke-CipherProtocolHardening.ps1
#>

begin {
  function Enable-Tls12 {
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value "1" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -PropertyType "DWord" -Force | Out-Null
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value "1" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Value 0 -PropertyType "DWord" -Force | Out-Null
  }

  function Disable-Tls11 {
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value "0" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force | Out-Null
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -Value "0" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force | Out-Null
  }

  function Disable-Tls10 {
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value "0" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force | Out-Null
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -Value "0" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force | Out-Null
  }

  function Disable-Ssl30 {
      New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force | Out-Null
      New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Value "0" -PropertyType "DWord" -Force | Out-Null
      New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force | Out-Null
      New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force | Out-Null
      New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -Value "0" -PropertyType "DWord" -Force | Out-Null
      New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force | Out-Null
  }

  function Disable-Ssl20 {
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Value "0" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force | Out-Null
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "Enabled" -Value "0" -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force | Out-Null
  }

  $logDir = "$PSScriptRoot\logs"
  $logFile = "$($MyInvocation.MyCommand.Name.Replace(".ps1","_"))" + "$(Get-Date -Format "yyyyMMddmmss").log"
  if (-not (Test-Path "$logDir")) {
    New-Item -Path "$logDir" -ItemType Directory -Confirm:$false | Out-Null
  }

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
  Start-Transcript -Path "$logDir\$logFile" -Force
  Set-Location -Path "HKLM:\"

  try {
    Enable-Tls12
    Write-Output "Enable TLS 1.2: Success."
  }
  catch {
    Write-Output "Enable TLS 1.2: Error."
    throw $_.Exception.Message
  }

  $dotNetFrameworks = @(
    (Get-ChildItem -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.*" | Select-Object -ExpandProperty Name) + `
    (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.*"  | Select-Object -ExpandProperty Name)
  )

  if ($dotNetFrameworks64.Count -ne 0) {
    try {
      foreach ($dotNetFramework in $dotNetFrameworks) {
        New-ItemProperty -Path $dotNetFramework -Name SystemDefaultTlsVersions -Value 1 -PropertyType DWORD
        New-ItemProperty -Path $dotNetFramework -Name SchUseStrongCrypto -Value 1 -PropertyType DWORD
      }
      Write-Output "Enforce strong crypto for .NET Apps : Success"
    }
    catch {
      Write-Output "Enforce strong crypto for .NET Apps : Error"
    }
  }

  try {
    Disable-Tls11
    Write-Output "Disable TLS 1.1: Success."
  }
  catch {
    Write-Output "Disable TLS 1.1: Error."
    throw $_.Exception.Message
  }

  try {
    Disable-Tls10
    Write-Output "Disable TLS 1.0: Success."
  }
  catch {
    Write-Output "Disable TLS 1.0 : Error."
    throw $_.Exception.Message
  }

  try {
    Disable-Ssl30
    Write-Output "Disable SSL 3.0: Success."
  }
  catch {
    Write-Output "Disable SSL 3.0 : Error."
    throw $_.Exception.Message
  }

  try {
    Disable-Ssl20
    Write-Output "Disable SSL 2.0: Success."
  }
  catch {
    Write-Output "Disable SSL 2.0: Error."
    throw $_.Exception.Message
  }

  try {
    foreach ($weakCipher in $weakCiphers) {
      Disable-TlsCipherSuite -Name $weakCipher
      Write-Output "Disable $($weakCipher): Success."
    }
  }
  catch {
    if ($_.Exception.Message -eq "Exception from HRESULT: 0xD0000225") {
      Write-Output "Disable $($weakCipher): Already disabled; no changes made."
    }
    else {
      Write-Output "Disable $($weakCipher): Error."
      Write-Output $_.Exception.Message
    }
  }
}

end {
  Stop-Transcript
}
