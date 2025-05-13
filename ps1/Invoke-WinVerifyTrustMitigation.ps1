<#
.SYNOPSIS
  This script remediates CVE-2013-3900.
.DESCRIPTION
  This script creates registry keys which mitigate CVE-2013-3900 to remediate a vulnverability which could allow attackers to run arbitrary
  code on the system. For more information, see https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Author         : Griff Barker (github@griff.systems)
  Creation Date  : 2025-01-09
  Purpose/Change : Initial script development
.EXAMPLE
  & .\Invoke-WinVerifyTrustMitigation.ps1
#>

begin {
  $logDir = "$PSScriptRoot\logs"
  $logFile = "$($MyInvocation.MyCommand.Name.Replace(".ps1","_"))" + "$(Get-Date -Format "yyyyMMddmmss").log"
  if (-not (Test-Path "$logDir")) {
    New-Item -Path "$logDir" -ItemType Directory -Confirm:$false | Out-Null
  }

  Start-Transcript -Path "$logDir\$logFile" -Force
}

process {
  # TODO: Export existing reg key config to filesystem

  # TODO: Add check if the keys exists already

  try {
    New-Item "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust" -Force | Out-Null
    New-Item "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null
    New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" -name "EnableCertPaddingcheck" -value "1" -PropertyType "DWord" -Force | Out-Null
    New-Item "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust" -Force | Out-Null
    New-Item "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null
    New-ItemProperty -path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -name "EnableCertPaddingcheck" -value "1" -PropertyType "DWord" -Force | Out-Null
    Write-Output "Set registry keys: Success."
  }
  catch {
    Write-Output "Set registry keys: Error."
    throw $_.Exception.Message
  }
}

end {
  Stop-Transcript
}
