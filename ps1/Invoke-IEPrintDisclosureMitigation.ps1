<#
.SYNOPSIS
  This script mitigates the Windows 10 / Windows Server 2016 September 2017 Information Disclosure Vulnerability (CVE-2017-8529).
.DESCRIPTION
  This script sets registry keys to mitigate the Windows 10 / Windows Server 2016 September 2017 Information Disclosure Vulnerability (CVE-2017-8529)
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Author         : Griff Barker (github@griff.systems)
  Creation Date  : 2025-01-09
  Purpose/Change : Initial script development
.EXAMPLE
  & .\Invoke-IEPrintDisclosureMitigation.ps1
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
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl" -Name "FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" -Name "iexplore.exe" -Value "1" -PropertyType "DWORD" -Force
    New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl" -Name "FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX"
    New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" -Name "iexplore.exe" -Value "1" -PropertyType "DWORD" -Force
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
