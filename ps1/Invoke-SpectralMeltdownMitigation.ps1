<#
.SYNOPSIS
  This script mitigates the Spectre/Meltdown vulnerabilities in Windows.
.DESCRIPTION
  This script sets registry keys to mitigate the Spectre/Meltdown vulnerabilities in Windows.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Author         : Griff Barker (github@griff.systems)
  Creation Date  : 2025-01-09
  Purpose/Change : Initial script development
.EXAMPLE
  & .\Invoke-SpectreMeltdownMitigation.ps1
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
  # TODO: Export existing reg config

  # TODO: Add check if the keys exists already
  if (72 -ne (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride").FeatureSettingsOverride) {
    try {
      New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value "72" -PropertyType "DWORD"
      New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value "3" -PropertyType "DWORD"
      Write-Output "Set registry keys: Success."
    }
    catch {
      Write-Output "Set registry keys: Error."
      throw $_.Exception.Message
    }
  }
}

end {
  Stop-Transcript
}
