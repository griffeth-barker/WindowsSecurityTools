<#
.SYNOPSIS
  This script disables Internet Explorer.
.DESCRIPTION
  This script disables the Internet Explorer feature in Windows.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Author         : Griff Barker (github@griff.systems)
  Creation Date  : 2025-01-09
  Purpose/Change : Initial script development
.EXAMPLE
  # Disable Internet Explorer using PowerShell's WindowsOptionalFeatures cmdlets
  & .\Disable-InternetExplorer
.EXAMPLE
  # Disable Internet Explorer using the Deployment Image Servicing and Management utility
  & .\Disable-InternetExplorer -Dism
#>

[CmdletBinding()]
param (
  [Parameter()]
  [switch]$Dism
)

begin {
  $logDir = "$PSScriptRoot\logs"
  $logFile = "$($MyInvocation.MyCommand.Name.Replace(".ps1","_"))" + "$(Get-Date -Format "yyyyMMddmmss").log"
  if (-not (Test-Path "$logDir")) {
    New-Item -Path "$logDir" -ItemType Directory -Confirm:$false | Out-Null
  }

  Start-Transcript -Path "$logDir\$logFile" -Force
}

process {
  if ($Dism) {
    try {
      DISM /online /disable-feature /featurename:Internet-Explorer-optional-amd64
      Write-Output "Disable Internet Explorer using DISM: Success."
    }
    catch {
      Write-Output "Disable Internet Explorer using DISM: Error."
      throw $_.Exception.Message
    }
  }
  else {
    try {
      Disable-WindowsOptionalFeature -Online -FeatureName internet-explorer-optional-amd64
      Write-Output "Disable Internet Explorer using WindowsOptionalFeatures cmdlets: Success."
    }
    catch {
      Write-Output "Disable Internet Explorer using WindowsOptionalFeatures cmdlets: Error."
      throw $_.Exception.Message
    }
  }
}

end {
  Stop-Transcript
}
