<#
.SYNOPSIS
  This script enables Internet Explorer.
.DESCRIPTION
  This script enables the Internet Explorer feature in Windows.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Author         : Griff Barker (github@griff.systems)
  Creation Date  : 2025-01-09
  Purpose/Change : Initial script development
.EXAMPLE
  # Enable Internet Explorer using PowerShell's WindowsOptionalFeatures cmdlets
  & .\Enable-InternetExplorer
.EXAMPLE
  # Enable Internet Explorer using the Deployment Image Servicing and Management utility
  & .\Enable-InternetExplorer -Dism
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
      DISM /online /enable-feature /featurename:Internet-Explorer-optional-amd64
      Write-Output "Enable Internet Explorer using DISM: Success."
    }
    catch {
      Write-Output "Enable Internet Explorer using DISM: Error."
      throw $_.Exception.Message
    }
  }
  else {
    try {
      Enable-WindowsOptionalFeature -Online -FeatureName internet-explorer-optional-amd64
      Write-Output "Enable Internet Explorer using WindowsOptionalFeatures cmdlets: Success."
    }
    catch {
      Write-Output "Enable Internet Explorer using WindowsOptionalFeatures cmdlets: Error."
      throw $_.Exception.Message
    }
  }
}

end {
  Stop-Transcript
}
