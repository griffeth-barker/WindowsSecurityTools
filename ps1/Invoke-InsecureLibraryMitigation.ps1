<#
.SYNOPSIS
  This script mitigates an insecure library vulnerability involving KB2269637.
.DESCRIPTION
  This script sets the registry key to mitigate an insecure library vulnerability involving KB2269637.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Author         : Griff Barker (github@griff.systems)
  Creation Date  : 2025-01-09
  Purpose/Change : Initial script development
.EXAMPLE
  & .\Invoke-InsecureLibraryMitigation.ps1
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
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "CWDIllegalInDllSearch" -Value "1" -PropertyType "DWORD"
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
