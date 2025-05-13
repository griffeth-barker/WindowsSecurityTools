<#
.SYNOPSIS
  This script hardens Internet Explorer.
.DESCRIPTION
  This script sets registry keys that harden Internet Explorer.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Author         : Griff Barker (github@griff.systems)
  Creation Date  : 2025-01-09
  Purpose/Change : Initial script development
.EXAMPLE
  & .\Invoke-IEHardening.ps1
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
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl" -Name "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -Name "iexplore.exe" -Value "1" -PropertyType "DWORD" -Force
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl" -Name "FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -Name "iexplore.exe" -Value "1" -PropertyType "DWORD" -Force
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
