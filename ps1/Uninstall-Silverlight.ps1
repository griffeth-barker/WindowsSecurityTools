<#
.SYNOPSIS
  This script uninstalls Microsoft Silverlight.
.DESCRIPTION
  This script checks for any installed application with caption "Microsoft Silverlight" then calls the uninstaller.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Author         : Griff Barker (github@griff.systems)
  Creation Date  : 2025-01-09
  Purpose/Change : Initial script development
.EXAMPLE
  & .\Uninstall-Silverlight.ps1
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
  # TODO: Change to use `Uninstall-Package` or add switch to determine whether to use manual removal or `Uninstall-Package`.

  $Uninstall64Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\"
  $Uninstall32Key = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
  $AllUninstallRegistryKeys = @($(Get-ChildItem $Uninstall64Key),$(Get-ChildItem $Uninstall32Key -ErrorAction SilentlyContinue))
  $UninstallStrings = $AllUninstallRegistryKeys | ForEach-Object {Get-ItemProperty $_.pspath | Where-Object {$_.DisplayName -like 'Microsoft Silverlight'}} | Select-Object -ExpandProperty UninstallString
  $UninstallStrings | ForEach-Object {
    try {
      & $_
      Write-Output "Uninstalled Microsoft Silverlight."
    }
    catch {
      Write-Output "Failed to uninstall Microsoft Silverlight."
      throw $_.Exception.Message
    }

  }
}

end {
  Stop-Transcript
}
