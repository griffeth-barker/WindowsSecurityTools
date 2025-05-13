<#
.SYNOPSIS
  This script enables the enforcement of SMB signing.
.DESCRIPTION
  This script checks the RequireSecuritySignature DWORD value for LanManWorkstation parameters, expecting "1".
  If "0" is found, it is corrected by setting it to "1".
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Author         : Griff Barker (github@griff.systems)
  Creation Date  : 2025-01-09
  Purpose/Change : Initial script development
.EXAMPLE
  & .\Enable-SmbSigningEnforcement.ps1
#>

begin {
  function Test-SmbSigningConfiguration {
    Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" | Select-Object -ExpandProperty RequireSecuritySignature
  }

  $logDir = "$PSScriptRoot\logs"
  $logFile = "$($MyInvocation.MyCommand.Name.Replace(".ps1","_"))" + "$(Get-Date -Format "yyyyMMddmmss").log"
  if (-not (Test-Path "$logDir")) {
    New-Item -Path "$logDir" -ItemType Directory -Confirm:$false | Out-Null
  }

  Start-Transcript -Path "$logDir\$logFile" -Force
}

process {
  # TODO: Export backup of existing reg key config to filesystem
  if (0 -eq (Test-SmbSigningConfiguration)) {
    try {
      Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -Value "1"
      Write-Output "Enforce SMB signing: Success."
    }
    catch {
      Write-Output "Enforce SMB signing: Error."
      Write-Output $_.Exception.Message
    }

  } elseif (0 -ne $CurrentSmbSigning) {
    Write-Output "SMB signing is already enforced."
  }
}

end {
  Stop-Transcript
}
