<#
.SYNOPSIS
  This script forces the uninstallation of the Flash Player components in Windows.
.DESCRIPTION
  This script fixes ownership/permissions issues with the Flash Player components in Windows, then removes them.
.PARAMETER UninstallPath
  A mandatory string containing the UNC path to the Adobe Flash Uninstaller executable.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Author         : Griff Barker (github@griff.systems)
  Creation Date  : 2025-01-09
  Purpose/Change : Initial script development
.EXAMPLE
  & .\Uninstall-FlashPlayer.ps1 -UninstallerPath "\\server\share\uninstaller.exe"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$UninstallerPath
)

begin {
  $logDir = "C:\Admin\$($MyInvocation.MyCommand.Name.Split(".")[0])"
  $logFile = "$($MyInvocation.MyCommand.Name.Replace(".ps1","_"))" + "$(Get-Date -Format "yyyyMMddmmss").log"
  if (-not (Test-Path "$logDir")) {
    New-Item -Path "$logDir" -ItemType Directory -Confirm:$false | Out-Null
  }

  Start-Transcript -Path "$logDir\$logFile" -Force
}

process {
  if ($UninstallerPath -like "\\*") {
    xcopy "$UninstallerPath" "$logDir\uninstall_flash_player.exe" /k/r/e/i/s/c/h/f/o/x/y
  }

  $srcHash = Get-FileHash -Path "$UninstallerPath"
  $dstHash = Get-FilePath -Path "$logDir\uninstall_flash_player.exe"
  if ($dstHash -eq $srcHash) {

    $acl = Get-Acl C:\Windows\SysWOW64\Macromed\Flash
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
    $acl.SetAccessRule($AccessRule)
    $acl | Set-Acl C:\Windows\SysWOW64\Macromed\Flash

    $acl = Get-Acl C:\Windows\SysWOW64\Macromed\Flash
    $object = New-Object System.Security.Principal.Ntaccount("NT AUTHORITY\SYSTEM")
    $acl.SetOwner($object)
    $acl | Set-Acl C:\Windows\SysWOW64\Macromed\Flash

    foreach ($_ in (Get-ChildItem "C:\Windows\SysWOW64\Macromed\Flash" -Recurse)) {
      $acl = Get-Acl $_.fullname
      $object = New-Object System.Security.Principal.Ntaccount("NT AUTHORITY\SYSTEM")
      $acl.SetOwner($object)
      $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
      $acl.SetAccessRule($AccessRule)
      $acl.SetAccessRuleProtection($false, $true)
      $acl | Set-Acl $_.fullname
      Set-ItemProperty $acl -name IsReadOnly -value $false
    }

    $acl = Get-Acl C:\Windows\system32\Macromed\Flash
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
    $acl.SetAccessRule($AccessRule)
    $acl | Set-Acl C:\Windows\system32\Macromed\Flash

    $acl = Get-Acl C:\Windows\system32\Macromed\Flash
    $object = New-Object System.Security.Principal.Ntaccount("NT AUTHORITY\SYSTEM")
    $acl.SetOwner($object)
    $acl | Set-Acl C:\Windows\system32\Macromed\Flash

    foreach ($_ in (Get-ChildItem "C:\Windows\system32\Macromed\Flash" -recurse)) {
      $acl = Get-Acl $_.fullname
      $object = New-Object System.Security.Principal.Ntaccount("NT AUTHORITY\SYSTEM")
      $acl.SetOwner($object)
      $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
      $acl.SetAccessRule($AccessRule)
      $acl.SetAccessRuleProtection($false, $true)
      $acl | Set-Acl $_.fullname
      Set-ItemProperty $acl -name IsReadOnly -value $false
    }

    Start-Process -FilePath "C:\temp\uninstall_flash_player.exe" -ArgumentList "/uninstall" -Wait -PassThru

    Remove-Item -Path "C:\Windows\system32\Macromed\Flash" -Recurse -Force -Confirm:$false
    Remove-Item -Path "C:\Windows\SysWOW64\Macromed\Flash" -Recurse -Force -Confirm:$false

    foreach ($user in (Get-ChildItem -Path "C:\Users" | Select-Object -ExpandProperty Name)) {
      Remove-Item -Path "C:\users\$user\AppData\Roaming\Adobe\Flash Player" -Recurse -Force -Confirm:$false
      Remove-Item -Path "C:\users\$user\AppData\Roaming\Macromedia\Flash Player" -Recurse -Force -Confirm:$false
    }
  }

  Remove-Item -Path "C:\temp\uninstall_flash_player.exe" -Force -Confirm:$false
}

end {
  Stop-Transcript
}
