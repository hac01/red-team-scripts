# Initial static paths
$paths = @(
    "$env:APPDATA\Mozilla\Firefox\Profiles\*\logins.json",
    "$env:APPDATA\Mozilla\Firefox\Profiles\*\key4.db",
    "$env:APPDATA\Microsoft\Credentials",
    "$env:USERPROFILE\AppData\Local\Packages\Microsoft.Windows.CredentialsStore_*",
    "$env:USERPROFILE\AppData\Local\Packages\Microsoft.Windows.CredentialManager_*",
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Credentials",
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Vault",
    "$env:USERPROFILE\AppData\Local\Microsoft\Vault",
    "$env:PROGRAMDATA\Microsoft\Crypto\RSA\MachineKeys",
    "$env:USERPROFILE\AppData\Local\Microsoft\Terminal Server Client\Cache",
    "$env:USERPROFILE\.ssh\id_rsa*",
    "$env:USERPROFILE\.ssh\id_dsa*",
    "$env:USERPROFILE\.ssh\known_hosts",
    "$env:USERPROFILE\.git-credentials",
    "$env:APPDATA\Slack\storage",
    "$env:APPDATA\discord\Local Storage",
    "$env:APPDATA\Microsoft\Teams\IndexedDB"
)

# Add Chrome and Edge profiles dynamically
$chromeUserData = "$env:LOCALAPPDATA\Google\Chrome\User Data"
$edgeUserData = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"

if (Test-Path $chromeUserData) {
    $chromeProfiles = Get-ChildItem -Path $chromeUserData -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' }
    foreach ($profile in $chromeProfiles) {
        $paths += "$($profile.FullName)\Login Data"
        $paths += "$($profile.FullName)\Web Data"
        $paths += "$($profile.FullName)\Cookies"
    }
}

if (Test-Path $edgeUserData) {
    $edgeProfiles = Get-ChildItem -Path $edgeUserData -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' }
    foreach ($profile in $edgeProfiles) {
        $paths += "$($profile.FullName)\Login Data"
        $paths += "$($profile.FullName)\Web Data"
        $paths += "$($profile.FullName)\Cookies"
    }
}

# Keywords to search for
$keywords = @("passwd", "password", "pass", "pwd", "secret")

foreach ($path in $paths) {
    Write-Output "Searching files matching: $path"
    $files = Get-ChildItem -Path $path -ErrorAction SilentlyContinue -Recurse -File
    if ($files) {
        foreach ($file in $files) {
            Write-Output "Found file: $($file.FullName)"
            try {
                if ($file.Length -lt 5MB) {
                    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
                    if ($null -ne $content) {
                        foreach ($keyword in $keywords) {
                            if ($content -match $keyword) {
                                Write-Host "!!! Potential password found in file: $($file.FullName) !!!" -ForegroundColor Red
                                break
                            }
                        }
                    }
                }
            } catch {
                # Ignore read errors
            }
        }
    } else {
        Write-Output "No files found at this path."
    }
    Write-Output "-----------------------------"
}
