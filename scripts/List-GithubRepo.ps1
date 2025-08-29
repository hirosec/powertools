<#
	Last Changed: 2025-08-29  - v1.0
	
	powershell -ep bypass -f List-GithubRepo.ps1
	
	powershell -ep bypass -f List-GithubRepo.ps1 -token <MY_API_TOKEN>

#>
param (

	$owner   = "hirosec",
	$repo    = "powertools",
	$path    = "scripts",
	$token   = $null,
	[switch] $Version
)



Add-Type -AssemblyName 'System.Security'

# Stores Github token on local filesystem using Data Protection API (DPAPI)
$GITHUB_API_STORE = "GithubApiStore"
$API_TOKEN        = "TokenProtect.db"


$CurrentVersion = '1.0.0'
$PublishedAt    = '2025-08-29'


# Display version if -Version is specified
if ($Version.IsPresent) {
	Write-Host "Version         : $CurrentVersion"
	Write-Host "Published at    : $PublishedAt"
    exit 0
}


#############################################################################################################

# Encrypted string with the Data Protection API (DPAPI)
# Anything encrpted with via DPAPI can only be decrypted on the same computer it was encrypted on.  
# Use the `ForUser` switch so that only the user who encrypted can decrypt. 
# Use the `ForComputer` switch so that any user who can log into the computer can decrypt. 

Function Protect-String
{
    param(
		[string] $String        
    )
    
	# convert text to bytes in UTF8 encoding
	$bytes = [System.Text.Encoding]::UTF8.GetBytes($String)

	# encrypt bytes using the built-in secret
    $scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
	$bytesEncrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, $scope)

	# convert bytes to Base64 encoding
	return [Convert]::ToBase64String($bytesEncrypted)
}


# Decrypts a string encrypted via the Data Protection API (DPAPI)
Function Unprotect-String
{
    param(
		[string] $ProtectedString
    )

	[byte[]]$bytesEncrypted  = [Convert]::FromBase64String($ProtectedString)
	$bytes = [Security.Cryptography.ProtectedData]::Unprotect($bytesEncrypted , $null, 0 )
	
	return [System.Text.Encoding]::UTF8.GetString($bytes)
}


#############################################################################################################
### MAIN


Write-Host ""
Write-Host "[+] Date                        : $(Get-Date -format s)"
Write-Host ""


# If API token is provided, update local protected file store
$TokenStorePath = "$($env:LOCALAPPDATA)\$GITHUB_API_STORE"
$TokenFile = Join-Path -Path $TokenStorePath -ChildPath $API_TOKEN


If (-Not ([string]::IsNullOrEmpty($token))) {
	$protectedKey = Protect-String -String $token 

	# Create a folder whether is exists or not
	New-Item -Path $TokenStorePath -ItemType Directory -Force | Out-Null

	Set-Content -Path $TokenFile  -Value $protectedKey -Encoding UTF8

	Write-Host "[+] Protected API token updated : $TokenFile"
} Else {
	# Test to load saved API key from DPAPI Protected config file
	If ((Test-Path -Path $TokenFile  -PathType leaf)) {
		$ProtectedAPIToken = Get-Content -Path $TokenFile -Encoding UTF8
		$token = Unprotect-String -ProtectedString $ProtectedAPIToken
		Write-Host "[+] SUCCESS                     : Loaded Github API Token from local store" -ForeGroundColor Green
	} Else {
		Write-Host "[+] ERROR - missing Github API Token." -ForeGroundColor Red
		Exit
	}
}




Write-Host "[+] Owner                       : $owner"
Write-Host "[+] Repo                        : $repo"
Write-Host "[+] Repo Path                   : $path"
Write-Host ""
Write-Host "[+] API Token                   : $token"
Write-Host ""
Write-Host "--------------------------------------------------------"

# GitHub API URL
$url = "https://api.github.com/repos/$owner/$repo/contents/$path"

# Headers for authentication (optional)
$headers = @{
    Authorization = "Bearer $token"
    Accept = "application/vnd.github.v3+json"
    "User-Agent" = "PowerShellScript"
}

# Make the API request
$response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

# Display file names
$response | ForEach-Object {
    if ($_.type -eq "file") {
        Write-Output $_.name
    }
}


############################################################