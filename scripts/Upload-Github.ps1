<#

	LAST CHANGED: 2025/08/27 - version 1.0

	powershell -ep bypass -f Upload-Github.ps1 


	# Update Protected API Token file
	powershell -ep bypass -f Upload-Github.ps1 -token <MY_API_TOKEN>	
	
	URL:  https://time.is/

#>


param (
	[string] $owner        	= "hirosec",
	[string] $repo          = "powertools",
	[string] $repoPath      = "lists",
	[string] $token        	= $null,
	[string] $fileName      = "time_20250827.JPG",
	[string] $filePath      = ".",
	[switch] $Version
)

Add-Type -AssemblyName 'System.Security'

$GITHUB_API_STORE = "GithubApiStore"
$API_TOKEN        = "TokenProtect.db"



$CurrentVersion = '1.0.0'
$PublishedAt    = '2025-08-27'

# Display version if -Version is specified
if ($Version.IsPresent) {
	Write-Host "Version         : $CurrentVersion"
	Write-Host "Published at    : $PublishedAt"
    exit 0
}



####################################################################################################

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



####################################################################################################

function git-uploadfile 
{
    param (
        $token,
        $message = '',
        $file,
        $owner,
        $repo,
        $path = '.\',
        $sha,
        [switch]$force
    )

    $path = (Join-Path $path (Split-Path $file -Leaf))

    $base64token = [System.Convert]::ToBase64String([char[]]$token)

    $headers = @{
        Authorization = 'Basic {0}' -f $base64token
    }

    if ($force -and !$sha) {
        $sha = $(
            try {
                (git-getfile -token $token -owner $owner -repo $repo -path $path).sha
            } catch {
                $null
            }
        )
    }

    $body = @{
        message = $message
        content = [convert]::ToBase64String((Get-Content $file -Encoding Byte))
        sha = $sha
    } | ConvertTo-Json

    Invoke-RestMethod -Headers $headers -Uri https://api.github.com/repos/$owner/$repo/contents/$path -Body $body -Method Put
}


###########################################################################################################################################
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
	} Else {
		Write-Host "[+] ERROR - missing Github API Token." -ForeGroundColor Red
		Exit
	}
}


Write-Host "[+] Owner                       : $owner"
Write-Host "[+] Repo                        : $repo"
Write-Host "[+] Repo Path                   : $repoPath"
Write-Host ""
Write-Host "[+] API Token                   : $token"
Write-Host ""


$file     = (Join-Path $filePath $fileName)

If (-Not (Test-Path -Path $file  -PathType leaf)) {
	Write-Host "[+] ERROR - Upload file not found : $file"
	exit
}

Write-Host ""
Write-Host "[+] Filename                    : $fileName"
Write-Host "[+] Size                        : $( (Get-Item -Path $file).Length) bytes"
Write-Host "[+] Hash                        : $( (Get-Filehash -Path $file -Algorithm SHA1).Hash)"

git-uploadfile -token $token -file $file -owner $owner -repo $repo -path $repoPath -force | FL *

Write-Host "[+] DONE !"