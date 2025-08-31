<#
	Last Changed: 2025-08-31  - v1.0
	
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
$PublishedAt    = '2025-08-31'


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



# Format File Size
Function Convert-Size {
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias("Length")]
        [int64]$Size
    )
    Begin {
        If (-Not $ConvertSize) {
            $Signature =  @"
                 [DllImport("Shlwapi.dll", CharSet = CharSet.Auto)]
                 public static extern long StrFormatByteSize( long fileSize, System.Text.StringBuilder buffer, int bufferSize );
"@
            $Global:ConvertSize = Add-Type -Name SizeConverter -MemberDefinition $Signature -PassThru
        }
        $stringBuilder = New-Object Text.StringBuilder 1024
    }
    Process {
        $ConvertSize::StrFormatByteSize( $Size, $stringBuilder, $stringBuilder.Capacity ) | Out-Null
        $stringBuilder.ToString() + " ($($Size.ToString('N0')) bytes)"
    }
}


Function Get-GithubFileinfo {
	Param (
		$owner,
		$repo,
		$path,
		$name
	)

	$url = "https://raw.githubusercontent.com/$owner/$repo/refs/heads/main/$path/$name"
	
	Try {
		$response = Invoke-WebRequest -Method Get -Uri $url 

		If ($($response.Headers.'Content-Type') -like "*text*") {
			$tmpData = $response.Content
		} else {
			Write-Host "ERROR - Wrong Content Type : $($response.Headers.'Content-Type')"
		}

				
		$hasher = [System.Security.Cryptography.HashAlgorithm]::Create("MD5") 
		$bytes = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($tmpData))
		$hash = [System.BitConverter]::ToString($bytes).Replace('-', '').ToUpperInvariant()
		
		$size = $tmpData.Length
	} Catch {
		Write-Host "   ERROR - Resource no found : $url" -ForegroundColor Red
		[int]$StatusCode = $_.Exception.Response.StatusCode
		# Write-Host "StatusCode  : $StatusCode"   -ForegroundColor Blue
		return
	}
	
	$myObject = [PSCustomObject]@{
		Name     = $name
		Size     = $($size | Convert-Size)
		MD5      = $hash
	}
	
	return $myObject
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
Write-Host "-----------------------------------------------------------------------------------"

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


$fileList = @()

# Display file names
$response | ForEach-Object {
    if ($_.type -eq "file") {
        # Write-Host $_.name -ForeGroundColor Yellow
		
		$fileList += Get-GithubFileinfo -owner $owner -repo $repo -path $path -name $_.name
    }
}

$fileList
