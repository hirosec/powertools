<#
	LAST CHANGED: 2025/08/14 - v1.00
	
	powershell -ep bypass -f Upload-HFSServer.ps1 -Filepath c:\temp\tux.png
	
	powershell -ep bypass -f Upload-HFSServer.ps1 -Filepath c:\temp\tux.png -verifyUpload

	.DESCRIPTION
		Upload file to HFS ~ HTTP File Server  using powershell cURL

#>
param (
	[string] $FilePath,
	[string] $uri = 'http://192.168.137.1/myShare2025/',
	[switch] $verifyUpload
)


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



function Get-FileInfo {
	param (
		[string] $FilePath
	)

	if (Test-Path -Path $FilePath -PathType leaf) {
		$file = Split-Path $FilePath -leaf
	
		$fileInfo = Get-Item $filepath

		Write-Host "File  : $file"
		Write-Host "Size  : $( $($fileInfo.Length) | Convert-Size)" 
		Write-Host "MD5   : $((Get-Filehash $($fileInfo.FullName) -algo md5).Hash)" 
	} else {
		Write-Host "ERROR - File `'$FilePath`' NOT found !"
	}
}


##################################################################################
### MAIN

Write-Host ""
Write-Host "[+] Date : $(Get-Date -format s)"
Write-Host "[+] Url  : $uri"
Write-Host ""
Get-FileInfo -Filepath $FilePath

# Upload file to Windows HFS server

$response = $(& C:\Windows\System32\curl.exe -s  -F "file=@$FilePath" $uri)

$response | % {
		If ($_ -like "*uploaded*") {
			Write-Host "[>] $_" -ForegroundColor Yellow  
		}
}

if ($verifyUpload) {
	$filename  = Split-Path $FilePath -leaf
	Write-Host "`n`n[!] Verifying Upload ..." -ForegroundColor Yellow  
	
	
	$uri = "$uri/$filename"
	Write-Host "URL   : $uri"
	
	$response = Invoke-WebRequest -Method Get -Uri $uri
			
	$AlgorithmObject = [System.Security.Cryptography.HashAlgorithm]::Create("MD5")
	$HashBytes = $AlgorithmObject.ComputeHash($response.Content)
	[string]$hash = [System.BitConverter]::ToString($HashBytes).Replace("-", [String]::Empty);
			
	$size = ($response.Content).Length

	Write-Host "Size  : $($size | Convert-Size) "
	Write-Host "MD5   : $hash"
}