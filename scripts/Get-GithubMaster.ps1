<#
	LAST CHANGED: 2025/08/14 - v1.00
		
	powershell -ep bypass -f Get-GithubMaster.ps1 
#>

param (
	[string] $url = "https://github.com/hirosec/powertools"
)

##############################################################################################


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


##############################################################################################

Write-Host "`n[+] Date    : $(Get-Date -format s)"
Write-Host "[+] URL     : $url"

$user = $url.Split('/')[3]
$repo = $url.Split('/')[4]

			
			
$uri = "https://api.github.com/repos/$user/$repo/zipball/"

$timestamp = Get-Date -format "yyyyMMddTHHmm"
			
			

$response = Invoke-WebRequest -Method Get -Headers $headers -Uri $uri
$filename = $response.headers['content-disposition'].Split('=')[1]
			
			
Set-Content -Path "$filename" -Encoding byte -Value $response.Content 

Write-Host "-------------------------------------------------------------"
Get-FileInfo $filename
Write-Host "-------------------------------------------------------------"
