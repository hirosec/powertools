<#
	LAST CHANGED: 2025/08/14 - v1.00
	
		
	powershell "& {Import-Module '.\myFileinfo.ps1'; Get-FileInfo -Filepath c:\temp\tux.png}"
		
	powershell "iex (iwr https://raw.githubusercontent.com/hirosec/powertools/refs/heads/main/scripts/myFileInfo.ps1 -UseBasicParsing);  Get-FileInfo -Filepath c:\temp\tux.png"

	powershell "iex (iwr https://tinyurl.com/7ae2e35r -UseBasicParsing);  Get-FileInfo -Filepath c:\temp\tux.png"
	
#>
param (
	[string] $FilePath
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
		Write-Host "Size  : $($($fileInfo.Length) | Convert-Size )" 
		Write-Host "MD5   : $((Get-Filehash $($fileInfo.FullName) -algo md5).Hash)" 
	} else {
		Write-Host "ERROR - File `'$FilePath`' NOT found !"
	}
}


