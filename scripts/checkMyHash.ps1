# Copyright (c) HIROSEC.
# Licensed under the MIT License.

# LAST CHANGED: 2026-01-06


function Check-Filehash 
{
	param (
        [string] $listItems = "*.*",
		[switch] $OnlyDup
    )

	$result = @()

	Get-ChildItem -Filter  $listItems | % {
		$hash = (Get-Filehash $_ -algo MD5).hash
		$filename = Split-Path -Path $_ -Leaf
	
	
		$result += [PSCustomObject]@{
			hash = $hash
			name = $filename
		}
	}

	Write-Host "$('-'*79)"


	$result = $result | Sort-Object -Property hash  

	for ($i=0; $i -lt $result.length; $i++) {
	
		$previousLine = $result[$i-1]
		$currentLine  = $result[$i]
		$nextLine     = $result[$i+1]
	
		if ( ($($currentLine.hash) -eq $($nextLine.hash) ) -or ($($currentLine.hash) -eq $($previousLine.hash)) ) {
			Write-Host "$($currentLine.hash) | $($currentLine.name)  "   -BackgroundColor Red
		} else {
			If (-Not $OnlyDup) {
				Write-Host "$($currentLine.hash) | $(($currentLine).name)" 
			}
		}
	}
}
