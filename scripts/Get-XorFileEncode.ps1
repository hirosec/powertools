# Copyright (c) HIROSEC. All rights reserved.
# Licensed under the MIT License.

# LAST CHANGED: 2025/09/25 - v1.00


function Get-XorFile {
	param (
		[string] $inFile,
		[string] $outFile,
		[int] $xorKey = 0x12
	)
	
	$bytes = [System.IO.File]::ReadAllBytes($inFile)

	$len = $bytes.Count
	$xord_byte_array = New-Object Byte[] $len


	for($i=0; $i -lt $len ; $i++) {
		$xord_byte_array[$i] = $bytes[$i] -bxor $xorKey
	}

	[System.IO.File]::WriteAllBytes($outFile, $xord_byte_array)
}
