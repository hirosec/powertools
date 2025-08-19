<#
	LAST CHANGED: 2025/07/17
	
	powershell -ep bypass -f create-FileInfoRevision.ps1

	https://github.com/RavinduMendis/FIM-powershell

	https://github.com/sdwyersec/File-Integrity-Monitor


	CHANGED
	CREATED
	DELETE


#>
param (
	[switch] $createBaseline,
	[string] $path = 'D:\temp\AD_setup\rockyou'
)



$gitRevision = 'revision.git'

################################################################################
#functions

#hashing function
function hashing($path, $algorithm = "MD5"){
    $fileHash = Get-FileHash -Path $path -Algorithm $algorithm
    return $fileHash
}

#delete baseline if exists
function deleteBaseline(){
    $baselineExists = Test-Path -Path (Join-Path -Path $path $gitRevision)
    if ($baselineExists){
        Remove-Item -Path (Join-Path -Path $path $gitRevision)
        # Write-Host "Old baseline deleted." -ForegroundColor DarkYellow
    }
}

#log message
function Format-FileSize {
    Param
    (
        [Parameter(
            ValueFromPipeline = $true
        )]
        [ValidateNotNullOrEmpty()]
        [float]$number
    )
    Begin{
        $sizes = 'KB','MB','GB','TB','PB'
    }
    Process {
		    $numberStr = "{0:N0}" -f $number
            return "$($numberStr.Replace(',', '.'))"
    }
    End{}
}


###################################################################
### MAIN


Write-Host "------------------------------------------------------------------------"
Write-Host "[+] Path          : $path"  -ForegroundColor Yellow
	

if ($createBaseline) {
        deleteBaseline #calling delete baseline funcion

        $files = Get-ChildItem -Path $path -Recurse -File  #gather files

        #hashing and store in baseline file
        foreach($item in $files){
            $hash = hashing -path $item.FullName
            "$($hash.Path)|$($hash.Hash)|$($item.LastWriteTime.ToString("yyyy-MM-dd HH:mm") )|$($item.Length)" | Out-File -FilePath (Join-Path -Path $path $gitRevision) -Append
            # $item
        }

        Write-Host "`n[$(Get-Date -format s)] New Revision : $gitRevision" -ForegroundColor DarkCyan

}

#store results CHANGED, CREATED, DELETE, n/a  in Arrary
$status = @()

#store baseline file to dictionary
$baselineDictionary = @{}
		
If (Test-Path -Path (Join-Path -Path $path $gitRevision)) {
	$baselineContent = Get-Content -Path (Join-Path -Path $path $gitRevision)
	$baselineTable   = Import-Csv -Path (Join-Path -Path $path $gitRevision) -delimiter '|' -Header FullName, Hash, LastWriteTime, Length
	
	$FileInfo = Get-ChildItem -Path (Join-Path -Path $path $gitRevision)
	Write-Host "[+] Revision Date : $($FileInfo.LastWriteTime.ToString('s'))" -ForegroundColor Yellow
}
	
Write-Host "------------------------------------------------------------------------"

	
foreach($data in $baselineContent) {
	$baselineDictionary.add($data.Split("|")[0], $data.Split("|")[1])
}


$files = Get-ChildItem -Path $path -Recurse -File 

        
foreach ($file in $files) {
	$hash = hashing -path $file.FullName

	if (-not [string]::IsNullOrEmpty($hash.Path)) {
		if($baselineDictionary[$hash.Path] -eq $null) {
			$myObject = [pscustomobject]@{
					status        = 'CREATED'
					name          = $file.Name
					fullname      = $file.FullName
					length        = Format-FileSize $file.Length
					LastWriteTime = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm") 
					Hash          = $($hash.Hash)
					Path          = $file.DirectoryName
			}
		} elseif ($baselineDictionary[$hash.Path] -ne $hash.Hash ) {
			$myObject = [pscustomobject]@{
					status        = 'CHANGED'
					name          = $file.Name
					fullname      = $file.FullName
					length        = Format-FileSize $file.Length
					LastWriteTime = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm") 
					Hash          = $($hash.Hash)
					Path          = $file.DirectoryName
			}
		} else {
			$myObject = [pscustomobject]@{
					status        = ' '
					name          = $file.Name
					fullname      = $file.FullName
					length        = Format-FileSize $file.Length
					LastWriteTime = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
					Hash          = $($hash.Hash)
					Path          = $file.DirectoryName
			}
		}
	}
	
	$status += $myObject
}

#checking file has been deleted
foreach($key in $baselineDictionary.Keys) {
	if (-not [string]::IsNullOrEmpty($key)){
        $existence = Test-Path -Path $key
    
		if(-not $existence) {
			$line = ($baselineTable | Where-Object -Property FullName -eq $key)
						
			$myObject = [pscustomobject]@{
				status        = 'DELETE'
				name          = $(Split-Path -Path $key -Leaf)
				path          = $(Split-Path -Path $key -Parent)
				fullname      = $key
				length        = Format-FileSize $($line.Length)
				LastWriteTime = $($line.LastWriteTime)
				Hash          = $($line.Hash)
			}
						
			$status += $myObject
        }
    }
}

# Print Result Table
$status | Sort-Object -Property  Path, Name | FT status, name, @{n='Length';e={$_.Length};align='right'}, LastWriteTime, Hash, path


