<#

	# LAST CHANGED 2026/09/27
	
	
	.DESCRIPTION
		Monitoring newly added exploited vulnerabilities using KEV (Known Exploited Vulnerabilities) Catalog
	
	powershell -ep bypass -f check-KEV_v1.ps1
	
	
	powershell -ep bypass -f check-KEV_v1.ps1 -cve CVE-2026-20079 
	
	# Dump all alerts form all vendors for last 10 days
	powershell -ep bypass -f check-KEV_v1.ps1 -latest
	
	
	# Check version is up-to-date and compare to online script version
	powershell -ep bypass -f check-KEV_v1.ps1 -version
		
	# Validate the Vendor list inline in the script with global online vendor list
	powershell -ep bypass -f check-KEV_v1.ps1 -checkVendorList
	
	
	https://github.com/synfinner/KEVin
	
	
	# URL                      https://cisa.gov/kev
	# URL KEV Commit History   https://cisagov.github.io/kev-data/
	# URL DATA                 https://github.com/cisagov/kev-data
	
	# Best practices API       https://learn.secbyte.org/tools/cisa-kev-api
	
	### JSON Structure Overview
		# High-level metadata about the feed:
		  - title / catalogVersion / count / dateReleased
		
		# An array containing the core records
		- vulnerabilities: 
			.cveID					The official CVE identifier
			.vendorProject			The affected vendor or project
			.product				The affected software or hardware product
			.vulnerabilityName		Descriptive title
			.dateAdded				Date CISA added the entry
			.dueDate				Required remediation deadline
			.shortDescription		Summary of the risk or exploit.
#>			
			
			
#>
param (
	[switch] $version,
	[switch] $latest,
	[string] $vendor = $null,
	[switch] $checkVendorList,
	[string] $cve_id = "CVE-2026-20079", 
	[int] $latestCount = 20,
	[int] $daysBack    = 90
	
)


$scriptVersion    = "v2.0 - 2026/09/27"
$updateScriptURL  = "https://raw.githubusercontent.com/hirosec/powertools/refs/heads/main/scripts/check-KEV_v1.ps1"



# URL KEV data in JSON format
$url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# URL Monitored Vendor List
$csvUrl_VendorList = "https://raw.githubusercontent.com/hirosec/powertools/refs/heads/main/lists/vendorlist.txt"




$global:catalogVersion   = $null
$global:dateReleased     = $null
$global:catalogKEV       = $null
$global:catalogKEV_File  = $null

# Path to Archive with KEV Commit History JSON files
$global:pathArchive    = "KEV_Archive\"	


# Monitored Vendor list - Maintained Updated from Github 
$global:vendorList = @()

	
	
#########################################################################################################

Function Check-LatestScriptVersion {

	try {
		$WebResponse = (Invoke-WebRequest $updateScriptURL -UseBasicParsing -Headers @{"Cache-Control"="no-cache"}).Content
		
		$bytes = [System.Text.Encoding]::UTF8.GetBytes($WebResponse)
		$hash = [System.Security.Cryptography.MD5]::Create().ComputeHash($bytes)
		$md5 = [BitConverter]::ToString($hash) -replace '-', ''
 
		foreach ($line in $WebResponse -split "`n") {

			If ($line -like "*scriptVersion*") {
				$tempStr = [regex]::matches($line,'(?<=\").+?(?=\")').value
				Write-Host "[+] Latest    : $tempStr - $md5" -ForeGroundColor Yellow
				return $null
			}
		}	 
	} catch {
            Write-host "[ERROR] $($_.Exception)" -ForeGroundColor Red
            return $null
	}	
}




# Display Monitored Vendor List

Function Check-VendorList {
	Write-Host "`n[+] Monitored Vendor List"  -ForeGroundColor Yellow
	Write-Host "`------------------------------"
	
	try {	
		$response = Invoke-WebRequest -Uri $csvUrl_VendorList -UseBasicParsing
	} catch {
		Write-host "[ERROR] $($_.Exception)" -ForeGroundColor Red
        return $null
	}	
	
	[string[]] $data = $response.Content.Split([Environment]::NewLine)
	
	$data | % {
		if ($_) {
			$global:vendorList += $_
		}
	 }
	 
	$global:vendorList | Sort-Object  | % {
		"[$_]"
	}
	
	Write-Host ""
	Write-Host "[+] Total Count : $($global:vendorList.Length)"
}


# Download Monitored Vendor List and update Global variable 

Function Get-VendorList {
	try {	
		$response = Invoke-WebRequest -Uri $csvUrl_VendorList -UseBasicParsing
	} catch {
		Write-host "[ERROR] $($_.Exception)" -ForeGroundColor Red
        return $null
	}	
	
	[string[]] $data = $response.Content.Split([Environment]::NewLine)

	
	$data | % {
		if ($_) {
			$global:vendorList += "$_"
		}
	}
}


# Find most recent KEV catalg file in Archive Folder
# If file is older then 60 minutes download new catalog file 

Function Get-Offline-KEVCatalog {
	$latestFile = Get-ChildItem -Path $global:pathArchive -Filter "*.json" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1

	If ($latestFile) {
		$FileLastWriteTime = $latestFile.LastWriteTime

		# Write-host "--------------------------------------------------"
		# Write-Host "Most recent file :  $($latestFile.FullName)"
		# Write-Host "Most recent file :  $($FileLastWriteTime.ToString('s'))"

		$currentDate = Get-Date
		$FileAge     = $currentDate  - $FileLastWriteTime

		[int] $FileAge_TotalMinutes = $FileAge.TotalMinutes
		If ($FileAge_TotalMinutes -le 60) { 
			$ageColor                = 'green' 
			$global:catalogKEV_File  = $latestFile.Name
		
			$data                    = GC $($latestFile.FullName)
			$global:catalogKEV       = $data | ConvertFrom-Json
		} Else {  
			$ageColor = 'red' 
		} 

		Write-Host "[+] KEV Catalog File Age : $($FileAge.Days) Days, $($FileAge.Hours) Hours, $($FileAge.Minutes) Minutes  [TotalMinutes : $FileAge_TotalMinutes]"  -ForeGroundColor $ageColor
	} 
}


Function Download-KEVCatalog {
	$Headers = @{
		"pragma" = "no-cache"
		"cache-control" = "no-cache"
		"ContentType" = "application/json"
	}

	try {	
		$response          = Invoke-WebRequest -Uri  $URL  -Headers $Headers -UseBasicParsing
	} catch {
		Write-host "[ERROR] $($_.Exception)" -ForeGroundColor Red
        return $null
	}	
	
	$global:catalogKEV = $response.Content | ConvertFrom-Json

	# Get Released Date from JSON file
	$UTC_DATE = $($global:catalogKEV.dateReleased)
	$CET_DATE = Get-Date -Date $UTC_DATE  -format 'yyyyMMddTHHmm'

	# Get Vulnerability count from  JSON file
	$count    = $($global:catalogKEV.count)

	$global:catalogKEV_File   = "KEVcatalog_$($CET_DATE)_$($count).json"
	
	if (-not(Test-Path $pathArchive -PathType Container)) {
		New-Item -path $pathArchive -ItemType Directory
	}
	
	$response | Set-Content -Path $(Join-Path -Path $pathArchive -ChildPath $global:catalogKEV_File  )
}



#########################################################################################################
### MAIN
	
If ($version) {
	$scriptName = $MyInvocation.MyCommand.Name
	Write-Host "[+ Script     : $scriptName"
	Write-Host "`n[+] Version   : $scriptVersion - $((Get-FileHash -Algorithm MD5 -Path $scriptName).Hash)"
	Check-LatestScriptVersion
	
	exit
}


If ($checkVendorList) {
	Check-VendorList
	exit
}


$offsetDate = (Get-Date).AddDays(-$daysBack).ToString("yyyy-MM-dd")



Write-Host "`n"
Write-Host "------------------------------------------------------------------------------------------------------------------------"
Write-Host "CISA KEV (Known Exploited Vulnerabilities) Catalog".PadRight(120, ' ') -ForeGroundColor White -BackGroundColor Blue
Write-Host ""
Write-Host "[+] Date                 : $(Get-Date -format 'yyyy-MM-dd HH:mm')"
Write-Host "[+] Version              : $scriptVersion - $((Get-FileHash $($MyInvocation.MyCommand.Name) -algo MD5).Hash)"	
Write-Host "[+] Days back            : $offsetDate (-$daysBack)"
Write-Host ""

Get-VendorList


# Find latest Offline KEV catalg
Get-Offline-KEVCatalog

# If Offline KEV catalg is NOT current (less 60 min) > download new file
If (! $global:catalogKEV) {
	Download-KEVCatalog
}

# Convert Catalog Time from UTC to CET
$UTC_DATE   = $($global:catalogKEV.dateReleased)
$CET_DATE   = Get-Date -Date $UTC_DATE  -format 'yyyyMMddTHHmm'


Write-Host "[+] dateReleased         : $($global:catalogKEV.dateReleased) | $CET_DATE"
Write-Host "[+] count                : $($global:catalogKEV.count)"	
Write-Host "[+] KEV catalog filename : $($global:catalogKEV_File)"
Write-Host "------------------------------------------------------------------------------------------------------------------------"


$vulnInfo = @()
$countRows = 0

$global:catalogKEV.vulnerabilities | % {
	$countRows++ 
	$vendor = $($_.vendorProject)
	
	if ($latest) {
		$inScope = $true
	} else {
		$inScope     = $(($global:vendorList -contains $vendor))
		$latestCount = 9999
	}


	# Check if the current date is within the range
	$dateAdded  = $_.dateAdded
	$dateCheck = ($dateAdded -ge $offsetDate)

	If ( ($inScope -and $dateCheck -and $countRows -le $latestCount)) {
			$vulnInfo += [PSCustomObject]@{
				cveID         	 	= $_.cveID 
				vendor         		= $_.vendorProject
				product        		= $_.product
				vulnerabilityName   = $_.vulnerabilityName
				dateAdded         	= $_.dateAdded
				shortDescription	= $_.shortDescription
			}
	}
	
	$onlySingleCVE = $false
	
	if ($onlySingleCVE) {
		if ($_.cveID -eq $cve_id) {
			Write-Host "cveID             : $($_.cveID)" -ForeGroundColor yellow
			Write-Host "vendorProject     : $($_.vendorProject)" 
			Write-Host "product           : $($_.product)" 
			Write-Host "vulnerabilityName : $($_.vulnerabilityName)" 
			Write-Host "dateAdded         : $($_.dateAdded)" 		
			Write-Host "shortDescription  : $($_.shortDescription)" 		
		}
	}	
}

$vulnInfo | Sort-Object -Property dateAdded -Descending  | FT dateAdded, cveID, vendor, product, vulnerabilityName  -AutoSize 





