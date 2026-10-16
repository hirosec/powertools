<#
	# LAST CHANGED 2026/10/16
	
	
	powershell -ep bypass -f check-EUVD_v2.ps1
	
	powershell -ep bypass -f check-EUVD_v2.ps1 -latest

	powershell -ep bypass -f check-EUVD_v2.ps1 -vendor "red hat"

	powershell -ep bypass -f check-EUVD_v2.ps1 -XALL
	
	powershell -ep bypass -f check-EUVD_v2.ps1 -version
	powershell -ep bypass -f check-EUVD_v2.ps1 -showVendorList
	
	powershell -ep bypass -f check-EUVD_v2.ps1 -fromScore 9
	
	
	.DESCRIPTION
		ENISA (European Network and Information Security Agency) 
	
	
	%E2%89%A4   ≤ 
	
	ASCII code for the "less than or equal to" symbol (≤) is 243
	Unicode, it is represented as U+2264
	
	
	https://euvd.enisa.europa.eu/apidoc
	
	https://github.com/bytew0lf/EUVD-API   !!!
	
	https://euvd.enisa.europa.eu/search?fromScore=8&toScore=10
	https://euvd.enisa.europa.eu/search?fromScore=8&toScore=10&vendor=Hashicorp
	
	https://euvd.enisa.europa.eu/search?text=CVE-2026-20348
	
	https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-54507
	
		

	https://nvd.nist.gov/vuln/detail/cve-2026-18922
	https://www.rapid7.com/db/vulnerabilities/cve-2026-18922/
	https://access.redhat.com/security/cve/cve-2026-18922
	https://euvd.enisa.europa.eu/vulnerability/cve-2026-18922
	
	
	
	.TODO
		>> change for  "Invoke-WebRequest"  to "Invoke-RestMethod" 
		$URL = "https://euvdservices.enisa.europa.eu/api/enisaid?id=EUVD-2026-70208"
		Invoke-RestMethod -Uri $URL



		$URL = "https://euvdservices.enisa.europa.eu/api/search?text=CVE-2026-2007"
		$data = Invoke-RestMethod -Uri $URL
		
		
	.UPDATE SCRIPT 
		# Create backup of current file and download new binary
		
		$ARCHIVE_PATH    = "Script_Archive"
		$Script_ORIGINAL = "check-EUVD_v2.ps1"
		$Script_UPDATE   = "check-EUVD_v2_UPDATE_$(Get-Date -f 'yyyyMMdd').ps1"
		$Script_BACKUP   = "check-EUVD_v2_BACKUP_$(Get-Date -f 'yyyyMMdd').ps1"
		
		$updateScriptURL = "https://raw.githubusercontent.com/hirosec/powertools/refs/heads/main/scripts/check-EUVD_v2.ps1"


		# Check Online Version
		$WebResponse = (Invoke-WebRequest $updateScriptURL -UseBasicParsing -Headers @{"Cache-Control"="no-cache"}).Content
		foreach ($line in $WebResponse -split "`n") { If ($line -like "*scriptVersion*") { Write-Host "[+] $line"; break }}
		
		# Check Offline version
		$data = GC $Script_ORIGINAL
		foreach ($line in $data -split "`n") { If ($line -like "*scriptVersion*") { Write-Host "[+] $line"; break }}
		
		# Download Latest version from GitHub
		## !!!! Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $Script_UPDATE   !!!!!
		
		
		# Copy curent version to Archive Folder 
		Copy-Item -Path $Script_ORIGINAL -Destination $(Join-Path -Path $ARCHIVE_PATH -ChildPath $Script_BACKUP)
		
		## !!!! Rename-Item -Path $Script_UPDATE -NewName $Script_ORIGINAL
		
#>

param (
	[switch] $XALL,
	[switch] $version,
	[switch] $showVendorList,
	[switch] $latest,
	[string] $vendor = $null,
	[int] $daysBack  = 3,
	[int] $fromScore = 8,
	[int] $maxAge    = 20       # Offline file in minutes
)

$scriptVersion					= "v2.2 - 2026/10/16"
$updateScriptURL             	= "https://raw.githubusercontent.com/hirosec/powertools/refs/heads/main/scripts/check-EUVD_v2.ps1"

$api_ENISA                  	= "https://euvdservices.enisa.europa.eu/api/search?size=100&page=PAGE&fromScore=FROMSCORE&fromDate=FROMDATE"


# URL Monitored Vendor List
$URL_VendorList            		= "https://raw.githubusercontent.com/hirosec/powertools/refs/heads/main/lists/vendorlist.txt"

# Local Monitored Vendor List
$local_VendorList				= "VendorList\Monitored_VendorList.txt"

# Monitored Vendor list, Updated from Github 
$global:vendorList         		= @()

# Vendors and Products to exclude entirely (updated on launch each time from local vendorList !
$global:vendorExcludeList     	= @()

$pathArchive               		= "ENISA_Archive\"	
$pathArchive_VendorList    		= "VendorList\"

$global:ENISA_JSON_File         = $null 
$global:ENISA_JSON_File_Latest  = $null 

# CVE call limited tp 100 calls per hour ?
$Global:cveMetadata_count  		= 0
		

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
				Write-Host "[+] Latest    : $tempStr - MD5: $md5 - Size: $($($bytes.Length) | Convert-Size )" -ForeGroundColor Yellow
				return $null
			}
		}	 
	} catch {
            Write-host "[ERROR] $($_.Exception)" -ForeGroundColor Red
            return $null
	}	
}


Function Launch-ScriptUpgrade {
	# Create backup of current file and download new binary
		
	$ARCHIVE_PATH    = "Script_Archive"
	$Script_ORIGINAL = "check-EUVD_v2.ps1"
	$Script_UPDATE   = "check-EUVD_v2_UPDATE_$(Get-Date -f 'yyyyMMdd').ps1"
	$Script_BACKUP   = "check-EUVD_v2_BACKUP_$(Get-Date -f 'yyyyMMdd').ps1"
		
	$updateScriptURL = "https://raw.githubusercontent.com/hirosec/powertools/refs/heads/main/scripts/check-EUVD_v2.ps1"



		
	# Check Offline version
	Write-Host "`n[+] Current Offline Version" -ForeGroundColor Yellow
	$data = GC $Script_ORIGINAL

	foreach ($line in $data -split "`n") { If ($line.StartsWith('$scriptVersion')) { Write-Host "[+] $line"; break }}
	
	
	# Check Online Version
	Write-Host "`n[+] GitHub Online Version" -ForeGroundColor Yellow
	$WebResponse = (Invoke-WebRequest $updateScriptURL -UseBasicParsing -Headers @{"Cache-Control"="no-cache"}).Content
	foreach ($line in $WebResponse -split "`n") { If ($line.StartsWith('$scriptVersion')) { Write-Host "[+] $line"; break }}
		
	# Download Latest version from GitHub
	## !!!! Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $Script_UPDATE   !!!!!
		
		
	# Copy curent version to Archive Folder 
	Copy-Item -Path $Script_ORIGINAL -Destination $(Join-Path -Path $ARCHIVE_PATH -ChildPath $Script_BACKUP)
		
	## !!!! Rename-Item -Path $Script_UPDATE -NewName $Script_ORIGINAL	
}




# Convert Number to Size format "11.2 KB (11,550 bytes)"

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




# Display Monitored Vendor List

Function Show-VendorList {
	Write-Host "`n[+] Monitored Vendor List"  -ForeGroundColor Yellow
	Write-Host "`------------------------------"
	
	try {	
		$response = Invoke-WebRequest -Uri $URL_VendorList -UseBasicParsing
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
	 
	# Remove Duplicates 
	$global:vendorList = $global:vendorList | Sort-Object -Unique 
	
	
	$global:vendorList | % {
		"[$_]"
	}
	
	Write-Host ""
	Write-Host "[+] Total Count     : $($global:vendorList.Length)"
	
	
	# Save Vendor List to Vendor List Archive Folder
	if (-not(Test-Path $pathArchive_VendorList -PathType Container)) {
		New-Item -path $pathArchive_VendorList -ItemType Directory
	}
	
	$timestamp  = Get-Date -format 'yyyyMMddTHHmm'
	$VendorList = "Monitored_Vendor_List_$($timestamp)_$($global:vendorList.Length).txt"
	
	$global:vendorList | Set-Content -Path $(Join-Path -Path $pathArchive_VendorList -ChildPath $VendorList  )
}




# Download Monitored Vendor List and update Global variable 

Function Get-OnlineVendorList {
	try {	
		$response = Invoke-WebRequest -Uri $URL_VendorList -UseBasicParsing
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
	
	# Remove Duplicates 
	$global:vendorList = $global:vendorList | Sort-Object -Unique 
}


Function Get-LocalVendorList {
	if (! (Test-Path -Path $local_VendorList -PathType Leaf)) {
		Write-Host "[+] WARNING - no local Vendor list"
		return
	}
	
	GC $local_VendorList | % {
		if ($_.StartsWith('!')) {
			$vendor = $_.Split(':')[0].Replace('!', '').Trim()
			$product = $_.Split(':')[1].Trim()
	
			$global:vendorExcludeList +=[PSCustomObject]@{
				vendor         = $vendor
				product        = $product
			}
		} else {
			$vendor = $_.Trim()
			
			if (-not [string]::IsNullOrEmpty($vendor)) {
				$global:vendorList += "$vendor"
			}
		}
	}
	

	
	# Remove Duplicates 
	$global:vendorList = $global:vendorList | Sort-Object -Unique 
}


Function Get-cveMetadata {
	param (
		$cve_id = "CVE-2026-20279"
	)
	
	# Limit Requests to "20 per 1 minute"
	$Global:cveMetadata_count += 1
	
	$URL    = "https://vulnerability.circl.lu/api/vulnerability/$cve_id"
	$URL    = "https://db.gcve.eu/api/vulnerability/$cve_id"
	
	$data = Invoke-RestMethod -Uri $URL

	
	$title     = $data.containers.cna.title
	$baseScore = $data.containers.cna.metrics.cvssV3_1.baseScore
	$product   = $data.containers.cna.affected.product -join ", "
	
	$vendor    = $data.containers.cna.affected.vendor
	
	# check if object is 'string' or 'array' (keep only first item of array)
	if ($vendor -is [array]) {	$vendor    = $data.containers.cna.affected.vendor[0]	} 
	
	
	$description = $($data.containers.cna.descriptions.value)
	$description = $description.Substring(0, [math]::Min(120, $description.Length))
	$description = $description -replace "`r|`n", " "


	[PSCustomObject]@{
		vendor         = $vendor
		product        = $product
		baseScore      = $baseScore
		title          = $title
		description    = $description
	}
}


Function format-Date {
	param (	
		[string] $dateStr,
		[string] $dateTemplate   = "MMM d, yyyy, h:mm:ss tt"    # "May 28, 2026, 4:17:21 PM"
	)	
	
	
	#  ERROR ParseDate ! 'Sep' !!  'Sept' wrong format AbbreviatedMonthNames 
	$Culture = [System.Globalization.CultureInfo]::CreateSpecificCulture('en-US')
	
	try	{
		# [datetime]::ParseExact($dateStr, $dateTemplate, $null).ToString('yyyy.MM.dd HH:mm:ss')
		[datetime]::ParseExact($dateStr, $dateTemplate, $Culture).ToString('yyyy.MM.dd HH:mm:ss')
	} catch {
		Write-Warning "$dateStr | FAIL - Parse Date !" 
		return '2026.10.15 01:02:03'
	}
}


Function calc-Days {
	param (	
		[string] $dateStr,
		[string] $dateTemplate   = "MMM d, yyyy, h:mm:ss tt"    # "May 28, 2026, 4:17:21 PM"
	)	
	
	return (([DateTime]::Now) - ([datetime]::ParseExact($dateStr, $dateTemplate, $null))).Days 
}


Function grep-CVE {
	param (	
		[string] $tmpStr
	)
	
	$tmpCVE = ""
	
	$tmpStr.Split("`n") | % {
		If ($_.StartsWith("CVE-")) {
			$tmpCVE = $_
		}
	}
	
	return "$tmpCVE"
}


# Search in Archive Folder for current JSON VUDB file

Function Get-Latest-Offline-ENISA-JSON {
	param (
		[int] $MaxAge = 60,
		[switch] $showInfo
	)
	
	
	$latestFile = Get-ChildItem -Path $global:pathArchive -Filter "EUVD_ENISA*.json" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1

	If ($latestFile) {
		$FileLastWriteTime = $latestFile.LastWriteTime

		$currentDate = Get-Date
		$FileAge     = $currentDate  - $FileLastWriteTime
		
		[int] $FileAge_TotalMinutes = $FileAge.TotalMinutes
		If ($FileAge_TotalMinutes -le $MaxAge) { 
			$ageColor                = 'green' 
			$global:ENISA_JSON_File_Latest = $($latestFile.FullName)
		} Else {  
			$ageColor = 'red'
		} 

		$jsonData = Get-Content -Path $($latestFile.FullName)
		$data  = $jsonData | ConvertFrom-Json  

		if ($showInfo) {
			Write-Host "[+] Using OFFLINE local JSON file ...".PadRight(120, ' ') -BackGroundColor Yellow -ForeGroundColor Blue
			Write-Host "[+] Most recent file     : $($latestFile.FullName)"
			# Write-Host "[+] File LastWriteTime   : $($FileLastWriteTime.ToString('s'))"
			Write-Host "[+] File Age             : $($FileAge.Days) Days, $($FileAge.Hours) Hours, $($FileAge.Minutes) Minutes  [TotalMinutes : $FileAge_TotalMinutes]"  -ForeGroundColor $ageColor
			Write-Host "[+] Total items          : $($data.Items.Length)"
		}
	}
}

#########################################################################################################
#########################################################################################################
### MAIN


Write-Host ""

Launch-ScriptUpgrade

exit


	
If ($version) {
	$scriptName = $MyInvocation.MyCommand.Name
	$fileInfo = Get-Item $scriptName
	
	Write-Host "`n[+] Script     : $scriptName"
	Write-Host "`n[+] Version   : $scriptVersion - MD5: $((Get-FileHash -Algorithm MD5 -Path $scriptName).Hash) - Size: $($($fileInfo.Length) | Convert-Size )"
	
	Check-LatestScriptVersion
	
	exit
}


If ($showVendorList) {
	Show-VendorList
	
	exit
}

# Update Vendor List and Excluded Vendor:ProductList
Get-OnlineVendorList
Get-LocalVendorList 


# LATEST Flag - Check only for last 24 hours and from CVSS baseScore 8
if ($latest) {
	$daysBack  = 1
	$fromScore = 8
}




If (! [string]::IsNullOrEmpty($vendor)) {
	$latest     = $true
	$vendorList = @()
	$vendorList += $vendor
	
	$daysBack  = [math]::Max($daysBack, 90)  
	$fromScore = 7
	$maxAge    = 0    # Force Download of new Catalog
	
	Write-Host "[+] Vendor    : $vendor" -ForeGroundColor yellow
	
	$api_ENISA                  	= "https://euvdservices.enisa.europa.eu/api/search?size=100&page=PAGE&fromScore=FROMSCORE&fromDate=FROMDATE&vendor=$vendor"
}



### ! Verify if Offline ENISA JSON file is older then 60 min - If YES - Download new database
Get-Latest-Offline-ENISA-JSON -MaxAge $maxAge


# API Parameters: fromDate (YYYY-MM-DD, e.g. fromDate=2023-01-14)
$to_date     = (Get-Date).ToString("yyyy-MM-dd")
$from_date   = (Get-Date).AddDays(-$daysBack).ToString("yyyy-MM-dd")

# ENISA API Parameters: page (integer, starts at 0) max Items returned by 1 call = 100
$page        = 0

# Holds raw JSON polled from ENISA API, and used to save to offline file 
$jsonDataArray = $null
		
# Holds parsed Vulnerability Data		
$vulnInfo = @()
		
do {
	If ($global:ENISA_JSON_File_Latest -eq $Null) {
		# Update/Replace 'page', 'fromDate' and 'fromScore' 
		$URL = $api_ENISA.Replace('PAGE', $page).Replace('FROMDATE', $from_date).Replace('FROMSCORE', $fromScore)
		# Write-Host "[+] API URL   : $URL"
		


		try {
			$response  = Invoke-WebRequest -Uri $URL -UseBasicParsing
			$data      =  ($response.Content | ConvertFrom-Json).items
		
			If ($jsonDataArray -eq $null) {
				# Show message only on first API clla
				Write-Host "[+] Requesting ENISA EUVD API..." -ForeGroundColor Yellow
			}
		
			$jsonDataArray += $data
			$recordsCount = $(($data).Length)
			
			Write-Host "[+] Page: $page  | Records : $recordsCount"
		
			Start-Sleep -m 100
		} catch {
			Write-host "[ERROR] $($_.Exception)" -ForeGroundColor Red
			return $null
		}
	} else {
		Get-Latest-Offline-ENISA-JSON -ShowInfo
		
		$jsonData = Get-Content -Path $($global:ENISA_JSON_File_Latest) -raw
		$data  = $jsonData | ConvertFrom-Json  
		$recordsCount = 0
	}


	$data | % {
			## $_ | FL *
			
	
		
			$idCVE          = grep-CVE $_.aliases
			$datePublished  = $(format-Date($_.datePublished))
			$vendor         = $($_.enisaIdProduct[0].Product.Vendor.Name)
			$productName    = $($_.enisaIdProduct[0].Product.Name) -replace "^(.{60}).*$", '${1}'
			$productVersion = $($_.enisaIdProduct[0].Product_version)  -replace "^(.{50}).*$", '${1}'
			# $vulnDaysBack  	= $(calc-Days  $_.datePublished)
			$inScope 		= $(($global:vendorList -contains $vendor))
			
			# Verify if Vendor:Product is in exclusion list
			$global:vendorExcludeList | % {
				If (($vendor -eq $_.vendor) -And $productName.StartsWith($_.product)) {
					$inScope		=  $false
				}
			}

			$vulnInfo += [PSCustomObject]@{
				id             = $_.id 
				vendor         = $vendor
				product        = $productName + ", " + $productVersion
				CVE            = $($idCVE.Trim())
				baseScore      = $_.baseScore
				datePublished  = $(format-Date($_.datePublished))
				page           = $page
				inScope		   = $inScope	
				CVE_title      = $($cveMetadata.title)
				CVE_vendor     = $($cveMetadata.vendor)
				CVE_product    = $($cveMetadata.product)
				CVE_baseScore  = $($cveMetadata.baseScore)
			}
	}
	
	$page++
} while ($recordsCount -eq 100)


# Create a local dump of JSON file from API calls

If (($global:ENISA_JSON_File_Latest -eq $Null)  -And (! $latest) ) {
	# Create local copy in Archive Folder from JSON file for History and avoid to download current	
	$timestamp                = Get-Date -format 'yyyyMMddTHHmm'
	$global:ENISA_JSON_File   = "EUVD_ENISA_$($timestamp ).json"	
	
	# IMPORTANT : Convert JSON use 'Depth 5'
	$jsonDataArray | ConvertTo-Json -Depth 5 | Set-Content -Path $(Join-Path -Path $pathArchive -ChildPath $global:ENISA_JSON_File)
}


Write-Host "`n"
Write-Host "------------------------------------------------------------------------------------------------------------------------"
Write-Host "[+] ENISA | European Vulnerability Database".PadRight(120, ' ') -ForeGroundColor White -BackGroundColor Blue
Write-Host ""
Write-Host "[+] Date           : $(Get-Date -format 'yyyy-MM-dd HH:mm')"
Write-Host "[+] Version        : $scriptVersion - $((Get-FileHash $($MyInvocation.MyCommand.Name) -algo MD5).Hash)"	
Write-Host "[+] Days back      : $from_date to $to_date (-$daysBack)"
Write-Host "[+] CVSS baseSCore : $fromScore"
Write-Host "------------------------------------------------------------------------------------------------------------------------"
	

if ($latest) {
	# If LATEST SWITCH - Show ALL Vendors in last 24 hours 
	
	$from_date   = (Get-Date).AddDays(-$daysBack)
	$vulnInfo |  Where-Object { $datePublished = [Datetime]::ParseExact($($_.datePublished), 'yyyy.MM.dd HH:mm:ss', $null); $($datePublished -gt $from_date) } | Sort-Object -Property datePublished -Descending | FT datePublished, vendor, Product, CVE, baseScore -AutoSize

	# If LATEST SWITCH do not create CSV file, and run advanced CVE check
	exit
}


$vulnInfo |  Where-Object { $_.inScope } | Sort-Object -Property datePublished -Descending | FT datePublished, vendor, Product, CVE, baseScore -AutoSize

exit

# Create CSV file in ARCHIVE Folder with results 
$currentDateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logFileName     = "ENISA_EUVD_$currentDateTime.csv"

if (-not(Test-Path $pathArchive -PathType Container)) {
    New-Item -path $pathArchive -ItemType Directory
}

# Output to screen
# $vulnInfo | Sort-Object -Property datePublished -Descending | Export-Csv -Path $(Join-Path -Path $pathArchive -ChildPath $logFileName)  -NoTypeInformation -Encoding UTF8 -Force



# Output to file and add CVE Metadata

$vulnInfo_file = @()

$vulnInfo |   % {

	if ($_.inScope) {
		$cveMetadata =  Get-cveMetadata $_.CVE
		Start-Sleep -m 1500
		Write-Host "$Global:cveMetadata_count " -NoNewline
		
		$CVE_title       = $($cveMetadata.title)
		$CVE_vendor      = $($cveMetadata.vendor)
		$CVE_product     = $($cveMetadata.product)
		$CVE_baseScore   = $($cveMetadata.baseScore)
		$CVE_description = $($cveMetadata.description)
	} else {
		$CVE_title       = "."
		$CVE_vendor      = "."
		$CVE_product     = "."
		$CVE_baseScore   = "."
		$CVE_description = "."
	}
	


				
	$vulnInfo_file += [PSCustomObject]@{			
				id              = $_.id 
				vendor          = $_.vendor
				product         = $_.product 
				CVE             = $_.CVE
				baseScore       = $_.baseScore
				datePublished   = $_.datePublished
				page            = $_.page
				inScope		    = $_.inScope
				CVE_title       = $CVE_title
				CVE_vendor      = $CVE_vendor
				CVE_product     = $CVE_product
				CVE_baseScore   = $CVE_baseScore
				CVE_description = $CVE_description
	}
				
}

$vulnInfo_file | Export-Csv -Path $(Join-Path -Path $pathArchive -ChildPath $logFileName)  -NoTypeInformation -Encoding UTF8 -Force

Write-Host "`n"
Write-Host "$('-'*79)"

