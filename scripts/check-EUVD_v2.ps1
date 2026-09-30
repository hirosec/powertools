<#

	# LAST CHANGED 2026/09/30
	

	
	powershell -ep bypass -f check-EUVD_v2.ps1

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
		
		$data.items
		
		"$($data.items.id) | $($data.items.enisaIDVendor) | $($data.items.enisaIDProduct) | $($data.items.alias) | $($data.items.baseScore) | $($data.items.datePublished)"

#>

param (
	[switch] $XALL,
	[switch] $version,
	[switch] $showVendorList,
	[string] $vendor = $null,
	[int] $daysBack  = 3,
	[int] $fromScore = 7
)


$scriptVersion             = "v2.0d - 2026/09/29"
$updateScriptURL           = "https://raw.githubusercontent.com/hirosec/powertools/refs/heads/main/scripts/check-EUVD_v2.ps1"
$updateScriptURL


$api_URL                   = "https://euvdservices.enisa.europa.eu/api/search?size=100&page=NNNN&fromScore=7.6&toScore=10&fromDate=yyyy-MM-dd"
$api_URL_vendor            = "https://euvdservices.enisa.europa.eu/api/search?size=100&page=NNNN&fromScore=FROMSCORE&toScore=10&fromDate=yyyy-MM-dd"


# URL Monitored Vendor List
$URL_VendorList            = "https://raw.githubusercontent.com/hirosec/powertools/refs/heads/main/lists/vendorlist.txt"

# Monitored Vendor list, Updated from Github 
$global:vendorList         = @()

$pathArchive               = "ENISA_Archive\"	
$pathArchive_VendorList    = "VendorList\"
$Global:cveMetadata_count  = 0
		

#########################################################################################################

Function OLD_Check-LatestScriptVersionOLD {

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

Function Get-VendorList {
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
	
	[datetime]::ParseExact($dateStr, $dateTemplate, $null).ToString('yyyy.MM.dd HH:mm:ss')
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
			# return "[$tmpCVE]"
		}
	}
	
	return "$tmpCVE"
}

#########################################################################################################
#########################################################################################################
### MAIN

Write-Host ""
	
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


Get-VendorList

# Used to cycle through all results (API return only 100 entries by call
$pageBack = 8


<#
If (! [string]::IsNullOrEmpty($vendor)) {
	$vendorList = @()
	$vendorList += $vendor
	
	$daysBack = 20
	$pageBack = 5
	
	Write-Host "[+] Vendor    : $vendor" -ForeGroundColor yellow
}
#>

$offsetDate = (Get-Date).AddDays(-$daysBack).ToString("yyyy-MM-dd")

$vulnInfo = @()

			
for ($page = 0; $page -lt $pageBack; $page++) {
		# Update/Replace 'page' and from 'fromDate' 
		$URL = $api_URL_vendor.Replace('NNNN', $page).Replace('yyyy-MM-dd', $offsetDate).Replace('FROMSCORE', $fromScore)
	
		# Write-Host "[+] API URL   : $URL"


		try {
			$data    = Invoke-WebRequest -Uri $URL -UseBasicParsing
			Start-Sleep -m 200
		} catch {
			Write-host "[ERROR] $($_.Exception)" -ForeGroundColor Red
            return $null
		}
	
		$jsonObj =  $data.Content | ConvertFrom-Json


		$jsonObj.items | % {
			$idCVE          = grep-CVE $_.aliases
			$datePublished  = $(format-Date($_.datePublished))
			$vendor         = $($_.enisaIdProduct[0].Product.Vendor.Name)
			$productName    = $($_.enisaIdProduct[0].Product.Name) -replace "^(.{60}).*$", '${1}'
			$productVersion = $($_.enisaIdProduct[0].Product_version)  -replace "^(.{50}).*$", '${1}'
			$vulnDaysBack  	= $(calc-Days  $_.datePublished)
			$inScope 		= $(($vendorList -contains $vendor))
			
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
}	



	
	
Write-Host "`n"
Write-Host "------------------------------------------------------------------------------------------------------------------------"
Write-Host "[+] ENISA | European Vulnerability Database".PadRight(120, ' ') -ForeGroundColor White -BackGroundColor Blue
Write-Host "[+] Date      : $(Get-Date -format 'yyyy-MM-dd HH:mm')"
Write-Host "[+] Version   : $scriptVersion - $((Get-FileHash $($MyInvocation.MyCommand.Name) -algo MD5).Hash)"	
Write-Host "[+] Days back : $offsetDate (-$daysBack)"
Write-Host "------------------------------------------------------------------------------------------------------------------------"
	
$vulnInfo |  Where-Object { $_.inScope } | Sort-Object -Property datePublished -Descending | FT datePublished, vendor, Product, CVE, baseScore -AutoSize

exit
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


