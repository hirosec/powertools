<#

	# LAST CHANGED 2026/08/14
	
	European Network and Information Security Agency
	
	powershell -ep bypass -f check-EUVD.ps1

	powershell -ep bypass -f check-EUVD.ps1 -vendor "red hat"

	powershell -ep bypass -f check-EUVD.ps1 -XALL
	
	powershell -ep bypass -f check-EUVD.ps1 -version
	
	
	
	
	https://euvd.enisa.europa.eu/apidoc
	
	https://github.com/bytew0lf/EUVD-API   !!!
	
	https://euvd.enisa.europa.eu/search?fromScore=8&toScore=10
	https://euvd.enisa.europa.eu/search?fromScore=8&toScore=10&vendor=Hashicorp
	
	https://euvd.enisa.europa.eu/search?text=CVE-2026-20348
	
	https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-54507

#>

param (
	[switch] $XALL,
	[switch] $version,
	[string] $vendor = $null,
	[int] $daysBack  = 3,
	[int] $fromScore = 7
)


$scriptVersion    = "v1.1 - 2026/08/16a"
$updateScriptURL  = "https://raw.githubusercontent.com/hirosec/powertools/refs/heads/main/scripts/check-EUVD.ps1"

$api_URL          = "https://euvdservices.enisa.europa.eu/api/search?size=100&page=NNNN&fromScore=7.6&toScore=10&fromDate=yyyy-MM-dd"
$api_URL_vendor   = "https://euvdservices.enisa.europa.eu/api/search?size=100&page=NNNN&fromScore=FROMSCORE&toScore=10&fromDate=yyyy-MM-dd&vendor=VENDOR"



$vendorList = @(
		'cisco',
		'f5',
		'Oracle Corporation',
		'Microsoft',
		'Red Hat',
		'redhat'
		'IBM',
		'Apache',
		'Apache Software Foundation',
		'Juniper',
		'Bluecat',
		'Splunk',
#		'Linux',
		'VMware',
		'Jenkins Project',
		'HCLSoftware',
#		'hackerone',
		'tenable',
		'dell',
		'Sonatype',
		'Grafana',
		'Hashicorp',
		'Elastic'		
)
	
$pathArchive = "ENISA_Archive\"	
		

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
### MAIN

Write-Host "[+] Date      : $(Get-Date -format 'yyyy-MM-dd HH:mm')"
Write-Host "[+] Version   : $scriptVersion - $((Get-FileHash $($MyInvocation.MyCommand.Name) -algo MD5).Hash)"
	
If ($version) {
	Check-LatestScriptVersion
	
	exit
}




$pageBack = 2

If (! [string]::IsNullOrEmpty($vendor)) {
	$vendorList = @()
	$vendorList += $vendor
	
	$daysBack = 90
	$pageBack = 5
	
	Write-Host "[+] Vendor    : $vendor" -ForeGroundColor yellow
}


$offsetDate = (Get-Date).AddDays(-$daysBack).ToString("yyyy-MM-dd")

Write-Host "[+] Days back : $offsetDate (-$daysBack)"
Write-Host "`n"



$vulnInfo = @()

foreach ($vendor in $vendorlist) {
	Write-Host "[+] $vendor"
			
	for ($page = 0; $page -lt $pageBack; $page++) {
		# Update/Replace 'page' and from 'fromDate' 
		$URL = $api_URL_vendor.Replace('NNNN', $page).Replace('yyyy-MM-dd', $offsetDate).Replace('VENDOR', $vendor).Replace('FROMSCORE', $fromScore)
	
		# Write-Host "[+] API URL   : $URL"


		try {
			$data    = Invoke-WebRequest -Uri $URL -UseBasicParsing
		} catch {
			Write-host "[ERROR] $($_.Exception)" -ForeGroundColor Red
            return $null
		}
	
		$jsonObj =  $data.Content | ConvertFrom-Json


		$jsonObj.items | % {
			$idCVE          = grep-CVE $_.aliases
			$datePublished  = $(format-Date($_.datePublished))
			$vendor        = $($_.enisaIdProduct[0].Product.Vendor.Name)
			$product       = $($_.enisaIdProduct[0].Product.Name) -replace "^(.{45}).*$", '${1}'
			$vulnDaysBack  = $(calc-Days  $_.datePublished)
		
			$vulnInfo += [PSCustomObject]@{
				id             = $_.id 
				vendor         = $vendor
				product        = $product
				CVE            = $idCVE
				baseScore      = $_.baseScore
				datePublished  = $(format-Date($_.datePublished))
				page           = $page
			}
		}
	}	
}
	
$vulnInfo | Sort-Object -Property datePublished -Descending | FT datePublished, vendor, Product, CVE, baseScore, id, page -AutoSize


$currentDateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logFileName     = "ENISA_EUVD_$currentDateTime.csv"

if (-not(Test-Path $pathArchive -PathType Container)) {
    New-Item -path $pathArchive -ItemType Directory
}

$vulnInfo | Sort-Object -Property datePublished -Descending | Export-Csv -Path $(Join-Path -Path $pathArchive -ChildPath $logFileName)  -NoTypeInformation -Encoding UTF8 -Force