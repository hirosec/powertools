<#
	Last Changed: 2025-12-09  - v1.0

	$profile ->     Directory: C:\Users\<USER>\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1

	https://lazyadmin.nl/powershell/powershell-profile/
	
#>

Function Get-RecommendedTake {

	$urlList = @(
		"https://sc1.checkpoint.com/documents/Jumbo_HFA/R81.10/R81.10/R81.10_Downloads.htm",
		"https://sc1.checkpoint.com/documents/Jumbo_HFA/R81.20/R81.20/R81.20_Downloads.htm",
		"https://sc1.checkpoint.com/documents/Jumbo_HFA/R82/R82.00/R82_Downloads.htm"
	)
	
	"`nDate : $(Get-Date -format s)`n"

	$JumboInfo = @()	
	
	$urlList | % {
			$url = $_
	
			try {
				$response = Invoke-WebRequest -Uri $url #-ErrorAction SilentlyContinue -UseBasicParsing -DisableKeepAlive
			} catch {
				$response = $null
			}
 
			$LatestTake = " "

			# If the HTTP status code is 200 (OK), write "OK" to the console with a green background
			if ($response.StatusCode -eq 200) {

				$response.RawContent -Split "`n" | % {
				$line = $_

				$posIndex = $line.IndexOf('<h1>')

				If ($posIndex -ne -1) {
					$cleanText = $line -replace '<[^>]+>', ''
					$Version = $cleanText.Replace(' Jumbo Hotfix Accumulator Downloads','').Trim()
				}

				$posIndex = $line.IndexOf('<h3>')

				If ($posIndex -ne -1) {
					$cleanText = $line -replace '<[^>]+>', ''
		
					if ($cleanText -like "*Recommended*") {
						$RecommdedTake = $cleanText.Replace(' - Recommended','').Trim()
					}
		
					
					if ($cleanText -like "*Latest*") {
						$LatestTake = $cleanText.Replace(' - Latest','').Trim()
					} 
				}
			}
	
	
			$JumboInfo += [PSCustomObject]@{
					Version      = "$($version)"
					Recommended  = "$($RecommdedTake)"
					Latest       = "$($LatestTake)"
			}
		}
	}

	$JumboInfo
}


