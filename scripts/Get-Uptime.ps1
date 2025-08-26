<#
	Last Changed: 2025-08-26  - v1.0
	
	powershell -ep bypass -f Get-Uptime.ps1
	
	powershell "iex (iwr https://raw.githubusercontent.com/hirosec/powertools/refs/heads/main/scripts/Get-Uptime.ps1 -UseBasicParsing)"
#>

$lastBoot = (Get-WmiObject win32_operatingsystem).LastBootUpTime
$bootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($lastBoot)

Write-Host "`nDate           : " -ForeGroundColor Green -NoNewLine
Write-Host "$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')"

Write-Host "LastBootUpTime : " -ForeGroundColor Green -NoNewLine
Write-Host "$($bootTime.ToString('yyyy-MM-dd hh:mm:ss'))"

$uptime = (Get-Date) - $bootTime

# Uptime in days, hours, minutes, and seconds
$days = $uptime.Days
$hours = $uptime.Hours
$minutes = $uptime.Minutes


Write-Host ("Uptime         : " -f $days, $hours, $minutes, $seconds) -ForegroundColor Green -NoNewLine
Write-Host ("{0} days, {1} hours, {2} minutes" -f $days, $hours, $minutes) 