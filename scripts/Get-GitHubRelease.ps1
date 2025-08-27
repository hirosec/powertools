<#
	LAST CHANGED: 2025/08/27 - version 1.0.0

	powershell -ep bypass -f Get-GitHubRelease.ps1 

	powershell -ep bypass -f Get-GitHubRelease.ps1 -RepoOwner The-Viper-One -RepoName PsMapExec


	.INFO
		https://github.com/asheroto/ChocolateyPackages/blob/master/Chocolatey-Package-Updater.ps1


#>
param (
	[string] $RepoOwner        	= "hirosec",
	[string] $RepoName          = "powertools",
	[switch]$Version
)


$CurrentVersion = '1.0.0'
$PublishedAt    = '2025-08-27'

# Display version if -Version is specified
if ($Version.IsPresent) {
	Write-Host "Version         : $CurrentVersion"
	Write-Host "Published at    : $PublishedAt"
    exit 0
}


function Get-GitHubRelease {
    <#
        .SYNOPSIS
        Fetches the latest release information of a GitHub repository.

        .DESCRIPTION
        This function uses the GitHub API to get information about the latest release of a specified repository, including its version and the date it was published.

        .PARAMETER Owner
        The GitHub username of the repository owner.

        .PARAMETER Repo
        The name of the repository.
    #>
    [CmdletBinding()]
    param (
        [string]$Owner,
        [string]$Repo
    )
    try {
        $url = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
        $response = Invoke-RestMethod -Uri $url -ErrorAction Stop

        $latestVersion = $response.tag_name
        $publishedAt = $response.published_at

        # Convert UTC time string to local time
        $UtcDateTime = [DateTime]::Parse($publishedAt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        # $PublishedLocalDateTime = $UtcDateTime.ToLocalTime()
        $PublishedLocalDateTime = $UtcDateTime.ToString('yyyy-MM-dd HH:mm')

        [PSCustomObject]@{
            LatestVersion     = $latestVersion
            PublishedDateTime = $PublishedLocalDateTime
        }
    } catch {
        Write-Error "Unable to check for updates.`nError: $_"
        exit 1
    }
}


###################################################################################
### Main

$Data = Get-GitHubRelease -Owner $RepoOwner -Repo $RepoName

Write-Host ""
Write-Host "Repository      : https://github.com/$RepoOwner/$RepoName/releases"
Write-Host "Latest version  : $($Data.LatestVersion)"
Write-Host "Published at    : $($Data.PublishedDateTime)"
