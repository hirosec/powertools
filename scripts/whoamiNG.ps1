# 2025/08/14 - v1.00

function Get-First {
    [CmdletBinding()]
    [OutputType([string])]
    Param( $List )
    [Regex]$reg = "\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}"
    $result = ""
    foreach ($ip in $List)     {
        $match = $reg.Match($ip)
        if ($match.Success)         {
            $result = $match.Groups[0].Value
            break
        }
    }
    $result
}


$NICIndex = Get-CimInstance -ClassName Win32_IP4RouteTable |  Where-Object { $_.Destination -eq "0.0.0.0"-and $_.Mask -eq "0.0.0.0" } |  Sort-Object Metric1 | Select-Object -First 1 | Select-Object -ExpandProperty InterfaceIndex
$AdapterConfig = Get-CimInstance -ClassName Win32_NetworkAdapter |     Where-Object { $_.InterfaceIndex -eq $NICIndex } |     Get-CimAssociatedInstance -ResultClassName Win32_NetworkAdapterConfiguration

$fqdn = [System.Net.Dns]::GetHostEntry($(Get-First $AdapterConfig.IPAddress)).HostName

	
$IsElevated     = (whoami /all | select-string S-1-16-12288) -ne $null	
$IsBUILTINAdmin = (whoami /all | select-string S-1-5-32-544) -ne $null	

$OSName         = (Get-WmiObject -class Win32_OperatingSystem).Caption
$OSVersion      = (Get-WmiObject -class Win32_OperatingSystem).Version
$DisplayVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion -ErrorAction Ignore).DisplayVersion

Write-Host ""
Write-Host "Date          : $(Get-Date -format s)"
Write-Host "Name          : $((([Security.Principal.WindowsIdentity]::GetCurrent()).Name))"
Write-Host "SID           : $((([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value))"
Write-Host "BUILTIN\Admin : $IsBUILTINAdmin"
Write-Host "IsElevated    : $IsElevated"
Write-Host "Hostname      : $env:COMPUTERNAME"
Write-Host "OSName        : $OSName"
Write-Host "OSVersion     : $OSVersion"
Write-Host "Build         : $DisplayVersion"
Write-Host ""
Write-Host "Address       : $(Get-First $AdapterConfig.IPAddress)"
Write-Host "Netmask       : $(Get-First $AdapterConfig.IPSubnet)"
Write-Host "Gateway       : $(Get-First $AdapterConfig.DefaultIPGateway)"
Write-Host "FQDN          : $fqdn"
Write-Host "DNSDomain     : $($AdapterConfig.DNSDomain)"
Write-Host "DNSSearch     : $($AdapterConfig.DNSDomainSuffixSearchOrder)"
Write-Host ""


