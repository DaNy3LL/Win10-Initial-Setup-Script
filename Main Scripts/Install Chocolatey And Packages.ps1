# Description:
# This script will use Windows package manager to bootstrap Chocolatey and install a list of packages.
# The script will also install Sysinternals Utilities into your default drive's root directory.
# NOTE: Those are the apps that I like to install. You are free to adopt it to your personal taste.

$packages = @(
	"7zip.install"
	"audacity"
	"dotnet4.5"
	"firefox"
	"gimp"
	"googledrive"
	"handbrake.install"
	"jre8"
	"k-litecodecpackfull"
	"keepass.install"
	"keepass-keepasshttp"
	"libreoffice"
	"notepadplusplus.install"
	"putty"
	"python"
	"python2"
	"qbittorrent"
	"sharex"
	"silverlight"
	"skype"
	"spotify"
	"sumatrapdf.install"
	"teamviewer"
	"thunderbird"
	"vlc"
	"winscp"
	"sysinternals"
)

Write-Host "Setting up Chocolatey in software package manager"
Get-PackageProvider -Name chocolatey -Force

Write-Host "Setting up full Chocolatey install"
Install-Package -Name Chocolatey -Force -ProviderName chocolatey
$chocopath = (Get-Package chocolatey | ?{$_.Name -eq "chocolatey"} | Select @{N="Source";E={((($a=($_.Source -split "\\"))[0..($a.length - 2)]) -join "\"),"Tools\chocolateyInstall" -join "\"}} | Select -ExpandProperty Source)
& $chocopath "upgrade all -y"
choco install chocolatey-core.extension --force

Write-Host "Creating daily task to automatically upgrade Chocolatey packages"
# Adapted from https://blogs.technet.microsoft.com/heyscriptingguy/2013/11/23/using-scheduled-tasks-and-scheduled-jobs-in-powershell/
$ScheduledJob = @{
	Name = "Chocolatey Daily Upgrade"
	ScriptBlock = {choco upgrade all -y}
	Trigger = New-JobTrigger -Daily -at 2am
	ScheduledJobOption = New-ScheduledJobOption -RunElevated -MultipleInstancePolicy StopExisting -RequireNetwork
}
Register-ScheduledJob @ScheduledJob

Write-Host "Installing Packages"
$packages | %{choco install $_ --force -y}

Write-Host "Installing Sysinternals Utilities to C:\Sysinternals"
$download_uri = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$wc = new-object net.webclient
$wc.DownloadFile($download_uri, "/SysinternalsSuite.zip")
Add-Type -AssemblyName "system.io.compression.filesystem"
[io.compression.zipfile]::ExtractToDirectory("/SysinternalsSuite.zip", "/Sysinternals")
Write-Host "Removing temporary file"
rm "/SysinternalsSuite.zip"
