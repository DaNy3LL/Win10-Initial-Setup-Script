######################################################################
# Win10/WinServer2016 Initial Setup Script
######################################################################
# Custom tweaks by DaNy3LL
######################################################################

# Default preset
$tweaks = @(
	############# Require administrator privileges
	"RequireAdmin",

	############# Perform registry backup before doing anything
	"BackupRegistryFiles",

	############# Privacy Tweaks
	"DisableDeviceSyncing",					# "EnableDeviceSyncing",
	"DisableAppLaunchTracking", 			# "EnableAppLaunchTracking",
	"DisableSettingsExperimentation",		# "EnableSettingsExperimentation",
	"DisableTypingInfo",					# "EnableTypingInfo",
	"DisableAccessToLanguage",				# "EnableAccessToLanguage",
	"DisableLocationTracking",				# "EnableLocationTracking",
	"DisableMapUpdates",					# "EnableMapUpdates",
	"DisableBluetoothAds",					# "EnableBluetoothAds",
	"RestrictAccessToCamera",				# "GiveAccessToCamera",
	"RestrictAccessToMic",					# "GiveAccessToMic",
	"RestrictAccessToNotifications",		# "GiveAccessToNotifications",
	"RestrictAccountInfo",					# "GiveAccessToAccountInfo",
	"RestrictAccessToContacts",				# "GiveAccessToContacts",
	"RestrictAccessToCalendar",				# "GiveAccessToCalendar",
	"RestrictAccessToCallHistory",			# "GiveAccessToCallHistory",
	"RestrictAccessToEmail",				# "GiveAccessToEmail",
	"RestrictAccessToTasks",				# "GiveAccessToTasks",
	"RestrictAccessToMessages",				# "GiveAccessToMessages",
	"RestrictAccessToRadio",				# "GiveAccessToRadio",
	"DisableAppDiagnostics",				# "EnableAppDiagnostics",
	"DisableTipsAboutWindows",				# "EnableTipsAboutWindows",
	"DisableHandwritingData",				# "EnableHandwritingData",
	"DisableCEIP",							# "EnableCEIP",
	"DisableAIT",							# "EnableAIT",
	"DisableACPI",							# "EnableACPI",
	"DisableDefenderReporting",				# "EnableDefenderReporting",
	"DisableSpotlight",						# "EnableSpotlight",
	"DisableWindowsServices",				# "EnableWindowsServices",
	"DisableScheduledTasks",				# "EnableScheduledTasks",
	
	############# Other Tweaks
	"InstallNETFramework35",				# "UninstallNETFramework35",
	"EnableOldVolumeMixer",					# "DisableOldVolumeMixer",
	"SetPowerPlan(`"High performance`")"	# "SetPowerPlan(`"Balanced`")"
)

#####################################
# Tweaks #
#####################################

# Create shortcut for HKCR
If (!(Test-Path "HKCR:")) {
	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}

# Perform a registry backup
Function BackupRegistryFiles {
	$date = (Get-Date).ToString('dd_MM_yyyy_HH_mm_ss')
	Write-Host "Performing a registry backup..."
	New-Item -ItemType Directory -Path $env:SYSTEMDRIVE\RegistryBackup\$date | Out-Null
	$RegistryTrees = ("HKLM", "HKCU", "HKCR", "HKU", "HKCC")
	Foreach ($Item in $RegistryTrees) {
		reg export $Item $env:SYSTEMDRIVE\RegistryBackup\$date\$Item.reg | Out-Null
	}
}

# Enable Controlled Folder Access
Function EnableControlledFolderAccess {
	Write-Host "Enabling Controlled Folder Access..."
	Set-MpPreference -EnableControlledFolderAccess Enabled
}

# Disable Controlled Folder Access
Function DisableControlledFolderAccess {
	Write-Host "Disabling Controlled Folder Access..."
	Set-MpPreference -EnableControlledFolderAccess Disabled
}

# Disable device syncing
Function DisableDeviceSyncing {
	Write-Host "Disabling device syncing..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Value" -Type String -Value "Deny"
}

# Enable device syncing
Function EnableDeviceSyncing {
	Write-Host "Enabling device syncing..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Value" -Type String -Value "Allow"
}

# Disable app launch tracking
Function DisableAppLaunchTracking {
	Write-Host "Disabling app launch tracking..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 0
}

# Enable app launch tracking
Function EnableAppLaunchTracking {
	Write-Host "Enabling app launch tracking..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 1
}

# Disable Settings experimentation
Function DisableSettingsExperimentation {
	Write-Host "Disabling Settings experimentation..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System" -Name "AllowExperimentation" -Type DWord -Value 0
}

# Enable Settings experimentation
Function EnableSettingsExperimentation {
	Write-Host "Enabling Settings experimentation..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System" -Name "AllowExperimentation" -ErrorAction SilentlyContinue
}

# Disable sending informations to Microsoft about typing and writing
Function DisableTypingInfo {
	Write-Host "Enable sending informations about typing and writing..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Type DWord -Value 0
}

# Enable sending informations to Microsoft about typing and writing
Function EnableTypingInfo {
	Write-Host "Disable sending informations about typing and writing..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Type DWord -Value 1
}

# Disable websites acces to language list
Function DisableAccessToLanguage {
	Write-Host "Disable websites acces to language list..."
	Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1
}

# Enable websites acces to language list
Function EnableAccessToLanguage {
	Write-Host "Enable websites acces to language list..."
	Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 0
}

# Disable Location Tracking
Function DisableLocationTracking {
	Write-Host "Disabling Location Tracking..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
}

# Enable Location Tracking
Function EnableLocationTracking {
	Write-Host "Enabling Location Tracking..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 1
}

# Disable Automatic Map Updates
Function DisableMapUpdates {
	Write-Host "Disabling automatic map updates..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
}

# Enable Automatic Map Updates
Function EnableMapUpdates {
	Write-Host "Enable automatic map updates..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 1
}

# Disable Bluetooth ads
Function DisableBluetoothAds {
	Write-Host "Disabling Bluetooth ads..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" -Name "AllowAdvertising" -Type DWord -Value 0
}

# Enable Bluetooth ads
Function EnableBluetoothAds {
	Write-Host "Enabling Bluetooth ads..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" -Name "AllowAdvertising" -ErrorAction SilentlyContinue
}

# Restrict apps acces to camera
Function RestrictAccessToCamera {
	Write-Host "Restricting apps acces to camera..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" -Name "Value" -Type String -Value "Deny"
}

# Give apps acces to camera
Function GiveAccessToCamera {
	Write-Host "Giving apps acces to camera..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" -Name "Value" -Type String -Value "Allow"
}

# Restrict apps acces to microphone
Function RestrictAccessToMic {
	Write-Host "Restricting apps acces to microphone..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" -Name "Value" -Type String -Value "Deny"
}

# Give apps acces to microphone
Function GiveAccessToMic {
	Write-Host "Giving apps acces to Microphone..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" -Name "Value" -Type String -Value "Allow"
}

# Restrict access to notificatons
Function RestrictAccessToNotifications {
	Write-Host "Restricting apps acces to notifications..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" -Name "Value" -Type String -Value "Deny"
}

# Give access to notificatons
Function GiveAccessToNotifications {
	Write-Host "Giving apps acces to notifications..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" -Name "Value" -Type String -Value "Allow"
}

# Restrict apps acces to name, picture & account info
Function RestrictAccountInfo {
	Write-Host "Restricting apps acces to account information..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" -Name "Value" -Type String -Value "Deny"
}

# Give apps acces to name, picture & account info
Function GiveAccessToAccountInfo {
	Write-Host "Giving apps acces to account information..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" -Name "Value" -Type String -Value "Allow"
}

# Restrict apps acces to contacts
Function RestrictAccessToContacts {
	Write-Host "Restricting apps acces to contacts..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" -Name "Value" -Type String -Value "Deny"
}

# Give apps acces to contacts
Function GiveAccessToContacts {
	Write-Host "Giving apps acces to contacts..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" -Name "Value" -Type String -Value "Allow"
}

# Restrict apps acces to calendar
Function RestrictAccessToCalendar {
	Write-Host "Restricting apps acces to calendar..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" -Name "Value" -Type String -Value "Deny"
}

# Give apps acces to calendar
Function GiveAccessToCalendar {
	Write-Host "Giving apps acces to calendar..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" -Name "Value" -Type String -Value "Allow"
}

# Restrict apps acces to call history
Function RestrictAccessToCallHistory {
	Write-Host "Restricting apps acces to call history..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Name "Value" -Type String -Value "Deny"
}

# Give apps acces to call history
Function GiveAccessToCallHistory {
	Write-Host "Giving apps acces to call history..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Name "Value" -Type String -Value "Allow"
}

# Restrict apps acces to email
Function RestrictAccessToEmail {
	Write-Host "Restricting apps acces to email..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" -Name "Value" -Type String -Value "Deny"
}

# Give apps acces to email
Function GiveAccessToEmail {
	Write-Host "Giving apps acces to email..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" -Name "Value" -Type String -Value "Allow"
}

# Restrict apps acces to tasks
Function RestrictAccessToTasks {
	Write-Host "Restricting apps acces to tasks..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" -Name "Value" -Type String -Value "Deny"
}

# Give apps acces to tasks
Function GiveAccessToTasks {
	Write-Host "Giving apps acces to tasks..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" -Name "Value" -Type String -Value "Allow"
}

# Restrict apps acces to messages
Function RestrictAccessToMessages {
	Write-Host "Restricting apps acces to messages..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -Name "Value" -Type String -Value "Deny"
}

# Give apps acces to messages
Function GiveAccessToMessages {
	Write-Host "Giving apps acces to messages..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -Name "Value" -Type String -Value "Allow"
}

# Restrict apps acces to radio
Function RestrictAccessToRadio {
	Write-Host "Restricting apps acces to radio..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" -Name "Value" -Type String -Value "Deny"
}

# Give apps acces to radio
Function GiveAccessToRadio {
	Write-Host "Giving apps acces to radio..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" -Name "Value" -Type String -Value "Allow"
}

# Disable app diagnostics
Function DisableAppDiagnostics {
	Write-Host "Disabling app diagnostics..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" -Name "Value" -Type String -Value "Deny"
}

# Enable app diagnostics
Function EnableAppDiagnostics {
	Write-Host "Enabling app diagnostics..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" -Name "Value" -Type String -Value "Allow"
}

# Disable tips about Windows
Function DisableTipsAboutWindows {
	Write-Host "Disabling tips about Windows..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Type DWord -Value 0
}

# Enable tips about Windows
Function EnableTipsAboutWindows {
	Write-Host "Enabling tips about Windows..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Type DWord -Value 1
}

# Disable Handwriting Data Sharing
Function DisableHandwritingData {
	Write-Host "Disabling Handwriting Data Sharing..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type DWord -Value 1
}

# Enable Handwriting Data Sharing
Function EnableHandwritingData {
	Write-Host "Enabling Handwriting Data Sharing..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -ErrorAction SilentlyContinue
}

# Disable Customer Experience Improvement Program
function DisableCEIP {
	Write-Host "Disabling Customer Experience Improvement Program..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0
	$tasks = @(
		"Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
		"Microsoft\Windows\Application Experience\ProgramDataUpdater"
		"Microsoft\Windows\Autochk\Proxy"
		"Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
		"Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
		"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
		"Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
	)
	foreach ($task in $tasks) {
		schtasks /Change /TN $task /Disable | Out-Null
	}
}

# Enable Customer Experience Improvement Program
function EnableCEIP {
	Write-Host "Enabling Customer Experience Improvement Program..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -ErrorAction SilentlyContinue
	$tasks = @(
		"Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
		"Microsoft\Windows\Application Experience\ProgramDataUpdater"
		"Microsoft\Windows\Autochk\Proxy"
		"Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
		"Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
		"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
		"Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
	)
	foreach ($task in $tasks) {
		schtasks /Change /TN $task /Enable | Out-Null
	}
}

# Disable Application Impact Telemetry
Function DisableAIT {
	Write-Host "Disabling Application Impact Telemetry..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0
}

# Enable Application Impact Telemetry
Function EnableAIT {
	Write-Host "Enabling Application Impact Telemetry..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -ErrorAction SilentlyContinue
}

# Disable Application Compatibility Program Inventory
Function DisableACPI {
	Write-Host "Disabling Application Compatibility Program Inventory..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 1
}

# Enable Application Compatibility Program Inventory
Function EnableACPI {
	Write-Host "Enabling Application Compatibility Program Inventory..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -ErrorAction SilentlyContinue
}

# Disable Defender Reporting
Function DisableDefenderReporting {
	Write-Host "Disabling Windows Defender's reporting..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type DWord -Value 1
}

# Enable Defender Reporting
Function EnableDefenderReporting {
	Write-Host "Enabling Windows Defender's reporting..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type DWord -Value 1
}

# Disable Windows Spotlight
Function DisableSpotlight {
	Write-Host "Disabling Windows Spotlight..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Type DWord -Value 1
}

# Enable Windows Spotlight
Function EnableSpotlight {
	Write-Host "Enabling Windows Spotlight..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -ErrorAction SilentlyContinue
}

# Disable services that are not needed
function DisableWindowsServices {
	$services = @(
		"MapsBroker"								# Downloaded Maps Manager
		"NetTcpPortSharing"							# Net.Tcp Port Sharing Service
		"RemoteAccess"								# Routing and Remote Access
		"RemoteRegistry"							# Remote Registry
		"SharedAccess"								# Internet Connection Sharing (ICS)
		"TrkWks"									# Distributed Link Tracking Client
		"WMPNetworkSvc"								# Windows Media Player Network Sharing Service
		"WbioSrvc"									# Windows Biometric Service
		"WinRM"										# Windows Remote Management (WS-Management)
		"XblAuthManager"							# Xbox Live Auth Manager
		"XblGameSave"								# Xbox Live Game Save Service
		"XboxNetApiSvc"								# Xbox Live Networking Service
		"diagnosticshub.standardcollector.service"	# Microsoft (R) Diagnostics Hub Standard Collector Service
		"lfsvc"										# Geolocation Service
		# "MessagingService_*"						# MessagingService_xxxxx
		# "OneSyncSvc_*" 							# Sync Host_xxxxx
		# "PimIndexMaintenanceSvc_*"				# Contact Data_xxxxx
		# "UnistoreSvc_*"							# User Data Storage_xxxxx
		# "UserDataSvc_*"							# User Data Access_xxxxx
	)

	foreach ($service in $services) {
		Write-Host "Trying to disable $service..."
		Get-Service -Name $service | Set-Service -StartupType Disabled
	}
}

# Enable services that are not needed
function EnableWindowsServices {
	$services = @(
		"MapsBroker"								# Downloaded Maps Manager
		"MessagingService_*"						# MessagingService_xxxxx
		"NetTcpPortSharing"							# Net.Tcp Port Sharing Service
		"RemoteAccess"								# Routing and Remote Access
		"RemoteRegistry"							# Remote Registry
		"SharedAccess"								# Internet Connection Sharing (ICS)
		"TrkWks"									# Distributed Link Tracking Client
		"WMPNetworkSvc"								# Windows Media Player Network Sharing Service
		"WbioSrvc"									# Windows Biometric Service
		"WinRM"										# Windows Remote Management (WS-Management)
		"XblAuthManager"							# Xbox Live Auth Manager
		"XblGameSave"								# Xbox Live Game Save Service
		"XboxNetApiSvc"								# Xbox Live Networking Service
		"diagnosticshub.standardcollector.service"	# Microsoft (R) Diagnostics Hub Standard Collector Service
		"lfsvc"										# Geolocation Service
		# "MessagingService_*"						# MessagingService_xxxxx
		# "OneSyncSvc_*" 							# Sync Host_xxxxx
		# "PimIndexMaintenanceSvc_*"				# Contact Data_xxxxx
		# "UnistoreSvc_*"							# User Data Storage_xxxxx
		# "UserDataSvc_*"							# User Data Access_xxxxx
	)

	foreach ($service in $services) {
		Write-Host "Trying to enable $service..."
		Get-Service -Name $service | Set-Service -StartupType Enable
	}
}

# Disable potentially unwanted scheduled tasks
function DisableScheduledTasks {
	$tasks = @(
		"Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
		"Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
		"Microsoft\Windows\DiskFootprint\Diagnostics"
		"Microsoft\Windows\Feedback\Siuf\DmClient"
		"Microsoft\Windows\NetTrace\GatherNetworkInfo"
		"Microsoft\Windows\Windows Error Reporting\QueueReporting"
	)
	foreach ($task in $tasks) {
		Write-Host "Trying to disable $task..."
		schtasks /Change /TN $task /Disable | Out-Null
	}
}

# Enable potentially unwanted scheduled tasks
function EnableScheduledTasks {
	$tasks = @(
		"Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
		"Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
		"Microsoft\Windows\DiskFootprint\Diagnostics"
		"Microsoft\Windows\Feedback\Siuf\DmClient"
		"Microsoft\Windows\NetTrace\GatherNetworkInfo"
		"Microsoft\Windows\Windows Error Reporting\QueueReporting"
	)
	foreach ($task in $tasks) {
		Write-Host "Trying to enable $task..."
		schtasks /Change /TN $task /Enable | Out-Null
	}
}

# Install .NET Framework 3.5
Function InstallNETFramework35 {
	Write-Host "Installing .NET Framework 3.5..."
	Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall .NET Framework 3.5
Function UninstallNETFramework35 {
	Write-Host "Uninstalling .NET Framework 3.5..."
	Disable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Enable old Volume Mixer
Function EnableOldVolumeMixer {
	Write-Host "Enabling old Volume Mixer..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC"))
	{
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name MTCUVC | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name "EnableMtcUvc" -Type DWord -Value 0
}

# Disable old Volume Mixer
Function DisableOldVolumeMixer {
	Write-Host "Disabling old Volume Mixer..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC"))
	{
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name MTCUVC | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name "EnableMtcUvc" -Type DWord -Value 1
}

# Set your preffered power option
Function SetPowerPlan ($NewPlan) {
	Try {
		Write-Host "Trying to set the power plan to $NewPlan..."
		$Plan = powercfg -l | %{if($_.contains($NewPlan)) {$_.split()[3]}}
		$CurrPlan = $(powercfg -getactivescheme).split()[3]
		if ($CurrPlan -ne $Plan) {powercfg -setactive $Plan}
    }
	Catch {
		Write-Warning -Message "Unable to set the power plan to $NewPlan!"
	}
}

# Uninstall the pre-installed flash player
Function UninstallFlashPlayer {
	Write-Host "Uninstalling Flash Player..."
	takeown /f "$env:SYSTEMROOT\System32\Macromed" /r /d y 2>&1 | Out-Null
	icacls "$env:SYSTEMROOT\System32\Macromed" /grant administrators:F /t 2>&1 | Out-Null
	Remove-Item -Recurse -Force "$Env:WinDir\System32\Macromed" -ErrorAction SilentlyContinue
	takeown /f "$env:SYSTEMROOT\SysWOW64\Macromed" /r /d y 2>&1 | Out-Null
	icacls "$env:SYSTEMROOT\SysWOW64\Macromed" /grant administrators:F /t 2>&1 | Out-Null
	Remove-Item -Recurse -Force "$Env:WinDir\SysWOW64\Macromed" -ErrorAction SilentlyContinue
	takeown /f "$env:SYSTEMROOT\SysWOW64\FlashPlayerApp.exe" /r /d y 2>&1 | Out-Null
	icacls "$env:SYSTEMROOT\SysWOW64\FlashPlayerApp.exe" /grant administrators:F 2>&1 | Out-Null
	Remove-Item -Force "$Env:WinDir\SysWOW64\FlashPlayerApp.exe" -ErrorAction SilentlyContinue
	takeown /f "$env:SYSTEMROOT\SysWOW64\FlashPlayerCPLApp.cpl" /r /d y 2>&1 | Out-Null
	icacls "$env:SYSTEMROOT\SysWOW64\FlashPlayerCPLApp.cpl" /grant administrators:F /t 2>&1 | Out-Null
	Remove-Item -Force "$Env:WinDir\SysWOW64\FlashPlayerCPLApp.cpl" -ErrorAction SilentlyContinue
	Remove-Item -Recurse -Force "$env:APPDATA\Adobe" -ErrorAction SilentlyContinue
	Remove-Item -Recurse -Force "$env:APPDATA\Macromedia" -ErrorAction SilentlyContinue
}

# Create a shortcut on desktop for Extended Control Panel aka GodMode
Function ExtendedPanelShortcut {
	$WshShell = New-Object -ComObject WScript.Shell
	$Shortcut = $WshShell.CreateShortcut("$env:userprofile\Desktop\Extended Control Panel.lnk")
	$Shortcut.TargetPath = $Shortcut.TargetPath = "$env:SYSTEMROOT\explorer.exe"
	$Shortcut.Arguments = "shell:::{ED7BA470-8E54-465E-825C-99712043E01C}"
	$Shortcut.Save()
}

# Add Notepad to desktop shell
Function AddNotepadToDesktopShell {
	Write-Host "Adding Notepad to desktop shell (right click menu)"
	If (!(Test-Path "HKCR:\Directory\Background\shell\Notepad")) {
		New-Item -Path "HKCR:\Directory\Background\shell\Notepad" | Out-Null
	}
	If (!(Test-Path "HKCR:\Directory\Background\shell\Notepad\command")) {
		New-Item -Path "HKCR:\Directory\Background\shell\Notepad\command" | Out-Null
	}
	Set-ItemProperty -Path "HKCR:\Directory\Background\shell\Notepad\command" -Name "(Default)" -Type String -Value "$env:SYSTEMDRIVE\Windows\System32\notepad.exe"
}

# Remove Notepad from desktop shell
Function RemoveNotepadFromDesktopShell {
	Write-Host "Removing Notepad from desktop shell (right click menu)"
	Remove-Item -Path "HKCR:\Directory\Background\shell\Notepad" -ErrorAction SilentlyContinue
}

# Add Notepad++ to desktop shell (The application must be already installed)
Function AddNotepadPPToDesktopShell {
	Write-Host "Adding Notepad++ to desktop shell (right click menu"
	If (!(Test-Path "HKCR:\Directory\Background\shell\Notepad++")) {
		New-Item -Path "HKCR:\Directory\Background\shell\Notepad++" | Out-Null
	}
	If (!(Test-Path "HKCR:\Directory\Background\shell\Notepad++\command")) {
		New-Item -Path "HKCR:\Directory\Background\shell\Notepad++\command" | Out-Null
	}
	Set-ItemProperty -Path "HKCR:\Directory\Background\shell\Notepad++\command" -Name "(Default)" -Type String -Value "$env:SYSTEMDRIVE\Program Files\Notepad++\notepad++.exe"
}

# Remove Notepad++ from dekstop shell
Function RemoveNotepadPPFromDesktopShell {
	Write-Host "Removing Notepad++ from desktop shell (right click menu)"
	Remove-Item -Path "HKCR:\Directory\Background\shell\Notepad++" -ErrorAction SilentlyContinue
}

# Install Sticky Notes
Function InstallStickyNotes {
	Write-Host "Installing Sticky Notes..."
	Get-AppxPackage -AllUsers "Microsoft.MicrosoftStickyNotes" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}

# Set some visual FX to my liking
Function SetVisualFX {
	Write-Host "Changing selection rectangle to translucent..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 1
	Write-Host "Enabling drop shadows on desktop icons..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
}

#####################################
# Parse parameters and apply tweaks #
#####################################

# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}

# Wait for key press
Function WaitForKey {
	Write-Host
	Write-Host "Press any key to continue..." -ForegroundColor Black -BackgroundColor White
	[Console]::ReadKey($true) | Out-Null
}

# Normalize path to preset file
$preset = ""
$PSCommandArgs = $args
If ($args -And $args[0].ToLower() -eq "-preset") {
	$preset = Resolve-Path $($args | Select-Object -Skip 1)
	$PSCommandArgs = "-preset `"$preset`""
}

# Load function names from command line arguments or a preset file
If ($args) {
	$tweaks = $args
	If ($preset) {
		$tweaks = Get-Content $preset -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" -and $_[0] -ne "#" }
	}
}

# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }
