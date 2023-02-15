# --------------------------------------------------
# Title		: Windows Update Agent (Offline)
# Author	: Benjamin TAN
# Version	: 0.1b, 2023-02-09
#
# Reference:
# https://learn.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline
# https://catalog.s.download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab
# --------------------------------------------------


# --------------------------------------------------
# Variables
# --------------------------------------------------
Set-Variable -Name "L_Msg100" -Value "===============================================================================" -Option constant
Set-Variable -Name "L_Msg105" -Value "	Search the applicable updates, download and install updates." -Option constant
Set-Variable -Name "L_Msg110" -Value "2) Search Updates"	-Option constant
Set-Variable -Name "L_Msg120" -Value "3) Download Updates"	-Option constant
Set-Variable -Name "L_Msg130" -Value "4) Install Updates"	-Option constant
Set-Variable -Name "L_Msg135" -Value "1) Download wsusscn2"	-Option constant
Set-Variable -Name "L_Msg137" -Value "5) Run Cleanup"		-Option constant
Set-Variable -Name "L_Msg140" -Value "6) Exit to Command Line"				-Option constant
Set-Variable -Name "L_Msg150" -Value "Enter number to select an option "	-Option constant

Set-Variable -Name "L_Msg161" -Value "***** Running Microsoft Baseline Security Analyzer ***************"	-Option constant
Set-Variable -Name "L_Msg162" -Value "***** Running Microsoft Baseline Security Analyzer Completed *****"	-Option constant
Set-Variable -Name "L_Msg163" -Value "***** Downloading updates ********************"	-Option constant
Set-Variable -Name "L_Msg164" -Value "***** Downloading updates completed **********"	-Option constant
Set-Variable -Name "L_Msg165" -Value "***** Installing updates *********************"	-Option constant
Set-Variable -Name "L_Msg166" -Value "***** Installing updates completed ***********"	-Option constant
Set-Variable -Name "L_Msg167" -Value "***** Downloading wsusscn2.cab ***************"	-Option constant
Set-Variable -Name "L_Msg168" -Value "***** Downloading wsusscn2.cab completed *****"	-Option constant
Set-Variable -Name "L_Msg169" -Value "***** Running Clean-up ***********************"	-Option constant
Set-Variable -Name "L_Msg170" -Value "***** Running Clean-up completed *************"	-Option constant

Set-Variable -Name "L_Msg171" -Value "`nDownloads started..."	-Option constant
Set-Variable -Name "L_Msg172" -Value "`nDownloads finished..."	-Option constant

$strPathInbox		= "inbox"
$strPathOutbox		= "outbox"
$strPathDbBox		= "db"
$strDBFile			= "wsusscn2.cab"
$strLogFile			= "WindowsUpdateAgent.log"
$strLogFileDownload	= "WindowsUpdateAgent-Downloads.log"

# --------------------------------------------------
# Function - Search Windows Updates
# --------------------------------------------------
function funcSearchWindowsUpdate {
	$UpdateSession = New-Object -ComObject Microsoft.Update.Session 
	$UpdateServiceManager  = New-Object -ComObject Microsoft.Update.ServiceManager 
	$UpdateService = $UpdateServiceManager.AddScanPackageService("Offline Sync Service", ($PSScriptRoot + '\' + $strPathDbBox + '\' + $strDBFile), 1) 
	$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

	funcEventLog ("Searching for updates...") # `r`n

	$UpdateSearcher.ServerSelection = 3 #ssOthers

	$UpdateSearcher.ServiceID = $UpdateService.ServiceID.ToString()
	
	$SearchResult = $UpdateSearcher.Search("IsInstalled=0") # or "IsInstalled=0 or IsInstalled=1" to also list the installed updates as MBSA did

	$Updates = $SearchResult.Updates

	if($Updates.Count -eq 0){ 
		funcEventLog ("There are no applicable updates.")
		return $null 
	}

	funcEventLog ("List of applicable items on the machine when using wssuscan.cab:")

	foreach ($Update in $Updates) {
		funcEventLog ($Update.Title)
		$BundledUpdate = @($Update.BundledUpdates) | ForEach-Object{
			$DownloadUrl = @($_.DownloadContents).DownloadUrl

			funcEventLog ($DownloadUrl)
			funcDownloadLog ($DownloadUrl)
		}
	}
}

# --------------------------------------------------
# Function - Download wsusscn2.cab
# --------------------------------------------------
function funcDownloadWsusscn2([string]$Message) {
	$ProgressPreference = 'SilentlyContinue'

	Invoke-WebRequest -Uri 'https://catalog.s.download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab' -OutFile ($strPathDbBox + '\' + $strDBFile)
}

# --------------------------------------------------
# Function - Download Windows Updates
# --------------------------------------------------
function funcDownloadWindowsUpdate {
	$arrFiles = @()

	[string[]]$files = Get-Content -Path ($strPathOutbox + '\' + $strLogFileDownload)
	
	$files | ForEach-Object {
		$NewFile = @{}
		$NewFile.Uri = $_
		$NewFile.OutFile = '.\' + $strPathInbox + '\' + $_.substring($_.LastIndexOf('/') + 1)
		
		$arrFiles += $NewFile
	}
	
	$jobs = @()
	$ProgressPreference = 'SilentlyContinue'
	
	foreach ($file in $arrFiles) {
		$KB = ($file.OutFile.ToUpper() | Select-String -Pattern "KB\d{6,7}" | % { $_.Matches } | % { $_.Value })
		if ([string]::IsNullOrEmpty($KB)) {
			$KB = $file.OutFile
		}
		
		$jobs += Start-ThreadJob -Name $KB -ScriptBlock {
			$params = $using:file
			Invoke-WebRequest @params
		}
	}
	
	Write-Host $L_Msg171
	Wait-Job -Job $jobs
	
	foreach ($job in $jobs) {
		funcEventLog ("Downloading " + $job.Name)
		Receive-Job -Job $job
	}
	Write-Host $L_Msg172
}

# --------------------------------------------------
# Function - Install Windows Updates
# --------------------------------------------------
function funcInstallWindowsUpdate {
    
    $SecurityUpdatesFile = Get-ChildItem -Path ($PSScriptRoot + "\" + $strPathInbox + "\") -Name

    Foreach ($i in $SecurityUpdatesFile) {
        $KB = ($i.ToUpper() | Select-String -Pattern "KB\d{6,7}" | % { $_.Matches } | % { $_.Value })
		if ([string]::IsNullOrEmpty($KB)) {
			$KB = $file.OutFile
		}

        funcEventLog ("Installing " + $KB)        
        $strFile = ($PSScriptRoot + "\" + $strPathInbox + "\" + $i)
        
        # --------------------------
        # For Executable File
        # --------------------------
        If ([IO.Path]::GetExtension($i) -eq ".exe") {
            
            # --------------------------
            # For Microsoft Windows Malicious Software Removal Tool
            # --------------------------
            If ($i.ToUpper().Contains("KB890830".ToUpper())) {
                funcEventLog ($StrFile)
                $process = Start-Process  -FilePath $strFile -ArgumentList (" /Q") -PassThru -Wait
                funcEventLog ("Exit Code: " + $process.ExitCode)
            }

			# --------------------------
			# For Generic Executable
			# --------------------------
			Else {
                funcEventLog ($StrFile)
                $process = Start-Process  -FilePath $strFile -ArgumentList (" /Quiet /NoRestart") -PassThru -Wait
                funcEventLog ("Exit Code: " + $process.ExitCode)
			}
        }        

		# --------------------------
		# For Update Package File
		# --------------------------        
        If ([IO.Path]::GetExtension($i) -eq ".msu") {      
            funcEventLog ($StrFile)      
            $process = Start-Process  -FilePath "C:\windows\system32\wusa.exe" -ArgumentList ($strFile + " /quiet /norestart") -PassThru -Wait
            funcEventLog ("Exit Code: " + $process.ExitCode)
        }

        # --------------------------
        # For Cabinet File
        # --------------------------
        If ([IO.Path]::GetExtension($i) -eq ".cab") {
            funcEventLog ($StrFile)
            $process = Start-Process  -FilePath "C:\Windows\System32\Dism.exe" -ArgumentList (" /Online /Add-Package /PackagePath:" + $strFile + " /Quiet /NoRestart") -PassThru -Wait
            funcEventLog ("Exit Code: " + $process.ExitCode)
        }
    }
}

# --------------------------------------------------
# Function - Startup
# --------------------------------------------------
function funcStartup {

	if (-not(Test-Path -Path ($PSScriptRoot + '\' + $strPathDbBox))) {
		New-Item -Path $PSScriptRoot -Name $strPathDbBox -ItemType "directory"
	}
	
	if (-not(Test-Path -Path ($PSScriptRoot + '\' + $strPathInbox))) {
		New-Item -Path $PSScriptRoot -Name $strPathInbox -ItemType "directory"
	}
	
	if (-not(Test-Path -Path ($PSScriptRoot + '\' + $strPathOutbox))) {
		New-Item -Path $PSScriptRoot -Name $strPathOutbox -ItemType "directory"
	}
}

# --------------------------------------------------
# Function - Clean-up
# --------------------------------------------------
function funcCleanup {

	if (Test-Path -Path ($PSScriptRoot + '\' + $strPathDbBox)) {
		<# Action to perform if the condition is true #>
		Remove-Item ($PSScriptRoot + '\' + $strPathDbBox + '\*.*')
	} else {
		<# Action when all if and elseif conditions are false #>
		New-Item -Path $PSScriptRoot -Name $strPathDbBox -ItemType "directory"
	}
	
	if (Test-Path -Path ($PSScriptRoot + '\' + $strPathInbox)) {
		
		Remove-Item ($PSScriptRoot + '\' + $strPathInbox + '\*.*')
	} else {
		<# Action when all if and elseif conditions are false #>
		New-Item -Path $PSScriptRoot -Name $strPathInbox -ItemType "directory"
	}
	
	if (Test-Path -Path ($PSScriptRoot + '\' + $strPathOutbox)) {
		<# Action to perform if the condition is true #>
		#Remove-Item ($PSScriptRoot + '\' + $strPathOutbox + '\*.*')
	} else {
		<# Action when all if and elseif conditions are false #>
		New-Item -Path $PSScriptRoot -Name $strPathOutbox -ItemType "directory"
	}
}

# --------------------------------------------------
# Function - Write Log File
# --------------------------------------------------
function funcEventLog([string]$Message) {
    $LogFile = $PSScriptRoot + "\" + $strPathOutbox + "\" + $strLogFile

    $timeStamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    Add-Content $LogFile -Value ("$timeStamp - $Message")
}

function funcDownloadLog([string]$Message) {
    $LogFile = $PSScriptRoot + "\" + $strPathOutbox + "\" + $strLogFileDownload
	
    Add-Content $LogFile -Value ("$Message")
}

# --------------------------------------------------
# Main
# --------------------------------------------------
funcStartup

do {
	Write-Host
	Write-Host $L_Msg100
	Write-Host $L_Msg105
	Write-Host $L_Msg100
	Write-Host
	Write-Host "Computer Name:	" $env:computername
	Write-Host
	Write-Host $L_Msg135
	Write-Host
	Write-Host $L_Msg110
	Write-Host $L_Msg120
	Write-Host $L_Msg130
	Write-Host
	Write-Host $L_Msg137
	Write-Host $L_Msg140
	Write-Host
	$selection = Read-Host $L_Msg150

	switch ($selection)
	{
		'1' {
			funcEventLog ("")
			funcEventLog ($L_Msg167)
			funcDownloadWsusscn2
			funcEventLog ($L_Msg168)
			funcEventLog ("")
		}
		'2' {
			funcEventLog ("")
			funcEventLog ($L_Msg161)
			funcSearchWindowsUpdate
			funcEventLog ($L_Msg162)
			funcEventLog ("")
		}
		'3' {
			funcEventLog ("")
			funcEventLog ($L_Msg163)
			funcDownloadWindowsUpdate
			funcEventLog ($L_Msg164)
			funcEventLog ("")
		}
		'4' {
			funcEventLog ("")
			funcEventLog ($L_Msg165)
			funcInstallWindowsUpdate
			funcEventLog ($L_Msg166)
			funcEventLog ("")
		}
		'5' {
			funcEventLog ("")
			funcEventLog ($L_Msg169)
			funcCleanup
			funcEventLog ($L_Msg170)
			funcEventLog ("")
		}
		'6' {return}
	}
 } until (
	$selection -eq '6'
	)