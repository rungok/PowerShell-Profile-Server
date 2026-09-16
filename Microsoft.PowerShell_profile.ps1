#####################################################################################################
$tit = 'Pimped PowerShell-Profile for Windows v3.0 by GOKS0R'			 							#
$githubUser = 'rungok'																				#
$FFConfig = Join-Path -Path $env:localappdata -ChildPath 'fastfetch\frames.jsonc' # Config-path		#
$FFlogo = Join-Path -Path $env:localappdata -ChildPath 'fastfetch\indianai_cropped2.png' # logopath	#
$FFlogoWidth = 60  # Width  in number of chars														#
$FFlogoHeight = 42 # Height in number of chars														#
#																									#
#  This script will try to install Windows Terminal (even on Windows Server 2022),					#
#  nice ANSI-prompt and other enhancments/alias so even some Linux-commands will work.				#
#																									#
#  The reason for making this script was to Rise up the CLI environment quickly when setting   		#
#  up VM servers by installing Windows Terminal, Fastfetch, NerdFont, Notepad++, Prompt				#
#  and a bunch of aliases for those of us that jump between Linux and Windows on a regular basis.	#
#  It won't meddle with other users	environment or overwrite any existing profiles if they already  #
#  exist (existing will be renamed to <filename><timestamp>.bak).									#
#																									#
#  A lot of testing has been done to make sure it doesn't mess up existing setups or overwrite		#
#  anything important in any way, so it should be safe to use on customers servers.					#			
#  It's also tested on 2019 (although it will skip installing Windows Terminal) and Win11.    		#
#																									#
#  The script will be saved in path-string $PROFILE, which is the default placement					#
#  Just write $PROFILE in Powershell if you wonder where it is. Usually in your						#
#  $HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1 			for PowerShell v7.x	 		#
#  $HOME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1 	for PowerShell v5.x			#
#																									#
#  Manual changes in Terminals needed after install:												#
#  1. Change your font to RobotoMono Size 10														#
#  2. Set font rendering to ClearType for icon rendering											#
#  																									#
#  Picture logo will be converted to raw sixel format to work in Windows Terminal v1.22+			#
#####################################################################################################

Write-Host("`n         .--------< ") -f white -nonewline
Write-Host($tit) -f Cyan -nonewline
Write-Host(" >----------------.") -f white
Write-Host("         '--------------------------------------------------------------------------------'`n") -f white

$execPolicy = Get-ExecutionPolicy
if ($execPolicy -ne "RemoteSigned") {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
}

#### DETECTION: Elevation - Test if Powershell is started in elevated mode for system installs that need it ####
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

#### CONFIG Admin: Opt-out of telemetry before doing anything if PowerShell is run as admin ####
if ($isAdmin) {
    [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'true', [System.EnvironmentVariableTarget]::Machine)
}

#### DETECTION: Check Windows version is Windows 10 or 2022 kernel (min build 18362) ####
If (([Environment]::OSVersion).Version.Build -lt 18362) { [bool] $is2022 = $false } else { [bool] $is2022 = $true }

#### CONFIG User: Set full right-click menu to ENABLED and Compact File Explorer to ENABLED if Windows 11/2025 ####
If (([Environment]::OSVersion).Version.Build -ge 22000) {
	[bool] $is2025 = $true
	If (-not (Test-Path -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}")) {
		# Set compact file explorer to ENABLED
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseCompactMode" -Value 1
		# Set full rightclick menu to ENABLED
		New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force
	}	
}

#### DETECTION Online: Initial GitHub.com connectivity check with 1 second timeout ####
$canConnectToGitHub = Test-Connection github.com -Count 1 -Quiet

#### FUNCTION: Write out a detection sentence with √ in front of it
function Write-Detect {
    param ([string]$Software = "Program")
    Write-host " " -nonewline
    If (($PSVersionTable.PSVersion.Major -gt 6) -and ($is2022)) { 
		Write-host ("✅") -nonewline -f DarkGreen
		} else {
		Write-host "v" -nonewline -b DarkGreen -f White
	} 
    Write-host " $Software detected.                     "  -f Green
	# Write-host "$([char]0x1b)[1F" # -nonewline
}

#### DETECTION function - Usage: if (Test-CommandExists nvim) { Write-Host 'nvim detected' }
function Test-CommandExists {
    param($command)
    $exists = $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
    return $exists
}


############################################################################
####### Test components status and install if they are not present #########
############################################################################


# DETECTION + User install: NuGet provider to ensure the other packages can be installed.
$nugetProvider = Get-PackageProvider | Select-Object Name | Where-Object Name -match NuGet
if (-not $nugetProvider) {
    Write-Host "NuGet provider not found. Installing..." -f Cyan
    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser
    Import-PackageProvider -Name NuGet -Force
    Write-Host "NuGet provider installed."
} else {
    Write-Detect "NuGet provider"
}

# DETECTION + User config: Trust the PSGallery repository if it's not trusted
If ((Get-PSRepository  | Select-Object Name,InstallationPolicy | Where-Object Name -match PSGallery | Select-Object -Expandproperty InstallationPolicy) -ne "Trusted") {
	Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted }

# DETECTION + User install: Terminal-Icons module
if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) { Install-Module -Name Terminal-Icons -Scope CurrentUser -Force -SkipPublisherCheck }
Import-Module -Name Terminal-Icons

# DETECTION + User install: ConvertTo-Sixel module
if (-not (Get-Module -ListAvailable -Name Sixel)) { Install-Module -Name Sixel -Scope CurrentUser -Force -SkipPublisherCheck }
Import-Module -Name Sixel

# DETECTION: .net v4.8 Framework
$dotnet = (Get-ItemPropertyValue -LiteralPath 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release) -ge 528040
if ($dotnet) {
    Write-Detect ".NET Framework v4.8 or higher"
} else {
    Write-Host "❌ .NET Framework Version 4.8 or later is not detected. Chocolatey packet manager needs .NET runtime libraries v4.8, and will try to install it automaticly." -f Cyan
    If ((!$is2022) -and ($isAdmin)) {
    	Write-Host "❌ Server 2019 detected. Unfortunately .NET v4.8 upgrade on server 2019 triggers some registry fixes that requires a FULL SERVER RESTART to activate." -f Magenta
    }
}

# DETECTION + Admin install: Chocolatey (if not installed and shell is started in administrative mode)
if (-not (Test-CommandExists choco)) {
	Write-Host ("❌ Chocolatey packet manager not installed...") -nonewline -f Cyan
	if ($isAdmin) {
		Write-Host ("Trying to install...") -nonewline -f Cyan
		Set-ExecutionPolicy Bypass -Scope Process -Force
  		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    		iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
		$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1";if (Test-Path($ChocolateyProfile)) { Import-Module "$ChocolateyProfile" }
  		refreshenv
		} else { Write-Host ("❌ Terminal must be started in elevated mode to install Chocolatey. Some extensions will not be activated until this is done.") -f Cyan }
	} else {
		Write-Detect "Chocolatey packet manager"
		$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1";if (Test-Path($ChocolateyProfile)) { Import-Module "$ChocolateyProfile" }
}

# DETECTION + Admin install: zoxide fuzzy shell (if not installed and shell is started in administrative mode)
if (Test-CommandExists zoxide) {
	Write-Detect "Zoxide"
	Invoke-Expression (& zoxide init --cmd cd powershell | Out-String)
	Set-Alias -Name z -Value __zoxide_z -Option AllScope -Scope Global -Force
	Set-Alias -Name zi -Value __zoxide_zi -Option AllScope -Scope Global -Force
} else {
	if ($isAdmin) {
		Write-Host "❌ Zoxide command not found. Attempting to install via Chocolatey..." -nonewline -f Cyan
		try {
			choco install zoxide -y
			Invoke-Expression (& { (zoxide init powershell | Out-String) })
			Write-Host "Zoxide installed successfully. Initializing..." -ForegroundColor DarkGreen
		} catch {
			Write-Error "❌ Failed to install zoxide. Error: $_"
		}
	} else { Write-Host ("❌ Terminal must be started in elevated mode to install Zoxide. Fuzzy shell will not be activated until this is done.") -f Cyan }
}

# DETECTION + Admin install: Notepad++ (if not installed and shell is started in administrative mode)
if (Test-CommandExists Notepad++) {
	Write-Detect "Notepad++"
} else {
	if ($isAdmin) {
		Write-Host "❌ Notepad++ not installed. Attempting to install via " -nonewline -f Cyan
		try {
			choco install notepadplusplus -y
			Write-Host "Notepad++ installed successfully. Initializing..." -ForegroundColor DarkGreen
   			refreshenv
		} catch {
			Write-Error "❌ Failed to install Notepad++. Error: $_"
		}
	} else { Write-Host ("❌ Powershell must be started in elevated mode to install Notepad++.") -f Cyan }
}

# DETECTION + Admin install: ImageMagick (if not installed and shell is started in administrative mode)
if (Test-CommandExists Magick) {
	Write-Detect "ImageMagick"
} else {
	if ($isAdmin) {
		Write-Host "❌ ImageMagick not installed. Attempting to install via " -nonewline -f Cyan
		try {
			choco install imagemagick -y
			Write-Host "ImageMagick installed successfully. Initializing..." -ForegroundColor DarkGreen
   			refreshenv
		} catch {
			Write-Error "❌ Failed to install ImageMagick. Error: $_"
		}
	} else { Write-Host ("❌ Powershell must be started in elevated mode to install ImageMagick.") -f Cyan }
}

# DETECTION + Admin install: FastFetch (if not installed and shell is started in administrative mode)
if (Test-CommandExists fastfetch) {
	Write-Detect "FastFetch"
} else {
	if ($isAdmin) {
		Write-Host "❌ FastFetch not installed. Attempting to install via " -nonewline -f Cyan
		try {
			choco install fastfetch -y
			Write-Host "FastFetch installed successfully. Initializing..." -ForegroundColor DarkGreen
   			refreshenv
		} catch {
			Write-Error "❌ Failed to install FastFetch. Error: $_"
		}
	} else { Write-Host ("❌ Powershell must be started in elevated mode to install FastFetch.") -f Cyan }
}

# DETECTION + User install: RobotoMono Nerd Font (if not installed)
If (choco list --local-only --limit-output | ConvertFrom-Csv -Delimiter '|' -Header Name, Version | Select-Object Name | Where-Object Name -match robotomono) {
	Write-Detect "RobotoMono Nerd Font"
} else {
 	Write-Host "❌ RobotoMono nerd font not installed. Attempting to install via " -nonewline -f Cyan
 	choco install nerd-fonts-robotomono -y
}


################################################################################################################
####### Profile creation or update if not present + download example picture and FastFetch config-file #########
################################################################################################################

#### Command to ad-hoc Download and write new profile for current version of Powershell + rename old to file+timemarker.ps1.
function Update-Profile {
    try {
		#### Test if My Documents is redirected by GPO so profiles has to be present under that folder instead
		Write-Host "Trying to download latest profile from GitHub. You old will be renamed to <filename><timestamp>.ps1 if it exist." -f Cyan
		Write-Host "Move any custom config at top of old file manually to the new if you had some special picture or FastFetch config." -f Cyan
		Write-Host ""
		
		# Create bak-filename and rename current profile to that filename
		$TimeMarker = Get-Date -Format "ddMMyyyy_HHmm"
		$Bakfile = ($PROFILE.CurrentUserCurrentHost -replace ".{4}$")+"_"+$TimeMarker+".ps1"
		Move-Item -Path $PROFILE.CurrentUserCurrentHost -Destination $Bakfile -Force
        
		# Test if current profile still exist (bak-rename may have failed) and download new one if it doesn't
		if (!(Test-Path -Path $PROFILE.CurrentUserCurrentHost -PathType Leaf)) {
			Invoke-RestMethod https://github.com/$githubUser/powershell-profile-server/raw/main/Microsoft.PowerShell_profile.ps1 -OutFile $PROFILE.CurrentUserCurrentHost
		}
        Write-Host "The profile has been created at " -f Cyan -nonewline;Write-Host $PROFILE;Write-Host "     and old profile renamed to " -f Cyan -nonewline;Write-Host $Bakfile -f DarkGray
    }
    catch {
        Write-Error "Failed to backup and update the profile. Error: $_"
    }
}

#### Try to Create Profiles for both versions of Powershell if they don't exist.
# Detect Documents redirection
$UserShellFoldersPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
$PersonalFolderValue = (Get-ItemProperty -Path $UserShellFoldersPath -Name "Personal").Personal

$profilePath = "$PersonalFolderValue\WindowsPowerShell"
if (!(Test-Path -Path $profilePath)) { New-Item -Path $profilePath -ItemType "directory" }
if (!(Test-Path -Path $profilePath\Microsoft.PowerShell_profile.ps1 -PathType Leaf)) {
	try {
		Invoke-RestMethod https://github.com/$githubUser/powershell-profile-server/raw/main/Microsoft.PowerShell_profile.ps1 -OutFile $profilePath\Microsoft.PowerShell_profile.ps1
		Write-Host "The profile @ [$profilePath\Microsoft.PowerShell_profile.ps1] has been created and will be executed on every Windows default version of Powershell launch." -f Cyan
		}
	catch { Write-Error "Failed to create or update the profile. Error: $_" }
}

$profilePath = "$PersonalFolderValue\Powershell"
if (!(Test-Path -Path $profilePath)) { New-Item -Path $profilePath -ItemType "directory" }
if (!(Test-Path -Path $profilePath\Microsoft.PowerShell_profile.ps1 -PathType Leaf)) {
    try {
        Invoke-RestMethod https://github.com/$githubUser/powershell-profile-server/raw/main/Microsoft.PowerShell_profile.ps1 -OutFile $profilePath\Microsoft.PowerShell_profile.ps1
        Write-Host "The profile @ [$profilePath\Microsoft.PowerShell_profile.ps1] has been created and will be executed on every Powershell 7.x launch." -f Cyan
    	}
    catch { Write-Error "Failed to create or update the profile. Error: $_" }
}

#### DETECTION + User download: fastfetch example profile picture and config at ~/.config/fastfetch/ if they don't exist.
if (!(Test-Path -Path $FFConfig -PathType Leaf)) {
    try {
        # Create Profile directories if they do not exist.
	    $FFPath = Join-Path -Path $env:localappdata -ChildPath "fastfetch"
	    if (!(Test-Path -Path $FFPath)) { New-Item -Path $FFPath -ItemType "directory" }
     	Invoke-RestMethod https://raw.githubusercontent.com/rungok/PowerShell-Profile-Server/refs/heads/main/frames.jsonc -OutFile $FFConfig
        Write-Host "FastFetch config-file @ [$FFConfig] has been created and will be used by FastFetch on every Terminal/Powershell-window launch." -f Cyan
		Invoke-RestMethod https://raw.githubusercontent.com/rungok/PowerShell-Profile-Server/refs/heads/main/indianai_cropped2.png -OutFile $FFlogo
        Write-Host "FastFetch profile-pic @ [$FFlogo] has been created and will be used by FastFetch on every Terminal/Powershell-window launch." -f Cyan
    	}
    catch { Write-Error "Failed to create or update $FFConfig and/or $FFLogo. Error: $_" }
}

#### DETECTION + Admin install: Powershell 7.x
function Update-PowerShell {
	if ($isAdmin) {
		Write-Host "PowerShell v7.x is not installed or outdated. Downloading latest MSI and starting the installer..." -f Cyan
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
		# iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
		# 1. Download the latest stable 64-bit MSI package
		Invoke-WebRequest -Uri 'https://github.com' -OutFile "$env:TEMP\pwsh7.msi"
		# 2. Execute the Windows Installer quietly 
		Start-Process msiexec.exe -ArgumentList '/i', "$env:TEMP\pwsh7.msi", '/quiet', '/norestart' -Wait
		} else { Write-Host ("❌ Shell must be started in elevated mode to update or install Powershell v7.x") -f Cyan }
}

if (-not (Test-CommandExists pwsh)) {
	Update-PowerShell
	} else { 
  	Write-Detect "PowerShell Core (pwsh)"
}

#### DETECTION + Admin install: Microsoft Windows Terminal for Windows 2022/10 kernel
if (-not (Test-CommandExists wt)) {
	if ($isAdmin) {
		if ($is2022) {
  		Write-Host "❌ Microsoft Windows Terminal not found. Attempting to install required components and Terminal from Microsoft and Github...:" -f Cyan
		 	try {
					CD $Home\Downloads
					if (!(Test-Path -Path '.\WindowsTerminalPreInstallKit')) { New-Item -Path '.\WindowsTerminalPreInstallKit' -ItemType "directory" }
					CD .\WindowsTerminalPreinstallKit\
					Write-Host "Downloading VCLibs..." -nonewline -f Cyan
						if (!(Test-Path -Path .\Microsoft.VCLibs.x86.14.00.Desktop.appx)) {
					Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -outfile .\Microsoft.VCLibs.x64.14.00.Desktop.appx }
					Write-Host "installing...: " -nonewline -f Cyan
					Add-AppxPackage .\Microsoft.VCLibs.x64.14.00.Desktop.appx
						Write-host "√" -b DarkGreen -f White
			
					Write-Host "Downloading WindowsTerminalPreinstallKit.zip..." -nonewline -f Cyan
					if (!(Test-Path -Path .\WindowsTerminalPreinstallKit.zip)) {
						Invoke-WebRequest -Uri https://github.com/microsoft/terminal/releases/download/v1.23.12371.0/Microsoft.WindowsTerminal_1.23.12371.0_8wekyb3d8bbwe.msixbundle_Windows10_PreinstallKit.zip -outfile .\WindowsTerminalPreInstallKit.zip }
					Write-Host "Expanding..." -nonewline -f Cyan
					Expand-Archive .\WindowsTerminalPreInstallKit.zip .
					Write-Host "installing...: " -nonewline -f Cyan
					Add-AppxPackage .\Microsoft.UI.Xaml.2.8_8.2501.31001.0_x64__8wekyb3d8bbwe.appx
					Add-AppxPackage .\7d37c32af9f64227a7f03dfb1d1ab7b2.msixbundle
						Write-host "√" -b DarkGreen -f White
				 
					Write-Host "Downloading Windows Terminal..." -nonewline -f Cyan
					if (!(Test-Path -Path .\Microsoft.WindowsTerminal_1.23.12371.0_8wekyb3d8bbwe.msixbundle)) {
						Invoke-WebRequest -Uri https://github.com/microsoft/terminal/releases/download/v1.23.12371.0/Microsoft.WindowsTerminal_1.23.12371.0_8wekyb3d8bbwe.msixbundle -outfile .\Microsoft.WindowsTerminal_1.23.12371.0_8wekyb3d8bbwe.msixbundle }
					Write-Host "installing...: " -nonewline -f Cyan
					Add-AppxPackage .\Microsoft.WindowsTerminal_1.23.12371.0_8wekyb3d8bbwe.msixbundle
						Write-host "√" -b DarkGreen -f White
						
					if (Test-CommandExists wt) {
					Write-Host "Terminal installed successfully. Initializing...:" -ForegroundColor DarkGreen
					wt
					exit
		  	    	}
			    }
			    catch { Write-Error "Failed to install Microsoft Windows Terminal. Error: $_" }
	        } else {
	      	  If ($PSVersionTable.PSVersion.Major -eq 5) { Write-Host "❌ Microsoft Windows Terminal cannot be installed on Windows 2019, so start Powershell v7.0 instead to install rest of components:" -f Cyan }
        }
   	}
} 

######################################################################
##### Setting aliases spesific to PowerShell-Profile-Server Pimp #####
######################################################################
New-Alias np "$env:Programfiles\Notepad++\Notepad++.exe" -Force
New-Alias vi np -Force
New-Alias edit np -Force
function hf {Get-Content (Get-PSReadlineOption).HistorySavePath}
New-Alias Get-FullHistory hf -Force
function Path { $env:Path }
function PathX { $env:Path -split ';' }
function env {Get-ChildItem env:}


#########################################################################
##### Aliases and functions spesific from forked powershell-profile ##### 
#########################################################################

# Terminal Window Title Customization if started in elevated mode
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$adminSuffix" -f $PSVersionTable.PSVersion.ToString()

# Editor Configuration
$EDITOR = if (Test-CommandExists nvim) { 'nvim' }
          elseif (Test-CommandExists pvim) { 'pvim' }
          elseif (Test-CommandExists vim) { 'vim' }
          elseif (Test-CommandExists vi) { 'vi' }
          elseif (Test-CommandExists code) { 'code' }
          elseif (Test-CommandExists notepad++) { 'notepad++' }
          elseif (Test-CommandExists sublime_text) { 'sublime_text' }
          else { 'notepad' }
Set-Alias -Name vim -Value $EDITOR -Force

function Edit-Profile {
    vim $PROFILE
}
function touch($file) { "" | Out-File $file -Encoding ASCII }
function ff($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.FullName)"
    }
}

# Network Utilities
function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip).Content }

# Open WinUtil
function winutil {
	iwr -useb https://christitus.com/win | iex
}

# System Utilities
function admin {
    if ($args.Count -gt 0) {
        $argList = "& '$args'"
        Start-Process wt -Verb runAs -ArgumentList "pwsh.exe -NoExit -Command $argList"
    } else {
        Start-Process wt -Verb runAs
    }
}

# Set UNIX-like aliases for the admin command, so sudo <command> will run the command with elevated rights.
Set-Alias -Name su -Value admin

function uptime {
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        Get-WmiObject win32_operatingsystem | Select-Object @{Name='LastBootUpTime'; Expression={$_.ConverttoDateTime($_.lastbootuptime)}} | Format-Table -HideTableHeaders
    } else {
        net statistics workstation | Select-String "since" | ForEach-Object { $_.ToString().Replace('Statistics since ', '') }
    }
}

function reload-profile {
    & $profile
}

function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter $file | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}
function hb {
    if ($args.Length -eq 0) {
        Write-Error "No file path specified."
        return
    }
    
    $FilePath = $args[0]
    
    if (Test-Path $FilePath) {
        $Content = Get-Content $FilePath -Raw
    } else {
        Write-Error "File path does not exist."
        return
    }
    
    $uri = "http://bin.christitus.com/documents"
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $Content -ErrorAction Stop
        $hasteKey = $response.key
        $url = "http://bin.christitus.com/$hasteKey"
        Write-Output $url
    } catch {
        Write-Error "Failed to upload the document. Error: $_"
    }
}

function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}

function df {
    get-volume
}

function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}

function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}

function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}

function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

function pgrep($name) {
    Get-Process $name
}

function head {
  param($Path, $n = 10)
  Get-Content $Path -Head $n
}

function tail {
  param($Path, $n = 10, [switch]$f = $false)
  Get-Content $Path -Tail $n -Wait:$f
}

# Quick File Creation
function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

# Directory Management
function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

### Quality of Life Aliases

# Navigation Shortcuts
function docs { Set-Location -Path $HOME\Documents }

function dtop { Set-Location -Path $HOME\Desktop }

# Quick Access to Editing the Profile
function ep { vim $PROFILE }

# Simplified Process Management
function k9 { Stop-Process -Name $args[0] }

# Enhanced Listing
function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }
function ll { Get-ChildItem -Path . -Force -Hidden | Format-Table -AutoSize }

# Git Shortcuts
function gs { git status }

function ga { git add . }

function gc { param($m) git commit -m "$m" }

function gp { git push }

function g { __zoxide_z github }

function gcl { git clone "$args" }

function gcom {
    git add .
    git commit -m "$args"
}
function lazyg {
    git add .
    git commit -m "$args"
    git push
}

# Quick Access to System Information
function sysinfo { Get-ComputerInfo }

# Networking Utilities
function flushdns {
	Clear-DnsClientCache
	Write-Host "DNS has been flushed"
}

# Clipboard Utilities
function cpy { Set-Clipboard $args[0] }

function pst { Get-Clipboard }


### Enhanced PowerShell Experience if Powershell v7+ ###
If ($PSVersionTable.PSVersion.Major -eq 7) { 
	Set-PSReadLineOption -Colors @{
	    Command = 'Yellow'
	    Parameter = 'Green'
	    String = 'DarkCyan'
	}
	
	$PSROptions = @{
	    ContinuationPrompt = '  '
	    Colors             = @{
	    Parameter          = $PSStyle.Foreground.Magenta
	    Selection          = $PSStyle.Background.Black
	    InLinePrediction   = $PSStyle.Foreground.BrightYellow + $PSStyle.Background.BrightBlack
	    }
	}
	Set-PSReadLineOption @PSROptions
	Set-PSReadLineKeyHandler -Chord 'Ctrl+f' -Function ForwardWord
	Set-PSReadLineKeyHandler -Chord 'Enter' -Function ValidateAndAcceptLine
	
	$scriptblock = {
	    param($wordToComplete, $commandAst, $cursorPosition)
	    dotnet complete --position $cursorPosition $commandAst.ToString() |
	        ForEach-Object {
	            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
	        }
	}
	Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock $scriptblock
}

########################################################################
##### Special Pink Prompt to replace the old Oh-My-Posh bloatware ##### 
########################################################################

# --- Colors (tweak these RGB triples to taste) ---
$Esc = [char]27

# Segment background colors
$BlueBG   = "48;2;76;94;172"    # "Rune" segment
$PinkBG   = "48;2;196;60;140"   # "~\OneDrive" segment
$LPinkBG  = "48;2;230;90;150"   # time segment

# Segment foreground colors (for arrow transitions, matches previous bg)
$BlueFG   = "38;2;76;94;172"
$PinkFG   = "38;2;196;60;140"
$LPinkFG  = "38;2;230;90;150"

$White    = "38;2;255;255;255"
$Green    = "38;2;0;220;120"

# Powerline separator glyphs (require Nerd Font)
$Sep      = [char]0xE0B0   # ""  sharp separator between segments
$RoundCap = [char]0xE0B6   # ""  rounded starting cap

function prompt {
    $path = (Get-Location).Path.Replace($HOME, "~")

    # Rounded cap: colored like segment 1, no background (blends into terminal bg)
    $cap = "$Esc[${BlueFG}m$RoundCap$Esc[0m"

    # Segment 1: user/machine label
    $seg1 = "$Esc[$BlueBG;${White}m $env:USERNAME" + "@" + "$env:computername $Esc[0m"
    $arrow1 = "$Esc[$BlueFG;48;2;196;60;140m$Sep$Esc[0m"

    # Segment 2: path with heart icon
    $seg2 = "$Esc[$PinkBG;${White}m $path $Esc[0m"
    $arrow2 = "$Esc[$PinkFG;48;2;230;90;150m$Sep$Esc[0m"

    # Segment 3: time
    $time = Get-Date -Format "HH:mm:ss"
    $seg3 = "$Esc[$LPinkBG;${White}m $time $Esc[0m"
    $arrow3 = "$Esc[${LPinkFG}m$Sep$Esc[0m"

    # Cursor: green block, same line, no line break
    $cursor = "$Esc[${Green}m$Esc[0m "

    "$cap$seg1$arrow1$seg2$arrow2$seg3$arrow3$cursor"
}


# Help Function
function Show-Help {
    @"
Help for $tit
`e[33m.=======================================================================================================================.
`e[33m|`e[37m Path - Prints out current users Path like MS-DOS.																		`e[121G`e[33m|
`e[33m|`e[37m PathX - Prints out current users Path like MS-DOS in listed format.													`e[121G`e[33m|
`e[33m|`e[37m np - Notepad++ full qualified path. Write np "$"PROFILE to edit script.												`e[121G`e[33m|
`e[33m|`e[37m vi - same as np																										`e[121G`e[33m|
`e[33m|`e[37m hf - Full commandline history (also Get-FullHistory works)           													`e[121G`e[33m|
`e[33m|`e[37m env - Prints out all environment variables (Get-ChildItam env:)      													`e[121G`e[33m|
`e[33m|`e[37m Update-Profile - Checks for profile updates from a remote repository and updates if necessary.						`e[121G`e[33m|
`e[33m|`e[37m Update-PowerShell - Checks for the latest PowerShell release and updates if a new version is available.				`e[121G`e[33m|
`e[33m|`e[37m Edit-Profile - Opens the current user's profile for editing using the configured editor.								`e[121G`e[33m|
`e[33m|`e[37m touch <file> - Creates a new empty file.																				`e[121G`e[33m|
`e[33m|`e[37m ff <name> - Finds files recursively with the specified name.															`e[121G`e[33m|
`e[33m|`e[37m Get-PubIP - Retrieves the public IP address of the machine.															`e[121G`e[33m|
`e[33m|`e[37m winutil - Runs the WinUtil script from Chris Titus Tech.																`e[121G`e[33m|
`e[33m|`e[37m uptime - Displays the system uptime.																					`e[121G`e[33m|
`e[33m|`e[37m reload-profile - Reloads the current user's PowerShell profile.														`e[121G`e[33m|
`e[33m|`e[37m unzip <file> - Extracts a zip file to the current directory.															`e[121G`e[33m|
`e[33m|`e[37m hb <file> - Uploads the specified file's content to a hastebin-like service and returns the URL.						`e[121G`e[33m|
`e[33m|`e[37m grep <regex> [dir] - Searches for a regex pattern in files within the specified directory or from the pipeline input.	`e[121G`e[33m|
`e[33m|`e[37m df - Displays information about volumes.																				`e[121G`e[33m|
`e[33m|`e[37m sed <file> <find> <replace> - Replaces text in a file.																`e[121G`e[33m|
`e[33m|`e[37m which <name> - Shows the path of the command.																			`e[121G`e[33m|
`e[33m|`e[37m export <name> <value> - Sets an environment variable.																	`e[121G`e[33m|
`e[33m|`e[37m pkill <name> - Kills processes by name.																				`e[121G`e[33m|
`e[33m|`e[37m pgrep <name> - Lists processes by name.																				`e[121G`e[33m|
`e[33m|`e[37m head <path> [n] - Displays the first n lines of a file (default 10).													`e[121G`e[33m|
`e[33m|`e[37m tail <path> [n] - Displays the last n lines of a file (default 10).													`e[121G`e[33m|
`e[33m|`e[37m nf <name> - Creates a new file with the specified name.																`e[121G`e[33m|
`e[33m|`e[37m mkcd <dir> - Creates and changes to a new directory.																	`e[121G`e[33m|
`e[33m|`e[37m docs - Changes the current directory to the user's Documents folder.													`e[121G`e[33m|
`e[33m|`e[37m dtop - Changes the current directory to the user's Desktop folder.													`e[121G`e[33m|
`e[33m|`e[37m ep - Opens the profile for editing.																					`e[121G`e[33m|
`e[33m|`e[37m k9 <name> - Kills a process by name.																					`e[121G`e[33m|
`e[33m|`e[37m la - Lists all files in the current directory with detailed formatting.												`e[121G`e[33m|
`e[33m|`e[37m ll - Lists all files, including hidden, in the current directory with detailed formatting.							`e[121G`e[33m|
`e[33m|`e[37m gs - Shortcut for 'git status'.																						`e[121G`e[33m|
`e[33m|`e[37m ga - Shortcut for 'git add .'.																						`e[121G`e[33m|
`e[33m|`e[37m gc <message> - Shortcut for 'git commit -m'.																			`e[121G`e[33m|
`e[33m|`e[37m gp - Shortcut for 'git push'.																							`e[121G`e[33m|
`e[33m|`e[37m g - Changes to the GitHub directory.																					`e[121G`e[33m|
`e[33m|`e[37m gcom <message> - Adds all changes and commits with the specified message.												`e[121G`e[33m|
`e[33m|`e[37m lazyg <message> - Adds all changes, commits with the specified message, and pushes to the remote repository.			`e[121G`e[33m|
`e[33m|`e[37m sysinfo - Displays detailed system information.																		`e[121G`e[33m|
`e[33m|`e[37m flushdns - Clears the DNS cache.																						`e[121G`e[33m|
`e[33m|`e[37m cpy <text> - Copies the specified text to the clipboard.																`e[121G`e[33m|
`e[33m|`e[37m pst - Retrieves text from the clipboard.																				`e[121G`e[33m|
`e[33m|`e[37m z - ehanced zoxide CD (change directory) that guess which directory you want to change to based on history.			`e[121G`e[33m|
'-----------------------------------------------------------------------------------------------------------------------'
Use 'Show-Help' to display this help message.
"@
}

# Write-host "$([char]0x1b)[1F" -nonewline
Write-host "$([char]0x1b)[9A" -nonewline
# Write-host "                                                                "

#### Function to check if Terminal version is above 1.22 which is the first version to support inline graphics
function Get-WindowsTerminalVersion {
    $currentPid = $PID
    while ($currentPid) {
        $proc = Get-Process -Id $currentPid -ErrorAction SilentlyContinue
        if ($proc -and $proc.ProcessName -eq 'WindowsTerminal') {
            $path = $proc.Path
            if ($path) {
                $verInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
                return [version]$verInfo.FileVersion
            }
        }
        $currentPid = $proc.Parent.Id
    }
    return $null
}

# Check version
$wtVersion = Get-WindowsTerminalVersion
$minVersion = [version]'1.22.0.0'

#### Execute sixel image conversion if the Terminal is v1.22 + Execute fastfetch according to Terminal capabilities
if ($wtVersion -and $wtVersion -ge $minVersion) {
	# Check if $FFLogo exist and convert $FFLogo to $FFLogo + ".sixel" if the sixel-version doesn's exist in same folder.
	$SixLogo = $FFlogo + ".sixel"
	if ((Test-Path -Path $FFLogo -PathType Leaf)) {
		# Remove old fubar file.sixel if it exist
		if ((Test-Path -Path $SixLogo -PathType Leaf)) {
			$SixObject = Get-Item -Path $Sixlogo
			If ($SixObject.Length -eq 0) { Remove-Item -Path $Sixlogo -Force }
		}
		# convert image to sixel format
		if (!(Test-Path -Path $SixLogo -PathType Leaf)) {
			ConvertTo-Sixel $FFlogo -Width $FFlogoWidth -Height $FFlogoHeight > $SixLogo
		}
	} 

	# Executing FastFetch (neofetch-port but faster compiled in C++)
	fastfetch --raw $SixLogo --logo-width $FFlogoWidth --logo-height $FFlogoHeight --config $FFConfig
	# optionally --logo-width 55 --logo-height 28 --logo-padding-top 1 --logo-padding 5 (--logo-width $NUMBER_OF_COLUMNS_USED --logo-height $NUMBER_OF_ROWS_USED)
} else { 
	If ($is2022) { fastfetch --logo "Windows" --percent-type 11 --bar-char-total "-" --bar-char-elapsed "o" } else { fastfetch }
}
# Write-host "                                                                "
Write-Host "Write 'Show-Help' to display overview of enhanced PowerShell commands in this setup" -f DarkGreen


#############################################################################################################################################################
#
#	Changes last few versions
#
#	Version 3.0
#	- Removed bug trying to overwrite the default history alias, which Powershell doesn't accept.
#	- Replaced oh-my-posh with some simpler code that just sets a prompt and leave it at that.
#	- Fixed bug where ConvertTo-Sixel didn't convert logo to appropriate format because of old terminal version.
#   - Set full right-click menu to ENABLED and Compact File Explorer to ENABLED if build is Windows 2025 / 11 shell.
#   - Performance-optimized detection-procedures and logic, which almost halfed the execution time.
#
#	Version 2.8
#	- ConvertTo-Sixel module added (since Windows Terminal now has support for real inline pictures like kitty on Linux, but in sixel format)
#	- FastFetch options modified to handle converted sixel picture via -raw option with size parameters
#
#	Version 2.5
#	- Changed from using winfetch to fastfetch (much more powerful and faster and winfetch might have been abandonded since it also stopped working)
#
