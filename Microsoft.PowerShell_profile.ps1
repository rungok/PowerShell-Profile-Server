#####################################################################################################
$tit = 'PowerShell-Profile-Server Pimp v2.6 by GOKS0R DEVELOPMENT'									#
$githubUser = 'rungok'																				#
$PoshTheme = 'quick-term'  # Write Get-PoshThemes to see all themes in action						#
$FFConfig = $env:UserProfile + '\.config\fastfetch\frames.jsonc'									#
$FFlogo = $env:UserProfile + '\.config\fastfetch\indianai_cropped2.png' # Specify logo path			#
$FFlogoWidth = 60  # Width  in number of chars														#
$FFlogoHeight = 43 # Height in number of chars														#
#																									#
#  This script will try to install Microsoft Windows Terminal with required components				#
#  in additions to Oh-My-Posh and other enhancments so even some Linux-commands will work.			#
#  Then it will insert this script where it should be placed, which is the path						#
#  of $PROFILE. Write $PROFILE in Powershell if you wonder where it is. Usually in your				#
#  $HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1										#
#																									#
#  Manual changes needed after install:																#
#  Change your font to RobotoMono Size 10 and set font rendering to ClearType for icon rendering	#
#  Write Fastfetch --print-logos to see all logos													#
#  When using picture, it will be converted to raw sixel format to work in Windows Terminal,		#
#  For some reason, it can payoff to resize picture out of aspect to 90% of its height. 			#
#####################################################################################################

Write-Host("`n         .--------< ") -f white -nonewline
Write-Host($tit) -f Cyan -nonewline
Write-Host(" >----------------.") -f white
Write-Host("         '-------------------------------------------------------------------------------------'`n") -f white

$execPolicy = Get-ExecutionPolicy
if ($execPolicy -ne "RemoteSigned") {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
}

#### Test if Powershell is started in elevated mode for system installs that need it ####
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

#### opt-out of telemetry before doing anything, only if PowerShell is run as admin ####
if ($isAdmin) {
    [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'true', [System.EnvironmentVariableTarget]::Machine)
}

#### Check Windows version is 2022 or lower ###
If (([Environment]::OSVersion).Version.Build -lt 18362) { [bool] $is2022 = $false } else { [bool] $is2022 = $true }

# Initial GitHub.com connectivity check with 1 second timeout
$canConnectToGitHub = Test-Connection github.com -Count 1 -Quiet

# Write out a detection sentence with √ in front of it
function Write-Detect {
    param ([string]$Software = "Program")
    Write-host " " -nonewline
    If (($PSVersionTable.PSVersion.Major -gt 6) -and ($is2022)) { 
	Write-host ("✅") -nonewline -f DarkGreen
	} else { Write-host "v" -nonewline -b DarkGreen -f White } 
    Write-host " $Software detected.                     "  -f Green
	Write-host "$([char]0x1b)[1F" -nonewline
}

################################################################################
####### Test all components status and install if they are not present #########
################################################################################


# Install NuGet to ensure the other packages can be installed.
$nugetProvider = Get-PackageProvider | Select-Object Name | Where-Object Name -match NuGet
if (-not $nugetProvider) {
    Write-Host "NuGet provider not found. Installing..." -f Cyan
    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser
    Import-PackageProvider -Name NuGet -Force
    Write-Host "NuGet provider installed."
} else {
    Write-Detect "NuGet provider"
}
# Trust the PSGallery repository.
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

### Detect and Install Terminal-Icons module
if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) {
    Install-Module -Name Terminal-Icons -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module -Name Terminal-Icons

### Detect and Install ConvertTo-Sixel module
if (-not (Get-Module -ListAvailable -Name Sixel)) {
    Install-Module -Name Sixel -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module -Name Sixel

##### Check if .net v4.8 is installed #### 
$dotnet = (Get-ItemPropertyValue -LiteralPath 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release) -ge 528040
if ($dotnet) {
    Write-Detect ".NET Framework v4.8 or higher"
} else {
    Write-Host "❌ .NET Framework Version 4.8 or later is not detected. Chocolatey packet manager needs .NET runtime libraries v4.8, and will try to install it automaticly." -f Cyan
    If ((!$is2022) -and ($isAdmin)) {
    	Write-Host "❌ Server 2019 detected. Unfortunately .NET v4.8 upgrade on server 2019 triggers some registry fixes that requires a FULL SERVER RESTART to activate." -f Magenta
    }
}

### Install Chocolatey if not installed and shell is started in administrative mode ####
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
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

### Talk about .net v4.8 restart ###
If ((!$is2022) -and ($isAdmin) -and (!$dotnet)) {
  	Write-Host "❌ You can close Powershell window or press CTRL+C and do a FULL SERVER RESTART from this point if you like." -f Magenta
	Write-Host "As this script is server oriented, it will never force a Windows restart." -f Magenta
    	Write-Host "However, rest of the script will keep whining about missing v4.8 if you don't" -f Magenta
        Write-Host "(But you can of course schedule that restart for later if need be. F.ex. write" -f Magenta
	Write-Host "'shutdown.exe -r -f -t 21600' in CLI where -(r)estart, -(f)orce, -(t)ime 21600 seconds is 6 hours )" -f Magenta
	######### Message-box ##########
        $delay = 10
        $wshell = New-Object -ComObject Wscript.Shell
        $wshell.Popup("Recommend a restart now to activate .NET v4.8",$delay,"Old Windows needs a reboot",0x0)
        start-sleep 1
        $delay -= 1
}

### Install zoxide fuzzy shell if not installed and shell is started in administrative mode ####
if (Get-Command zoxide -ErrorAction SilentlyContinue) {
	Write-Detect "Zoxide"
	Invoke-Expression (& { (zoxide init --cmd cd powershell | Out-String) })
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


####### Install Oh-My-Posh if not installed and shell is started in administrative mode ########
if (Get-Command oh-my-posh -ErrorAction SilentlyContinue) {
	Write-Detect "Oh-My-Posh"
	# Invoke-Expression (& { (Oh-My-Posh init --cmd cd powershell | Out-String) })
} else {
	if ($isAdmin) {
		Write-Host "❌ Oh-My-Posh not installed. Attempting to install via " -nonewline -f Cyan
		try {
			choco install Oh-My-Posh -y
			Write-Host "Oh-My-Posh installed successfully. Initializing..." -ForegroundColor DarkGreen
   			refreshenv
		} catch {
			Write-Error "❌ Failed to install Oh-My-Posh. Error: $_"
		}
	} else { Write-Host ("❌ Powershell must be started in elevated mode to install Oh-My-Posh. Oh-My-Posh will not be activated until this is done.") -f Cyan }
}

####### Install Notepad++ if not installed and shell is started in administrative mode ########
if (Get-Command Notepad++ -ErrorAction SilentlyContinue) {
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


####### Install ImageMagick if not installed and shell is started in administrative mode ########
if (Get-Command Magick -ErrorAction SilentlyContinue) {
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


####### Install FastFetch if not installed and shell is started in administrative mode ########
if (Get-Command fastfetch -ErrorAction SilentlyContinue) {
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


#### Download extra fastfetch profile picture and config at ~/.config/fastfetch/
if (!(Test-Path -Path $FFConfig -PathType Leaf)) {
    try {
        # Detect Version of PowerShell & Create Profile directories if they do not exist.
        $profilePath = ""
	    $profilePath = "$env:userprofile\Documents\.config\fastfetch"
	    if (!(Test-Path -Path $profilePath)) { New-Item -Path $profilePath -ItemType "directory" }
     	    Invoke-RestMethod https://github.com/$githubUser/PowerShell-Profile-Server/blob/main/frames.jsonc -OutFile $FFConfig
            Write-Host "FastFetch config-file @ [$FFConfig] has been created and will be used by FastFetch on every Terminal/Powershell-window launch." -f Cyan
			Invoke-RestMethod https://github.com/$githubUser/PowerShell-Profile-Server/blob/main/indianai_cropped2.png -OutFile $FFlogo
            Write-Host "FastFetch logo @ [$FFlogo] has been created and will be used by FastFetch on every Terminal/Powershell-window launch." -f Cyan
    	}
    catch { Write-Error "Failed to create or update the profile. Error: $_" }
}

#### Install Cascadia Mono (default Terminal Nerd Font)
If (choco list --local-only --limit-output | ConvertFrom-Csv -Delimiter '|' -Header Name, Version | Select-Object Name | Where-Object Name -match robotomono) {
	Write-Detect "RobotoMono Nerd Font"
} else {
 	Write-Host "❌ RobotoMono nerd font not installed. Attempting to install via " -nonewline -f Cyan
 	choco install nerd-fonts-robotomono -y
}

###########################################################
####### Profile creation or update if not present #########
###########################################################

if (!(Test-Path -Path $PROFILE -PathType Leaf)) {
    try {
        # Detect Version of PowerShell & Create Profile directories if they do not exist.
        $profilePath = ""
	    $profilePath = "$env:userprofile\Documents\WindowsPowerShell"
	    if (!(Test-Path -Path $profilePath)) { New-Item -Path $profilePath -ItemType "directory" }
     	    Invoke-RestMethod https://github.com/$githubUser/powershell-profile-server/raw/main/Microsoft.PowerShell_profile.ps1 -OutFile $PROFILE
	    $profilePath = "$env:userprofile\Documents\Powershell"
	    if (!(Test-Path -Path $profilePath)) { New-Item -Path $profilePath -ItemType "directory" }
            Invoke-RestMethod https://github.com/$githubUser/powershell-profile-server/raw/main/Microsoft.PowerShell_profile.ps1 -OutFile $profilePath\Microsoft.PowerShell_profile.ps1
            Write-Host "The profile @ [$PROFILE] has been created and will be executed on every Terminal/Powershell-window launch." -f Cyan
    	}
    catch { Write-Error "Failed to create or update the profile. Error: $_" }
}

function Update-Profile {
    try {
		$TimeMarker = Get-Date -Format "ddMMyyyy_HHmm"
		$Bakfile = "Microsoft.PowerShell_profile_"+$TimeMarket+".ps1.bak"
        Get-Item -Path $PROFILE | Move-Item -Destination $Bakfile -Force
        Invoke-RestMethod https://github.com/$githubUser/powershell-profile-server/raw/main/Microsoft.PowerShell_profile.ps1 -OutFile $PROFILE
        Write-Host "The profile has been created at " -f Cyan -nonewline;Write-Host $PROFILE;Write-Host "     and old profile renamed to " -f Cyan -nonewline;Write-Host $Bakfile -f DarkGray
    }
    catch {
        Write-Error "Failed to backup and update the profile. Error: $_"
    }
}

##########################################
##### Install opensource Powershell ######
##########################################

function Update-PowerShell {
	if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
 		if ($isAdmin) {
			Write-Host "PowerShell Core (pwsh v7.x) is not installed. Starting the install..." -f Cyan
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
			# Start-Sleep -Seconds 8 # Wait for the update to finish
			# Write-Host "Restarting the installation script with Powershell Core" -ForegroundColor DarkGreen
			# Start-Process pwsh -ArgumentList "-NoExit", "-Command Invoke-Expression (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/$githubUser/powershell-profile-server/main/Microsoft.PowerShell_profile.ps1'-UseBasicParsing).Content"
			# exit
	  		}
		} else { 
  		Write-Detect "PowerShell Core (pwsh)"
    		}
}
Update-PowerShell

######################################
# Microsoft Windows Terminal Install # -> Must be installed manually to get around the Windows edition check on Windows Servers
######################################
if (-not (Get-Command wt -ErrorAction SilentlyContinue)) {
	if ($isAdmin) {
		if ($is2022) {
  		Write-Host "❌ Microsoft Windows Terminal not found. Attempting to install required components and Terminal from Microsoft and Github...:" -f Cyan
		 	try {
			    CD $Home\Downloads
			    Write-Host "Downloading VCLibs..." -nonewline -f Cyan
		     	    if (!(Test-Path -Path .\Microsoft.VCLibs.x86.14.00.Desktop.appx)) {
			  	Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -outfile Microsoft.VCLibs.x86.14.00.Desktop.appx }
			    Write-Host "installing...: " -nonewline -f Cyan
			    Add-AppxPackage .\Microsoft.VCLibs.x86.14.00.Desktop.appx
		     	    Write-host "√" -b DarkGreen -f White
		
		     	    Write-Host "Downloading PreinstallKit..." -nonewline -f Cyan
			    if (!(Test-Path -Path .\PreinstallKit.zip)) {
		     		Invoke-WebRequest -Uri https://github.com/microsoft/terminal/releases/download/v1.21.2361.0/Microsoft.WindowsTerminal_1.21.2361.0_8wekyb3d8bbwe.msixbundle_Windows10_PreinstallKit.zip -outfile .\PreinstallKit.zip }
		     	    
			    Write-Host "installing...: " -nonewline -f Cyan
		     	    Expand-Archive .\PreinstallKit.zip .
			    Add-AppxPackage .\Microsoft.UI.Xaml.2.8_8.2310.30001.0_x64__8wekyb3d8bbwe.appx
			    Add-AppxPackage .\754329278a2d4caa964755f3410dd892.msixbundle
		     	    Write-host "√" -b DarkGreen -f White
		     
			    Write-Host "Downloading Terminal..." -nonewline -f Cyan
			    if (!(Test-Path -Path .\Microsoft.WindowsTerminal_1.21.2361.0_8wekyb3d8bbwe.msixbundle)) {
		     		Invoke-WebRequest -Uri https://github.com/microsoft/terminal/releases/download/v1.21.2361.0/Microsoft.WindowsTerminal_1.21.2361.0_8wekyb3d8bbwe.msixbundle -outfile .\Microsoft.WindowsTerminal_1.21.2361.0_8wekyb3d8bbwe.msixbundle }
			    Write-Host "installing...: " -nonewline -f Cyan
			    Add-AppxPackage Microsoft.WindowsTerminal_1.21.2361.0_8wekyb3d8bbwe.msixbundle
		     	    Write-host "√" -b DarkGreen -f White
		     	    
		   	    if (Get-Command wt -ErrorAction SilentlyContinue) {
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
New-Alias Notepad "$env:Programfiles\Notepad++\Notepad++.exe"
New-Alias np "$env:Programfiles\Notepad++\Notepad++.exe"
New-Alias vi "$env:Programfiles\Notepad++\Notepad++.exe"
function hf {Get-Content (Get-PSReadlineOption).HistorySavePath}
New-Alias Get-FullHistory hf
function Path { $env:Path }
function PathX { $env:Path -split ';' }
function env {Get-ChildItem env:}


#########################################################################
##### Aliases and functions spesific from forked powershell-profile ##### 
#########################################################################

# Prompt Customization if started in elevated mode
function prompt {
    if ($isAdmin) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$adminSuffix" -f $PSVersionTable.PSVersion.ToString()

# Utility Functions
function Test-CommandExists {
    param($command)
    $exists = $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
    return $exists
}

# Editor Configuration
$EDITOR = if (Test-CommandExists nvim) { 'nvim' }
          elseif (Test-CommandExists pvim) { 'pvim' }
          elseif (Test-CommandExists vim) { 'vim' }
          elseif (Test-CommandExists vi) { 'vi' }
          elseif (Test-CommandExists code) { 'code' }
          elseif (Test-CommandExists notepad++) { 'notepad++' }
          elseif (Test-CommandExists sublime_text) { 'sublime_text' }
          else { 'notepad' }
Set-Alias -Name vim -Value $EDITOR

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

# Get theme from profile.ps1 or use a default theme
function Get-Theme {
    if (Test-Path -Path $PROFILE.CurrentUserAllHosts -PathType leaf) {
        $existingTheme = Select-String -Raw -Path $PROFILE.CurrentUserAllHosts -Pattern "oh-my-posh init pwsh --config"
        if ($null -ne $existingTheme) {
            Invoke-Expression $existingTheme
            return
        }
    } else {
        oh-my-posh init pwsh --config https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/$PoshTheme.omp.json | Invoke-Expression
    }
}
## Final Line to set prompt
Get-Theme


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
`e[33m|`e[37m Get-PoshThemes - See overview of all Oh-My-Posh themes in action based on your current folder							`e[121G`e[33m|
'-----------------------------------------------------------------------------------------------------------------------'
Use 'Show-Help' to display this help message.
"@
}


# Write-host "$([char]0x1b)[1F" -nonewline
Write-host "                                                                "
# Check if $FFLogo exist and convert $FFLogo to $FFLogo + ".sixel" if it doesn't
$SixLogo = $FFlogo + ".sixel"
if (!(Test-Path -Path $SixLogo -PathType Leaf)) {
	ConvertTo-Sixel $FFlogo -Width $FFlogoWidth -Height $FFlogoHeight > $SixLogo
} # convert image to sixel format

# Executing FastFetch (neofetch-port but faster compiled in C++ to powershell)
fastfetch --raw $SixLogo --logo-width $FFlogoWidth --logo-height $FFlogoHeight --config $FFConfig
# optionally --logo-width 55 --logo-height 28 --logo-padding-top 1 --logo-padding 5 (--logo-width $NUMBER_OF_COLUMNS_USED --logo-height $NUMBER_OF_ROWS_USED)
# optionally2 for config-file usually designed --config "C:\Users\runeg\OneDrive - Dustin Group\Documents\PowerShell\Scripts\Bash\fastfetch\frames.jsonc"

Write-host "                                                                "
Write-Host "Write 'Show-Help' to display overview of enhanced PowerShell commands in this setup" -f DarkGreen
#############################################################################################################################################################
#
#	Changes last few versions
#
#	Version 2.6
#	- ConvertTo-Sixel module added (since Windows Terminal now has support for real inline pictures like kitty on Linux, but in sixel format)
#	- FastFetch options modified to handle converted sixel picture via -raw option with size parameters
#
#	Version 2.5
#	- Changed from using winfetch to fastfetch (much more powerful and faster and winfetch might have been abandonded since it also stopped working)
#

