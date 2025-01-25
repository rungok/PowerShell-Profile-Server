# :unicorn: PowerShell Profile Server Pimping
Have you ever tried to install the excellent Microsoft Windows Terminal on a Windows Server?
Well, you simply don't want to go through that pain twice. This powershell startup profile script does that for you including all the prereqs required for it to work on Windows 2022.
Furthermore, it will and install a couple of other powershell and terminal enhancements for you if they are not installed from before.

## ⚡ One Line Install (Elevated PowerShell Recommended)
Execute the following command in an elevated PowerShell window to install the PowerShell profile:
```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;irm "https://github.com/rungok/powershell-profile-server/raw/main/Microsoft.PowerShell_profile.ps1" | iex
```

## :male_detective: Here is a full list of what it will try to do:
- NuGet (to install Terminal-Icons in directory listings)
   - Terminal-Icons powershell module
   - WinFetch (neofetch-clone for Windows)
- Powershell v7.x
- Chocolatey Packet Manager (winget replacement that works on server OS) with following packages
     - zoxide fuzzy shell (PowerShell enhancement with predictive writing and easier folder changes)
     - Oh-My-Posh beautiful prompt with colors (and ribbons if you want)
     - notepadplusplus (Extended Notepad app with colorizing of text-types and a lot of functions)
     - nerd-fonts-robotomono (good font with extended set of terminal icons)
- VCLibs and .NET v4.8 (runtime libraries for C and .NET code)
- Aliases to ease the everyday life of ppl switching often between Linux and Windows (grep and tail works just as in Linux)
-----------------------------------------------------------------------------------------------------------------------------

## 🎨 PreView
![image](https://github.com/user-attachments/assets/d45ff30c-43d8-485a-a826-c637f8ea0e38)

When it has installed all its components, your Powershell Terminal will look and feel almost as good as a Linux terminal.
This version (compared to Titus's version) is tailored to work better for Windows Server and simplified to be only 1 significant powershell-script you can paste in
manually if you have security-blocks blocking ps-files or whatever.

This script will respect your server even if it's running in production. It will NOT do anything recless like rebooting the OS or replace already installed software/libraries (so you can let the first round run safely while you eat lunch). All versions of the files/software downloaded will be stable versions and downloaded from official Microsoft and Chocolatey main repo. If you want to run this on an offline server, that's totally possible. But you need to transfer all downloaded files manually from an online server that has ran the script before, and copy those files into your logged on users default download catalog. Choco-files are normally placed under C:\ProgramData\chocolatey\.

This script is tested on:
 - Windows Server 2019: Windows Terminal doesn't work on server 2019 or older, so script will skip trying to download or install that one. The rest will work almost as fine under standard console and PSv7.x.
 - Windows Server 2022: Windows Terminal is not officially supported on this OS, but this script will install it anyway incl. required libraries (Windows Terminal does a much better job rendering and has split and tab features).
 - Windows Server 2025: Windows Terminal is included in Windows 2025, but the rest will install even faster and work fine in the included Terminal.



## 🛠️ Fix the terminal config

After running the script. That means starting the OS-included Powershell (preferably in Administrative mode),
you need to manually change these settings by pressing CTRL + , in Windows Terminal:

1. Defaults -> Appearance -> Text -> Font Face -> <b>Robotomono</b> (Nerd font with icon set for Oh-My-Posh)
2. Defaults ->	Advanced -> Text antialiasing -> <b>ClearType</b> (important for visual quality)
3. Save. DONE!
   
## Customize this profile

There are no license restrictions on this code, so copy, fork, modify, make your own version or whatever you want. Enjoy your enhanced and stylish PowerShell experience! 🚀
