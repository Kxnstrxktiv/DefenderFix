@echo off

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo AdminCheck (GETADMIN)
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo AdminCheck (DONE)
echo Setting Vars
set "RED=[91m"
set "YELLOW=[93m"
set "GREEN=[92m"
set "CYAN=[96m"
set "BLUE=[94m"
set "MAGENTA=[95m"
set "RESET=[0m"
set log=DefenderFixLOG_D%date%_R%random%.txt
set ver=1.0.1
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo.
echo %CYAN%Starting.%MAGENTA%
title DefenderFix V%ver%                ~Kxnstrxktiv / 1e310
echo.
echo.
echo  %CYAN%DefenderFix %YELLOW%V%ver%
echo %CYAN%\___________________/
echo.
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo.
echo %BLUE%setlocal%RED%
setlocal EnableExtensions DisableDelayedExpansion >> %log%
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo.
echo %BLUE%Disable managed by IT provider prompt%RED%
:: Remove main management flags
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "ManagedDefender" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "IsManaged" /f >> %log%
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f >> %log%
:: Remove Enterprise Management keys
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /f >> %log%
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "IsManaged" /f >> %log%
:: Disable UI management notifications
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "UI_Lockdown" /t REG_DWORD /d 0 /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "UI_ShowGroupPolicyManagedDefender" /f >> %log%
:: Clear Group Policy enforcement
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{B587E2B1-4D59-4E7E-AED9-22B9DF11D053}" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{A2E30F80-D7DE-11d2-BBDE-00C04F86AE3B}" /f >> %log%
:: Reset all component management states
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "IsManaged" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Scan" /v "IsManaged" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "IsManaged" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard" /v "IsManaged" /f >> %log%
:: Reset Windows Security app UI
reg delete "HKLM\SOFTWARE\Microsoft\SecurityCenter\Feature" /v "DisableAvNotifications" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\SecurityCenter\Feature" /v "DisableAccountProtectionUI" /f >> %log%
:: Reset Tamper Protection enforcement
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtectionEnforced" /f >> %log%
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d 1 /f >> %log%
:: Clear enterprise cloud settings
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "ForceCloudBlockLevel" /f >> %log%
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /f >> %log%
:: Reset component defaults
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f >> %log%
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "DisableNetworkProtection" /t REG_DWORD /d 0 /f >> %log%
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo.
echo %BLUE%DELETING BAD REG KEYS%RED%
:: Core Protection Keys
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /f >> %log%
:: Real-Time Protection
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /f >> %log%
:: Scanning Features
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Scan" /v "DisableEmailScanning" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Scan" /v "DisableRemovableDriveScanning" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Scan" /v "DisableScriptScanning" /f >> %log%
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Scan" /v "DisableAutoExclusions" /f >> %log%
:: Cloud Protection
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /f >> %log%
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /f >> %log%
:: Exploit Protection
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableExploitProtection" /f >> %log%
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard" /v "DisableExploitProtection" /f >> %log%
:: Network Protection
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "DisableNetworkProtection" /f >> %log%
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v "DisableNetworkProtection" /f >> %log%
:: Controlled Folder Access
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" /v "DisableControlledFolderAccess" /f >> %log%
:: Policy Manager
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" /v "DisableAntiSpyware" /f >> %log%
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" /v "DisableAntiVirus" /f >> %log%
:: Updates
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableUpdateOnStartupWithoutEngine" /f >> %log%
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo.
echo %BLUE%ADDING GOOD REG KEYS (1)%RED%
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f >> %log%
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRoutinelyTakingAction /t REG_DWORD /d 0 /f >> %log%
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v ServiceKeepAlive /t REG_DWORD /d 1 /f >> %log%
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 0 /f >> %log%
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 0 /f >> %log%
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 0 /f >> %log%
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f >> %log%
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v DisableEnhancedNotifications /t REG_DWORD /d 0 /f >> %log%
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 1 /f >> %log%
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 0 /f >> %log%
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MRT" /v DontReportInfectionInformation /t REG_DWORD /d 0 /f >> %log%
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo.
echo %BLUE%ADDING GOOD REG KEYS (2)%RED%
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f >> %log%
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f >> %log%
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 0 /f >> %log%
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d 1 /f >> %log%
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 1 /f >> %log%
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 1 /f >> %log%
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f >> %log%
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d 0 /f >> %log%
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo.
echo %BLUE%DISM (Checkhealth)%RED%
DISM /Online /Cleanup-Image /CheckHealth >> %log%
echo %BLUE%DISM (ScanHealth)%RED%
DISM /Online /Cleanup-Image /ScanHealth >> %log%
echo %BLUE%DISM (RestoreHealth)%RED%
DISM /Online /Cleanup-Image /RestoreHealth >> %log%

echo %CYAN%DISM: Repairing Windows Component Store%RED%
dism /online /cleanup-image /restorehealth /source:WIM:X:\sources\install.wim:1 /limitaccess >> %log%
if %errorlevel% neq 0 (
    echo %RED%[ERROR] First attempt failed, trying with Windows Update as source...%GREEN%
    dism /online /cleanup-image /restorehealth /source:windowsupdate /limitaccess >> %log%
)

echo %CYAN%DISM: Cleaning up component store%RED%
dism /online /cleanup-image /startcomponentcleanup >> %log%
dism /online /cleanup-image /startcomponentcleanup /resetbase >> %log%

echo %CYAN%DISM: Exporting and repairing packages%RED%
dism /online /cleanup-image /analyzecomponentstore >> %log%
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo.
echo %BLUE%SFC%RED%
sfc /scannow >> %log%
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo.
echo %BLUE%Starting Windows Update services%RED%
net start wuauserv >> %log%
net start cryptSvc >> %log%
net start bits >> %log%
net start msiserver >> %log%
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo.
echo %BLUE%OTHER PATCHES%RED%
bcdedit -set TESTSIGNING OFF >> %log%
PowerShell -ExecutionPolicy Unrestricted -Command "$bin = (New-Object -ComObject Shell.Application).NameSpace(10); $bin.items() | ForEach { Write-Host "^""Deleting $($_.Name) from Recycle Bin"^""; Remove-Item $_.Path -Recurse -Force; }" >> %log%
PowerShell -ExecutionPolicy Unrestricted -Command "$revertData =  '1'; reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration' /v 'DisableResetbase' /t 'REG_DWORD' /d "^""$revertData"^"" /f" >> %log%
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

reg flush /y
exit /b 0
