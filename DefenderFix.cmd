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
REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo.
echo %CYAN%Starting.%MAGENTA%
REM \________________________________________________________________________________________________________________________________________________________________________________________________/
:Start
echo.
echo %BLUE%setlocal%RED%
setlocal EnableExtensions DisableDelayedExpansion >> %log%
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo.
echo %BLUE%REG KEYS (1)%RED%
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
echo %BLUE%REG KEYS (2)%RED%
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
echo %BLUE%DISM%RED%
DISM /Online /Cleanup-Image /CheckHealth >> %log%
DISM /Online /Cleanup-Image /ScanHealth >> %log%
DISM /Online /Cleanup-Image /RestoreHealth >> %log%

echo %CYAN%DISM: Repairing Windows Component Store%RED%
dism /online /cleanup-image /restorehealth /source:WIM:X:\sources\install.wim:1 /limitaccess
if %errorlevel% neq 0 (
    echo %RED%[ERROR] First attempt failed, trying with Windows Update as source...%GREEN%
    dism /online /cleanup-image /restorehealth /source:windowsupdate /limitaccess
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
echo %BLUE%Checking Defender status%RED%
sc query WinDefend | find "RUNNING"
if %errorlevel% neq 0 (
    echo %RED%[ERROR] Windefend not running.
    echo Starting Windows Defender service.%GREEN%
    net start WinDefend
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

REM \________________________________________________________________________________________________________________________________________________________________________________________________/
echo.
echo %BLUE%OTHER PATCHES%RED%
bcdedit -set TESTSIGNING OFF >> %log%
PowerShell -ExecutionPolicy Unrestricted -Command "$bin = (New-Object -ComObject Shell.Application).NameSpace(10); $bin.items() | ForEach { Write-Host "^""Deleting $($_.Name) from Recycle Bin"^""; Remove-Item $_.Path -Recurse -Force; }" >> %log%
PowerShell -ExecutionPolicy Unrestricted -Command "$revertData =  '1'; reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration' /v 'DisableResetbase' /t 'REG_DWORD' /d "^""$revertData"^"" /f" >> %log%
REM \________________________________________________________________________________________________________________________________________________________________________________________________/

exit
