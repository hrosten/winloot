@echo off

::#############################################################################

:begin
set MY_NAME=%~n0

if [%1]==[] goto usage
if [%2]==[] goto usage
if [%3]==[] goto usage
if not [%4]==[] goto usage

set IP=%1
set PORT=%2
set FILE=%3

set URL=http://%IP%:%PORT%/%FILE%
set LOCAL=%~dp0%FILE%

echo [+] Downloading: %URL% to %LOCAL%

echo.
pause
powershell -command "& { (New-Object Net.WebClient).DownloadFile('%URL%', '%LOCAL%') }"

goto :EOF

::#############################################################################

:usage
echo Usage: %MY_NAME% ^<ip^> ^<port^> ^<file^>
goto :end

::#############################################################################

:end