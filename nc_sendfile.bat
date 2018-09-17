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
if not exist %FILE% (
    echo [+] Error: file ^"%FILE%^" not found
    goto end
)

echo.
echo Start running the server on the receiving end, e.g.: 
echo  nc -nlvp %PORT% ^> %FILE% or
echo  nc -nlvp %PORT% ^| pv -b ^> %FILE%
pause

pv %FILE% | nc -nv %IP% %PORT%

goto :EOF

::#############################################################################

:usage
echo Usage: %MY_NAME% ^<ip^> ^<port^> ^<file^>
goto :end

::#############################################################################

:end
