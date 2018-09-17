@echo off

::#############################################################################

:begin
set MY_NAME=%~n0

if [%1]==[] goto usage
if [%2]==[] goto usage
if not [%3]==[] goto usage

set PORT=%1
set FILE=%2
if not exist %FILE% (
    echo [+] Error: file ^"%FILE%^" not found
    goto end
)

echo.
echo Run the client on the receiving end, e.g.: 
echo  nc -nv MY_IP %PORT% ^> %FILE% or
echo  nc -nv MY_IP %PORT% ^| pv -b ^> %FILE% 
echo.
echo Waiting for connection from the client...

pv %FILE% | nc -nlvp %PORT%

goto :EOF

::#############################################################################

:usage
echo Usage: %MY_NAME% ^<port^> ^<file^>
goto :end

::#############################################################################

:end
