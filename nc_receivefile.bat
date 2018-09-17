@echo off

::#############################################################################

:begin
set MY_NAME=%~n0

if [%1]==[] goto usage
if [%2]==[] goto usage
if not [%3]==[] goto usage

set PORT=%1
set FILE=%2

echo.
echo Run the client on the sending end, e.g.: 
echo  nc -nv MY_IP %PORT% ^< %FILE% or
echo  pv %FILE% ^| nc -nv MY_IP %PORT%
echo.
echo Waiting for connection from the client...

nc -nlvp %PORT% | pv -b > %FILE%

goto :EOF

::#############################################################################

:usage
echo Usage: %MY_NAME% ^<port^> ^<file^>
goto :end

::#############################################################################

:end
