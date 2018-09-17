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

echo.
echo Start running the server on the sending end, e.g.: 
echo  nc -nlvp %PORT% or
echo  pv -b %FILE% ^| nc -nlvp %PORT%
pause

nc -nv %IP% %PORT% | pv -b > %FILE%

goto :EOF

::#############################################################################

:usage
echo Usage: %MY_NAME% ^<ip^> ^<port^> ^<file^>
goto :end

::#############################################################################

:end
