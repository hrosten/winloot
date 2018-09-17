@echo off

::#############################################################################

:begin
set MY_NAME=%~n0

if [%1]==[] goto usage
if not [%2]==[] goto usage

set HANDLENAME=%1

handle.exe /accepteula  > nul 2>&1
handle.exe %HANDLENAME%

goto :EOF

::#############################################################################

:usage
echo Usage: %MY_NAME% ^<full_or_partial_filepathname^>
goto :end

::#############################################################################

:end
