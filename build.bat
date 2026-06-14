@if "%~1"=="inner" goto :mk_inner
@cmd.exe /c ""%~f0" "inner" %*"
@if %errorlevel% neq 0 goto :mk_outer_bad
@goto :mk_outer_gud

:mk_inner
@echo off
if exist "c:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" goto :mk_enterprise_amd64
if exist "c:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" goto :mk_community_amd64
goto :mk_fail

:mk_enterprise_amd64
call "c:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" amd64
@echo off
goto :mk_next

:mk_community_amd64
call "c:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" amd64
@echo off
goto :mk_next

:mk_next
set INCLUDE=%INCLUDE%;c:\path\to\phnt
cl ^
/nologo ^
/std:c++latest ^
/O2 ^
/Ob2 ^
/Os ^
/GL ^
/MT ^
/GS- ^
/Gs1048576 ^
peb.cpp ^
/link ^
/NODEFAULTLIB ^
/LTCG ^
/RELEASE ^
/ENTRY:mk_entry ^
/SUBSYSTEM:CONSOLE ^
/STACK:1048576,1048576
if %errorlevel% neq 0 goto :mk_bad
goto :mk_gud

:mk_fail
exit /b 1
goto :mk_end

:mk_bad
exit /b %errorlevel%
goto :mk_end

:mk_gud
goto :mk_end

:mk_outer_bad
@echo Bad.
@exit /b %errorlevel%
@goto :mk_end

:mk_outer_gud
@echo Gud.
@goto :mk_end

:mk_end
