@echo off
setlocal
set "JDK_FAILURE=hardeningw: JDK 17 or newer is required"
set "JAVA_VERSION="
for /f "tokens=3" %%v in ('java -version 2^>^&1') do if not defined JAVA_VERSION set "JAVA_VERSION=%%~v"
if not defined JAVA_VERSION goto :jdk_failure
if "%JAVA_VERSION:~0,2%"=="1." (
    for /f "tokens=2 delims=." %%v in ("%JAVA_VERSION%") do set "JAVA_MAJOR=%%v"
) else (
    for /f "tokens=1 delims=." %%v in ("%JAVA_VERSION%") do set "JAVA_MAJOR=%%v"
)
for /f "delims=0123456789" %%v in ("%JAVA_MAJOR%") do set "JAVA_MAJOR="
if not defined JAVA_MAJOR goto :jdk_failure
if %JAVA_MAJOR% LSS 17 goto :jdk_failure
java "-Dhardening.launcher.source=%~dp0" "%~dp0bootstrap\HardeningLauncher.java" %*
exit /b %ERRORLEVEL%

:jdk_failure
echo %JDK_FAILURE% 1>&2
exit /b 2
