@echo off
setlocal
if not exist starter.txt exit /b 2
set "input="
set /p input=<starter.txt
if not "%input%"=="fixture-v1" exit /b 3
> result.txt echo verified-v1
if errorlevel 1 exit /b 4
set "result="
set /p result=<result.txt
if not "%result%"=="verified-v1" exit /b 5
echo WORKLOAD_OK
exit /b 0
