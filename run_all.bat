@echo off
:: Switch to UTF-8 code page
chcp 65001 > nul
echo ===== v2formyfellas - Proxy Download and Testing =====
echo.

REM Creating results directory if it doesn't exist
if not exist "results" mkdir results

REM Current date and time for filenames
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /format:list') do set datetime=%%I
set datestamp=%datetime:~0,8%
set timestamp=%datetime:~8,6%
set filename=configs_%datestamp%_%timestamp%.txt
set output_file=results\%filename%

echo Downloading configurations...
python filter\download_configs.py -s filter\sources.txt -o %output_file%
if %ERRORLEVEL% NEQ 0 (
    echo Error downloading configurations!
    exit /b 1
)

echo.
echo Running basic URL testing...
python -m filter.main %output_file% -o results\working_url_%datestamp%.txt -w 30 --singbox-path bin\sing-box.exe
if %ERRORLEVEL% NEQ 0 (
    echo Warning: URL testing found no working configurations.
)

echo.
echo Running advanced testing...
python -m filter.main results\working_url_%datestamp%.txt -o results\working_advanced_%datestamp%.txt -a -w 30 --singbox-path bin\sing-box.exe
if %ERRORLEVEL% NEQ 0 (
    echo Warning: Advanced testing found no working configurations.
)

echo.
echo Done! Results saved in 'results' directory.
echo All configurations: %output_file%
echo Working URL test: results\working_url_%datestamp%.txt
echo Working advanced test: results\working_advanced_%datestamp%.txt
echo. 