@echo off
setlocal enabledelayedexpansion

:: Configuration
set "TARGET_DIR=Include"

:: Generate clean YYYYMMDD_HHMMSS timestamp via PowerShell
for /f "tokens=*" %%a in ('powershell -Command "Get-Date -Format 'yyyyMMdd_HHmmss'"') do set "TIMESTAMP=%%a"

echo 🚀 Executing Open Code Review via Local LM Studio Configuration...
echo 📊 Targets detected: Folder "%TARGET_DIR%"
echo 🔍 Direct local link stream active...
echo -----------------------------------------------------------------

:: Run code review cleanly relying on the stored wizard credentials
:: Capture output as UTF-8 (no BOM) so the report renders on GitHub.
:: Tee-Object is avoided on purpose: Windows PowerShell 5.1 writes its
:: file as UTF-16LE, which GitHub and most Markdown tooling cannot decode.
powershell -NoProfile -Command "& { $path = Join-Path (Get-Location) 'review_report_%TIMESTAMP%.md'; $sw = New-Object System.IO.StreamWriter($path, $false, (New-Object System.Text.UTF8Encoding($false))); try { ocr scan --path '%TARGET_DIR%' --concurrency 1 2>&1 | ForEach-Object { $l = $_.ToString(); Write-Host $l; $sw.WriteLine($l) } } finally { $sw.Dispose() } }"

echo -----------------------------------------------------------------
echo ✅ Code review pipeline run complete.
pause
