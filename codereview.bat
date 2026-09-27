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
::
:: Making the report readable on GitHub takes two independent fixes:
::
::   1. The file has to be UTF-8, not UTF-16LE. Tee-Object -FilePath writes
::      UTF-16LE under Windows PowerShell, which GitHub cannot decode, so the
::      output goes through a StreamWriter with UTF8Encoding(false) instead.
::      The live console echo is kept.
::
::   2. The child output has to be decoded as UTF-8. PowerShell reads a native
::      command's stdout using [Console]::OutputEncoding, which is the OEM code
::      page when this runs from an ordinary console. ocr writes UTF-8, so
::      without this the report is mojibake: a box-drawing character shows up as
::      the three letters "O-tilde o-diaeresis C-cedilla". Setting it before ocr
::      runs fixes both the written file and what the console echo shows.
powershell -NoProfile -Command "& { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $path = Join-Path (Get-Location) 'review_report_%TIMESTAMP%.md'; $sw = New-Object System.IO.StreamWriter($path, $false, (New-Object System.Text.UTF8Encoding($false))); try { ocr scan --path '%TARGET_DIR%' --concurrency 1 2>&1 | ForEach-Object { $l = $_.ToString(); Write-Host $l; $sw.WriteLine($l) } } finally { $sw.Dispose() } }"

echo -----------------------------------------------------------------
echo ✅ Code review pipeline run complete.
pause
