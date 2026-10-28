@echo off
cd /d "%~dp0"
echo ========================================================
echo  Pushing WebTrust to https://github.com/vishnub-lab/webtrust
echo ========================================================
echo.
git add .
git commit -m "Update WebTrust UI, templates, and styling"
git push -u origin main
echo.
if %ERRORLEVEL% equ 0 (
    echo [SUCCESS] WebTrust was successfully pushed to GitHub!
) else (
    echo [NOTE] If a browser window opened, click 'Authorize' to finish.
)
echo.
pause
